# tools/nvd_tool.py
# 功能：NVD (National Vulnerability Database) 漏洞查詢 Tool
# Harness 支柱：Graceful Degradation（五層降級瀑布）+ Observability（原子化日誌）
# 擁有者：成員 B（Scout Agent Pipeline）
#
# 使用方式：
#   from tools.nvd_tool import search_nvd
#
# 架構定位：
#   Scout Agent 的「手」— 負責查詢 NVD API 取得 CVE 清單
#   Agent 透過 ReAct 迴圈自動決定何時呼叫此 Tool

import json
import os
import time
import hashlib
import logging
from datetime import datetime, timezone

import requests

logger = logging.getLogger("ThreatHunter")

# ══════════════════════════════════════════════════════════════
# 常數
# ══════════════════════════════════════════════════════════════

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 10  # Agent 輸入的 context 有限，太多 CVE 會導致 LLM 忽略工具輸出
REQUEST_TIMEOUT = 30  # 秒

# Rate limit 控制
RATE_LIMIT_WITH_KEY = 0.6    # 有 API Key: 50 req / 30s → 0.6s 間隔
RATE_LIMIT_WITHOUT_KEY = 6.0  # 無 API Key: 5 req / 30s → 6s 間隔
MAX_RETRIES = 2

# 離線快取
CACHE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
CACHE_TTL = 3600 * 24  # 24 小時過期

# 套件名稱對應表
PACKAGE_MAP_PATH = os.path.join(CACHE_DIR, "package_map.json")

# 上次請求時間（模組級 rate limiter）
_last_request_time = 0.0


# ══════════════════════════════════════════════════════════════
# 輔助函式
# ══════════════════════════════════════════════════════════════

def _load_package_map() -> dict:
    """載入套件名稱對應表，失敗回傳空 dict"""
    try:
        if os.path.exists(PACKAGE_MAP_PATH):
            with open(PACKAGE_MAP_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        logger.warning("[WARN] package_map.json load failed: %s", e)
    return {}


def _normalize_package_name(raw_name: str) -> list[str]:
    """
    將使用者輸入的套件名稱正規化，回傳可能的查詢名稱列表。
    第一個是最可能的，後續是別名備選。

    例如：
      "postgres" → ["postgresql", "postgres"]
      "django"   → ["django"]
    """
    name = raw_name.strip().lower()
    # 去掉版本號（如 "django 4.2" → "django"）
    name = name.split()[0] if " " in name else name

    pkg_map = _load_package_map()
    candidates = []

    if name in pkg_map:
        mapped = pkg_map[name]
        candidates.append(mapped)
        if mapped != name:
            candidates.append(name)
    else:
        candidates.append(name)
        # 反查：看有沒有別名指向自己
        for alias, target in pkg_map.items():
            if target == name and alias not in candidates:
                candidates.append(alias)

    return candidates


def _get_cache_path(package_name: str) -> str:
    """取得離線快取檔案路徑"""
    safe_name = hashlib.md5(package_name.encode()).hexdigest()[:12]
    return os.path.join(CACHE_DIR, f"nvd_cache_{package_name}_{safe_name}.json")


def _read_cache(package_name: str) -> dict | None:
    """讀取離線快取，過期或不存在回傳 None"""
    cache_path = _get_cache_path(package_name)
    try:
        if os.path.exists(cache_path):
            with open(cache_path, "r", encoding="utf-8") as f:
                cached = json.load(f)
            cached_time = cached.get("_cached_at", 0)
            if time.time() - cached_time < CACHE_TTL:
                logger.info("[OK] NVD cache hit: %s", package_name)
                return cached
            else:
                logger.info("[INFO] NVD cache expired: %s", package_name)
    except (json.JSONDecodeError, IOError) as e:
        logger.warning("[WARN] NVD cache read failed: %s", e)
    return None


def _write_cache(package_name: str, data: dict) -> None:
    """寫入離線快取"""
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        cache_path = _get_cache_path(package_name)
        data["_cached_at"] = time.time()
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except (IOError, PermissionError) as e:
        logger.warning("[WARN] NVD cache write failed: %s", e)


def _rate_limit() -> None:
    """Rate limiter — 確保不超過 NVD API 限速"""
    global _last_request_time
    api_key = os.getenv("NVD_API_KEY", "")
    interval = RATE_LIMIT_WITH_KEY if api_key else RATE_LIMIT_WITHOUT_KEY
    elapsed = time.time() - _last_request_time
    if elapsed < interval:
        wait = interval - elapsed
        logger.info("[WAIT] NVD rate limit: waiting %.1fs", wait)
        time.sleep(wait)
    _last_request_time = time.time()


def _extract_cvss(metrics: dict) -> tuple[float, str]:
    """
    從 NVD metrics 中提取 CVSS 分數和嚴重度。
    優先 v3.1 → v3.0 → v2 → 預設值。

    Returns:
        (cvss_score, severity)
    """
    # 嘗試 CVSS v3.1
    v31 = metrics.get("cvssMetricV31", [])
    if v31:
        data = v31[0].get("cvssData", {})
        score = data.get("baseScore", 0.0)
        severity = data.get("baseSeverity", "")
        if score and severity:
            return float(score), severity.upper()

    # 嘗試 CVSS v3.0
    v30 = metrics.get("cvssMetricV30", [])
    if v30:
        data = v30[0].get("cvssData", {})
        score = data.get("baseScore", 0.0)
        severity = data.get("baseSeverity", "")
        if score and severity:
            return float(score), severity.upper()

    # 嘗試 CVSS v2（備用）
    v2 = metrics.get("cvssMetricV2", [])
    if v2:
        data = v2[0].get("cvssData", {})
        score = data.get("baseScore", 0.0)
        if score:
            severity = _cvss_to_severity(float(score))
            return float(score), severity

    return 0.0, "LOW"


def _cvss_to_severity(score: float) -> str:
    """CVSS 分數 → 嚴重度等級轉換（僅在 API 未提供 severity 時使用）"""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"


def _extract_affected_versions(configurations: list) -> str:
    """嘗試從 NVD configurations 提取受影響版本範圍"""
    versions = []
    try:
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable", False):
                        cpe = cpe_match.get("criteria", "")
                        version_start = cpe_match.get("versionStartIncluding", "")
                        version_end = cpe_match.get("versionEndExcluding", "")
                        version_end_incl = cpe_match.get("versionEndIncluding", "")

                        if version_end:
                            versions.append(f"< {version_end}")
                        elif version_end_incl:
                            versions.append(f"<= {version_end_incl}")
                        elif version_start:
                            versions.append(f">= {version_start}")
                        elif cpe:
                            # 從 CPE URI 提取版本
                            parts = cpe.split(":")
                            if len(parts) > 5 and parts[5] not in ("*", "-"):
                                versions.append(parts[5])
    except (KeyError, IndexError, TypeError):
        pass

    return ", ".join(versions[:3]) if versions else ""


def _extract_description(descriptions: list) -> str:
    """提取英文描述，優先 en，fallback 到第一個"""
    for desc in descriptions:
        if desc.get("lang", "") == "en":
            return desc.get("value", "")
    if descriptions:
        return descriptions[0].get("value", "")
    return ""


# ══════════════════════════════════════════════════════════════
# 核心查詢邏輯
# ══════════════════════════════════════════════════════════════

def _query_nvd_api(keyword: str) -> dict | None:
    """
    呼叫 NVD API，回傳原始 JSON response dict。
    失敗回傳 None。

    包含：
      - Rate limiting
      - 重試機制（最多 MAX_RETRIES 次）
      - Timeout 處理
    """
    api_key = os.getenv("NVD_API_KEY", "")

    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": RESULTS_PER_PAGE,
    }

    for attempt in range(1, MAX_RETRIES + 1):
        _rate_limit()
        try:
            logger.info("[QUERY] NVD API: %s (attempt %d)", keyword, attempt)
            response = requests.get(
                NVD_API_BASE,
                params=params,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )

            if response.status_code == 200:
                return response.json()

            if response.status_code == 403:
                logger.warning("[WARN] NVD API 403 (rate limited), retrying...")
                time.sleep(RATE_LIMIT_WITHOUT_KEY * 2)
                continue

            if response.status_code >= 500:
                logger.warning("[WARN] NVD API %d (server error)", response.status_code)
                time.sleep(2)
                continue

            # 其他錯誤碼
            logger.warning("[WARN] NVD API returned %d: %s", response.status_code, response.text[:200])
            return None

        except requests.exceptions.Timeout:
            logger.warning("[WARN] NVD API timeout (%ds)", REQUEST_TIMEOUT)
            continue
        except requests.exceptions.ConnectionError:
            logger.warning("[WARN] NVD API connection failed (network issue)")
            continue
        except requests.exceptions.RequestException as e:
            logger.warning("[WARN] NVD API request error: %s", e)
            return None

    return None  # 所有重試都失敗


def _parse_nvd_response(raw: dict, package_name: str) -> dict:
    """
    將 NVD API 原始 response 轉換為 Tool 輸出格式。

    轉換 mapping（見 architecture_spec.md §4.1）:
      response.vulnerabilities[].cve.id              → cve_id
      response.vulnerabilities[].cve.descriptions     → description
      response.vulnerabilities[].cve.metrics          → cvss_score, severity
      response.vulnerabilities[].cve.configurations   → affected_versions
    """
    vulnerabilities = []
    raw_vulns = raw.get("vulnerabilities", [])

    for item in raw_vulns:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")

        # 跳過非標準 CVE ID
        if not cve_id.startswith("CVE-"):
            continue

        description = _extract_description(cve.get("descriptions", []))
        metrics = cve.get("metrics", {})
        cvss_score, severity = _extract_cvss(metrics)
        published = cve.get("published", "")
        configurations = cve.get("configurations", [])
        affected_versions = _extract_affected_versions(configurations)

        vulnerabilities.append({
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "severity": severity,
            "description": description[:500],  # 截斷過長描述
            "published": published,
            "affected_versions": affected_versions,
        })

    # 按 CVSS 分數降序排列（最危險的在最前面）
    vulnerabilities.sort(key=lambda v: v["cvss_score"], reverse=True)

    return {
        "package": package_name,
        "source": "NVD",
        "count": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
    }


def _search_nvd_impl(package_name: str) -> str:
    """
    search_nvd 的核心實作（與 CrewAI @tool 解耦，方便單元測試）。

    五層降級瀑布：
      1. 正規化名稱 → 嘗試首選名稱查 API
      2. API 失敗 → 嘗試別名查 API
      3. 所有別名都失敗 → 讀離線快取
      4. 快取也沒有 → 回傳空結果 + error 訊息
      5. 任何未預期錯誤 → 回傳安全的空結果（絕不 crash）
    """
    try:
        candidates = _normalize_package_name(package_name)
        logger.info("[QUERY] NVD package: %s -> candidates: %s", package_name, candidates)

        # ── 第一優先：讀取本地快取（Cache-First，避免 API timeout 浪費時間）──
        for keyword in candidates:
            cached = _read_cache(keyword)
            if cached:
                cached.pop("_cached_at", None)
                cached["fallback_used"] = False  # 快取命中不算降級
                logger.info("[OK] NVD cache hit (cache-first): %s -> %d CVEs",
                            keyword, len(cached.get("vulnerabilities", [])))
                return json.dumps(cached, ensure_ascii=False, indent=2)

        # ── 第二優先：呼叫 NVD API（快取未命中才嘗試）──
        for keyword in candidates:
            raw = _query_nvd_api(keyword)

            if raw is not None:
                result = _parse_nvd_response(raw, package_name)

                if result["count"] > 0:
                    # 成功！寫入快取供離線使用
                    _write_cache(keyword, result)
                    logger.info(
                        "[OK] NVD API query success: %s -> %d CVEs", package_name, result['count']
                    )
                    return json.dumps(result, ensure_ascii=False, indent=2)

                # API 回傳成功但 0 筆結果 → 嘗試下一個別名
                logger.info("[INFO] NVD no results for: %s, trying next alias", keyword)
                continue

            # API 失敗 → 再次嘗試快取（理論上已在第一步命中，這是防禦層）
            cached = _read_cache(keyword)
            if cached:
                cached.pop("_cached_at", None)
                cached["fallback_used"] = True
                cached["error"] = f"NVD API unavailable, using cached data for '{keyword}'"
                logger.info("[OK] NVD cache fallback (after API fail): %s", keyword)
                return json.dumps(cached, ensure_ascii=False, indent=2)

        # 所有候選名稱都查不到
        empty_result = {
            "package": package_name,
            "source": "NVD",
            "count": 0,
            "vulnerabilities": [],
            "error": f"No vulnerabilities found for '{package_name}' (tried: {candidates})",
            "fallback_used": False,
        }
        logger.info("[INFO] NVD no results for: %s", package_name)
        return json.dumps(empty_result, ensure_ascii=False, indent=2)

    except Exception as e:
        # 最後一道防線：任何未預期錯誤都不能讓 Agent crash
        logger.error("[FAIL] NVD Tool unexpected error: %s", e, exc_info=True)
        error_result = {
            "package": package_name,
            "source": "NVD",
            "count": 0,
            "vulnerabilities": [],
            "error": f"Unexpected error: {str(e)}",
            "fallback_used": False,
        }
        return json.dumps(error_result, ensure_ascii=False, indent=2)


# ══════════════════════════════════════════════════════════════
# CrewAI @tool 包裝（Agent 呼叫用）
# ══════════════════════════════════════════════════════════════

def _create_tool():
    """延遲建立 CrewAI Tool，僅在 Agent 實際使用時才 import"""
    from crewai.tools import tool

    @tool("search_nvd")
    def search_nvd(package_name: str) -> str:
        """查詢 NVD (National Vulnerability Database) 中指定套件的已知漏洞。
輸入套件名稱（如 django、redis、postgresql），回傳該套件的 CVE 漏洞清單（JSON 格式）。
包含 CVE 編號、CVSS 分數、嚴重度、描述、受影響版本等資訊。
若 API 不可用會自動使用離線快取。"""
        return _search_nvd_impl(package_name)

    return search_nvd


# ── 延遲載入機制（與 memory_tool.py 相同模式）──────────────────

class _LazyToolLoader:
    def __init__(self):
        self._tool = None

    def _load(self):
        if self._tool is None:
            self._tool = _create_tool()

    @property
    def search_nvd(self):
        self._load()
        return self._tool


_loader = _LazyToolLoader()


def __getattr__(name):
    """模組層級 __getattr__，支援 from tools.nvd_tool import search_nvd"""
    if name == "search_nvd":
        return _loader.search_nvd
    raise AttributeError(f"module 'tools.nvd_tool' has no attribute {name!r}")
