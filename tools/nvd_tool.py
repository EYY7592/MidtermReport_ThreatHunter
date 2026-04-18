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
    呼叫 NVD API，以 keywordSearch 全文搜尋。
    失敗回傳 None。
    """
    api_key = os.getenv("NVD_API_KEY", "")
    headers = {"apiKey": api_key} if api_key else {}
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": RESULTS_PER_PAGE,
    }
    for attempt in range(1, MAX_RETRIES + 1):
        _rate_limit()
        try:
            logger.info("[QUERY] NVD keywordSearch: %s (attempt %d)", keyword, attempt)
            response = requests.get(NVD_API_BASE, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
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
    return None


def _query_nvd_api_cpe(cpe_name: str) -> dict | None:
    """
    呼叫 NVD API，以 cpeName 精確搜尋。
    比 keywordSearch 精確 — 只回傳受影響 CPE 比對成功的 CVE，
    避免語法關鍵字（eval、html 等）污染結果。
    失敗回傳 None。
    """
    api_key = os.getenv("NVD_API_KEY", "")
    headers = {"apiKey": api_key} if api_key else {}
    params = {
        "cpeName": cpe_name,
        "resultsPerPage": RESULTS_PER_PAGE,
    }
    for attempt in range(1, MAX_RETRIES + 1):
        _rate_limit()
        try:
            logger.info("[QUERY] NVD cpeName: %s (attempt %d)", cpe_name, attempt)
            response = requests.get(NVD_API_BASE, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                return response.json()
            if response.status_code == 403:
                logger.warning("[WARN] NVD API 403 (rate limited), retrying...")
                time.sleep(RATE_LIMIT_WITHOUT_KEY * 2)
                continue
            if response.status_code >= 500:
                time.sleep(2)
                continue
            logger.warning("[WARN] NVD cpeName returned %d", response.status_code)
            return None
        except requests.exceptions.Timeout:
            continue
        except requests.exceptions.ConnectionError:
            continue
        except requests.exceptions.RequestException as e:
            logger.warning("[WARN] NVD cpe request error: %s", e)
            return None
    return None


def _extract_cpe_vendors(configurations: list) -> list[str]:
    """
    從 NVD configurations 提取受影響 CPE 的 vendor:product 組合。
    供 Analyst CPE 相關性過濾使用。
    回傳格式如：["nodejs:node.js", "expressjs:express"]
    """
    vendors = []
    try:
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable", False):
                        cpe = cpe_match.get("criteria", "")
                        parts = cpe.split(":")
                        # cpe:2.3:a:vendor:product:version:...
                        if len(parts) >= 5:
                            vendor_product = f"{parts[3]}:{parts[4]}"
                            if vendor_product not in vendors:
                                vendors.append(vendor_product)
    except (KeyError, IndexError, TypeError):
        pass
    return vendors[:10]


def _parse_nvd_response(raw: dict, package_name: str) -> dict:
    """
    將 NVD API 原始 response 轉換為 Tool 輸出格式。
    v3.8: 輸出 cpe_vendors 供 Analyst 做相關性驗證。
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
        cpe_vendors = _extract_cpe_vendors(configurations)  # v3.8: 供相關性驗證

        vulnerabilities.append({
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "severity": severity,
            "description": description[:500],
            "published": published,
            "affected_versions": affected_versions,
            "cpe_vendors": cpe_vendors,  # v3.8: Analyst 用於 CPE 相關性過濾
        })

    # 按 CVSS 分數降序排列（最危險的在最前面）
    vulnerabilities.sort(key=lambda v: v["cvss_score"], reverse=True)

    return {
        "package": package_name,
        "source": "NVD",
        "count": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
    }


# CPE 名稱推斷對應表（套件名 → NVD CPE vendor:product）
# 未命中的套件 fallback 到 keywordSearch
PACKAGE_CPE_MAP: dict[str, str] = {
    # Node.js 生態
    "express":      "cpe:2.3:a:expressjs:express:*:*:*:*:*:*:*:*",
    "node":         "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*",
    "nodejs":       "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*",
    "lodash":       "cpe:2.3:a:lodash:lodash:*:*:*:*:*:*:*:*",
    "axios":        "cpe:2.3:a:axios:axios:*:*:*:*:*:node.js:*:*",
    "webpack":      "cpe:2.3:a:webpack:webpack:*:*:*:*:*:node.js:*:*",
    "moment":       "cpe:2.3:a:momentjs:moment.js:*:*:*:*:*:node.js:*:*",
    "next":         "cpe:2.3:a:vercel:next.js:*:*:*:*:*:node.js:*:*",
    "nextjs":       "cpe:2.3:a:vercel:next.js:*:*:*:*:*:node.js:*:*",
    "react":        "cpe:2.3:a:facebook:react:*:*:*:*:*:node.js:*:*",
    "vue":          "cpe:2.3:a:vuejs:vue.js:*:*:*:*:*:node.js:*:*",
    "angular":      "cpe:2.3:a:google:angular.js:*:*:*:*:*:node.js:*:*",
    # Python 生態
    "django":       "cpe:2.3:a:djangoproject:django:*:*:*:*:*:*:*:*",
    "flask":        "cpe:2.3:a:palletsprojects:flask:*:*:*:*:*:*:*:*",
    "requests":     "cpe:2.3:a:python-requests:requests:*:*:*:*:*:*:*:*",
    "pillow":       "cpe:2.3:a:python:pillow:*:*:*:*:*:*:*:*",
    "pyyaml":       "cpe:2.3:a:pyyaml:pyyaml:*:*:*:*:*:*:*:*",
    "cryptography": "cpe:2.3:a:cryptography.io:cryptography:*:*:*:*:*:python:*:*",
    "jinja2":       "cpe:2.3:a:palletsprojects:jinja:*:*:*:*:*:python:*:*",
    "werkzeug":     "cpe:2.3:a:palletsprojects:werkzeug:*:*:*:*:*:python:*:*",
    "sqlalchemy":   "cpe:2.3:a:sqlalchemy:sqlalchemy:*:*:*:*:*:*:*:*",
    # Java 生態
    "log4j":        "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
    "spring":       "cpe:2.3:a:pivotal_software:spring_framework:*:*:*:*:*:*:*:*",
    "struts":       "cpe:2.3:a:apache:struts:*:*:*:*:*:*:*:*",
    # Go 生態
    "go":           "cpe:2.3:a:golang:go:*:*:*:*:*:*:*:*",
    # DB
    "redis":        "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*",
    "postgresql":   "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
    "postgres":     "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
    "mysql":        "cpe:2.3:a:mysql:mysql:*:*:*:*:*:*:*:*",
    "mongodb":      "cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*",
    "nginx":        "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
    "openssl":      "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
}


def _search_nvd_impl(package_name: str) -> str:
    """
    search_nvd 核心實作（v3.8）。

    搜尋策略優先順序：
      1. 快取命中 → 直接回傳（Cache-First）
      2. CPE 精確搜尋（PACKAGE_CPE_MAP 命中時）→ 只回傳真正影響該套件的 CVE
      3. Keyword 全文搜尋（CPE 未命中 fallback）
      4. 離線快取 fallback
      5. 回傳空結果（絕不 crash）
    """
    try:
        candidates = _normalize_package_name(package_name)
        logger.info("[QUERY] NVD package: %s -> candidates: %s", package_name, candidates)

        # ── 1. Cache-First ──────────────────────────────────────────
        for keyword in candidates:
            cached = _read_cache(keyword)
            if cached:
                cached.pop("_cached_at", None)
                cached["fallback_used"] = False
                logger.info("[OK] NVD cache hit: %s -> %d CVEs",
                            keyword, len(cached.get("vulnerabilities", [])))
                return json.dumps(cached, ensure_ascii=False, indent=2)

        # ── 2. CPE 精確搜尋（防止語法關鍵字污染 NVD 結果）──────────
        primary = candidates[0]
        cpe_name = PACKAGE_CPE_MAP.get(primary)
        if cpe_name:
            raw = _query_nvd_api_cpe(cpe_name)
            if raw is not None:
                result = _parse_nvd_response(raw, package_name)
                result["search_mode"] = "cpe"
                if result["count"] > 0:
                    _write_cache(primary, result)
                    logger.info("[OK] NVD CPE query: %s -> %d CVEs", package_name, result["count"])
                    return json.dumps(result, ensure_ascii=False, indent=2)
                logger.info("[INFO] NVD CPE no results for: %s", primary)

        # ── 3. Keyword 搜尋（fallback，僅對套件名本身 — 非程式碼關鍵字）──
        for keyword in candidates:
            raw = _query_nvd_api(keyword)
            if raw is not None:
                result = _parse_nvd_response(raw, package_name)
                result["search_mode"] = "keyword"
                if result["count"] > 0:
                    _write_cache(keyword, result)
                    logger.info("[OK] NVD keyword query: %s -> %d CVEs", package_name, result["count"])
                    return json.dumps(result, ensure_ascii=False, indent=2)
                logger.info("[INFO] NVD keyword no results for: %s, trying next alias", keyword)
                continue
            cached = _read_cache(keyword)
            if cached:
                cached.pop("_cached_at", None)
                cached["fallback_used"] = True
                cached["error"] = f"NVD API unavailable, using cached data for '{keyword}'"
                return json.dumps(cached, ensure_ascii=False, indent=2)

        # ── 4. 全部查不到 ──────────────────────────────────────────
        empty_result = {
            "package": package_name,
            "source": "NVD",
            "count": 0,
            "vulnerabilities": [],
            "search_mode": "none",
            "error": f"No vulnerabilities found for '{package_name}' (tried: {candidates})",
            "fallback_used": False,
        }
        logger.info("[INFO] NVD no results for: %s", package_name)
        return json.dumps(empty_result, ensure_ascii=False, indent=2)

    except Exception as e:
        logger.error("[FAIL] NVD Tool unexpected error: %s", e, exc_info=True)
        return json.dumps({
            "package": package_name, "source": "NVD", "count": 0,
            "vulnerabilities": [], "error": f"Unexpected error: {str(e)}",
            "fallback_used": False,
        }, ensure_ascii=False, indent=2)


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
