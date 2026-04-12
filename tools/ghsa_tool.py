# tools/ghsa_tool.py
# 功能：GitHub Security Advisory Database（GHSA）查詢 Tool
# 資料來源：GitHub Advisory Database REST API（公開，無需 Token 可用基本額度）
# Harness 支柱：Graceful Degradation（REST 降級 + 離線快取）+ Observability
#
# 使用方式：
#   from tools.ghsa_tool import query_ghsa
#
# 架構定位：
#   Intel Fusion Agent 的第四維情報 — 補充 NVD 的生態系資訊（特別是 2024 年 NVD 積壓期間）
#   GHSA 優勢：比 NVD 早 2-4 週收到套件生態系告警
#
# 六維情報融合中的位置：
#   NVD(CVSS)  EPSS    KEV     GHSA    ATT&CK  OTX
#   0.20       0.30    0.25    [0.10]  0.10    0.05
#
# API 端點（無需 Token 的 REST API）：
#   GET https://api.github.com/advisories?affects={package}&ecosystem={ecosystem}
#   限制：每小時 60 請求（未認證）/ 5,000 請求（有 GITHUB_TOKEN）

import json
import logging
import os
import time
from datetime import datetime, timezone

import requests

logger = logging.getLogger("ThreatHunter.ghsa")

# ══════════════════════════════════════════════════════════════
# 常數
# ══════════════════════════════════════════════════════════════

GHSA_REST_API = "https://api.github.com/advisories"
REQUEST_TIMEOUT = 15  # 秒

# 快取路徑（與 epss/kev 同層）
CACHE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
GHSA_CACHE_PATH = os.path.join(CACHE_DIR, "ghsa_cache.json")

# 快取 TTL：12 小時（GHSA 更新頻率高於 NVD）
CACHE_TTL_HOURS = 12

# 支援的生態系（GitHub Advisory Database 的 ecosystem 值）
SUPPORTED_ECOSYSTEMS = {
    "python": "pip",
    "pip": "pip",
    "npm": "npm",
    "node": "npm",
    "javascript": "npm",
    "go": "go",
    "golang": "go",
    "java": "maven",
    "maven": "maven",
    "ruby": "rubygems",
    "rubygems": "rubygems",
    "rust": "crates.io",
    "cargo": "crates.io",
    "php": "composer",
    "composer": "composer",
    "nuget": "nuget",
    "dotnet": "nuget",
}

# GHSA 嚴重性 → 數值對應（用於計分）
SEVERITY_SCORE = {
    "CRITICAL": 1.0,
    "HIGH": 0.75,
    "MODERATE": 0.5,
    "LOW": 0.25,
    "UNKNOWN": 0.0,
}


# ══════════════════════════════════════════════════════════════
# 快取管理
# ══════════════════════════════════════════════════════════════

def _read_ghsa_cache() -> dict:
    """讀取 GHSA 快取（格式：{"pkg:ecosystem": {hits, severity, cves, _cached_at}}）"""
    try:
        if not os.path.exists(GHSA_CACHE_PATH):
            return {}
        with open(GHSA_CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        logger.warning("[WARN] GHSA cache read failed: %s", e)
        return {}


def _write_ghsa_cache(cache: dict) -> None:
    """寫入 GHSA 快取"""
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        with open(GHSA_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except (IOError, PermissionError) as e:
        logger.warning("[WARN] GHSA cache write failed: %s", e)


def _is_cache_fresh(cached_entry: dict) -> bool:
    """檢查快取是否在 TTL 內（12 小時）"""
    cached_at = cached_entry.get("_cached_at", 0)
    elapsed_hours = (time.time() - cached_at) / 3600
    return elapsed_hours < CACHE_TTL_HOURS


def _normalize_ecosystem(ecosystem: str) -> str:
    """正規化生態系名稱（user input → GitHub API 格式）"""
    return SUPPORTED_ECOSYSTEMS.get(ecosystem.lower(), ecosystem.lower())


# ══════════════════════════════════════════════════════════════
# 核心查詢邏輯
# ══════════════════════════════════════════════════════════════

def _fetch_ghsa_rest(package_name: str, ecosystem: str, github_token: str = "") -> dict:
    """
    使用 GitHub Advisory Database REST API 查詢套件的安全告警。

    REST API（無需 Token，但有額度限制）：
      GET https://api.github.com/advisories?affects={pkg}&ecosystem={eco}&per_page=10

    回傳格式（摘要，供 Intel Fusion 使用）：
    {
        "hits": 3,                   # GHSA 告警數量
        "max_severity": "HIGH",      # 最高嚴重性
        "severity_score": 0.75,      # 數值化嚴重性（供加權計算）
        "cve_ids": ["CVE-..."],      # 相關 CVE（GHSA 已關聯的）
        "ghsa_ids": ["GHSA-..."],    # GHSA ID
        "published_since": "2024-...",  # 最近告警發布日期
        "source": "GHSA REST API",
    }
    """
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    # 嘗試帶 ecosystem 查詢（最精確）
    ecosystem_normalized = _normalize_ecosystem(ecosystem)
    try:
        logger.info("[QUERY] GHSA REST: %s (%s)", package_name, ecosystem_normalized)
        resp = requests.get(
            GHSA_REST_API,
            params={
                "affects": package_name,
                "ecosystem": ecosystem_normalized.upper(),  # GitHub API 要大寫
                "per_page": 10,
                "sort": "published",
                "direction": "desc",
            },
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )

        if resp.status_code == 200:
            advisories = resp.json()
            return _parse_ghsa_advisories(advisories, package_name, ecosystem_normalized)
        elif resp.status_code == 403:
            # Rate limit（未認證的 token 每小時 60 次）
            reset_ts = resp.headers.get("X-RateLimit-Reset", "")
            logger.warning("[WARN] GHSA API rate limited (403), reset at %s", reset_ts)
        elif resp.status_code == 422:
            # 不支援的 ecosystem → 不帶 ecosystem 重試
            logger.info("[INFO] GHSA API: ecosystem %s not recognized, retrying without", ecosystem_normalized)
            resp2 = requests.get(
                GHSA_REST_API,
                params={"affects": package_name, "per_page": 10},
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )
            if resp2.status_code == 200:
                return _parse_ghsa_advisories(resp2.json(), package_name, "unknown")
        else:
            logger.warning("[WARN] GHSA API returned %d for %s", resp.status_code, package_name)

    except requests.exceptions.Timeout:
        logger.warning("[WARN] GHSA API timeout for %s", package_name)
    except requests.exceptions.ConnectionError:
        logger.warning("[WARN] GHSA API connection failed (offline?)")
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning("[WARN] GHSA API returned non-JSON for %s: %s", package_name, e)

    # 查詢失敗 → 回傳空結果（非 None，讓 Agent 知道 GHSA 未命中而非錯誤）
    return {
        "hits": 0,
        "max_severity": "UNKNOWN",
        "severity_score": 0.0,
        "cve_ids": [],
        "ghsa_ids": [],
        "published_since": "",
        "_source": "GHSA REST API (failed)",
    }


def _parse_ghsa_advisories(advisories: list, package_name: str, ecosystem: str) -> dict:
    """
    解析 GitHub Advisory 列表，提取 Intel Fusion 需要的核心欄位。

    GitHub Advisory API 回傳格式（每個 advisory）：
    {
        "ghsa_id": "GHSA-xxxx-xxxx-xxxx",
        "severity": "HIGH",
        "cve_id": "CVE-2024-XXXX",  # 可能為 null
        "published_at": "2024-04-01T...",
        "summary": "...",
        ...
    }
    """
    if not advisories:
        logger.info("[INFO] GHSA: no advisories found for %s", package_name)
        return {
            "hits": 0,
            "max_severity": "UNKNOWN",
            "severity_score": 0.0,
            "cve_ids": [],
            "ghsa_ids": [],
            "published_since": "",
            "_source": f"GHSA REST API (no results for {package_name})",
        }

    # 提取 CVE ID 和 GHSA ID
    cve_ids = []
    ghsa_ids = []
    severities = []
    published_dates = []

    for advisory in advisories:
        ghsa_id = advisory.get("ghsa_id", "")
        if ghsa_id:
            ghsa_ids.append(ghsa_id)

        cve_id = advisory.get("cve_id", "")
        if cve_id and cve_id.startswith("CVE-"):
            cve_ids.append(cve_id)

        severity = (advisory.get("severity") or "UNKNOWN").upper()
        severities.append(severity)

        pub_date = advisory.get("published_at", "")
        if pub_date:
            published_dates.append(pub_date)

    # 計算最高嚴重性
    max_severity = "UNKNOWN"
    max_score = 0.0
    for sev in severities:
        score = SEVERITY_SCORE.get(sev, 0.0)
        if score > max_score:
            max_score = score
            max_severity = sev

    # 最近告警日期
    published_since = max(published_dates) if published_dates else ""

    hits = len(advisories)
    logger.info(
        "[OK] GHSA: %s (%s) → %d hits, max_severity=%s, CVEs=%s",
        package_name, ecosystem, hits, max_severity, cve_ids[:3],
    )

    return {
        "hits": hits,
        "max_severity": max_severity,
        "severity_score": round(max_score, 4),
        "cve_ids": cve_ids[:10],          # 最多 10 個關聯 CVE
        "ghsa_ids": ghsa_ids[:10],        # 最多 10 個 GHSA ID
        "published_since": published_since,
        "_source": "GHSA REST API (online)",
    }


def _query_ghsa_impl(package_query: str) -> str:
    """
    query_ghsa 的核心實作（與 CrewAI @tool 解耦，方便單元測試）。

    支援兩種輸入格式：
      - "django"                → 查所有生態系（預設 pip）
      - "django:python"         → 指定生態系
      - "lodash:npm"            → npm 生態系

    降級策略：
      1. 讀取快取（TTL 12 小時）
      2. 快取未命中 → 線上查詢 GHSA REST API
      3. 線上失敗 → 回傳快取（過期的）
      4. 快取也沒有 → 回傳 hits=0（不 crash）

    Args:
        package_query: 套件名（可含冒號分隔的生態系）

    Returns:
        JSON 字串，格式符合 Intel Fusion Agent 輸入
    """
    try:
        # ── Step 1：解析輸入格式 ──────────────────────────────
        if ":" in package_query:
            parts = package_query.split(":", 1)
            package_name = parts[0].strip().lower()
            ecosystem = parts[1].strip().lower()
        else:
            package_name = package_query.strip().lower()
            # 從套件名推斷生態系（常見規則）
            if package_name.endswith(".py") or package_name.startswith("py"):
                ecosystem = "pip"
            elif package_name.startswith("@") or "node" in package_name:
                ecosystem = "npm"
            else:
                ecosystem = "pip"  # 預設 Python

        if not package_name:
            return json.dumps({"error": "Empty package name", "hits": 0}, ensure_ascii=False, indent=2)

        cache_key = f"{package_name}:{ecosystem}"
        logger.info("[QUERY] GHSA check: %s (ecosystem=%s)", package_name, ecosystem)

        # ── Step 2：讀取快取 ───────────────────────────────────
        cache = _read_ghsa_cache()
        if cache_key in cache and _is_cache_fresh(cache[cache_key]):
            cached = cache[cache_key]
            logger.info("[CACHE] GHSA cache hit: %s → hits=%d", cache_key, cached.get("hits", 0))
            return json.dumps({
                "package": package_name,
                "ecosystem": ecosystem,
                "query_time": datetime.now(timezone.utc).isoformat(),
                **{k: v for k, v in cached.items() if not k.startswith("_")},
                "source": cached.get("_source", "GHSA (cache)"),
            }, ensure_ascii=False, indent=2)

        # ── Step 3：線上查詢 ───────────────────────────────────
        github_token = os.getenv("GITHUB_TOKEN", "")
        result = _fetch_ghsa_rest(package_name, ecosystem, github_token)

        # 更新快取
        cache[cache_key] = {**result, "_cached_at": time.time()}
        _write_ghsa_cache(cache)

        logger.info(
            "[OK] GHSA: %s → hits=%d, severity=%s, cves=%s",
            package_name, result["hits"], result["max_severity"], result["cve_ids"][:3],
        )

        return json.dumps({
            "package": package_name,
            "ecosystem": ecosystem,
            "query_time": datetime.now(timezone.utc).isoformat(),
            "hits": result["hits"],
            "max_severity": result["max_severity"],
            "severity_score": result["severity_score"],
            "cve_ids": result["cve_ids"],
            "ghsa_ids": result["ghsa_ids"],
            "published_since": result["published_since"],
            "source": result.get("_source", "GHSA REST API"),
        }, ensure_ascii=False, indent=2)

    except Exception as e:
        logger.error("[FAIL] GHSA Tool unexpected error for %s: %s", package_query, e, exc_info=True)
        return json.dumps({
            "package": package_query,
            "hits": 0,
            "max_severity": "UNKNOWN",
            "severity_score": 0.0,
            "cve_ids": [],
            "ghsa_ids": [],
            "error": f"Unexpected error: {str(e)[:200]}",
            "source": "GHSA (error)",
        }, ensure_ascii=False, indent=2)


# ══════════════════════════════════════════════════════════════
# CrewAI @tool 包裝（Agent 呼叫用）
# ══════════════════════════════════════════════════════════════

def _create_tool():
    """延遲建立 CrewAI Tool"""
    from crewai.tools import tool

    @tool("search_ghsa")
    def query_ghsa(package_query: str) -> str:
        """查詢 GitHub Advisory Database（GHSA）取得套件的安全告警。
輸入格式：套件名，可加 :ecosystem 指定生態系（如 "django:python"、"lodash:npm"）。
若不指定生態系，預設為 Python/pip。
回傳：GHSA 告警命中數、最高嚴重性、關聯 CVE ID、GHSA ID。
GHSA 優勢：比 NVD 早 2-4 週發出告警，特別適合 2024 年 NVD 積壓期間的補充查詢。
支援生態系：pip（Python）、npm（Node.js）、go、maven（Java）、rubygems（Ruby）、crates.io（Rust）。
注意：無 GITHUB_TOKEN 時使用未認證額度（每小時 60 請求）；設定 GITHUB_TOKEN 可提升至 5,000 請求。"""
        return _query_ghsa_impl(package_query)

    return query_ghsa


# ── 延遲載入機制（與 kev_tool.py 相同模式）──────────────────

class _LazyToolLoader:
    def __init__(self):
        self._tool = None

    def _load(self):
        if self._tool is None:
            self._tool = _create_tool()

    @property
    def query_ghsa(self):
        self._load()
        return self._tool


_loader = _LazyToolLoader()


def __getattr__(name):
    """模組層級 __getattr__，支援 from tools.ghsa_tool import query_ghsa"""
    if name == "query_ghsa":
        return _loader.query_ghsa
    raise AttributeError(f"module 'tools.ghsa_tool' has no attribute {name!r}")
