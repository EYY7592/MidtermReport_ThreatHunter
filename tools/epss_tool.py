# tools/epss_tool.py
# 功能：FIRST.org EPSS (Exploit Prediction Scoring System) 查詢
# 架構定位：補全 Intel Fusion 六維分析的 EPSS 維度（權重 30%，最重要）
#
# EPSS 是什麼：
#   Exploit Prediction Scoring System — 預測 CVE 在接下來 30 天內被野外利用的機率
#   數值 0.0-1.0，0.94 = 94% 機率在野外被利用（如 Log4Shell）
#
# 為何重要：
#   - Intel Fusion 六維中 EPSS 佔 30% 權重
#   - 目前 EPSS 是 LLM 自己猜的（無 API 驗證）→ 現在改為真實 API 查詢
#   - 佐證：Jacobs et al. (2023) WEIS — EPSS 比 CVSS 更能預測實際利用
#
# API 格式（GET）：
#   https://api.first.org/data/v1/epss?cve=CVE-2021-44228
#   Response: {"data": [{"cve": "CVE-...", "epss": "0.943580000", "percentile": "0.999620000"}]}
#
# 使用方式：
#   from tools.epss_tool import fetch_epss_score

import json
import os
import time
import hashlib
import logging
from datetime import datetime, timezone

import requests

# 將 CrewAI 儲存路徑固定到專案內，避免測試收集階段寫入使用者 AppData。
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("CREWAI_STORAGE_DIR", os.path.join(_PROJECT_ROOT, ".crewai_storage"))
from crewai.tools import tool

logger = logging.getLogger("ThreatHunter.epss_tool")

# ══════════════════════════════════════════════════════════════
# 常數
# ══════════════════════════════════════════════════════════════

EPSS_API_BASE = "https://api.first.org/data/v1/epss"
REQUEST_TIMEOUT = 15
MAX_RETRIES = 2

# 快取：EPSS 每日更新，TTL = 24h
CACHE_DIR = os.path.join(_PROJECT_ROOT, "data")
CACHE_TTL = 3600 * 24  # 24 小時

# EPSS 閾值（業界參考）
EPSS_HIGH_THRESHOLD = 0.10   # > 10% → 高風險（TOP 5% 的漏洞）
EPSS_CRITICAL_THRESHOLD = 0.50  # > 50% → 極高風險
EPSS_MEDIUM_THRESHOLD = 0.05


def _get_cache_path(cve_id: str) -> str:
    safe = hashlib.md5(cve_id.encode()).hexdigest()[:12]
    return os.path.join(CACHE_DIR, f"epss_cache_{cve_id}_{safe}.json")


def _read_cache(cve_id: str) -> dict | None:
    try:
        path = _get_cache_path(cve_id)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                cached = json.load(f)
            if time.time() - cached.get("_cached_at", 0) < CACHE_TTL:
                logger.info("[OK] EPSS cache hit: %s", cve_id)
                return cached
    except (json.JSONDecodeError, IOError):
        pass
    return None


def _write_cache(cve_id: str, data: dict) -> None:
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        data["_cached_at"] = time.time()
        with open(_get_cache_path(cve_id), "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except (IOError, PermissionError) as e:
        logger.warning("[WARN] EPSS cache write failed: %s", e)


def _normalize_cve_ids(cve_ids_str: str) -> list[str]:
    """解析並正規化逗號分隔的 CVE ID。"""
    normalized: list[str] = []
    for raw in cve_ids_str.split(","):
        candidate = raw.strip().upper()
        if candidate.startswith("CVE-"):
            normalized.append(candidate)
    return normalized


def _query_epss_api(cve_id: str) -> dict | None:
    """
    呼叫 FIRST.org EPSS API。

    GET https://api.first.org/data/v1/epss?cve=CVE-2021-44228
    Response: {"data": [{"cve": "...", "epss": "0.XX", "percentile": "0.XX", "date": "YYYY-MM-DD"}]}
    """
    for attempt in range(MAX_RETRIES):
        try:
            logger.info("[QUERY] EPSS API: %s (attempt %d)", cve_id, attempt + 1)
            response = requests.get(
                EPSS_API_BASE,
                params={"cve": cve_id},
                timeout=REQUEST_TIMEOUT,
            )
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 429:
                logger.warning("[WARN] EPSS API 429 (rate limited), waiting...")
                time.sleep(3)
            else:
                logger.warning("[WARN] EPSS API %d", response.status_code)
                return None
        except requests.exceptions.Timeout:
            logger.warning("[WARN] EPSS API timeout")
        except requests.exceptions.ConnectionError:
            logger.warning("[WARN] EPSS API connection failed")
        except requests.exceptions.RequestException as e:
            logger.warning("[WARN] EPSS API error: %s", e)
    return None


def _interpret_epss(score: float) -> str:
    """將 EPSS 分數轉為人類可讀說明。"""
    if score >= EPSS_CRITICAL_THRESHOLD:
        return f"CRITICAL_RISK — {score:.1%} probability of exploitation in 30 days"
    elif score >= EPSS_HIGH_THRESHOLD:
        return f"HIGH_RISK — {score:.1%} probability of exploitation in 30 days"
    elif score >= 0.01:
        return f"MODERATE_RISK — {score:.2%} probability of exploitation in 30 days"
    else:
        return f"LOW_RISK — {score:.3%} probability of exploitation in 30 days"


def _risk_level_from_epss(score: float) -> str:
    """將 EPSS 分數映射成測試與 UI 使用的風險等級。"""
    if score >= EPSS_CRITICAL_THRESHOLD:
        return "CRITICAL"
    if score >= 0.20:
        return "HIGH"
    if score >= EPSS_MEDIUM_THRESHOLD:
        return "MEDIUM"
    return "LOW"


def _fetch_epss_online(cve_ids: list[str]) -> dict[str, dict]:
    """查詢多個 CVE 的 EPSS 資料，先讀快取，失敗時回傳空結果。"""
    results: dict[str, dict] = {}
    for cve_id in cve_ids:
        cached = _read_cache(cve_id)
        if cached:
            results[cve_id] = cached
            continue

        raw = _query_epss_api(cve_id)
        if raw and raw.get("data"):
            entry = raw["data"][0]
            results[cve_id] = {
                "epss": float(entry.get("epss", 0.0)),
                "percentile": float(entry.get("percentile", 0.0)),
                "date": entry.get("date", ""),
                "_cached_at": time.time(),
                "_source": "FIRST.org EPSS API (online)",
            }
    return results


def get_epss_score(cve_id: str) -> dict:
    """
    取得單一 CVE 的 EPSS 分數（程式碼層呼叫，供 Intel Fusion 直接使用）。

    Returns:
        {
            "cve_id": "CVE-...",
            "epss": float,         # 0.0-1.0
            "percentile": float,   # 0.0-1.0
            "date": "YYYY-MM-DD",
            "source": "EPSS",
            "error": str | None,
        }
    """
    if not cve_id or not cve_id.startswith("CVE-"):
        return {"cve_id": cve_id, "epss": 0.0, "percentile": 0.0,
                "source": "EPSS", "error": "Invalid CVE ID"}

    online_results = _fetch_epss_online([cve_id])
    if cve_id in online_results:
        entry = online_results[cve_id]
        result = {
            "cve_id": cve_id,
            "epss": float(entry.get("epss", 0.0)),
            "percentile": float(entry.get("percentile", 0.0)),
            "date": entry.get("date", ""),
            "source": "EPSS",
            "error": None,
        }
        if not _read_cache(cve_id):
            _write_cache(cve_id, result)
        logger.info("[OK] EPSS: %s -> %.4f (percentile %.2f)",
                    cve_id, result["epss"], result["percentile"])
        return result

    logger.warning("[WARN] EPSS unavailable for: %s", cve_id)
    return {
        "cve_id": cve_id,
        "epss": 0.0,
        "percentile": 0.0,
        "source": "EPSS",
        "error": f"EPSS API unavailable for {cve_id}",
    }


def _fetch_epss_impl(cve_ids_str: str) -> str:
    """fetch_epss_score 的核心實作，接受逗號分隔的 CVE ID。"""
    cve_ids = _normalize_cve_ids(cve_ids_str)
    if not cve_ids:
        return json.dumps({"error": "No valid CVE IDs provided", "results": []})

    limited_cve_ids = cve_ids[:10]
    online_results = _fetch_epss_online(limited_cve_ids)

    results = []
    high_risk = 0
    found_count = 0

    for cve_id in limited_cve_ids:
        data = online_results.get(cve_id)
        if data:
            if not _read_cache(cve_id):
                _write_cache(cve_id, data)
            epss_score = float(data.get("epss", 0.0))
            percentile = float(data.get("percentile", 0.0))
            found = True
            found_count += 1
        else:
            epss_score = 0.0
            percentile = 0.0
            found = False

        risk_level = _risk_level_from_epss(epss_score)
        if epss_score >= EPSS_HIGH_THRESHOLD:
            high_risk += 1

        results.append({
            "cve_id": cve_id,
            "epss_score": epss_score,
            "percentile": percentile,
            "date": data.get("date", "") if data else "",
            "risk_level": risk_level,
            "found": found,
            "interpretation": _interpret_epss(epss_score),
        })

    return json.dumps({
        "source": "FIRST.org EPSS",
        "results": results,
        "summary": {
            "total_queried": len(limited_cve_ids),
            "found": found_count,
            "high_risk": high_risk,
        },
        "query_time": datetime.now(timezone.utc).isoformat(),
    }, ensure_ascii=False)


# ══════════════════════════════════════════════════════════════
# CrewAI @tool 裝飾器（延遲載入）
# ══════════════════════════════════════════════════════════════

class _Loader:
    def __init__(self):
        self._tool = None

    def _load(self):
        if self._tool is None:
            @tool("fetch_epss_score")
            def fetch_epss_score(cve_ids: str) -> str:
                """查詢 FIRST.org EPSS (Exploit Prediction Scoring System) 分數。

                輸入：逗號分隔的 CVE ID，例如 "CVE-2021-44228,CVE-2024-1234"
                返回：每個 CVE 在接下來 30 天內被野外利用的機率（0.0-1.0）

                EPSS > 0.1 (10%) 表示高風險，應優先修補。
                EPSS > 0.5 (50%) 表示極高風險，應立即修補。
                取得 CVE 列表後立即查詢 EPSS，判斷修補優先順序。
                """
                return _fetch_epss_impl(cve_ids)
            self._tool = fetch_epss_score
        return self._tool

    @property
    def fetch_epss_score(self):
        return self._load()


_loader = _Loader()


def __getattr__(name: str):
    if name == "fetch_epss_score":
        return _loader.fetch_epss_score
    raise AttributeError(f"module 'tools.epss_tool' has no attribute {name!r}")
