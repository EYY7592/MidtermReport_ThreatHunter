# tools/otx_tool.py
# 功能：AlienVault OTX 威脅情報查詢 Tool
# Harness 支柱：Graceful Degradation（降級瀑布）+ Observability（原子化日誌）
# 擁有者：成員 B（Scout Agent Pipeline）
#
# 使用方式：
#   from tools.otx_tool import search_otx
#
# 架構定位：
#   Scout Agent 的「第二隻手」— 負責查詢 OTX 威脅情報
#   僅在 Agent 判斷 CVSS >= 7.0 時才會被呼叫（由 Skill SOP 引導）

import json
import os
import time
import hashlib
import logging
from datetime import datetime, timezone, timedelta

import requests

logger = logging.getLogger("ThreatHunter")

# ══════════════════════════════════════════════════════════════
# 常數
# ══════════════════════════════════════════════════════════════

OTX_API_BASE = "https://otx.alienvault.com/api/v1"
OTX_SEARCH_ENDPOINT = f"{OTX_API_BASE}/search/pulses"
RESULTS_LIMIT = 10
REQUEST_TIMEOUT = 20  # 秒

# Rate limit 控制（OTX 較寬鬆：10,000 req/hr）
RATE_LIMIT_INTERVAL = 1.0  # 保守間隔
MAX_RETRIES = 2

# 離線快取
CACHE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
CACHE_TTL = 3600 * 12  # 12 小時過期（OTX 資料更新較頻繁）

# 活躍度判定
ACTIVE_THRESHOLD_DAYS = 90  # 90 天內有新 pulse → active
ACTIVE_PULSE_COUNT = 3      # pulse 數 >= 3 → 更可能 active

# 上次請求時間
_last_request_time = 0.0


# ══════════════════════════════════════════════════════════════
# 輔助函式
# ══════════════════════════════════════════════════════════════

def _get_cache_path(package_name: str) -> str:
    """取得離線快取檔案路徑"""
    safe_name = hashlib.md5(package_name.encode()).hexdigest()[:12]
    return os.path.join(CACHE_DIR, f"otx_cache_{package_name}_{safe_name}.json")


def _read_cache(package_name: str) -> dict | None:
    """讀取離線快取，過期或不存在回傳 None"""
    cache_path = _get_cache_path(package_name)
    try:
        if os.path.exists(cache_path):
            with open(cache_path, "r", encoding="utf-8") as f:
                cached = json.load(f)
            cached_time = cached.get("_cached_at", 0)
            if time.time() - cached_time < CACHE_TTL:
                logger.info("[OK] OTX cache hit: %s", package_name)
                return cached
            else:
                logger.info("[INFO] OTX cache expired: %s", package_name)
    except (json.JSONDecodeError, IOError) as e:
        logger.warning("[WARN] OTX cache read failed: %s", e)
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
        logger.warning("[WARN] OTX cache write failed: %s", e)


def _rate_limit() -> None:
    """Rate limiter — OTX 較寬鬆但仍需保守"""
    global _last_request_time
    elapsed = time.time() - _last_request_time
    if elapsed < RATE_LIMIT_INTERVAL:
        wait = RATE_LIMIT_INTERVAL - elapsed
        time.sleep(wait)
    _last_request_time = time.time()


def _determine_threat_level(pulse_count: int, pulses: list) -> str:
    """
    根據 pulse 數量和時間判定威脅等級。

    規則（見 architecture_spec.md §4.2）：
      pulse_count >= 3 且最近 90 天有新 pulse → "active"
      pulse_count >= 1 但都超過 90 天         → "inactive"
      pulse_count == 0                        → "unknown"
    """
    if pulse_count == 0:
        return "unknown"

    cutoff = datetime.now(timezone.utc) - timedelta(days=ACTIVE_THRESHOLD_DAYS)

    has_recent = False
    for pulse in pulses:
        created_str = pulse.get("created", "")
        try:
            # OTX 時間格式：2024-08-10T12:00:00.000000 或 2024-08-10T12:00:00
            created_str_clean = created_str.replace("Z", "+00:00")
            if "." in created_str_clean and "+" not in created_str_clean.split(".")[-1]:
                created_str_clean = created_str_clean.split(".")[0] + "+00:00"
            elif "+" not in created_str_clean and "-" not in created_str_clean[10:]:
                created_str_clean += "+00:00"

            created = datetime.fromisoformat(created_str_clean)
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)

            if created > cutoff:
                has_recent = True
                break
        except (ValueError, TypeError):
            continue

    if pulse_count >= ACTIVE_PULSE_COUNT and has_recent:
        return "active"
    elif has_recent:
        return "active"  # 即使 pulse 少，最近有活動也算 active
    else:
        return "inactive"


def _parse_pulse(pulse: dict) -> dict:
    """將單一 OTX pulse 轉為 Tool 輸出格式"""
    # 提取 indicator 統計
    indicators = pulse.get("indicators", [])
    indicator_count = len(indicators) if isinstance(indicators, list) else 0

    # 提取 tags
    tags = pulse.get("tags", [])
    if not isinstance(tags, list):
        tags = []

    # 提取時間（只取日期部分）
    created = pulse.get("created", "")
    if "T" in created:
        created = created.split("T")[0]

    return {
        "name": pulse.get("name", "")[:200],  # 截斷過長名稱
        "description": (pulse.get("description", "") or "")[:300],  # 截斷過長描述
        "created": created,
        "tags": tags[:10],  # 最多 10 個 tag
        "indicator_count": indicator_count,
    }


# ══════════════════════════════════════════════════════════════
# 核心查詢邏輯
# ══════════════════════════════════════════════════════════════

def _query_otx_api(keyword: str) -> dict | None:
    """
    呼叫 OTX API，回傳原始 JSON response dict。
    失敗回傳 None。
    """
    api_key = os.getenv("OTX_API_KEY", "")

    headers = {
        "Accept": "application/json",
    }
    if api_key:
        headers["X-OTX-API-KEY"] = api_key

    params = {
        "q": keyword,
        "limit": RESULTS_LIMIT,
    }

    for attempt in range(1, MAX_RETRIES + 1):
        _rate_limit()
        try:
            logger.info("[QUERY] OTX API: %s (attempt %d)", keyword, attempt)
            response = requests.get(
                OTX_SEARCH_ENDPOINT,
                params=params,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )

            if response.status_code == 200:
                return response.json()

            if response.status_code == 403:
                logger.warning("[WARN] OTX API 403 (unauthorized) -- API Key needed")
                return None

            if response.status_code == 429:
                logger.warning("[WARN] OTX API 429 (rate limited)")
                time.sleep(5)
                continue

            if response.status_code >= 500:
                logger.warning("[WARN] OTX API %d (server error)", response.status_code)
                time.sleep(2)
                continue

            logger.warning("[WARN] OTX API returned %d: %s", response.status_code, response.text[:200])
            return None

        except requests.exceptions.Timeout:
            logger.warning("[WARN] OTX API timeout (%ds)", REQUEST_TIMEOUT)
            continue
        except requests.exceptions.ConnectionError:
            logger.warning("[WARN] OTX API connection failed (network issue)")
            continue
        except requests.exceptions.RequestException as e:
            logger.warning("[WARN] OTX API request error: %s", e)
            return None

    return None


def _parse_otx_response(raw: dict, package_name: str) -> dict:
    """
    將 OTX API 原始 response 轉換為 Tool 輸出格式。

    轉換 mapping（見 architecture_spec.md §4.2）:
      response.results[].name              → pulse_name
      response.results[].description       → description
      response.results[].created           → created
      response.results[].indicators        → indicator_count
      response.results[].tags              → tags
      len(response.results)                → pulse_count
    """
    raw_results = raw.get("results", [])
    if not isinstance(raw_results, list):
        raw_results = []

    pulses = [_parse_pulse(p) for p in raw_results]
    pulse_count = len(pulses)
    threat_level = _determine_threat_level(pulse_count, raw_results)

    return {
        "package": package_name,
        "source": "OTX",
        "pulse_count": pulse_count,
        "threat_level": threat_level,
        "pulses": pulses,
    }


def _search_otx_impl(package_name: str) -> str:
    """
    search_otx 的核心實作（與 CrewAI @tool 解耦，方便單元測試）。

    降級瀑布：
      1. 查 OTX API
      2. API 失敗 → 讀離線快取
      3. 快取也沒有 → 回傳 threat_level: "unknown"
      4. 任何未預期錯誤 → 回傳安全的預設結果（絕不 crash）
    """
    try:
        # 清理套件名稱
        name = package_name.strip().lower()
        name = name.split()[0] if " " in name else name

        logger.info("[QUERY] OTX package: %s", name)

        # 嘗試 API 查詢
        raw = _query_otx_api(name)

        if raw is not None:
            result = _parse_otx_response(raw, package_name)

            # 寫入快取
            _write_cache(name, result)

            logger.info(
                "[OK] OTX query success: %s -> %d pulses, threat_level=%s",
                package_name, result['pulse_count'], result['threat_level']
            )
            return json.dumps(result, ensure_ascii=False, indent=2)

        # API 失敗 → 嘗試快取
        cached = _read_cache(name)
        if cached:
            cached.pop("_cached_at", None)
            cached["fallback_used"] = True
            cached["error"] = f"OTX API unavailable, using cached data for '{name}'"
            logger.info("[OK] OTX using cache: %s", name)
            return json.dumps(cached, ensure_ascii=False, indent=2)

        # 完全沒有資料
        empty_result = {
            "package": package_name,
            "source": "OTX",
            "pulse_count": 0,
            "threat_level": "unknown",
            "pulses": [],
            "error": f"OTX API unavailable and no cache for '{name}'",
            "fallback_used": False,
        }
        logger.info("[INFO] OTX no data for: %s", package_name)
        return json.dumps(empty_result, ensure_ascii=False, indent=2)

    except Exception as e:
        # 最後一道防線
        logger.error("[FAIL] OTX Tool unexpected error: %s", e, exc_info=True)
        error_result = {
            "package": package_name,
            "source": "OTX",
            "pulse_count": 0,
            "threat_level": "unknown",
            "pulses": [],
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

    @tool("search_otx")
    def search_otx(package_name: str) -> str:
        """查詢 AlienVault OTX 中指定套件的活躍威脅情報。
輸入套件名稱（如 django、redis），回傳該套件的威脅情報 pulse 清單（JSON 格式）。
包含活躍度判定（active/inactive/unknown）、威脅 pulse 名稱、描述、IOC 數量等。
建議僅在 CVSS >= 7.0 的高危套件才查詢 OTX。"""
        return _search_otx_impl(package_name)

    return search_otx


# ── 延遲載入機制（與 memory_tool.py 相同模式）──────────────────

class _LazyToolLoader:
    def __init__(self):
        self._tool = None

    def _load(self):
        if self._tool is None:
            self._tool = _create_tool()

    @property
    def search_otx(self):
        self._load()
        return self._tool


_loader = _LazyToolLoader()


def __getattr__(name):
    """模組層級 __getattr__，支援 from tools.otx_tool import search_otx"""
    if name == "search_otx":
        return _loader.search_otx
    raise AttributeError(f"module 'tools.otx_tool' has no attribute {name!r}")
