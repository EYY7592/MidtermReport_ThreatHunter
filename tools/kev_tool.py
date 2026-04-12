# tools/kev_tool.py
# 功能：CISA KEV（Known Exploited Vulnerabilities）清單查詢 Tool
# Harness 支柱：Graceful Degradation（降級瀑布）+ Observability（原子化日誌）
# 擁有者：成員 C（Analyst Agent Pipeline）
#
# 使用方式：
#   from tools.kev_tool import check_cisa_kev
#
# 架構定位：
#   Analyst Agent 的「第一隻手」— 驗證 CVE 是否已被野外利用
#   在 KEV 清單上 = 已確認被利用 = 風險極高，需立即處理

import json
import os
import time
import logging
from datetime import datetime, timezone

import requests

logger = logging.getLogger("ThreatHunter")

# ══════════════════════════════════════════════════════════════
# 常數
# ══════════════════════════════════════════════════════════════

KEV_API_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REQUEST_TIMEOUT = 30  # 秒

# 離線快取
CACHE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
KEV_CACHE_PATH = os.path.join(CACHE_DIR, "kev_cache.json")

# 模組級 KEV 查詢表（首次呼叫時載入，之後重複使用）
_kev_lookup: dict | None = None
_kev_total_count: int = 0
_kev_source: str = "CISA KEV (unavailable)"


# ══════════════════════════════════════════════════════════════
# 輔助函式
# ══════════════════════════════════════════════════════════════

def _download_kev_catalog() -> dict | None:
    """
    下載完整 CISA KEV JSON 資料。
    成功回傳原始 JSON dict，失敗回傳 None。
    """
    try:
        logger.info("[QUERY] Downloading CISA KEV catalog...")
        response = requests.get(KEV_API_URL, timeout=REQUEST_TIMEOUT)

        if response.status_code == 200:
            data = response.json()
            logger.info("[OK] KEV catalog downloaded: %d entries", len(data.get('vulnerabilities', [])))
            return data

        logger.warning("[WARN] KEV API returned %d", response.status_code)
        return None

    except requests.exceptions.Timeout:
        logger.warning("[WARN] KEV API timeout (%ds)", REQUEST_TIMEOUT)
        return None
    except requests.exceptions.ConnectionError:
        logger.warning("[WARN] KEV API connection failed (network issue)")
        return None
    except requests.exceptions.RequestException as e:
        logger.warning("[WARN] KEV API request error: %s", e)
        return None
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning("[WARN] KEV API returned non-JSON: %s", e)
        return None


def _write_kev_cache(data: dict) -> None:
    """將 KEV 完整資料寫入離線快取"""
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        data["_cached_at"] = time.time()
        with open(KEV_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info("[OK] KEV cache updated: %s", KEV_CACHE_PATH)
    except (IOError, PermissionError) as e:
        logger.warning("[WARN] KEV cache write failed: %s", e)


def _read_kev_cache() -> dict | None:
    """讀取 KEV 離線快取，不存在回傳 None（KEV 快取不設過期，因為有更新機制）"""
    try:
        if os.path.exists(KEV_CACHE_PATH):
            with open(KEV_CACHE_PATH, "r", encoding="utf-8") as f:
                cached = json.load(f)
            logger.info("[OK] KEV cache hit: %d entries", len(cached.get('vulnerabilities', [])))
            return cached
    except (json.JSONDecodeError, IOError) as e:
        logger.warning("[WARN] KEV cache read failed: %s", e)
    return None


def _build_kev_lookup(raw_data: dict) -> dict:
    """
    將 KEV 原始資料建立為 {cve_id: details} 查詢表。

    KEV JSON 結構：
      vulnerabilities[].cveID → CVE ID
      vulnerabilities[].dateAdded → 加入日期
      vulnerabilities[].dueDate → 修補期限
      vulnerabilities[].vendorProject → 供應商
      vulnerabilities[].product → 產品
      vulnerabilities[].knownRansomwareCampaignUse → 是否被勒索軟體利用
      vulnerabilities[].shortDescription → 簡短描述
    """
    lookup = {}
    for vuln in raw_data.get("vulnerabilities", []):
        cve_id = vuln.get("cveID", "")
        if cve_id:
            lookup[cve_id] = {
                "date_added": vuln.get("dateAdded", ""),
                "due_date": vuln.get("dueDate", ""),
                "vendor": vuln.get("vendorProject", ""),
                "product": vuln.get("product", ""),
                "known_ransomware_use": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                "short_description": vuln.get("shortDescription", ""),
            }
    return lookup


def _ensure_kev_loaded() -> None:
    """
    確保 KEV 查詢表已載入（Lazy Loading）。

    降級策略：
      1. 下載線上 KEV JSON → 成功則建立查詢表 + 更新快取
      2. 下載失敗 → 讀離線快取
      3. 快取也沒有 → 查詢表為空 dict（所有 CVE 都回傳 in_kev=false）
    """
    global _kev_lookup, _kev_total_count, _kev_source

    if _kev_lookup is not None:
        return  # 已載入，不重複下載

    # 嘗試線上下載
    raw_data = _download_kev_catalog()
    if raw_data is not None:
        _kev_lookup = _build_kev_lookup(raw_data)
        _kev_total_count = len(_kev_lookup)
        _kev_source = "CISA KEV (online)"
        _write_kev_cache(raw_data)
        logger.info("[OK] KEV lookup table built (online): %d entries", _kev_total_count)
        return

    # 降級：讀離線快取
    cached = _read_kev_cache()
    if cached is not None:
        _kev_lookup = _build_kev_lookup(cached)
        _kev_total_count = len(_kev_lookup)
        _kev_source = "CISA KEV (cache)"
        logger.info("[OK] KEV lookup table built (cache): %d entries", _kev_total_count)
        return

    # 最終降級：空查詢表
    _kev_lookup = {}
    _kev_total_count = 0
    _kev_source = "CISA KEV (unavailable)"
    logger.warning("[WARN] KEV catalog unavailable (online + cache both failed), all queries return in_kev=false")


# ══════════════════════════════════════════════════════════════
# 核心查詢邏輯
# ══════════════════════════════════════════════════════════════

def _check_kev_impl(cve_ids: str) -> str:
    """
    check_cisa_kev 的核心實作（與 CrewAI @tool 解耦，方便單元測試）。

    接收逗號分隔的 CVE ID 字串，回傳每個 CVE 的 KEV 狀態 JSON。

    降級策略：
      1. 線上 KEV → 使用 + 更新快取
      2. 線上失敗 → 讀離線快取
      3. 快取也沒有 → in_kev: false（保守預設，不 crash）
      4. 任何未預期錯誤 → 回傳安全的空結果（絕不 crash）
    """
    try:
        # 確保 KEV 查詢表已載入
        _ensure_kev_loaded()

        # 解析逗號分隔的 CVE ID
        raw_ids = [cid.strip() for cid in cve_ids.split(",") if cid.strip()]
        if not raw_ids:
            logger.warning("[WARN] KEV Tool received empty CVE ID input")
            return json.dumps({
                "source": _kev_source,
                "results": [],
                "kev_total_count": _kev_total_count,
                "error": "No CVE IDs provided",
            }, ensure_ascii=False, indent=2)

        logger.info("[QUERY] KEV check: %d CVEs -- %s", len(raw_ids), raw_ids)

        results = []
        for cve_id in raw_ids:
            # 正規化 CVE ID 格式（去除空白、統一大寫）
            cve_id = cve_id.strip().upper()

            if cve_id in _kev_lookup:
                details = _kev_lookup[cve_id]
                results.append({
                    "cve_id": cve_id,
                    "in_kev": True,
                    "date_added": details["date_added"],
                    "due_date": details["due_date"],
                    "vendor": details["vendor"],
                    "product": details["product"],
                    "known_ransomware_use": details["known_ransomware_use"],
                    "short_description": details["short_description"],
                })
                logger.info("[ALERT] %s is in CISA KEV list! (confirmed wild exploitation)", cve_id)
            else:
                results.append({
                    "cve_id": cve_id,
                    "in_kev": False,
                })
                logger.info("[OK] %s is not in CISA KEV list", cve_id)

        kev_count = sum(1 for r in results if r["in_kev"])
        logger.info(
            "[OK] KEV check complete: %d queries, %d in KEV list",
            len(results), kev_count
        )

        return json.dumps({
            "source": _kev_source,
            "results": results,
            "kev_total_count": _kev_total_count,
        }, ensure_ascii=False, indent=2)

    except Exception as e:
        # 最後一道防線：任何未預期錯誤都不能讓 Agent crash
        logger.error("[FAIL] KEV Tool unexpected error: %s", e, exc_info=True)
        error_result = {
            "source": "CISA KEV (error)",
            "results": [],
            "kev_total_count": 0,
            "error": f"Unexpected error: {str(e)}",
        }
        return json.dumps(error_result, ensure_ascii=False, indent=2)


# ══════════════════════════════════════════════════════════════
# CrewAI @tool 包裝（Agent 呼叫用）
# ══════════════════════════════════════════════════════════════

# ⚠️ 重要：使用「延遲載入」模式（LazyToolLoader）
# 原因：避免在 import 階段就觸發 CrewAI 的 tool 註冊
def _create_tool():
    """延遲建立 CrewAI Tool，僅在 Agent 實際使用時才 import"""
    from crewai.tools import tool

    @tool("check_cisa_kev")
    def check_cisa_kev(cve_ids: str) -> str:
        """查詢 CVE 是否在 CISA KEV（已知被利用漏洞）清單上。
輸入一或多個 CVE ID（逗號分隔，如 "CVE-2021-44228,CVE-2024-1234"），
回傳每個 CVE 的 KEV 狀態，包含加入日期、到期日、是否被勒索軟體利用等資訊。
在 KEV 清單上的 CVE = 已確認被野外利用 = 風險極高。"""
        return _check_kev_impl(cve_ids)

    return check_cisa_kev


# ── 延遲載入機制（與 nvd_tool.py 相同模式）──────────────────

class _LazyToolLoader:
    def __init__(self):
        self._tool = None

    def _load(self):
        if self._tool is None:
            self._tool = _create_tool()

    @property
    def check_cisa_kev(self):
        self._load()
        return self._tool


_loader = _LazyToolLoader()


def __getattr__(name):
    """模組層級 __getattr__，支援 from tools.kev_tool import check_cisa_kev"""
    if name == "check_cisa_kev":
        return _loader.check_cisa_kev
    raise AttributeError(f"module 'tools.kev_tool' has no attribute {name!r}")
