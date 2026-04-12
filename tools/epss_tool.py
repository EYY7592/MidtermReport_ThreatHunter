# tools/epss_tool.py
# 功能：EPSS（Exploit Prediction Scoring System）查詢 Tool
# 資料來源：FIRST.org 官方公開 API（免費，無需 API Key）
# Harness 支柱：Graceful Degradation（API 掛掉時離線降級）+ Observability（原子化日誌）
#
# 使用方式：
#   from tools.epss_tool import fetch_epss_score
#
# 架構定位：
#   Intel Fusion Agent 的第二維情報 — 預測漏洞在未來 30 天內被利用的機率
#   EPSS 分數：0.0（不可能）~ 1.0（極高機率），來源：FIRST.org
#
# 六維情報融合中的位置：
#   NVD(CVSS)  EPSS    KEV     GHSA    ATT&CK  OTX
#   0.20       [0.30]  0.25    0.10    0.10    0.05
#   ←─────  由本模組提供  ───────────────────────────────→

import json
import logging
import os
import time
from datetime import datetime, timezone

import requests

logger = logging.getLogger("ThreatHunter.epss")

# ══════════════════════════════════════════════════════════════
# 常數
# ══════════════════════════════════════════════════════════════

EPSS_API_URL = "https://api.first.org/data/v1/epss"
REQUEST_TIMEOUT = 15  # 秒
MAX_BATCH_SIZE = 30   # FIRST.org API 建議每次查詢上限

# 離線快取目錄（與 nvd/kev 相同層級）
CACHE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
EPSS_CACHE_PATH = os.path.join(CACHE_DIR, "epss_cache.json")

# 快取 TTL：24 小時（EPSS 分數每日更新）
CACHE_TTL_HOURS = 24


# ══════════════════════════════════════════════════════════════
# 快取管理
# ══════════════════════════════════════════════════════════════

def _read_epss_cache() -> dict:
    """
    讀取 EPSS 快取（格式：{cve_id: {epss, percentile, date, _cached_at}}）。
    若快取不存在或讀取失敗，回傳空 dict。
    """
    try:
        if not os.path.exists(EPSS_CACHE_PATH):
            return {}
        with open(EPSS_CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        logger.warning("[WARN] EPSS cache read failed: %s", e)
        return {}


def _write_epss_cache(cache: dict) -> None:
    """寫入 EPSS 快取（失敗不影響主流程）"""
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        with open(EPSS_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except (IOError, PermissionError) as e:
        logger.warning("[WARN] EPSS cache write failed: %s", e)


def _is_cache_fresh(cached_entry: dict) -> bool:
    """
    檢查快取條目是否在 TTL 內（24 小時）。
    EPSS 分數每日更新，24 小時快取足夠。
    """
    cached_at = cached_entry.get("_cached_at", 0)
    elapsed_hours = (time.time() - cached_at) / 3600
    return elapsed_hours < CACHE_TTL_HOURS


# ══════════════════════════════════════════════════════════════
# 核心查詢邏輯
# ══════════════════════════════════════════════════════════════

def _fetch_epss_online(cve_ids: list[str]) -> dict[str, dict]:
    """
    從 FIRST.org 線上 API 查詢 EPSS 分數。

    API 文件：https://www.first.org/epss/api
    端點：GET https://api.first.org/data/v1/epss?cve=CVE-2024-XXXX,CVE-2024-YYYY

    回傳格式：
    {
        "cve_id": {
            "epss": 0.97,          # 惡意利用機率 0.0-1.0
            "percentile": 0.999,   # 在所有 CVE 中的百分位數
            "date": "2024-04-09"   # EPSS 評分日期
        }
    }
    """
    results: dict[str, dict] = {}
    cached_at_now = time.time()

    # 分批查詢（防止 URL 過長）
    for i in range(0, len(cve_ids), MAX_BATCH_SIZE):
        batch = cve_ids[i:i + MAX_BATCH_SIZE]
        cve_param = ",".join(batch)

        try:
            logger.info("[QUERY] EPSS API batch %d: %s", i // MAX_BATCH_SIZE + 1, batch[:3])
            resp = requests.get(
                EPSS_API_URL,
                params={"cve": cve_param},
                timeout=REQUEST_TIMEOUT,
            )

            if resp.status_code == 200:
                data = resp.json()
                # FIRST.org 回傳格式：{"data": [{"cve": "CVE-...", "epss": "0.97", "percentile": "0.999", "date": "..."}]}
                for item in data.get("data", []):
                    cve_id = item.get("cve", "").upper()
                    if cve_id:
                        results[cve_id] = {
                            "epss": float(item.get("epss", 0.0)),
                            "percentile": float(item.get("percentile", 0.0)),
                            "date": item.get("date", ""),
                            "_cached_at": cached_at_now,
                            "_source": "FIRST.org EPSS API (online)",
                        }
                logger.info("[OK] EPSS batch %d: %d results", i // MAX_BATCH_SIZE + 1, len(data.get("data", [])))

            elif resp.status_code == 429:
                logger.warning("[WARN] EPSS API rate limited (429), skipping batch")
            else:
                logger.warning("[WARN] EPSS API returned %d for batch", resp.status_code)

        except requests.exceptions.Timeout:
            logger.warning("[WARN] EPSS API timeout (%ds) for batch", REQUEST_TIMEOUT)
        except requests.exceptions.ConnectionError:
            logger.warning("[WARN] EPSS API connection failed (offline?)")
            break  # 網路不通，直接跳出（後續批次也會失敗）
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning("[WARN] EPSS API returned non-JSON: %s", e)

    return results


def _fetch_epss_impl(cve_ids_str: str) -> str:
    """
    fetch_epss_score 的核心實作（與 CrewAI @tool 解耦，方便單元測試）。

    降級策略（Graceful Degradation）：
      1. 讀取快取，識別哪些 CVE 需要線上查詢（快取缺失或過期）
      2. 線上查詢缺失的 CVE → 更新快取
      3. 線上失敗 → 回傳快取（若有）
      4. 快取也沒有 → 回傳 epss=0.0（保守預設）

    Args:
        cve_ids_str: 逗號分隔的 CVE ID 字串（如 "CVE-2024-1234,CVE-2024-5678"）

    Returns:
        JSON 字串，格式符合 Intel Fusion Agent 的六維評分輸入
    """
    try:
        # ── Step 1：解析輸入 ─────────────────────────────────
        raw_ids = [c.strip().upper() for c in cve_ids_str.split(",") if c.strip()]
        if not raw_ids:
            logger.warning("[WARN] EPSS Tool received empty CVE ID input")
            return json.dumps({
                "source": "FIRST.org EPSS API",
                "results": [],
                "error": "No CVE IDs provided",
            }, ensure_ascii=False, indent=2)

        logger.info("[QUERY] EPSS check: %d CVEs: %s", len(raw_ids), raw_ids[:5])

        # ── Step 2：讀取快取，識別缺失的 CVE ─────────────────
        cache = _read_epss_cache()
        cached_results: dict[str, dict] = {}
        missing_cves: list[str] = []

        for cve_id in raw_ids:
            if cve_id in cache and _is_cache_fresh(cache[cve_id]):
                cached_results[cve_id] = cache[cve_id]
                logger.info("[CACHE] EPSS cache hit: %s = %.4f", cve_id, cache[cve_id].get("epss", 0))
            else:
                missing_cves.append(cve_id)

        # ── Step 3：線上查詢缺失的 CVE ───────────────────────
        online_results: dict[str, dict] = {}
        if missing_cves:
            online_results = _fetch_epss_online(missing_cves)
            # 更新快取
            if online_results:
                cache.update(online_results)
                _write_epss_cache(cache)
                logger.info("[OK] EPSS cache updated with %d new entries", len(online_results))

        # ── Step 4：組裝最終結果 ──────────────────────────────
        all_data = {**cached_results, **online_results}
        output_results = []

        for cve_id in raw_ids:
            if cve_id in all_data:
                entry = all_data[cve_id]
                epss_score = float(entry.get("epss", 0.0))
                percentile = float(entry.get("percentile", 0.0))

                # EPSS 語義解釋（供 Agent 快速判斷）
                if epss_score >= 0.5:
                    risk_level = "CRITICAL"   # 極高機率近期被利用
                elif epss_score >= 0.2:
                    risk_level = "HIGH"
                elif epss_score >= 0.05:
                    risk_level = "MEDIUM"
                else:
                    risk_level = "LOW"

                output_results.append({
                    "cve_id": cve_id,
                    "epss_score": round(epss_score, 6),
                    "percentile": round(percentile, 6),
                    "risk_level": risk_level,
                    "date": entry.get("date", ""),
                    "source": entry.get("_source", "FIRST.org EPSS API (cache)"),
                    "found": True,
                })
                logger.info(
                    "[OK] EPSS: %s = %.4f (%s, percentile=%.4f)",
                    cve_id, epss_score, risk_level, percentile,
                )
            else:
                # CVE 不在 EPSS 資料庫中（老漏洞 or 未入庫）
                output_results.append({
                    "cve_id": cve_id,
                    "epss_score": 0.0,
                    "percentile": 0.0,
                    "risk_level": "UNKNOWN",
                    "date": "",
                    "source": "not_found",
                    "found": False,
                })
                logger.info("[INFO] EPSS: %s not found in FIRST.org database", cve_id)

        found_count = sum(1 for r in output_results if r["found"])
        high_risk_count = sum(1 for r in output_results if r.get("risk_level") in ("CRITICAL", "HIGH"))

        logger.info(
            "[OK] EPSS complete: %d/%d found, %d high-risk",
            found_count, len(raw_ids), high_risk_count,
        )

        return json.dumps({
            "source": "FIRST.org EPSS API",
            "results": output_results,
            "summary": {
                "total_queried": len(raw_ids),
                "found": found_count,
                "high_risk": high_risk_count,
                "query_time": datetime.now(timezone.utc).isoformat(),
            },
        }, ensure_ascii=False, indent=2)

    except Exception as e:
        # 最後一道防線：任何未預期錯誤都不能讓 Agent crash
        logger.error("[FAIL] EPSS Tool unexpected error: %s", e, exc_info=True)
        return json.dumps({
            "source": "FIRST.org EPSS API (error)",
            "results": [],
            "error": f"Unexpected error: {str(e)[:200]}",
        }, ensure_ascii=False, indent=2)


# ══════════════════════════════════════════════════════════════
# CrewAI @tool 包裝（Agent 呼叫用）
# ══════════════════════════════════════════════════════════════

# ⚠️ 重要：使用「延遲載入」模式（與 nvd_tool.py / kev_tool.py 相同模式）
# 原因：避免在 import 階段就觸發 CrewAI 的 tool 註冊，防止初始化順序問題

def _create_tool():
    """延遲建立 CrewAI Tool，僅在 Agent 實際使用時才 import"""
    from crewai.tools import tool

    @tool("search_epss")
    def fetch_epss_score(cve_ids: str) -> str:
        """查詢 FIRST.org EPSS API，取得 CVE 在未來 30 天內被惡意利用的機率分數。
輸入一或多個 CVE ID（逗號分隔，如 "CVE-2024-1234,CVE-2024-5678"）。
回傳每個 CVE 的 EPSS 分數（0.0-1.0），分數越高表示越可能被利用。
EPSS >= 0.5 = CRITICAL（極高機率），>= 0.2 = HIGH，>= 0.05 = MEDIUM。
EPSS 分數由 FIRST.org 每日更新，來自機器學習模型。
注意：若 in_kev=True，可跳過 EPSS 查詢（KEV 已是更高可信度的確認）。"""
        return _fetch_epss_impl(cve_ids)

    return fetch_epss_score


# ── 延遲載入機制（與 kev_tool.py 相同模式）──────────────────

class _LazyToolLoader:
    def __init__(self):
        self._tool = None

    def _load(self):
        if self._tool is None:
            self._tool = _create_tool()

    @property
    def fetch_epss_score(self):
        self._load()
        return self._tool


_loader = _LazyToolLoader()


def __getattr__(name):
    """模組層級 __getattr__，支援 from tools.epss_tool import fetch_epss_score"""
    if name == "fetch_epss_score":
        return _loader.fetch_epss_score
    raise AttributeError(f"module 'tools.epss_tool' has no attribute {name!r}")
