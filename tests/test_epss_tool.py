# tests/test_epss_tool.py
# 功能：EPSS Tool 測試套件
# 覆蓋：Happy Path + 邊界情況 + 離線降級 + JSON 格式驗證
# 遵守：project_CONSTITUTION.md §5

import json
import os
import sys
import time
import unittest
from unittest.mock import MagicMock, patch

# 確保專案根目錄在 sys.path 中
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.epss_tool import (
    _fetch_epss_impl,
    _is_cache_fresh,
    _read_epss_cache,
    _write_epss_cache,
)

# calculate_composite_score 在 agents/intel_fusion（非 tools/epss_tool）
try:
    from agents.intel_fusion import calculate_composite_score
    HAS_INTEL_FUSION = True
except ImportError:
    HAS_INTEL_FUSION = False


class TestEpssToolHappyPath(unittest.TestCase):
    """Happy Path：正常 API 查詢情境"""

    def test_parse_empty_cve_ids(self):
        """空字串輸入 → 回傳 error JSON（不 crash）"""
        result = _fetch_epss_impl("")
        data = json.loads(result)
        self.assertIn("error", data)
        self.assertEqual(data["results"], [])

    def test_whitespace_only_input(self):
        """只有空白的輸入 → 與空字串一樣處理"""
        result = _fetch_epss_impl("   ,  ,  ")
        data = json.loads(result)
        self.assertIn("error", data)

    @patch("tools.epss_tool._fetch_epss_online")
    def test_single_cve_online_success(self, mock_online):
        """單一 CVE 線上查詢成功"""
        mock_online.return_value = {
            "CVE-2024-27351": {
                "epss": 0.97346,
                "percentile": 0.99921,
                "date": "2024-04-09",
                "_cached_at": time.time(),
                "_source": "FIRST.org EPSS API (online)",
            }
        }
        result = _fetch_epss_impl("CVE-2024-27351")
        data = json.loads(result)

        self.assertIn("results", data)
        self.assertEqual(len(data["results"]), 1)
        self.assertEqual(data["results"][0]["cve_id"], "CVE-2024-27351")
        self.assertAlmostEqual(data["results"][0]["epss_score"], 0.97346, places=4)
        self.assertEqual(data["results"][0]["risk_level"], "CRITICAL")  # >= 0.5
        self.assertTrue(data["results"][0]["found"])

    @patch("tools.epss_tool._fetch_epss_online")
    def test_multiple_cves(self, mock_online):
        """多個 CVE 批次查詢"""
        mock_online.return_value = {
            "CVE-2024-0001": {"epss": 0.05, "percentile": 0.80, "date": "2024-01-01", "_cached_at": time.time()},
            "CVE-2024-0002": {"epss": 0.25, "percentile": 0.90, "date": "2024-01-02", "_cached_at": time.time()},
        }
        result = _fetch_epss_impl("CVE-2024-0001, CVE-2024-0002")
        data = json.loads(result)
        self.assertEqual(len(data["results"]), 2)
        cve_ids = {r["cve_id"] for r in data["results"]}
        self.assertIn("CVE-2024-0001", cve_ids)
        self.assertIn("CVE-2024-0002", cve_ids)


class TestEpssToolRiskLevels(unittest.TestCase):
    """EPSS 分數風險等級分類測試"""

    @patch("tools.epss_tool._fetch_epss_online")
    def test_critical_risk_level(self, mock_online):
        """EPSS >= 0.5 → CRITICAL"""
        mock_online.return_value = {
            "CVE-2024-TEST1": {"epss": 0.75, "percentile": 0.99, "date": "2024-04-09", "_cached_at": time.time()}
        }
        result = json.loads(_fetch_epss_impl("CVE-2024-TEST1"))
        self.assertEqual(result["results"][0]["risk_level"], "CRITICAL")

    @patch("tools.epss_tool._fetch_epss_online")
    def test_high_risk_level(self, mock_online):
        """EPSS 0.2-0.5 → HIGH"""
        mock_online.return_value = {
            "CVE-2024-TEST2": {"epss": 0.35, "percentile": 0.95, "date": "2024-04-09", "_cached_at": time.time()}
        }
        result = json.loads(_fetch_epss_impl("CVE-2024-TEST2"))
        self.assertEqual(result["results"][0]["risk_level"], "HIGH")

    @patch("tools.epss_tool._fetch_epss_online")
    def test_medium_risk_level(self, mock_online):
        """EPSS 0.05-0.2 → MEDIUM"""
        mock_online.return_value = {
            "CVE-2024-TEST3": {"epss": 0.10, "percentile": 0.85, "date": "2024-04-09", "_cached_at": time.time()}
        }
        result = json.loads(_fetch_epss_impl("CVE-2024-TEST3"))
        self.assertEqual(result["results"][0]["risk_level"], "MEDIUM")

    @patch("tools.epss_tool._fetch_epss_online")
    def test_low_risk_level(self, mock_online):
        """EPSS < 0.05 → LOW"""
        mock_online.return_value = {
            "CVE-2024-TEST4": {"epss": 0.001, "percentile": 0.10, "date": "2024-04-09", "_cached_at": time.time()}
        }
        result = json.loads(_fetch_epss_impl("CVE-2024-TEST4"))
        self.assertEqual(result["results"][0]["risk_level"], "LOW")


class TestEpssToolOfflineDegradation(unittest.TestCase):
    """離線降級測試（API 失敗時使用快取）"""

    @patch("tools.epss_tool._fetch_epss_online")
    def test_api_failure_returns_not_found(self, mock_online):
        """API 完全失敗時，CVE 標記為 found=False（不 crash）"""
        mock_online.return_value = {}  # 線上查詢返回空
        result = _fetch_epss_impl("CVE-9999-9999")
        data = json.loads(result)
        self.assertEqual(len(data["results"]), 1)
        self.assertFalse(data["results"][0]["found"])
        self.assertEqual(data["results"][0]["cve_id"], "CVE-9999-9999")
        self.assertEqual(data["results"][0]["epss_score"], 0.0)

    def test_cache_freshness_within_ttl(self):
        """快取在 TTL 內 → is_cache_fresh 返回 True"""
        fresh_entry = {"_cached_at": time.time()}
        self.assertTrue(_is_cache_fresh(fresh_entry))

    def test_cache_freshness_expired(self):
        """快取超過 TTL → is_cache_fresh 返回 False"""
        expired_entry = {"_cached_at": time.time() - 25 * 3600}  # 25 小時前
        self.assertFalse(_is_cache_fresh(expired_entry))

    @patch("tools.epss_tool._fetch_epss_online")
    @patch("tools.epss_tool._write_epss_cache")
    def test_cache_is_updated_after_online_query(self, mock_write, mock_online):
        """線上查詢成功後，快取應該被更新"""
        mock_online.return_value = {
            "CVE-2024-CACHE": {"epss": 0.5, "percentile": 0.95, "date": "2024-04-09", "_cached_at": time.time()}
        }
        _fetch_epss_impl("CVE-2024-CACHE")
        mock_write.assert_called_once()


class TestEpssToolCveIdNormalization(unittest.TestCase):
    """CVE ID 正規化測試（大小寫、空白）"""

    @patch("tools.epss_tool._fetch_epss_online")
    def test_lowercase_cve_id_normalized(self, mock_online):
        """小寫 CVE ID → 正規化為大寫"""
        mock_online.return_value = {
            "CVE-2024-1234": {"epss": 0.5, "percentile": 0.95, "date": "2024-04-09", "_cached_at": time.time()}
        }
        result = json.loads(_fetch_epss_impl("cve-2024-1234"))
        self.assertEqual(result["results"][0]["cve_id"], "CVE-2024-1234")

    @patch("tools.epss_tool._fetch_epss_online")
    def test_cve_with_spaces(self, mock_online):
        """帶空格的 CVE ID → 正確解析"""
        mock_online.return_value = {
            "CVE-2024-5678": {"epss": 0.3, "percentile": 0.90, "date": "2024-04-09", "_cached_at": time.time()}
        }
        result = json.loads(_fetch_epss_impl("  CVE-2024-5678  "))
        self.assertEqual(len(result["results"]), 1)


class TestEpssToolJsonOutput(unittest.TestCase):
    """JSON 輸出格式驗證（符合 Intel Fusion 輸入要求）"""

    @patch("tools.epss_tool._fetch_epss_online")
    def test_output_has_required_fields(self, mock_online):
        """輸出包含所有必要欄位（供 Intel Fusion 使用）"""
        mock_online.return_value = {
            "CVE-2024-FIELDS": {"epss": 0.5, "percentile": 0.95, "date": "2024-04-09", "_cached_at": time.time()}
        }
        result = json.loads(_fetch_epss_impl("CVE-2024-FIELDS"))

        self.assertIn("source", result)
        self.assertIn("results", result)
        self.assertIn("summary", result)

        r = result["results"][0]
        required_fields = ["cve_id", "epss_score", "percentile", "risk_level", "found"]
        for field in required_fields:
            self.assertIn(field, r, f"Missing required field: {field}")

    @patch("tools.epss_tool._fetch_epss_online")
    def test_summary_counts_are_correct(self, mock_online):
        """summary 中的計數正確"""
        mock_online.return_value = {
            "CVE-2024-A": {"epss": 0.9, "percentile": 0.99, "date": "2024-04-09", "_cached_at": time.time()},
            "CVE-2024-B": {"epss": 0.6, "percentile": 0.97, "date": "2024-04-09", "_cached_at": time.time()},
        }
        result = json.loads(_fetch_epss_impl("CVE-2024-A, CVE-2024-B"))
        summary = result["summary"]
        self.assertEqual(summary["total_queried"], 2)
        self.assertEqual(summary["found"], 2)
        self.assertEqual(summary["high_risk"], 2)  # 兩個都 >= 0.5 = CRITICAL


@unittest.skipIf(not HAS_INTEL_FUSION, "intel_fusion module not available")
class TestEpssToolWithIntelFusion(unittest.TestCase):
    """EPSS Tool 與 Intel Fusion 六維評分整合測試"""

    def test_calculate_composite_score_with_high_epss(self):
        """高 EPSS 分數應該顯著提升複合分數"""
        score_high_epss, weights, confidence = calculate_composite_score(
            cvss=7.0, epss=0.95, in_kev=False, ghsa_hits=0,
            attack_techniques=0, otx_count=0, cve_year=2024,
        )
        score_low_epss, _, _ = calculate_composite_score(
            cvss=7.0, epss=0.01, in_kev=False, ghsa_hits=0,
            attack_techniques=0, otx_count=0, cve_year=2024,
        )
        self.assertGreater(score_high_epss, score_low_epss)

    def test_kev_disables_epss_weight(self):
        """in_kev=True → EPSS 權重應為 0"""
        _, weights, _ = calculate_composite_score(
            cvss=7.0, epss=0.01, in_kev=True, ghsa_hits=0,
            attack_techniques=0, otx_count=0, cve_year=2024,
        )
        self.assertEqual(weights["epss"], 0.0)

    def test_old_cve_reduces_epss_weight(self):
        """cve_year < 2020 → EPSS 權重應降至 0.10"""
        _, weights, _ = calculate_composite_score(
            cvss=7.0, epss=0.5, in_kev=False, ghsa_hits=0,
            attack_techniques=0, otx_count=0, cve_year=2018,
        )
        self.assertEqual(weights["epss"], 0.10)

    def test_kev_floor_score(self):
        """in_kev=True 時，複合分數不可低於 8.0"""
        score, _, _ = calculate_composite_score(
            cvss=1.0, epss=0.0, in_kev=True, ghsa_hits=0,
            attack_techniques=0, otx_count=0, cve_year=2024,
        )
        self.assertGreaterEqual(score, 8.0)

    def test_weights_sum_to_one(self):
        """所有情境下，調整後的權重總和應接近 1.0"""
        for in_kev in [True, False]:
            for cve_year in [2018, 2024]:
                _, weights, _ = calculate_composite_score(
                    cvss=7.0, epss=0.5, in_kev=in_kev, ghsa_hits=0,
                    attack_techniques=0, otx_count=0, cve_year=cve_year,
                )
                total = sum(weights.values())
                self.assertAlmostEqual(total, 1.0, places=5,
                    msg=f"Weights sum={total:.6f} for in_kev={in_kev}, cve_year={cve_year}")

    def test_confidence_high_with_multiple_dims(self):
        """多維度有資料 → confidence = HIGH"""
        _, _, confidence = calculate_composite_score(
            cvss=9.8, epss=0.97, in_kev=True, ghsa_hits=3,
            attack_techniques=2, otx_count=5, cve_year=2024,
        )
        self.assertEqual(confidence, "HIGH")

    def test_confidence_needs_verification_with_few_dims(self):
        """CVSS=0 + EPSS=0 + no KEV → confidence = NEEDS_VERIFICATION

        註：KEV 在 calculate_composite_score 中永遠算被查詢過（dims_with_data 包含 it）。
        要達到 NEEDS_VERIFICATION 需要 dims_with_data < 2，
        也就是 cvss=0(False) + epss=0(False) + kev=False就只有 1 個維度。
        """
        _, _, confidence = calculate_composite_score(
            cvss=0.0, epss=0.0, in_kev=False, ghsa_hits=0,
            attack_techniques=0, otx_count=0, cve_year=2024,
        )
        self.assertEqual(confidence, "NEEDS_VERIFICATION")


if __name__ == "__main__":
    unittest.main(verbosity=2)
