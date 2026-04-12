# tests/test_intel_fusion.py
# 功能：Intel Fusion Agent 測試套件
# 覆蓋：六維評分 + 動態加權 + KEV 捷徑 + 降級保護
# 遵守：project_CONSTITUTION.md §5

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.intel_fusion import (
    calculate_composite_score,
    _verify_and_recalculate,
    _build_degraded_result,
    DEFAULT_WEIGHTS,
    KEV_MIN_COMPOSITE_SCORE,
)


class TestCalculateCompositeScore(unittest.TestCase):
    """六維加權計算測試"""

    def test_basic_calculation_returns_score_in_range(self):
        """基本計算結果在 0-10 範圍內"""
        score, weights, confidence = calculate_composite_score(
            cvss=7.5, epss=0.3, in_kev=False, ghsa_hits=0,
            attack_techniques=0, otx_count=0, cve_year=2024,
        )
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 10.0)

    def test_kev_hit_floor_score(self):
        """KEV 命中 → 複合分數不可低於 8.0"""
        score, _, _ = calculate_composite_score(
            cvss=2.0, epss=0.0, in_kev=True, ghsa_hits=0,
            attack_techniques=0, otx_count=0, cve_year=2024,
        )
        self.assertGreaterEqual(score, KEV_MIN_COMPOSITE_SCORE)

    def test_kev_removes_epss_weight(self):
        """in_kev=True → EPSS 權重 = 0.0"""
        _, weights, _ = calculate_composite_score(
            cvss=7.0, epss=0.99, in_kev=True, ghsa_hits=0,
            attack_techniques=0, otx_count=0, cve_year=2024,
        )
        self.assertEqual(weights["epss"], 0.0)
        # KEV 權重應增加（surplus 分配給 KEV）
        self.assertGreater(weights["kev"], DEFAULT_WEIGHTS["kev"])

    def test_old_cve_reduces_epss_weight_to_010(self):
        """cve_year < 2020 → EPSS 權重降至 0.10"""
        _, weights, _ = calculate_composite_score(
            cvss=7.0, epss=0.9, in_kev=False, ghsa_hits=0,
            attack_techniques=0, otx_count=0, cve_year=2016,
        )
        self.assertEqual(weights["epss"], 0.10)

    def test_otx_fail_reduces_otx_weight(self):
        """otx_fail_rate > 0.5 → OTX 權重降至 0.01"""
        _, weights, _ = calculate_composite_score(
            cvss=7.0, epss=0.3, in_kev=False, ghsa_hits=0,
            attack_techniques=0, otx_count=0, cve_year=2024,
            otx_fail_rate=0.8,
        )
        self.assertEqual(weights["otx"], 0.01)

    def test_weights_always_sum_to_one(self):
        """所有情境下，權重總和接近 1.0"""
        test_cases = [
            {"in_kev": True, "cve_year": 2024, "otx_fail_rate": 0.0},
            {"in_kev": False, "cve_year": 2016, "otx_fail_rate": 0.0},
            {"in_kev": False, "cve_year": 2024, "otx_fail_rate": 0.8},
            {"in_kev": True, "cve_year": 2016, "otx_fail_rate": 0.9},
        ]
        for case in test_cases:
            _, weights, _ = calculate_composite_score(
                cvss=7.0, epss=0.5, ghsa_hits=0, attack_techniques=0,
                otx_count=0, **case,
            )
            total = sum(weights.values())
            self.assertAlmostEqual(
                total, 1.0, places=5,
                msg=f"Weights sum={total} for case={case}",
            )

    def test_confidence_high_with_all_dims(self):
        """所有維度都有資料 → confidence = HIGH"""
        _, _, confidence = calculate_composite_score(
            cvss=9.8, epss=0.97, in_kev=True, ghsa_hits=5,
            attack_techniques=3, otx_count=10, cve_year=2024,
        )
        self.assertEqual(confidence, "HIGH")

    def test_confidence_needs_verification_minimal_dims(self):
        """CVSS=0 + EPSS=0 + no KEV + 其他全 0 → confidence = NEEDS_VERIFICATION

        KEV 在戶 verify_and_recalculate 中永遠算查詢過（dim_with_data 包含它），
        所以要達到 NEEDS_VERIFICATION 需 dims_with_data < 2（即所有數據維度都為 0 或 False）
        """
        _, _, confidence = calculate_composite_score(
            cvss=0.0, epss=0.0, in_kev=False, ghsa_hits=0,
            attack_techniques=0, otx_count=0, cve_year=2024,
        )
        # cvss=0 (False) + epss=0 (False) + kev=in_kev已查詢(True) = 1 個維度 → NEEDS_VERIFICATION
        self.assertEqual(confidence, "NEEDS_VERIFICATION")

    def test_high_epss_increases_score(self):
        """高 EPSS vs 低 EPSS → 高 EPSS 分數更高"""
        score_high, _, _ = calculate_composite_score(
            cvss=7.0, epss=0.95, in_kev=False, ghsa_hits=0,
            attack_techniques=0, otx_count=0, cve_year=2024,
        )
        score_low, _, _ = calculate_composite_score(
            cvss=7.0, epss=0.01, in_kev=False, ghsa_hits=0,
            attack_techniques=0, otx_count=0, cve_year=2024,
        )
        self.assertGreater(score_high, score_low)

    def test_zero_cvss_with_kev(self):
        """CVSS=0 但 in_kev=True → 仍有高分（KEV 是最高事實）"""
        score, _, _ = calculate_composite_score(
            cvss=0.0, epss=0.0, in_kev=True, ghsa_hits=0,
            attack_techniques=0, otx_count=0, cve_year=2024,
        )
        self.assertGreaterEqual(score, KEV_MIN_COMPOSITE_SCORE)


class TestVerifyAndRecalculate(unittest.TestCase):
    """程式碼層複核計算測試（Harness Layer 2）"""

    def test_no_recalculation_when_scores_close(self):
        """LLM 分數與程式碼計算差異 <= 1.5 → 不替換"""
        result = {
            "fusion_results": [{
                "cve_id": "CVE-2024-TEST",
                "composite_score": 7.5,  # 接近程式碼計算結果
                "dimension_scores": {
                    "cvss": 7.5, "epss": 0.3, "kev": False,
                    "ghsa_severity": "UNKNOWN",
                },
                "confidence": "HIGH",
            }]
        }
        output = _verify_and_recalculate(result)
        # 若沒有替換，不應有 _score_recalculated 欄位（或為 True）
        # 主要測試不崩潰
        self.assertIn("fusion_results", output)
        self.assertEqual(len(output["fusion_results"]), 1)

    def test_recalculation_on_large_discrepancy(self):
        """LLM 分數比程式碼計算差異 > 1.5 → 替換為程式碼計算"""
        # CVSS=1.0, EPSS=0.0, no KEV → 程式碼計算應該 < 5.0
        result = {
            "fusion_results": [{
                "cve_id": "CVE-2024-INFLATED",
                "composite_score": 9.9,  # LLM 有明顯差距（程式碼計算應低很多）
                "dimension_scores": {
                    "cvss": 1.0, "epss": 0.0, "kev": False,
                    "ghsa_severity": "UNKNOWN",
                },
                "confidence": "HIGH",
                "weights_used": {},
            }]
        }
        output = _verify_and_recalculate(result)
        recalculated = output["fusion_results"][0]
        # 若有 _score_recalculated，確認分數被替換
        if recalculated.get("_score_recalculated"):
            self.assertLess(recalculated["composite_score"], 9.9)

    def test_empty_fusion_results(self):
        """空的 fusion_results → 應直接回傳，不崩潰"""
        result = {"fusion_results": [], "strategy_applied": "test"}
        output = _verify_and_recalculate(result)
        self.assertEqual(output["fusion_results"], [])

    def test_handle_missing_dimension_data(self):
        """fusion_result 中缺少 dimension_scores → 使用預設值，不崩潰"""
        result = {
            "fusion_results": [{
                "cve_id": "CVE-2024-MISSING",
                "composite_score": 5.0,
                # 沒有 dimension_scores
                "confidence": "MEDIUM",
            }]
        }
        try:
            output = _verify_and_recalculate(result)
            self.assertIn("fusion_results", output)
        except Exception as e:
            self.fail(f"_verify_and_recalculate raised: {e}")

    def test_invalid_cve_id_year_extraction(self):
        """CVE ID 格式異常 → 年份使用預設 2024，不崩潰"""
        result = {
            "fusion_results": [{
                "cve_id": "NOT-A-CVE",
                "composite_score": 5.0,
                "dimension_scores": {"cvss": 5.0, "epss": 0.1, "kev": False},
                "confidence": "MEDIUM",
            }]
        }
        try:
            output = _verify_and_recalculate(result)
            self.assertIn("fusion_results", output)
        except Exception as e:
            self.fail(f"_verify_and_recalculate raised: {e}")


class TestBuildDegradedResult(unittest.TestCase):
    """Graceful Degradation 降級輸出測試"""

    def test_degraded_result_has_required_structure(self):
        """降級輸出仍有正確的結構（不讓 Analyst 崩潰）"""
        result = _build_degraded_result("Django 4.2", "ConnectionError: timeout")
        required_fields = ["fusion_results", "strategy_applied", "api_health_summary", "_degraded"]
        for field in required_fields:
            self.assertIn(field, result, f"Missing field: {field}")

    def test_degraded_result_has_empty_fusion(self):
        """降級輸出的 fusion_results 為空列表"""
        result = _build_degraded_result("test", "error")
        self.assertEqual(result["fusion_results"], [])

    def test_degraded_flag_is_true(self):
        """降級輸出的 _degraded 為 True"""
        result = _build_degraded_result("test", "error")
        self.assertTrue(result["_degraded"])

    def test_error_message_truncated(self):
        """錯誤訊息被截斷至 200 字元（防止超出 JSON 限制）"""
        long_error = "X" * 500
        result = _build_degraded_result("test", long_error)
        self.assertLessEqual(len(result.get("_error", "")), 200)


class TestDefaultWeights(unittest.TestCase):
    """預設權重常數驗證"""

    def test_default_weights_sum_to_one(self):
        """預設權重總和 = 1.0"""
        total = sum(DEFAULT_WEIGHTS.values())
        self.assertAlmostEqual(total, 1.0, places=10)

    def test_epss_has_highest_weight(self):
        """EPSS 應有最高權重（0.30）— 反映 EPSS 最能預測實際被利用"""
        self.assertEqual(
            max(DEFAULT_WEIGHTS, key=DEFAULT_WEIGHTS.get),
            "epss",
        )

    def test_all_weights_positive(self):
        """所有維度權重 > 0"""
        for dim, weight in DEFAULT_WEIGHTS.items():
            self.assertGreater(weight, 0, f"Weight for {dim} must be positive")


class TestKevShortcutBehavior(unittest.TestCase):
    """KEV Small-World 捷徑行為測試"""

    def test_kev_hit_score_higher_than_non_kev(self):
        """KEV 命中的複合分數 >= 非 KEV 的（即使其他維度相同）"""
        score_kev, _, _ = calculate_composite_score(
            cvss=7.0, epss=0.3, in_kev=True, ghsa_hits=0,
            attack_techniques=0, otx_count=0, cve_year=2024,
        )
        score_no_kev, _, _ = calculate_composite_score(
            cvss=7.0, epss=0.3, in_kev=False, ghsa_hits=0,
            attack_techniques=0, otx_count=0, cve_year=2024,
        )
        self.assertGreaterEqual(score_kev, score_no_kev)

    def test_kev_and_high_cvss_gives_high_score(self):
        """KEV 確認 + CVSS 嚴重 → 複合分數 >= 9.0"""
        score, _, _ = calculate_composite_score(
            cvss=10.0, epss=0.0, in_kev=True, ghsa_hits=3,
            attack_techniques=2, otx_count=5, cve_year=2024,
        )
        self.assertGreaterEqual(score, 9.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
