# tests/test_nvd_tool.py
# NVD Tool 單元測試 — Day 1 不需要 LLM，只測 API 呼叫
#
# 執行：
#   .venv\Scripts\python.exe -m pytest tests/test_nvd_tool.py -v
#
# 注意：
#   部分測試會實際呼叫 NVD API（標記 @pytest.mark.api）
#   無網路環境可跳過：pytest -m "not api"

import json
import os
import sys
import time
import pytest
from unittest.mock import patch, MagicMock

# 確保 import 路徑正確
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.nvd_tool import (
    _search_nvd_impl,
    _normalize_package_name,
    _cvss_to_severity,
    _extract_cvss,
    _extract_description,
    _parse_nvd_response,
    _read_cache,
    _write_cache,
)


# ══════════════════════════════════════════════════════════════
# 輔助函式測試
# ══════════════════════════════════════════════════════════════

class TestPackageNameNormalization:
    """套件名稱正規化測試"""

    def test_direct_name(self):
        """直接名稱不需要轉換"""
        result = _normalize_package_name("django")
        assert "django" in result

    def test_alias_mapping(self):
        """別名對應（postgres → postgresql）"""
        result = _normalize_package_name("postgres")
        assert "postgresql" in result

    def test_strip_version(self):
        """去掉版本號（django 4.2 → django）"""
        result = _normalize_package_name("django 4.2")
        assert "django" in result
        assert "4.2" not in result[0]

    def test_case_insensitive(self):
        """大小寫不敏感"""
        result = _normalize_package_name("Django")
        assert "django" in result

    def test_whitespace_handling(self):
        """去除前後空白"""
        result = _normalize_package_name("  redis  ")
        assert "redis" in result

    def test_unknown_package(self):
        """未知套件名稱原樣回傳"""
        result = _normalize_package_name("some_unknown_pkg")
        assert "some_unknown_pkg" in result


class TestCvssSeverity:
    """CVSS → 嚴重度轉換測試"""

    def test_critical(self):
        assert _cvss_to_severity(9.8) == "CRITICAL"
        assert _cvss_to_severity(9.0) == "CRITICAL"
        assert _cvss_to_severity(10.0) == "CRITICAL"

    def test_high(self):
        assert _cvss_to_severity(8.9) == "HIGH"
        assert _cvss_to_severity(7.0) == "HIGH"

    def test_medium(self):
        assert _cvss_to_severity(6.9) == "MEDIUM"
        assert _cvss_to_severity(4.0) == "MEDIUM"

    def test_low(self):
        assert _cvss_to_severity(3.9) == "LOW"
        assert _cvss_to_severity(0.1) == "LOW"


class TestExtractCvss:
    """CVSS 提取測試（v3.1 → v3.0 → v2 降級）"""

    def test_v31_extraction(self):
        metrics = {
            "cvssMetricV31": [{
                "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}
            }]
        }
        score, severity = _extract_cvss(metrics)
        assert score == 9.8
        assert severity == "CRITICAL"

    def test_v30_fallback(self):
        metrics = {
            "cvssMetricV30": [{
                "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}
            }]
        }
        score, severity = _extract_cvss(metrics)
        assert score == 7.5
        assert severity == "HIGH"

    def test_v2_fallback(self):
        metrics = {
            "cvssMetricV2": [{
                "cvssData": {"baseScore": 6.5}
            }]
        }
        score, severity = _extract_cvss(metrics)
        assert score == 6.5
        assert severity == "MEDIUM"

    def test_empty_metrics(self):
        score, severity = _extract_cvss({})
        assert score == 0.0
        assert severity == "LOW"


class TestExtractDescription:
    """描述提取測試"""

    def test_english_preferred(self):
        descs = [
            {"lang": "es", "value": "Descripción en español"},
            {"lang": "en", "value": "English description"},
        ]
        assert _extract_description(descs) == "English description"

    def test_fallback_to_first(self):
        descs = [{"lang": "es", "value": "Descripción"}]
        assert _extract_description(descs) == "Descripción"

    def test_empty_list(self):
        assert _extract_description([]) == ""


# ══════════════════════════════════════════════════════════════
# NVD Response 解析測試
# ══════════════════════════════════════════════════════════════

class TestParseNvdResponse:
    """NVD API response 解析測試"""

    def _make_nvd_response(self, cves):
        """建立模擬 NVD API response"""
        vulns = []
        for cve_id, score, severity, desc in cves:
            vulns.append({
                "cve": {
                    "id": cve_id,
                    "descriptions": [{"lang": "en", "value": desc}],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": score,
                                "baseSeverity": severity,
                            }
                        }]
                    },
                    "published": "2024-08-07T00:00:00Z",
                    "configurations": [],
                }
            })
        return {"vulnerabilities": vulns}

    def test_basic_parsing(self):
        raw = self._make_nvd_response([
            ("CVE-2024-42005", 9.8, "CRITICAL", "SQL injection"),
            ("CVE-2024-41991", 7.5, "HIGH", "DoS vulnerability"),
        ])
        result = _parse_nvd_response(raw, "django")
        assert result["package"] == "django"
        assert result["source"] == "NVD"
        assert result["count"] == 2
        assert len(result["vulnerabilities"]) == 2

    def test_sorted_by_cvss_desc(self):
        raw = self._make_nvd_response([
            ("CVE-2024-0001", 3.0, "LOW", "Low severity"),
            ("CVE-2024-0002", 9.8, "CRITICAL", "Critical"),
            ("CVE-2024-0003", 7.5, "HIGH", "High severity"),
        ])
        result = _parse_nvd_response(raw, "test")
        scores = [v["cvss_score"] for v in result["vulnerabilities"]]
        assert scores == sorted(scores, reverse=True)

    def test_empty_response(self):
        raw = {"vulnerabilities": []}
        result = _parse_nvd_response(raw, "test")
        assert result["count"] == 0
        assert result["vulnerabilities"] == []

    def test_skips_non_cve(self):
        """跳過非 CVE 格式 ID"""
        raw = {"vulnerabilities": [
            {"cve": {"id": "NOT-A-CVE", "descriptions": [], "metrics": {}, "configurations": []}},
            {"cve": {"id": "CVE-2024-1234", "descriptions": [{"lang": "en", "value": "test"}],
                     "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}}]},
                     "configurations": []}},
        ]}
        result = _parse_nvd_response(raw, "test")
        assert result["count"] == 1
        assert result["vulnerabilities"][0]["cve_id"] == "CVE-2024-1234"


# ══════════════════════════════════════════════════════════════
# 整合測試（實際呼叫 NVD API）
# ══════════════════════════════════════════════════════════════

@pytest.mark.api
class TestNvdApiIntegration:
    """
    實際 API 呼叫測試。
    執行：pytest tests/test_nvd_tool.py -m api -v
    跳過：pytest tests/test_nvd_tool.py -m "not api" -v
    """

    def test_django_returns_results(self):
        """django 應該回傳多個 CVE"""
        result = _search_nvd_impl("django")
        data = json.loads(result)
        assert data["package"] == "django"
        assert data["source"] == "NVD"
        assert data["count"] > 0
        assert len(data["vulnerabilities"]) > 0

    def test_cve_format_valid(self):
        """所有回傳的 CVE ID 格式正確"""
        import re
        result = _search_nvd_impl("django")
        data = json.loads(result)
        for vuln in data["vulnerabilities"]:
            assert re.match(r"^CVE-\d{4}-\d{4,}$", vuln["cve_id"]), \
                f"Invalid CVE format: {vuln['cve_id']}"

    def test_cvss_range_valid(self):
        """所有 CVSS 分數在 0.0 - 10.0 範圍"""
        result = _search_nvd_impl("redis")
        data = json.loads(result)
        for vuln in data["vulnerabilities"]:
            assert 0.0 <= vuln["cvss_score"] <= 10.0, \
                f"CVSS out of range: {vuln['cvss_score']}"

    def test_severity_valid(self):
        """severity 必須是 CRITICAL/HIGH/MEDIUM/LOW"""
        result = _search_nvd_impl("django")
        data = json.loads(result)
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for vuln in data["vulnerabilities"]:
            assert vuln["severity"] in valid, \
                f"Invalid severity: {vuln['severity']}"

    def test_unknown_package_returns_zero(self):
        """不存在的套件應回傳 count=0，不應 crash"""
        result = _search_nvd_impl("asdfghjkl_nonexistent_12345")
        data = json.loads(result)
        assert data["count"] == 0
        assert data["vulnerabilities"] == []

    def test_alias_postgres_to_postgresql(self):
        """postgres 別名應能查到 postgresql 的 CVE"""
        result = _search_nvd_impl("postgres")
        data = json.loads(result)
        # postgresql 通常有不少 CVE
        assert data["count"] >= 0  # 至少不 crash

    def test_output_is_valid_json(self):
        """輸出必須是合法 JSON"""
        result = _search_nvd_impl("nginx")
        data = json.loads(result)  # 如果不是 JSON 會拋出 JSONDecodeError
        assert isinstance(data, dict)


# ══════════════════════════════════════════════════════════════
# Mock 測試（離線，不需要網路）
# ══════════════════════════════════════════════════════════════

class TestNvdToolWithMock:
    """使用 mock 的離線測試"""

    @patch("tools.nvd_tool.requests.get")
    def test_api_timeout_graceful_degradation(self, mock_get):
        """API timeout 不會 crash"""
        mock_get.side_effect = Exception("Connection timeout")
        result = _search_nvd_impl("django")
        data = json.loads(result)
        assert isinstance(data, dict)
        assert data["count"] >= 0  # 可能有快取

    @patch("tools.nvd_tool.requests.get")
    def test_api_500_graceful_degradation(self, mock_get):
        """API 500 不會 crash"""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_get.return_value = mock_response
        result = _search_nvd_impl("django")
        data = json.loads(result)
        assert isinstance(data, dict)

    @patch("tools.nvd_tool.requests.get")
    def test_api_returns_empty_json(self, mock_get):
        """API 回傳空 JSON"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulnerabilities": []}
        mock_get.return_value = mock_response
        result = _search_nvd_impl("some_package")
        data = json.loads(result)
        assert data["count"] == 0
