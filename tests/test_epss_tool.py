# tests/test_epss_tool.py
# 測試：FIRST.org EPSS (Exploit Prediction Scoring System) 查詢

import json
import pytest
from unittest.mock import patch, Mock

from tools.epss_tool import (
    get_epss_score,
    _fetch_epss_impl,
    _interpret_epss,
)


class TestEpssBasicFunctionality:
    """EPSS Tool 基本功能"""

    @patch("tools.epss_tool._query_epss_api")
    def test_single_cve_query(self, mock_api, fake_epss_response, isolated_cache):
        """單一 CVE 查詢應回傳正確的 EPSS 分數"""
        mock_api.return_value = fake_epss_response
        result = get_epss_score("CVE-2021-44228")
        assert result["epss"] == pytest.approx(0.94358, abs=0.001)
        assert result["percentile"] == pytest.approx(0.99962, abs=0.001)
        assert result["error"] is None

    @patch("tools.epss_tool._query_epss_api")
    def test_batch_query_comma_separated(self, mock_api, fake_epss_response, isolated_cache):
        """批次查詢（逗號分隔）應正確處理"""
        mock_api.return_value = fake_epss_response
        result = json.loads(_fetch_epss_impl("CVE-2021-44228,CVE-2024-12345"))
        assert result["total"] == 2

    def test_invalid_cve_id_format(self):
        """無效 CVE ID 格式應回傳預設值"""
        result = get_epss_score("NOT-A-CVE")
        assert result["epss"] == 0.0
        assert result["error"] is not None

    def test_empty_cve_id(self):
        """空 CVE ID 應回傳預設值"""
        result = get_epss_score("")
        assert result["epss"] == 0.0

    def test_interpret_critical(self):
        """EPSS >= 0.5 應為 CRITICAL_RISK"""
        assert "CRITICAL_RISK" in _interpret_epss(0.943)

    def test_interpret_high(self):
        """EPSS >= 0.1 應為 HIGH_RISK"""
        assert "HIGH_RISK" in _interpret_epss(0.15)

    def test_interpret_moderate(self):
        """EPSS >= 0.01 應為 MODERATE_RISK"""
        assert "MODERATE_RISK" in _interpret_epss(0.05)

    def test_interpret_low(self):
        """EPSS < 0.01 應為 LOW_RISK"""
        assert "LOW_RISK" in _interpret_epss(0.005)

    def test_max_10_cves_truncation(self):
        """批次查詢最多 10 個 CVE"""
        cves = ",".join(f"CVE-2024-{i:05d}" for i in range(20))
        result = json.loads(_fetch_epss_impl(cves))
        assert result["total"] <= 10

    def test_no_valid_cve_ids(self):
        """全部無效 CVE ID 回傳空結果"""
        result = json.loads(_fetch_epss_impl("invalid1,invalid2"))
        assert result["results"] == []


class TestEpssDegradation:
    """EPSS Tool 降級"""

    @patch("tools.epss_tool._query_epss_api")
    def test_api_failure_returns_zero(self, mock_api):
        """API 失敗回傳 epss=0.0"""
        mock_api.return_value = None
        result = get_epss_score("CVE-2021-44228")
        assert result["epss"] == 0.0
        assert result["error"] is not None
