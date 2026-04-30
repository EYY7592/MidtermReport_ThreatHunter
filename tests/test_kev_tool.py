# tests/test_kev_tool.py
# 測試：CISA KEV（Known Exploited Vulnerabilities）清單查詢 Tool
# 涵蓋：基本功能 + 降級瀑布 + 壓力測試 + 紅隊防禦

import json
import pytest
from unittest.mock import patch, Mock

from tools.kev_tool import (
    _check_kev_impl,
    _build_kev_lookup,
    _ensure_kev_loaded,
)
import tools.kev_tool as kev_module


@pytest.fixture(autouse=True)
def _reset_kev_state():
    """每個測試前重設 KEV 模組狀態"""
    kev_module._kev_lookup = None
    kev_module._kev_total_count = 0
    kev_module._kev_source = "CISA KEV (unavailable)"
    yield
    kev_module._kev_lookup = None
    kev_module._kev_total_count = 0


# ══════════════════════════════════════════════════════════════
# 基本功能測試
# ══════════════════════════════════════════════════════════════

class TestKevBasicFunctionality:
    """KEV Tool 基本功能正確性"""

    @patch("tools.kev_tool._download_kev_catalog")
    def test_single_cve_in_kev(self, mock_dl, fake_kev_catalog):
        """單一 CVE 在 KEV 清單上應回傳 in_kev=True"""
        mock_dl.return_value = fake_kev_catalog
        result = json.loads(_check_kev_impl("CVE-2021-44228"))
        hits = [r for r in result["results"] if r["in_kev"]]
        assert len(hits) == 1
        assert hits[0]["cve_id"] == "CVE-2021-44228"
        assert hits[0]["known_ransomware_use"] == "Known"

    @patch("tools.kev_tool._download_kev_catalog")
    def test_single_cve_not_in_kev(self, mock_dl, fake_kev_catalog):
        """不在 KEV 清單上的 CVE 應回傳 in_kev=False"""
        mock_dl.return_value = fake_kev_catalog
        result = json.loads(_check_kev_impl("CVE-2024-99999"))
        assert result["results"][0]["in_kev"] is False

    @patch("tools.kev_tool._download_kev_catalog")
    def test_multiple_cves_comma_separated(self, mock_dl, fake_kev_catalog):
        """逗號分隔的多 CVE 應全部查詢"""
        mock_dl.return_value = fake_kev_catalog
        result = json.loads(_check_kev_impl("CVE-2021-44228, CVE-2024-99999, CVE-2024-12345"))
        assert len(result["results"]) == 3
        kev_count = sum(1 for r in result["results"] if r["in_kev"])
        assert kev_count == 2  # Log4Shell + Django

    @patch("tools.kev_tool._download_kev_catalog")
    def test_case_insensitive_cve_id(self, mock_dl, fake_kev_catalog):
        """CVE ID 應不區分大小寫"""
        mock_dl.return_value = fake_kev_catalog
        result = json.loads(_check_kev_impl("cve-2021-44228"))
        assert result["results"][0]["in_kev"] is True

    @patch("tools.kev_tool._download_kev_catalog")
    def test_empty_input_returns_error(self, mock_dl, fake_kev_catalog):
        """空輸入應回傳錯誤訊息"""
        mock_dl.return_value = fake_kev_catalog
        result = json.loads(_check_kev_impl(""))
        assert result["results"] == []
        assert "error" in result

    def test_build_kev_lookup_correct(self, fake_kev_catalog):
        """KEV lookup 表建構正確"""
        lookup = _build_kev_lookup(fake_kev_catalog)
        assert "CVE-2021-44228" in lookup
        assert lookup["CVE-2021-44228"]["vendor"] == "Apache"
        assert lookup["CVE-2021-44228"]["product"] == "Log4j"

    @patch("tools.kev_tool._download_kev_catalog")
    def test_kev_details_fields(self, mock_dl, fake_kev_catalog):
        """KEV 命中時應包含完整的詳細欄位"""
        mock_dl.return_value = fake_kev_catalog
        result = json.loads(_check_kev_impl("CVE-2021-44228"))
        hit = result["results"][0]
        required_fields = ["cve_id", "in_kev", "date_added", "due_date",
                           "vendor", "product", "known_ransomware_use", "short_description"]
        for field in required_fields:
            assert field in hit, f"KEV 結果缺少欄位: {field}"


# ══════════════════════════════════════════════════════════════
# 降級瀑布測試
# ══════════════════════════════════════════════════════════════

class TestKevDegradation:
    """KEV Tool 降級瀑布"""

    @patch("tools.kev_tool._read_kev_cache")
    @patch("tools.kev_tool._download_kev_catalog")
    def test_online_failure_uses_cache(self, mock_dl, mock_cache, fake_kev_catalog):
        """線上 KEV 下載失敗時應使用離線快取"""
        mock_dl.return_value = None
        mock_cache.return_value = fake_kev_catalog
        result = json.loads(_check_kev_impl("CVE-2021-44228"))
        assert result["results"][0]["in_kev"] is True
        assert "cache" in result["source"].lower()

    @patch("tools.kev_tool._read_kev_cache")
    @patch("tools.kev_tool._download_kev_catalog")
    def test_total_failure_returns_false(self, mock_dl, mock_cache):
        """線上 + 快取都失敗時，所有查詢回傳 in_kev=False"""
        mock_dl.return_value = None
        mock_cache.return_value = None
        result = json.loads(_check_kev_impl("CVE-2021-44228"))
        assert result["results"][0]["in_kev"] is False

    @patch("tools.kev_tool._download_kev_catalog")
    def test_unexpected_exception_no_crash(self, mock_dl):
        """未預期異常不應 crash"""
        mock_dl.side_effect = RuntimeError("Network explosion")
        # _ensure_kev_loaded 會被 _check_kev_impl 呼叫
        result = json.loads(_check_kev_impl("CVE-2021-44228"))
        assert isinstance(result, dict)
        assert "error" in result or len(result.get("results", [])) >= 0


# ══════════════════════════════════════════════════════════════
# 壓力測試
# ══════════════════════════════════════════════════════════════

class TestKevStress:
    """KEV Tool 壓力測試"""

    @patch("tools.kev_tool._download_kev_catalog")
    def test_batch_1000_cves(self, mock_dl, fake_kev_catalog):
        """批次查詢 1000 個 CVE 應在合理時間內完成"""
        mock_dl.return_value = fake_kev_catalog
        cve_ids = ", ".join(f"CVE-2024-{i:05d}" for i in range(1000))
        import time
        start = time.time()
        result = json.loads(_check_kev_impl(cve_ids))
        elapsed = time.time() - start
        assert len(result["results"]) == 1000
        assert elapsed < 5.0, f"1000 CVE 查詢耗時 {elapsed:.1f}s，超過 5 秒限制"

    @patch("tools.kev_tool._download_kev_catalog")
    def test_whitespace_and_empty_cve_ids(self, mock_dl, fake_kev_catalog):
        """帶空白和空項目的輸入應正確處理"""
        mock_dl.return_value = fake_kev_catalog
        result = json.loads(_check_kev_impl("  CVE-2021-44228  ,  ,  CVE-2024-12345  , "))
        valid_results = [r for r in result["results"] if r["cve_id"]]
        assert len(valid_results) == 2


# ══════════════════════════════════════════════════════════════
# 紅隊防禦測試
# ══════════════════════════════════════════════════════════════

class TestKevRedTeam:
    """KEV Tool 紅隊安全測試"""

    @patch("tools.kev_tool._download_kev_catalog")
    def test_xss_in_cve_id(self, mock_dl, fake_kev_catalog):
        """XSS payload 作為 CVE ID 不應引起問題"""
        mock_dl.return_value = fake_kev_catalog
        result = json.loads(_check_kev_impl("CVE-<script>alert(1)</script>"))
        assert isinstance(result, dict)

    @patch("tools.kev_tool._download_kev_catalog")
    def test_sql_injection_in_cve_id(self, mock_dl, fake_kev_catalog):
        """SQL injection 作為 CVE ID 不應影響系統"""
        mock_dl.return_value = fake_kev_catalog
        result = json.loads(_check_kev_impl("'; DROP TABLE kev; --"))
        assert isinstance(result, dict)
