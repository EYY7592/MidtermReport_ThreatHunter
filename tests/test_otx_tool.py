# tests/test_otx_tool.py
# OTX Tool 單元測試 — Day 1 不需要 LLM，只測 API 呼叫
#
# 執行：
#   .venv\Scripts\python.exe -m pytest tests/test_otx_tool.py -v
#
# 注意：
#   部分測試會實際呼叫 OTX API（標記 @pytest.mark.api）
#   需要 OTX_API_KEY 環境變數
#   無 API Key 可跳過：pytest -m "not api"

import json
import os
import sys
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.otx_tool import (
    _search_otx_impl,
    _determine_threat_level,
    _parse_pulse,
    _parse_otx_response,
)


# ══════════════════════════════════════════════════════════════
# 威脅等級判定測試
# ══════════════════════════════════════════════════════════════

class TestThreatLevelDetermination:
    """threat_level 判定邏輯測試"""

    def test_no_pulses_returns_unknown(self):
        """0 筆 pulse → unknown"""
        assert _determine_threat_level(0, []) == "unknown"

    def test_recent_pulses_returns_active(self):
        """最近 90 天有 pulse → active"""
        recent_date = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        pulses = [
            {"created": recent_date},
            {"created": recent_date},
            {"created": recent_date},
        ]
        assert _determine_threat_level(3, pulses) == "active"

    def test_old_pulses_returns_inactive(self):
        """所有 pulse 都超過 90 天 → inactive"""
        old_date = (datetime.now(timezone.utc) - timedelta(days=180)).isoformat()
        pulses = [
            {"created": old_date},
            {"created": old_date},
        ]
        assert _determine_threat_level(2, pulses) == "inactive"

    def test_single_recent_pulse_returns_active(self):
        """即使只有 1 筆 recent pulse 也算 active"""
        recent = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        pulses = [{"created": recent}]
        assert _determine_threat_level(1, pulses) == "active"

    def test_mixed_old_and_recent(self):
        """混合新舊 pulse — 只要有 recent 就 active"""
        old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
        recent = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
        pulses = [
            {"created": old},
            {"created": recent},
            {"created": old},
        ]
        assert _determine_threat_level(3, pulses) == "active"

    def test_bad_date_format_handled(self):
        """無法解析的日期不會 crash"""
        pulses = [{"created": "not-a-date"}, {"created": "also-bad"}]
        result = _determine_threat_level(2, pulses)
        assert result in ("active", "inactive", "unknown")


# ══════════════════════════════════════════════════════════════
# Pulse 解析測試
# ══════════════════════════════════════════════════════════════

class TestParsePulse:
    """單一 pulse 解析測試"""

    def test_basic_parsing(self):
        pulse = {
            "name": "Django Critical CVE-2024-42005",
            "description": "Active exploitation observed",
            "created": "2024-08-10T12:00:00",
            "tags": ["django", "sqli"],
            "indicators": [{"type": "CVE"}, {"type": "URL"}],
        }
        result = _parse_pulse(pulse)
        assert result["name"] == "Django Critical CVE-2024-42005"
        assert result["indicator_count"] == 2
        assert result["created"] == "2024-08-10"
        assert result["tags"] == ["django", "sqli"]

    def test_truncates_long_name(self):
        pulse = {"name": "A" * 300, "description": "", "created": "", "tags": [], "indicators": []}
        result = _parse_pulse(pulse)
        assert len(result["name"]) <= 200

    def test_truncates_long_description(self):
        pulse = {"name": "", "description": "B" * 500, "created": "", "tags": [], "indicators": []}
        result = _parse_pulse(pulse)
        assert len(result["description"]) <= 300

    def test_handles_missing_fields(self):
        """缺失欄位不會 crash"""
        result = _parse_pulse({})
        assert result["name"] == ""
        assert result["indicator_count"] == 0
        assert result["tags"] == []

    def test_limits_tags(self):
        pulse = {"name": "", "description": "", "created": "", "tags": list(range(20)), "indicators": []}
        result = _parse_pulse(pulse)
        assert len(result["tags"]) <= 10


# ══════════════════════════════════════════════════════════════
# OTX Response 解析測試
# ══════════════════════════════════════════════════════════════

class TestParseOtxResponse:
    """OTX API response 解析測試"""

    def test_basic_parsing(self):
        recent = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        raw = {
            "results": [
                {"name": "Pulse 1", "description": "desc", "created": recent,
                 "tags": ["django"], "indicators": [{"type": "CVE"}]},
                {"name": "Pulse 2", "description": "desc2", "created": recent,
                 "tags": [], "indicators": []},
            ]
        }
        result = _parse_otx_response(raw, "django")
        assert result["package"] == "django"
        assert result["source"] == "OTX"
        assert result["pulse_count"] == 2
        assert result["threat_level"] == "active"

    def test_empty_results(self):
        raw = {"results": []}
        result = _parse_otx_response(raw, "test")
        assert result["pulse_count"] == 0
        assert result["threat_level"] == "unknown"

    def test_missing_results_key(self):
        raw = {}
        result = _parse_otx_response(raw, "test")
        assert result["pulse_count"] == 0


# ══════════════════════════════════════════════════════════════
# 整合測試（需要 OTX API Key）
# ══════════════════════════════════════════════════════════════

@pytest.mark.api
class TestOtxApiIntegration:
    """
    實際 API 呼叫測試。
    需要 OTX_API_KEY 環境變數。
    執行：pytest tests/test_otx_tool.py -m api -v
    """

    @pytest.fixture(autouse=True)
    def check_api_key(self):
        if not os.getenv("OTX_API_KEY"):
            pytest.skip("OTX_API_KEY not set")

    def test_django_returns_pulses(self):
        result = _search_otx_impl("django")
        data = json.loads(result)
        assert data["package"] == "django"
        assert data["source"] == "OTX"
        assert data["threat_level"] in ("active", "inactive", "unknown")

    def test_output_is_valid_json(self):
        result = _search_otx_impl("redis")
        data = json.loads(result)
        assert isinstance(data, dict)
        assert "pulse_count" in data
        assert "threat_level" in data

    def test_unknown_package(self):
        result = _search_otx_impl("asdfghjkl_nonexistent_xyz")
        data = json.loads(result)
        assert data["pulse_count"] >= 0  # 不 crash 就好


# ══════════════════════════════════════════════════════════════
# Mock 測試（離線）
# ══════════════════════════════════════════════════════════════

class TestOtxToolWithMock:
    """使用 mock 的離線測試 — 同時 patch 快取避免干擾"""

    @patch("tools.otx_tool._read_cache", return_value=None)
    @patch("tools.otx_tool.requests.get")
    def test_api_failure_returns_unknown(self, mock_get, mock_cache):
        """API 完全失敗 → threat_level: unknown"""
        mock_get.side_effect = Exception("Connection failed")
        result = _search_otx_impl("mock_pkg_fail")
        data = json.loads(result)
        assert data["threat_level"] == "unknown"
        assert isinstance(data, dict)

    @patch("tools.otx_tool._read_cache", return_value=None)
    @patch("tools.otx_tool.requests.get")
    def test_api_403_returns_unknown(self, mock_get, mock_cache):
        """API 403 + 無快取 → threat_level: unknown"""
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_get.return_value = mock_response
        result = _search_otx_impl("mock_pkg_403")
        data = json.loads(result)
        assert data["threat_level"] == "unknown"

    @patch("tools.otx_tool._read_cache", return_value=None)
    @patch("tools.otx_tool.requests.get")
    def test_successful_api_call(self, mock_get, mock_cache):
        """模擬成功的 API 回傳"""
        recent = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [
                {"name": "Test Pulse", "description": "test",
                 "created": recent, "tags": ["test"], "indicators": [{"type": "CVE"}]},
            ]
        }
        mock_get.return_value = mock_response
        result = _search_otx_impl("mock_pkg_ok")
        data = json.loads(result)
        assert data["pulse_count"] == 1
        assert data["threat_level"] == "active"
