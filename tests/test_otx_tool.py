# tests/test_otx_tool.py
# 測試：AlienVault OTX 威脅情報查詢 Tool
# 涵蓋：基本功能 + 時間邏輯 + 降級瀑布

import json
import pytest
from unittest.mock import patch, Mock
from datetime import datetime, timezone, timedelta

from tools.otx_tool import (
    _search_otx_impl,
    _determine_threat_level,
    _parse_pulse,
    _parse_otx_response,
)


class TestOtxBasicFunctionality:
    """OTX Tool 基本功能正確性"""

    @patch("tools.otx_tool._query_otx_api")
    def test_active_threat_level(self, mock_api, isolated_cache):
        """有最近 pulse 且數量 >= 3 應判定為 active"""
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        # 動態生成最近日期的 OTX 回應
        fresh_response = {
            "results": [
                {"name": "pulse1", "description": "d1",
                 "created": (now - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%S.000000"),
                 "tags": ["django"], "indicators": []},
                {"name": "pulse2", "description": "d2",
                 "created": (now - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S.000000"),
                 "tags": ["django"], "indicators": []},
                {"name": "pulse3", "description": "d3",
                 "created": (now - timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%S.000000"),
                 "tags": ["django"], "indicators": []},
            ]
        }
        mock_api.return_value = fresh_response
        result = json.loads(_search_otx_impl("django"))
        assert result["pulse_count"] == 3
        assert result["threat_level"] == "active"
        assert result["source"] == "OTX"

    @patch("tools.otx_tool._query_otx_api")
    def test_no_results_unknown(self, mock_api, isolated_cache):
        """無 pulse 應判定為 unknown"""
        mock_api.return_value = {"results": []}
        result = json.loads(_search_otx_impl("nonexistent"))
        assert result["pulse_count"] == 0
        assert result["threat_level"] == "unknown"

    def test_parse_pulse_truncation(self):
        """pulse 解析應截斷過長欄位"""
        pulse = {
            "name": "x" * 500,
            "description": "y" * 500,
            "created": "2024-03-20T12:00:00.000000",
            "tags": list(range(20)),
            "indicators": [{"type": "IPv4", "indicator": "1.2.3.4"}] * 50,
        }
        parsed = _parse_pulse(pulse)
        assert len(parsed["name"]) <= 200
        assert len(parsed["description"]) <= 300
        assert len(parsed["tags"]) <= 10


class TestOtxThreatLevel:
    """OTX 威脅等級判定時間邏輯"""

    def test_active_recent_pulse(self):
        """90 天內有 pulse → active"""
        now = datetime.now(timezone.utc)
        recent = (now - timedelta(days=30)).isoformat()
        pulses = [{"created": recent}]
        assert _determine_threat_level(1, pulses) == "active"

    def test_inactive_old_pulse(self):
        """所有 pulse 都超過 90 天 → inactive"""
        old = (datetime.now(timezone.utc) - timedelta(days=180)).isoformat()
        pulses = [{"created": old}]
        assert _determine_threat_level(1, pulses) == "inactive"

    def test_unknown_zero_pulses(self):
        """零 pulse → unknown"""
        assert _determine_threat_level(0, []) == "unknown"

    def test_boundary_90_days(self):
        """恰好 90 天邊界測試"""
        boundary = (datetime.now(timezone.utc) - timedelta(days=89)).isoformat()
        pulses = [{"created": boundary}]
        assert _determine_threat_level(1, pulses) == "active"


class TestOtxDegradation:
    """OTX Tool 降級瀑布"""

    @patch("tools.otx_tool._query_otx_api")
    def test_api_failure_uses_cache(self, mock_api, fake_otx_response, isolated_cache):
        """API 失敗時使用快取"""
        mock_api.return_value = fake_otx_response
        _search_otx_impl("django")  # 第一次：寫快取

        mock_api.return_value = None
        result = json.loads(_search_otx_impl("django"))
        assert result["pulse_count"] == 3
        assert result.get("fallback_used") is True

    @patch("tools.otx_tool._query_otx_api")
    def test_total_failure_safe_empty(self, mock_api, isolated_cache):
        """API + 快取都失敗 → 安全空結果"""
        mock_api.return_value = None
        result = json.loads(_search_otx_impl("unknown-pkg"))
        assert result["pulse_count"] == 0
        assert result["threat_level"] == "unknown"

    @patch("tools.otx_tool._query_otx_api")
    def test_unexpected_exception_no_crash(self, mock_api, isolated_cache):
        """未預期異常不 crash"""
        mock_api.side_effect = ValueError("bad json")
        result = json.loads(_search_otx_impl("django"))
        assert result["pulse_count"] == 0
        assert "error" in result
