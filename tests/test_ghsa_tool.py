# tests/test_ghsa_tool.py
# 測試：GitHub Security Advisory Database（GHSA）查詢 Tool

import json
import pytest
from unittest.mock import patch, Mock

from tools.ghsa_tool import (
    _query_ghsa_impl,
    _parse_ghsa_advisories,
    _normalize_ecosystem,
    SEVERITY_SCORE,
)


class TestGhsaBasicFunctionality:

    @patch("tools.ghsa_tool._fetch_ghsa_rest")
    def test_package_query(self, mock_fetch, fake_ghsa_advisories, isolated_cache):
        mock_fetch.return_value = _parse_ghsa_advisories(fake_ghsa_advisories, "django", "pip")
        result = json.loads(_query_ghsa_impl("django:python"))
        assert result["hits"] == 2
        assert result["max_severity"] == "HIGH"

    @patch("tools.ghsa_tool._fetch_ghsa_rest")
    def test_no_ecosystem_defaults_pip(self, mock_fetch, isolated_cache):
        mock_fetch.return_value = {"hits": 0, "max_severity": "UNKNOWN", "severity_score": 0.0, "cve_ids": [], "ghsa_ids": [], "published_since": "", "_source": "GHSA"}
        result = json.loads(_query_ghsa_impl("django"))
        assert result["ecosystem"] == "pip"

    def test_normalize_ecosystem(self):
        assert _normalize_ecosystem("python") == "pip"
        assert _normalize_ecosystem("javascript") == "npm"
        assert _normalize_ecosystem("golang") == "go"

    def test_parse_empty_advisories(self):
        result = _parse_ghsa_advisories([], "django", "pip")
        assert result["hits"] == 0

    def test_severity_score_values(self):
        assert SEVERITY_SCORE["CRITICAL"] == 1.0
        assert SEVERITY_SCORE["HIGH"] == 0.75

    @patch("tools.ghsa_tool._fetch_ghsa_rest")
    def test_empty_package_name(self, mock_fetch, isolated_cache):
        result = json.loads(_query_ghsa_impl(""))
        assert result["hits"] == 0

    @patch("tools.ghsa_tool._read_ghsa_cache")
    @patch("tools.ghsa_tool._fetch_ghsa_rest")
    def test_unexpected_exception(self, mock_fetch, mock_cache, isolated_cache):
        """未預期異常不 crash，回傳 hits=0"""
        mock_cache.return_value = {}  # 空快取
        mock_fetch.side_effect = RuntimeError("boom")
        result = json.loads(_query_ghsa_impl("django"))
        assert result["hits"] == 0
        # 異常時 GHSA 回傳 error 鍵
        assert "error" in result
