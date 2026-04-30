# tests/test_osv_tool.py
# 測試：OSV.dev 精確套件漏洞查詢

import json
import pytest
from unittest.mock import patch

from tools.osv_tool import (
    _search_osv_impl,
    _detect_ecosystem,
    _get_canonical_name,
    _parse_osv_vuln,
    search_osv_batch,
)


class TestOsvBasicFunctionality:

    def test_detect_ecosystem_npm(self):
        assert _detect_ecosystem("express") == "npm"
        assert _detect_ecosystem("lodash") == "npm"

    def test_detect_ecosystem_pypi(self):
        assert _detect_ecosystem("django") == "PyPI"
        assert _detect_ecosystem("flask") == "PyPI"

    def test_detect_ecosystem_maven(self):
        assert _detect_ecosystem("log4j") == "Maven"

    def test_canonical_name_mapping(self):
        assert _get_canonical_name("log4j") == "log4j-core"
        assert _get_canonical_name("spring") == "spring-core"

    @patch("tools.osv_tool._query_osv_api")
    def test_basic_query(self, mock_api, fake_osv_response, isolated_cache):
        mock_api.return_value = fake_osv_response
        result = json.loads(_search_osv_impl("django"))
        assert result["count"] >= 1
        assert result["source"] == "OSV"

    def test_parse_osv_vuln_cve_alias(self):
        vuln = {
            "id": "GHSA-test-1234-abcd",
            "aliases": ["CVE-2024-12345"],
            "summary": "Test vuln",
            "severity": [],
            "database_specific": {"severity": "HIGH"},
            "published": "2024-03-15",
            "affected": [{"ranges": [{"events": [{"fixed": "4.2.11"}]}]}],
        }
        parsed = _parse_osv_vuln(vuln, "django")
        assert parsed["cve_id"] == "CVE-2024-12345"
        assert parsed["affected_versions"] == "< 4.2.11"

    def test_parse_osv_vuln_skip_invalid_id(self):
        vuln = {"id": "INVALID-ID", "aliases": [], "summary": "x", "severity": [], "database_specific": {}, "affected": []}
        assert _parse_osv_vuln(vuln, "test") is None

    @patch("tools.osv_tool._query_osv_api")
    def test_api_failure_safe_empty(self, mock_api, isolated_cache):
        mock_api.return_value = None
        result = json.loads(_search_osv_impl("unknown"))
        assert result["count"] == 0
        assert "error" in result


class TestOsvBatch:

    @patch("tools.osv_tool.requests.post")
    def test_batch_query(self, mock_post, isolated_cache):
        """batch 查詢基本功能"""
        from unittest.mock import Mock as _Mock
        mock_post.return_value = _Mock(status_code=200, json=lambda: {
            "results": [{"vulns": []}, {"vulns": []}]
        })
        results = search_osv_batch(["django", "flask"])
        assert isinstance(results, dict)

    def test_empty_batch(self):
        results = search_osv_batch([])
        assert results == {}
