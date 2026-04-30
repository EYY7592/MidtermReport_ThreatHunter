# tests/test_attck_tool.py
# 測試：CWE → CAPEC → MITRE ATT&CK Technique 映射

import pytest
from tools.attck_tool import (
    lookup_attck_by_cwe,
    lookup_attck_by_description,
    get_attck_for_cve,
    CWE_TO_ATTCK,
    KEYWORD_TO_CWE,
)


class TestAttckBasicFunctionality:

    def test_cwe79_maps_to_javascript(self):
        result = lookup_attck_by_cwe("CWE-79")
        assert result is not None
        assert result["technique_id"] == "T1059.007"
        assert result["tactic"] == "Execution"

    def test_cwe89_maps_to_t1190(self):
        result = lookup_attck_by_cwe("CWE-89")
        assert result["technique_id"] == "T1190"
        assert result["capec"] == "CAPEC-66"

    def test_cwe_without_prefix(self):
        """輸入 '79' 也應正確映射"""
        result = lookup_attck_by_cwe("79")
        assert result is not None
        assert result["technique_id"] == "T1059.007"

    def test_cwe_case_insensitive(self):
        result = lookup_attck_by_cwe("cwe-89")
        assert result is not None

    def test_unknown_cwe_returns_none(self):
        result = lookup_attck_by_cwe("CWE-99999")
        assert result is None

    def test_description_keyword_xss(self):
        result = lookup_attck_by_description("Cross-site scripting vulnerability in web app")
        assert result is not None
        assert result["technique_id"] == "T1059.007"

    def test_description_keyword_sqli(self):
        result = lookup_attck_by_description("SQL injection allows data exfiltration")
        assert result is not None
        assert result["technique_id"] == "T1190"

    def test_description_keyword_ssrf(self):
        result = lookup_attck_by_description("SSRF vulnerability allows internal service access")
        assert result is not None
        assert result["technique_id"] == "T1090"

    def test_description_with_cwe_id(self):
        """描述中包含 CWE 編號應優先使用"""
        result = lookup_attck_by_description("CWE-502 deserialization flaw")
        assert result is not None
        assert result["technique_id"] == "T1059"

    def test_no_match_returns_none(self):
        result = lookup_attck_by_description("This is a normal log message")
        assert result is None

    def test_get_attck_for_cve_with_cwe_list(self):
        """提供 CWE 列表應優先使用"""
        result = get_attck_for_cve("CVE-2024-00001", cwe_ids=["CWE-79"])
        assert result["technique_id"] == "T1059.007"
        assert result["matched_by"] == "CWE-79"

    def test_get_attck_for_cve_fallback_description(self):
        """無 CWE 列表時 fallback 到描述推斷"""
        result = get_attck_for_cve("CVE-2024-00001", description="SQL injection flaw")
        assert result["technique_id"] == "T1190"
        assert "keyword" in result["matched_by"]

    def test_get_attck_for_cve_default_t1190(self):
        """完全無法匹配時回傳 T1190 預設值"""
        result = get_attck_for_cve("CVE-2024-00001")
        assert result["technique_id"] == "T1190"
        assert result["matched_by"] is None

    def test_all_keyword_mappings_valid(self):
        """所有 keyword 映射的 CWE 都在 CWE_TO_ATTCK 表中"""
        for keyword, cwe in KEYWORD_TO_CWE.items():
            assert cwe in CWE_TO_ATTCK, f"Keyword '{keyword}' maps to {cwe} which is not in CWE_TO_ATTCK"
