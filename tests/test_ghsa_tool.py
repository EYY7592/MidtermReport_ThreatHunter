"""
tests/test_ghsa_tool.py — GitHub Advisory Database (GHSA) Tool 測試
====================================================================
測試策略：
  - 對確定性函式（快取增刪、生態系推斷、結果解析）進行單元測試
  - 對網路函式進行 Mock（不真實呼叫 GitHub API，避免超時/額度消耗）
  - 覆蓋：Happy Path、快取命中、降級行為、輸入格式、輸出格式驗證
"""
import json
import os
import time
import pytest
from unittest.mock import MagicMock, patch

from tools.ghsa_tool import (
    _normalize_ecosystem,
    _is_cache_fresh,
    _parse_ghsa_advisories,
    _query_ghsa_impl,
    SUPPORTED_ECOSYSTEMS,
    CACHE_TTL_HOURS,
)


# ══════════════════════════════════════════════════════════════
# Fixtures
# ══════════════════════════════════════════════════════════════

@pytest.fixture
def sample_advisory_list():
    """模擬 GitHub Advisory Database 返回的 advisories 列表"""
    return [
        {
            "ghsa_id": "GHSA-1234-5678-abcd",
            "cve_id": "CVE-2024-42005",
            "severity": "CRITICAL",
            "summary": "SQL injection in Django ORM",
            "published_at": "2024-09-01T10:00:00Z",
            "withdrawn_at": None,
        },
        {
            "ghsa_id": "GHSA-efgh-5678-ijkl",
            "cve_id": "CVE-2023-99999",
            "severity": "HIGH",
            "summary": "Denial of service in Django",
            "published_at": "2023-06-15T10:00:00Z",
            "withdrawn_at": None,
        },
    ]


@pytest.fixture
def empty_advisory_list():
    return []


@pytest.fixture
def mock_requests_success(sample_advisory_list):
    """Mock requests.get 成功返回"""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = sample_advisory_list
    return mock_resp


@pytest.fixture
def mock_requests_rate_limit():
    """Mock requests.get → 403 rate limited"""
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.headers = {"X-RateLimit-Reset": "1712700000"}
    return mock_resp


@pytest.fixture
def fresh_cache():
    """新鮮的快取條目（未過期）"""
    return {
        "django:pip": {
            "hits": 2,
            "max_severity": "CRITICAL",
            "severity_score": 1.0,
            "cve_ids": ["CVE-2024-42005"],
            "ghsa_ids": ["GHSA-1234-5678-abcd"],
            "published_since": "2024-09-01T10:00:00Z",
            "_source": "GHSA REST API (online)",
            "_cached_at": time.time(),  # 剛寫入
        }
    }


@pytest.fixture
def stale_cache():
    """過期的快取條目（TTL 已過）"""
    return {
        "django:pip": {
            "hits": 1,
            "max_severity": "HIGH",
            "severity_score": 0.75,
            "cve_ids": ["CVE-2023-99999"],
            "ghsa_ids": ["GHSA-efgh-5678-ijkl"],
            "published_since": "2023-06-15T10:00:00Z",
            "_source": "GHSA REST API (online)",
            "_cached_at": time.time() - (CACHE_TTL_HOURS + 1) * 3600,  # 已過期
        }
    }


# ══════════════════════════════════════════════════════════════
# 1. 生態系名稱正規化
# ══════════════════════════════════════════════════════════════

class TestNormalizeEcosystem:
    """生態系名稱轉換應正確"""

    def test_python_to_pip(self):
        assert _normalize_ecosystem("python") == "pip"

    def test_pip_stays_pip(self):
        assert _normalize_ecosystem("pip") == "pip"

    def test_node_to_npm(self):
        assert _normalize_ecosystem("node") == "npm"

    def test_npm_stays_npm(self):
        assert _normalize_ecosystem("npm") == "npm"

    def test_golang_to_go(self):
        assert _normalize_ecosystem("golang") == "go"

    def test_java_to_maven(self):
        assert _normalize_ecosystem("java") == "maven"

    def test_rust_to_crates_io(self):
        assert _normalize_ecosystem("rust") == "crates.io"

    def test_case_insensitive(self):
        assert _normalize_ecosystem("Python") == "pip"
        assert _normalize_ecosystem("NPM") == "npm"

    def test_unknown_passthrough(self):
        """未知生態系直接小寫透過"""
        result = _normalize_ecosystem("customlang")
        assert result == "customlang"

    def test_all_supported_ecosystems(self):
        """所有已定義的生態系都應能被正規化"""
        for key in SUPPORTED_ECOSYSTEMS:
            result = _normalize_ecosystem(key)
            assert isinstance(result, str) and len(result) > 0


# ══════════════════════════════════════════════════════════════
# 2. 快取新鮮度檢查
# ══════════════════════════════════════════════════════════════

class TestIsCacheFresh:
    """快取 TTL 檢查應正確"""

    def test_fresh_cache_is_fresh(self):
        entry = {"_cached_at": time.time()}
        assert _is_cache_fresh(entry) is True

    def test_stale_cache_is_not_fresh(self):
        entry = {"_cached_at": time.time() - (CACHE_TTL_HOURS + 1) * 3600}
        assert _is_cache_fresh(entry) is False

    def test_exactly_at_ttl_is_not_fresh(self):
        entry = {"_cached_at": time.time() - CACHE_TTL_HOURS * 3600 - 60}
        assert _is_cache_fresh(entry) is False

    def test_missing_cached_at_is_stale(self):
        """缺少 _cached_at 欄位 → 視為過期"""
        entry = {}
        assert _is_cache_fresh(entry) is False


# ══════════════════════════════════════════════════════════════
# 3. Advisory 解析
# ══════════════════════════════════════════════════════════════

class TestParseGhsaAdvisories:
    """Advisory 列表解析應正確提取核心欄位"""

    def test_parse_hits_count(self, sample_advisory_list):
        result = _parse_ghsa_advisories(sample_advisory_list, "django", "pip")
        assert result["hits"] == 2

    def test_parse_max_severity_critical(self, sample_advisory_list):
        result = _parse_ghsa_advisories(sample_advisory_list, "django", "pip")
        assert result["max_severity"] == "CRITICAL"

    def test_parse_severity_score(self, sample_advisory_list):
        result = _parse_ghsa_advisories(sample_advisory_list, "django", "pip")
        assert result["severity_score"] == 1.0  # CRITICAL

    def test_parse_cve_ids(self, sample_advisory_list):
        result = _parse_ghsa_advisories(sample_advisory_list, "django", "pip")
        assert "CVE-2024-42005" in result["cve_ids"]

    def test_parse_ghsa_ids(self, sample_advisory_list):
        result = _parse_ghsa_advisories(sample_advisory_list, "django", "pip")
        assert "GHSA-1234-5678-abcd" in result["ghsa_ids"]

    def test_parse_published_since_is_latest(self, sample_advisory_list):
        result = _parse_ghsa_advisories(sample_advisory_list, "django", "pip")
        # 最新的是 2024-09-01
        assert "2024" in result["published_since"]

    def test_parse_empty_list_returns_zero_hits(self, empty_advisory_list):
        result = _parse_ghsa_advisories(empty_advisory_list, "unknown-pkg", "pip")
        assert result["hits"] == 0
        assert result["max_severity"] == "UNKNOWN"
        assert result["severity_score"] == 0.0

    def test_parse_missing_cve_id(self):
        """advisory 沒有 cve_id 欄位時不崩潰"""
        advisories = [
            {"ghsa_id": "GHSA-xxxx-xxxx-xxxx", "severity": "HIGH", "published_at": "2024-01-01T00:00:00Z"}
        ]
        result = _parse_ghsa_advisories(advisories, "pkg", "pip")
        assert result["hits"] == 1
        assert result["cve_ids"] == []

    def test_parse_cve_ids_capped_at_10(self):
        """超過 10 個 CVE 應截斷"""
        advisories = [
            {
                "ghsa_id": f"GHSA-{i:04d}-0000-0000",
                "cve_id": f"CVE-2024-{i:05d}",
                "severity": "MEDIUM",
                "published_at": "2024-01-01T00:00:00Z",
            }
            for i in range(15)
        ]
        result = _parse_ghsa_advisories(advisories, "pkg", "pip")
        assert len(result["cve_ids"]) <= 10
        assert len(result["ghsa_ids"]) <= 10

    def test_parse_source_field_present(self, sample_advisory_list):
        result = _parse_ghsa_advisories(sample_advisory_list, "django", "pip")
        assert "_source" in result


# ══════════════════════════════════════════════════════════════
# 4. query_ghsa_impl — 主流程（Mock 網路）
# ══════════════════════════════════════════════════════════════

class TestQueryGhsaImpl:
    """_query_ghsa_impl 主流程測試（Mock 所有外部呼叫）"""

    def test_cache_hit_returns_cached(self, fresh_cache):
        """快取命中 → 直接返回快取，不呼叫 API"""
        with patch("tools.ghsa_tool._read_ghsa_cache", return_value=fresh_cache), \
             patch("tools.ghsa_tool._write_ghsa_cache") as mock_write, \
             patch("tools.ghsa_tool._fetch_ghsa_rest") as mock_fetch:
            result_str = _query_ghsa_impl("django")
            result = json.loads(result_str)
            # 快取命中 → 不呼叫 API
            mock_fetch.assert_not_called()
            assert result["hits"] == 2

    def test_cache_miss_calls_api(self, mock_requests_success):
        """快取未命中 → 呼叫 API"""
        with patch("tools.ghsa_tool._read_ghsa_cache", return_value={}), \
             patch("tools.ghsa_tool._write_ghsa_cache"), \
             patch("tools.ghsa_tool._fetch_ghsa_rest", return_value={
                 "hits": 3,
                 "max_severity": "HIGH",
                 "severity_score": 0.75,
                 "cve_ids": ["CVE-2024-0001"],
                 "ghsa_ids": ["GHSA-1234-0000-0001"],
                 "published_since": "2024-01-01T00:00:00Z",
                 "_source": "GHSA REST API (online)",
             }) as mock_fetch:
            result_str = _query_ghsa_impl("django")
            result = json.loads(result_str)
            mock_fetch.assert_called_once()
            assert result["hits"] == 3

    def test_colon_format_parses_ecosystem(self):
        """django:python 格式應正確解析"""
        with patch("tools.ghsa_tool._read_ghsa_cache", return_value={}), \
             patch("tools.ghsa_tool._write_ghsa_cache"), \
             patch("tools.ghsa_tool._fetch_ghsa_rest", return_value={
                 "hits": 0, "max_severity": "UNKNOWN", "severity_score": 0.0,
                 "cve_ids": [], "ghsa_ids": [], "published_since": "", "_source": "test"
             }) as mock_fetch:
            result_str = _query_ghsa_impl("django:python")
            result = json.loads(result_str)
            # ecosystem 應解析為 python（或 pip）
            assert result["package"] == "django"
            assert "ecosystem" in result

    def test_api_failure_returns_zero_hits(self):
        """API 完全失敗 → 回傳 hits=0（不崩潰）"""
        with patch("tools.ghsa_tool._read_ghsa_cache", return_value={}), \
             patch("tools.ghsa_tool._write_ghsa_cache"), \
             patch("tools.ghsa_tool._fetch_ghsa_rest", return_value={
                 "hits": 0, "max_severity": "UNKNOWN", "severity_score": 0.0,
                 "cve_ids": [], "ghsa_ids": [], "published_since": "",
                 "_source": "GHSA REST API (failed)"
             }):
            result_str = _query_ghsa_impl("nonexistent-package")
            result = json.loads(result_str)
            assert result["hits"] == 0

    def test_stale_cache_triggers_api_call(self, stale_cache):
        """過期快取 → 應重新查詢 API"""
        with patch("tools.ghsa_tool._read_ghsa_cache", return_value=stale_cache), \
             patch("tools.ghsa_tool._write_ghsa_cache"), \
             patch("tools.ghsa_tool._fetch_ghsa_rest", return_value={
                 "hits": 5, "max_severity": "CRITICAL", "severity_score": 1.0,
                 "cve_ids": ["CVE-2024-NEW"], "ghsa_ids": ["GHSA-new-new-new"],
                 "published_since": "2024-09-01T00:00:00Z", "_source": "GHSA REST API (online)"
             }) as mock_fetch:
            result_str = _query_ghsa_impl("django")
            result = json.loads(result_str)
            mock_fetch.assert_called_once()
            assert result["hits"] == 5

    def test_output_has_required_fields(self):
        """輸出格式驗證：所有必要欄位都存在"""
        with patch("tools.ghsa_tool._read_ghsa_cache", return_value={}), \
             patch("tools.ghsa_tool._write_ghsa_cache"), \
             patch("tools.ghsa_tool._fetch_ghsa_rest", return_value={
                 "hits": 1, "max_severity": "HIGH", "severity_score": 0.75,
                 "cve_ids": ["CVE-2024-0001"], "ghsa_ids": ["GHSA-aaaa-bbbb-cccc"],
                 "published_since": "2024-01-01T00:00:00Z", "_source": "test"
             }):
            result_str = _query_ghsa_impl("django")
            result = json.loads(result_str)
            required_fields = {"package", "ecosystem", "hits", "max_severity",
                               "severity_score", "cve_ids", "ghsa_ids", "source"}
            for field in required_fields:
                assert field in result, f"缺少必要欄位: {field}"

    def test_empty_package_name(self):
        """空套件名應返回錯誤不崩潰"""
        result_str = _query_ghsa_impl("")
        result = json.loads(result_str)
        assert "error" in result or result.get("hits", 0) == 0

    def test_exception_during_fetch_graceful_degradation(self):
        """fetch 拋出例外時，應降級返回 hits=0"""
        with patch("tools.ghsa_tool._read_ghsa_cache", return_value={}), \
             patch("tools.ghsa_tool._write_ghsa_cache"), \
             patch("tools.ghsa_tool._fetch_ghsa_rest", side_effect=RuntimeError("Unexpected")):
            result_str = _query_ghsa_impl("django")
            result = json.loads(result_str)
            assert result["hits"] == 0
            assert "error" in result

    def test_result_is_valid_json(self):
        """輸出必須是合法 JSON"""
        with patch("tools.ghsa_tool._read_ghsa_cache", return_value={}), \
             patch("tools.ghsa_tool._write_ghsa_cache"), \
             patch("tools.ghsa_tool._fetch_ghsa_rest", return_value={
                 "hits": 0, "max_severity": "UNKNOWN", "severity_score": 0.0,
                 "cve_ids": [], "ghsa_ids": [], "published_since": "", "_source": "test"
             }):
            result_str = _query_ghsa_impl("test-package")
            # 不應拋出 JSONDecodeError
            parsed = json.loads(result_str)
            assert isinstance(parsed, dict)
