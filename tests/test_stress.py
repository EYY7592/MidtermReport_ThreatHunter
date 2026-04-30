# tests/test_stress.py
# 多維度壓力測試（跨 Tool 整合）
# 涵蓋：並行查詢、快取一致性、大量數據、降級瀑布壓力、邊界輸入

import json
import time
import threading
import pytest
from unittest.mock import patch, Mock

from tools.nvd_tool import _search_nvd_impl
from tools.kev_tool import _check_kev_impl
from tools.otx_tool import _search_otx_impl
from tools.package_extractor import extract_third_party_packages, MAX_PACKAGES
import tools.kev_tool as kev_module


@pytest.fixture(autouse=True)
def _reset_kev():
    kev_module._kev_lookup = None
    kev_module._kev_total_count = 0
    yield
    kev_module._kev_lookup = None


# ══════════════════════════════════════════════════════════════
# 並行查詢壓力測試
# ══════════════════════════════════════════════════════════════

class TestParallelQueryStress:

    @patch("tools.nvd_tool._query_nvd_api_cpe")
    @patch("tools.otx_tool._query_otx_api")
    @patch("tools.kev_tool._download_kev_catalog")
    def test_10_threads_concurrent(self, mock_kev, mock_otx, mock_nvd,
                                    fake_nvd_response, fake_otx_response, fake_kev_catalog,
                                    isolated_cache):
        """10 個執行緒同時查詢 NVD + OTX + KEV 不應 crash"""
        mock_nvd.return_value = fake_nvd_response
        mock_otx.return_value = fake_otx_response
        mock_kev.return_value = fake_kev_catalog

        results = []
        errors = []

        def worker(pkg_name):
            try:
                nvd = json.loads(_search_nvd_impl(pkg_name))
                otx = json.loads(_search_otx_impl(pkg_name))
                kev = json.loads(_check_kev_impl("CVE-2021-44228"))
                results.append({"nvd": nvd["count"], "otx": otx["pulse_count"], "kev": kev["results"][0]["in_kev"]})
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=worker, args=(f"pkg-{i}",)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert len(errors) == 0, f"並行錯誤: {errors}"
        assert len(results) == 10


# ══════════════════════════════════════════════════════════════
# 快取一致性壓力測試
# ══════════════════════════════════════════════════════════════

class TestCacheConsistency:

    @patch("tools.nvd_tool._query_nvd_api_cpe")
    def test_cache_write_then_read(self, mock_cpe, fake_nvd_response, isolated_cache):
        """寫入快取 → 讀取應一致"""
        mock_cpe.return_value = fake_nvd_response
        result1 = json.loads(_search_nvd_impl("django"))

        mock_cpe.return_value = None  # API 失敗
        result2 = json.loads(_search_nvd_impl("django"))

        assert result1["count"] == result2["count"]


# ══════════════════════════════════════════════════════════════
# 大量數據壓力測試
# ══════════════════════════════════════════════════════════════

class TestLargeDataStress:

    def test_50_packages_extraction(self):
        """50 個套件的 imports 列表應正確處理"""
        imports = [{"module": f"package{i}", "level": 0} for i in range(50)]
        result = extract_third_party_packages(imports)
        assert len(result) == MAX_PACKAGES  # 截斷到 8 個

    @patch("tools.kev_tool._download_kev_catalog")
    def test_200_cves_kev_check(self, mock_dl, fake_kev_catalog):
        """200 個 CVE 批次 KEV 查詢效能"""
        mock_dl.return_value = fake_kev_catalog
        cves = ", ".join(f"CVE-2024-{i:05d}" for i in range(200))
        start = time.time()
        result = json.loads(_check_kev_impl(cves))
        elapsed = time.time() - start
        assert len(result["results"]) == 200
        assert elapsed < 3.0, f"200 CVE 查詢耗時 {elapsed:.1f}s"


# ══════════════════════════════════════════════════════════════
# 降級瀑布壓力測試
# ══════════════════════════════════════════════════════════════

class TestDegradationCascade:

    @patch("tools.nvd_tool._query_nvd_api")
    @patch("tools.nvd_tool._query_nvd_api_cpe")
    @patch("tools.otx_tool._query_otx_api")
    @patch("tools.kev_tool._download_kev_catalog")
    @patch("tools.kev_tool._read_kev_cache")
    def test_all_apis_fail(self, mock_kev_cache, mock_kev, mock_otx, mock_nvd_cpe, mock_nvd_kw, isolated_cache):
        """所有 API 同時失敗 → 全部降級到安全空結果"""
        mock_nvd_cpe.return_value = None
        mock_nvd_kw.return_value = None
        mock_otx.return_value = None
        mock_kev.return_value = None
        mock_kev_cache.return_value = None

        nvd = json.loads(_search_nvd_impl("django"))
        otx = json.loads(_search_otx_impl("django"))
        kev = json.loads(_check_kev_impl("CVE-2021-44228"))

        assert nvd["count"] == 0
        assert otx["pulse_count"] == 0
        assert kev["results"][0]["in_kev"] is False


# ══════════════════════════════════════════════════════════════
# 邊界輸入壓力測試
# ══════════════════════════════════════════════════════════════

class TestBoundaryInputs:

    @patch("tools.nvd_tool._query_nvd_api_cpe")
    def test_unicode_package_name(self, mock_cpe, isolated_cache):
        mock_cpe.return_value = {"vulnerabilities": []}
        result = json.loads(_search_nvd_impl("日本語パッケージ"))
        assert result["count"] == 0

    @patch("tools.nvd_tool._query_nvd_api_cpe")
    def test_10kb_string(self, mock_cpe, isolated_cache):
        mock_cpe.return_value = {"vulnerabilities": []}
        result = json.loads(_search_nvd_impl("x" * 10240))
        assert result["count"] == 0

    @patch("tools.nvd_tool._query_nvd_api_cpe")
    def test_sql_injection_string(self, mock_cpe, isolated_cache):
        mock_cpe.return_value = {"vulnerabilities": []}
        result = json.loads(_search_nvd_impl("'; DROP TABLE cves; --"))
        assert isinstance(result, dict)

    @patch("tools.nvd_tool._query_nvd_api_cpe")
    def test_script_injection(self, mock_cpe, isolated_cache):
        mock_cpe.return_value = {"vulnerabilities": []}
        result = json.loads(_search_nvd_impl("<script>alert(1)</script>"))
        assert isinstance(result, dict)

    @patch("tools.nvd_tool._query_nvd_api_cpe")
    def test_null_bytes(self, mock_cpe, isolated_cache):
        mock_cpe.return_value = {"vulnerabilities": []}
        result = json.loads(_search_nvd_impl("django\x00evil"))
        assert isinstance(result, dict)
