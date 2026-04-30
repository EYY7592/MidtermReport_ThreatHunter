# tests/test_package_extractor.py
# 測試：確定性套件萃取橋接層

import pytest
from tools.package_extractor import (
    extract_third_party_packages,
    packages_from_security_guard,
    format_packages_for_intel_fusion,
    extract_packages_with_versions,
    build_version_disclaimer,
    _normalize_package_name,
    _is_valid_package_name,
    MAX_PACKAGES,
)


class TestPackageExtractorBasic:

    def test_extract_flask(self):
        imports = [{"module": "flask", "items": ["Flask"], "level": 0}]
        result = extract_third_party_packages(imports)
        assert result == ["flask"]

    def test_filter_python_stdlib(self):
        """Python 標準庫應被過濾"""
        imports = [
            {"module": "os", "level": 0},
            {"module": "json", "level": 0},
            {"module": "sys", "level": 0},
            {"module": "requests", "level": 0},
        ]
        result = extract_third_party_packages(imports)
        assert result == ["requests"]

    def test_filter_nodejs_builtin(self):
        """Node.js 內建模組應被過濾"""
        imports = [
            {"module": "fs", "level": 0},
            {"module": "path", "level": 0},
            {"module": "express", "level": 0},
        ]
        result = extract_third_party_packages(imports)
        assert result == ["express"]

    def test_filter_go_stdlib(self):
        """Go 標準庫應被過濾"""
        imports = [
            {"module": "fmt", "level": 0},
            {"module": "gin", "level": 0},
        ]
        result = extract_third_party_packages(imports)
        assert result == ["gin"]

    def test_filter_java_stdlib(self):
        """Java JDK 標準庫應被過濾"""
        imports = [
            {"module": "java.io", "level": 0},
            {"module": "java.sql", "level": 0},
            {"module": "spring", "level": 0},
        ]
        result = extract_third_party_packages(imports)
        assert "spring" in result
        assert "java" not in result

    def test_filter_relative_imports(self):
        """相對匯入（level > 0）應被跳過"""
        imports = [
            {"module": "models", "level": 1},
            {"module": "requests", "level": 0},
        ]
        result = extract_third_party_packages(imports)
        assert result == ["requests"]

    def test_max_packages_truncation(self):
        """超過 MAX_PACKAGES 應截斷"""
        imports = [{"module": f"pkg{i}", "level": 0} for i in range(20)]
        result = extract_third_party_packages(imports)
        assert len(result) <= MAX_PACKAGES

    def test_deduplication(self):
        """重複套件名應去重"""
        imports = [
            {"module": "requests", "level": 0},
            {"module": "requests.auth", "level": 0},
        ]
        result = extract_third_party_packages(imports)
        assert result.count("requests") == 1

    def test_empty_imports(self):
        assert extract_third_party_packages([]) == []

    def test_invalid_import_entries(self):
        """非 dict 項目應被跳過"""
        imports = [None, "string", 123, {"module": "flask", "level": 0}]
        result = extract_third_party_packages(imports)
        assert result == ["flask"]

    def test_normalize_package_name(self):
        assert _normalize_package_name("flask.views") == "flask"
        assert _normalize_package_name("PIL.Image") == "pil"
        assert _normalize_package_name("") is None

    def test_is_valid_package_name(self):
        assert _is_valid_package_name("requests") is True
        assert _is_valid_package_name("a") is False  # 太短
        assert _is_valid_package_name("123") is False  # 純數字
        assert _is_valid_package_name("pkg!name") is False  # 特殊字元


class TestPackageExtractorVersions:

    def test_requirements_txt(self):
        content = "requests==2.28.0\nflask>=2.0.0\ndjango\n# comment"
        result = extract_packages_with_versions(content, "requirements.txt")
        assert len(result) == 3
        assert result[0]["package"] == "requests"
        assert result[0]["version"] == "2.28.0"
        assert result[0]["version_known"] is True
        assert result[2]["version_known"] is False

    def test_package_json(self):
        content = '{"dependencies": {"express": "^4.18.0"}, "devDependencies": {"jest": "~29.0.0"}}'
        result = extract_packages_with_versions(content, "package.json")
        assert len(result) == 2

    def test_version_disclaimer(self):
        assert build_version_disclaimer("requests", "2.28.0") == ""
        disclaimer = build_version_disclaimer("requests", None)
        assert "版本未知" in disclaimer


class TestPackageExtractorHelpers:

    def test_packages_from_security_guard(self):
        sg_result = {"imports": [{"module": "flask", "level": 0}]}
        result = packages_from_security_guard(sg_result)
        assert result == ["flask"]

    def test_packages_from_invalid_sg_result(self):
        assert packages_from_security_guard(None) == []
        assert packages_from_security_guard("invalid") == []

    def test_format_packages(self):
        assert format_packages_for_intel_fusion(["a", "b"]) == "a, b"
        assert format_packages_for_intel_fusion([]) == ""
