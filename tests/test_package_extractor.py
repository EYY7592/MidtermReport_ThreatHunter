# tests/test_package_extractor.py
# 測試：確定性套件萃取橋接層
# 架構依據：憲法第五條 — 每個新功能都要有測試
# 執行：uv run pytest tests/test_package_extractor.py -v

import pytest
from tools.package_extractor import (
    extract_third_party_packages,
    packages_from_security_guard,
    format_packages_for_intel_fusion,
    STDLIB_BLACKLIST,
    MAX_PACKAGES,
)


# ══════════════════════════════════════════════════════════════
# 基本萃取功能測試
# ══════════════════════════════════════════════════════════════

def test_extract_from_imports_with_requests():
    """imports 含 requests → 正確萃取單一套件"""
    imports = [
        {"module": "requests", "items": [], "line": 1, "type": "import"},
    ]
    result = extract_third_party_packages(imports)
    assert "requests" in result, f"Expected 'requests' in {result}"


def test_extract_multiple_packages():
    """imports 含多個第三方套件 → 全部萃取"""
    imports = [
        {"module": "requests", "items": [], "line": 1, "type": "import"},
        {"module": "flask", "items": [], "line": 2, "type": "import"},
        {"module": "pymysql", "items": [], "line": 3, "type": "import"},
    ]
    result = extract_third_party_packages(imports)
    assert "requests" in result
    assert "flask" in result
    assert "pymysql" in result


def test_stdlib_filtered_out():
    """標準庫（os, sys, re, json, time）不應出現在結果中"""
    imports = [
        {"module": "os", "items": [], "line": 1, "type": "import"},
        {"module": "sys", "items": [], "line": 2, "type": "import"},
        {"module": "re", "items": [], "line": 3, "type": "import"},
        {"module": "json", "items": [], "line": 4, "type": "import"},
        {"module": "time", "items": [], "line": 5, "type": "import"},
        {"module": "threading", "items": [], "line": 6, "type": "import"},
        {"module": "subprocess", "items": [], "line": 7, "type": "import"},
        {"module": "hashlib", "items": [], "line": 8, "type": "import"},
        {"module": "requests", "items": [], "line": 9, "type": "import"},  # 這個要留
    ]
    result = extract_third_party_packages(imports)
    assert "os" not in result, f"stdlib 'os' should be filtered: {result}"
    assert "sys" not in result, f"stdlib 'sys' should be filtered: {result}"
    assert "re" not in result, f"stdlib 're' should be filtered: {result}"
    assert "json" not in result, f"stdlib 'json' should be filtered: {result}"
    assert "subprocess" not in result, f"stdlib 'subprocess' should be filtered: {result}"
    assert "requests" in result, f"'requests' should survive stdlib filter: {result}"


def test_empty_imports_returns_empty_list():
    """空 imports 列表 → 回傳 [] 不崩潰"""
    result = extract_third_party_packages([])
    assert result == [], f"Expected empty list, got {result}"


def test_none_input_raises_no_exception():
    """None 輸入 → 回傳 [] 不崩潰（Graceful Degradation）"""
    result = extract_third_party_packages(None)
    assert result == [], f"Expected empty list for None input, got {result}"


def test_max_packages_truncated():
    """超過 MAX_PACKAGES 個套件 → 截斷到上限"""
    imports = [
        {"module": f"pkg{i}", "items": [], "line": i, "type": "import"}
        for i in range(MAX_PACKAGES + 5)
    ]
    result = extract_third_party_packages(imports)
    assert len(result) <= MAX_PACKAGES, f"Expected <= {MAX_PACKAGES}, got {len(result)}"


def test_dotted_module_uses_top_level():
    """點式模組路徑 → 取頂層套件名"""
    imports = [
        {"module": "flask.views", "items": [], "line": 1, "type": "from_import"},
        {"module": "PIL.Image", "items": [], "line": 2, "type": "from_import"},
        {"module": "django.db.models", "items": [], "line": 3, "type": "from_import"},
    ]
    result = extract_third_party_packages(imports)
    assert "flask" in result, f"Expected 'flask' from 'flask.views': {result}"
    assert "pil" in result, f"Expected 'pil' from 'PIL.Image': {result}"
    assert "django" in result, f"Expected 'django' from 'django.db.models': {result}"


def test_version_stripped_from_module():
    """模組名稱含版本號 → 去除版本號"""
    imports = [
        {"module": "django 4.2", "items": [], "line": 1, "type": "import"},
    ]
    result = extract_third_party_packages(imports)
    assert "django" in result, f"Expected 'django' after version strip: {result}"
    assert "django 4.2" not in result, f"Version should be stripped: {result}"


def test_relative_import_skipped():
    """相對匯入（level > 0）→ 跳過，不出現在結果"""
    imports = [
        {"module": "utils", "items": [], "line": 1, "type": "from_import", "level": 1},
        {"module": "models", "items": [], "line": 2, "type": "from_import", "level": 2},
        {"module": "requests", "items": [], "line": 3, "type": "import", "level": 0},
    ]
    result = extract_third_party_packages(imports)
    assert "utils" not in result, f"Relative import 'utils' should be skipped: {result}"
    assert "models" not in result, f"Relative import 'models' should be skipped: {result}"
    assert "requests" in result, f"Absolute import 'requests' should be included: {result}"


def test_deduplication():
    """重複套件 → 只出現一次"""
    imports = [
        {"module": "requests", "items": [], "line": 1, "type": "import"},
        {"module": "requests", "items": [], "line": 5, "type": "import"},  # 重複
        {"module": "requests.auth", "items": [], "line": 9, "type": "from_import"},  # 同頂層套件
    ]
    result = extract_third_party_packages(imports)
    assert result.count("requests") == 1, f"'requests' should appear only once: {result}"


def test_malformed_import_entry_no_crash():
    """格式不正確的 imports 項目 → 不崩潰"""
    imports = [
        None,                           # None 元素
        "not_a_dict",                   # 字串而非 dict
        {"no_module_key": "value"},     # 缺少 module 欄位
        {"module": "", "line": 1},     # 空 module 名稱
        {"module": "requests", "line": 2},  # 正常的
    ]
    result = extract_third_party_packages(imports)
    assert "requests" in result, f"Valid package should still be extracted: {result}"


# ══════════════════════════════════════════════════════════════
# packages_from_security_guard 便利函式測試
# ══════════════════════════════════════════════════════════════

def test_packages_from_security_guard_basic():
    """Security Guard 結構化輸出 → 正確萃取套件"""
    sg_result = {
        "extraction_status": "ok",
        "imports": [
            {"module": "requests", "items": [], "line": 1, "type": "import"},
            {"module": "flask", "items": [], "line": 2, "type": "import"},
            {"module": "os", "items": [], "line": 3, "type": "import"},  # 標準庫
        ],
        "functions": [],
        "patterns": [],
        "stats": {"total_lines": 10, "functions_found": 0, "patterns_found": 0},
    }
    result = packages_from_security_guard(sg_result)
    assert "requests" in result
    assert "flask" in result
    assert "os" not in result  # 標準庫已過濾


def test_packages_from_security_guard_empty():
    """Security Guard 結果為空 → 回傳空列表"""
    result = packages_from_security_guard({})
    assert result == []


def test_packages_from_security_guard_invalid():
    """Security Guard 結果不是 dict → 回傳空列表不崩潰"""
    result = packages_from_security_guard(None)
    assert result == []

    result = packages_from_security_guard("string input")
    assert result == []


def test_packages_from_security_guard_no_imports_key():
    """Security Guard 結果沒有 imports 欄位 → 回傳空列表"""
    sg_result = {"extraction_status": "ok", "functions": [], "patterns": []}
    result = packages_from_security_guard(sg_result)
    assert result == []


# ══════════════════════════════════════════════════════════════
# format_packages_for_intel_fusion 格式化函式測試
# ══════════════════════════════════════════════════════════════

def test_format_packages_basic():
    """套件列表 → 逗號分隔字串"""
    result = format_packages_for_intel_fusion(["requests", "flask", "pymysql"])
    assert result == "requests, flask, pymysql"


def test_format_packages_empty():
    """空列表 → 空字串"""
    result = format_packages_for_intel_fusion([])
    assert result == ""


def test_format_single_package():
    """單一套件 → 字串不含逗號"""
    result = format_packages_for_intel_fusion(["requests"])
    assert result == "requests"
    assert "," not in result


# ══════════════════════════════════════════════════════════════
# 整合性測試：模擬真實掃描場景
# ══════════════════════════════════════════════════════════════

def test_real_world_python_code_imports():
    """
    模擬真實 Python 程式碼的 Security Guard 輸出：
    混合標準庫 + 第三方套件 + 相對匯入
    """
    sg_result = {
        "imports": [
            {"module": "os", "items": [], "line": 1, "type": "import"},
            {"module": "sys", "items": [], "line": 2, "type": "import"},
            {"module": "json", "items": [], "line": 3, "type": "import"},
            {"module": "logging", "items": [], "line": 4, "type": "import"},
            {"module": "requests", "items": ["get", "post"], "line": 6, "type": "from_import"},
            {"module": "flask", "items": ["Flask", "render_template"], "line": 7, "type": "from_import"},
            {"module": "flask.views", "items": ["View"], "line": 8, "type": "from_import"},  # 同頂層套件
            {"module": "pymysql", "items": [], "line": 9, "type": "import"},
            {"module": "utils", "items": ["helper"], "line": 10, "type": "from_import", "level": 1},  # 相對匯入
        ]
    }

    result = packages_from_security_guard(sg_result)

    # 第三方套件應萃取
    assert "requests" in result
    assert "flask" in result
    assert "pymysql" in result

    # 標準庫應過濾
    assert "os" not in result
    assert "sys" not in result
    assert "json" not in result
    assert "logging" not in result

    # 相對匯入應跳過
    assert "utils" not in result

    # 去重：flask 只出現一次
    assert result.count("flask") == 1

    # 數量在合理範圍
    assert 1 <= len(result) <= MAX_PACKAGES

    formatted = format_packages_for_intel_fusion(result)
    assert "requests" in formatted
    assert "flask" in formatted


def test_only_stdlib_imports_returns_empty():
    """
    只有標準庫 imports 的程式碼 → 回傳空列表
    Intel Fusion 應顯示 no_packages 而非 DEGRADED
    """
    sg_result = {
        "imports": [
            {"module": "os", "items": [], "line": 1},
            {"module": "sys", "items": [], "line": 2},
            {"module": "subprocess", "items": [], "line": 3},
            {"module": "hashlib", "items": [], "line": 4},
        ]
    }
    result = packages_from_security_guard(sg_result)
    assert result == [], f"Only stdlib imports should yield empty list: {result}"
