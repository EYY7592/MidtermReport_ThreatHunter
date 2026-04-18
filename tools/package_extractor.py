# tools/package_extractor.py
# 功能：確定性套件萃取橋接層
# 架構依據：Harness Engineering — Constrain + Graceful Degradation
#
# 核心職責：
#   從 Security Guard 提取的 imports 列表萃取第三方套件名稱。
#   過濾 Python 標準庫、相對匯入、雜訊模組。
#   限制最多 MAX_PACKAGES 個套件（保護 Rate Limit）。
#
# 重要設計原則：
#   - 完全確定性，無 LLM 依賴
#   - 輸入失敗時回傳空列表（不崩潰）
#   - 此模組不生成任何 CVE，不做安全判斷

import logging
import re
from typing import Any

logger = logging.getLogger("ThreatHunter.package_extractor")

# ══════════════════════════════════════════════════════════════
# Python 標準庫黑名單（cpython 3.12 全集，僅列常見者）
# 完整清單：https://docs.python.org/3/library/index.html
# ══════════════════════════════════════════════════════════════

STDLIB_BLACKLIST: frozenset[str] = frozenset({
    # 內建
    "__future__", "__main__", "builtins",
    # 文字、字串
    "string", "re", "difflib", "textwrap", "unicodedata", "readline",
    "rlcompleter", "codecs", "encodings",
    # 資料型別
    "datetime", "calendar", "collections", "heapq", "bisect",
    "array", "weakref", "types", "copy", "pprint", "reprlib",
    "enum", "graphlib", "dataclasses",
    # 數學
    "numbers", "math", "cmath", "decimal", "fractions", "random",
    "statistics",
    # 函式式程式設計
    "itertools", "functools", "operator",
    # 檔案與 I/O
    "io", "time", "logging", "os", "os.path", "pathlib",
    "fileinput", "stat", "filecmp", "shutil", "tempfile",
    "glob", "fnmatch", "linecache", "pickle", "shelve",
    "marshal", "dbm", "sqlite3", "csv", "configparser",
    "tomllib", "netrc", "plistlib",
    # 壓縮
    "zlib", "gzip", "bz2", "lzma", "zipfile", "tarfile",
    # 資料格式
    "json", "html", "html.parser", "xml", "xml.etree",
    "xml.etree.ElementTree", "xml.dom", "xml.sax",
    "csv", "struct",
    # 密碼學
    "hashlib", "hmac", "secrets",
    # 通用 OS 服務
    "sys", "sysconfig", "builtins", "warnings", "contextlib",
    "abc", "atexit", "traceback", "gc", "inspect", "site",
    "codeop", "code", "zipimport", "pkgutil", "modulefinder",
    "importlib", "ast", "dis", "py_compile",
    # 並發
    "threading", "multiprocessing", "concurrent",
    "concurrent.futures", "subprocess", "sched", "queue",
    "asyncio", "socket", "ssl", "select", "selectors",
    "signal", "mmap", "ctypes",
    # 網路
    "urllib", "urllib.parse", "urllib.request", "urllib.error",
    "urllib.response", "urllib.robotparser",
    "http", "http.client", "http.server", "http.cookies",
    "http.cookiejar", "ftplib", "poplib", "imaplib",
    "smtplib", "uuid", "socketserver", "xmlrpc",
    "email", "mailbox", "mimetypes",
    # 單元測試
    "unittest", "doctest", "pdb", "profile", "cProfile",
    "timeit", "trace", "tracemalloc",
    # 類型
    "typing", "typing_extensions",
    # 其他常見
    "platform", "errno", "ctypes", "locale", "gettext",
    "argparse", "getopt", "getpass", "curses", "turtle",
    "copy", "pprint", "base64", "binascii", "quopri",
    "uu", "struct", "codecs", "unicodedata",
})

# 相對匯入的模組名稱前綴（會以 "." 開頭，但有時解析後是空字串或數字 level）
_RELATIVE_IMPORT_MODULE_PREFIXES = frozenset({"", None})

# 套件最大數量（保護 LLM Rate Limit）
MAX_PACKAGES = 8

# 排除的不合理套件名稱（太短、含特殊字元）
_MIN_PACKAGE_NAME_LEN = 2
_INVALID_NAME_RE = re.compile(r"[^a-zA-Z0-9_\-]")

# Node.js 內建模組黑名單（不應視為 npm 套件查詢 NVD）
# 來源：https://nodejs.org/api/ (Node.js 20 LTS)
NODEJS_BUILTIN_BLACKLIST: frozenset[str] = frozenset({
    "fs", "path", "http", "https", "url", "events", "stream",
    "util", "crypto", "os", "child_process", "net", "tls",
    "dns", "readline", "cluster", "worker_threads", "buffer",
    "assert", "querystring", "punycode", "string_decoder",
    "zlib", "timers", "process", "console", "module",
    "v8", "vm", "perf_hooks", "async_hooks", "inspector",
    "http2", "dgram", "domain", "repl", "tty", "wasi",
    "trace_events", "diagnostics_channel", "node:fs", "node:path",
})


def _is_valid_package_name(name: str) -> bool:
    """
    判斷套件名稱是否為合理的 PyPI/npm 套件名稱。

    過濾規則：
      - 長度 >= 2
      - 不含特殊字元（除 _ 和 - 外）
      - 不是純數字
    """
    if not name or len(name) < _MIN_PACKAGE_NAME_LEN:
        return False
    if name.isdigit():
        return False
    if _INVALID_NAME_RE.search(name):
        return False
    return True


def _normalize_package_name(module_str: str) -> str | None:
    """
    將模組路徑正規化為頂層套件名稱。

    例如：
      "flask.views"    → "flask"
      "PIL.Image"      → "PIL"
      "requests"       → "requests"
      "os.path"        → "os"（後續由黑名單過濾）
      ""               → None（相對匯入）
    """
    if not module_str:
        return None
    # 去掉版本號（如 "django 4.2" → "django"）
    module_str = module_str.strip().split()[0]
    # 取頂層模組
    top_level = module_str.split(".")[0].strip()
    if not top_level:
        return None
    return top_level.lower()


def extract_third_party_packages(
    imports: list[dict[str, Any]],
    max_packages: int = MAX_PACKAGES,
) -> list[str]:
    """
    從 Security Guard 提取的 imports 列表中萃取第三方套件名稱。

    Harness 設計：
      - 確定性邏輯，不依賴 LLM
      - 過濾 Python 標準庫
      - 限制數量上限（保護 Rate Limit）
      - 輸入格式錯誤時不崩潰

    Args:
        imports: Security Guard extract_code_surface() 回傳的 imports 列表。
                 每個元素為 {"module": "requests", "items": [...], "line": 1, ...}
        max_packages: 最多回傳幾個套件（預設 8）

    Returns:
        去重後的第三方套件名稱列表（小寫）。
        例如：["requests", "flask", "pymysql"]
    """
    if not imports:
        logger.info("[PKG_EX] No imports provided, returning empty list")
        return []

    seen: set[str] = set()
    packages: list[str] = []

    for imp in imports:
        try:
            if not isinstance(imp, dict):
                continue

            module_raw: str = imp.get("module", "") or ""

            # 相對匯入（level > 0 or module is empty）：跳過
            level = imp.get("level", 0)
            if level and level > 0:
                continue
            if not module_raw.strip():
                continue

            top_level = _normalize_package_name(module_raw)
            if top_level is None:
                continue

            # 過濾標準庫（Python）
            if top_level in STDLIB_BLACKLIST:
                logger.debug("[PKG_EX] Filtered Python stdlib: %s", top_level)
                continue

            # 過濾 Node.js 內建模組
            if top_level in NODEJS_BUILTIN_BLACKLIST:
                logger.debug("[PKG_EX] Filtered Node.js builtin: %s", top_level)
                continue

            # 過濾不合理名稱
            if not _is_valid_package_name(top_level):
                logger.debug("[PKG_EX] Filtered invalid name: %s", top_level)
                continue

            # 去重
            if top_level in seen:
                continue

            seen.add(top_level)
            packages.append(top_level)

            if len(packages) >= max_packages:
                logger.info("[PKG_EX] Reached max_packages=%d, truncating", max_packages)
                break

        except Exception as exc:
            # 不因單個 import 解析失敗而崩潰
            logger.warning("[PKG_EX] Failed to parse import entry %r: %s", imp, exc)
            continue

    logger.info(
        "[PKG_EX] Extracted %d third-party packages from %d imports: %s",
        len(packages), len(imports), packages,
    )
    return packages


def packages_from_security_guard(sg_result: dict[str, Any]) -> list[str]:
    """
    便利函式：直接從 Security Guard 完整輸出中萃取套件列表。

    Args:
        sg_result: run_security_guard() 的回傳值

    Returns:
        第三方套件名稱列表
    """
    if not sg_result or not isinstance(sg_result, dict):
        logger.warning("[PKG_EX] Invalid sg_result type: %s", type(sg_result))
        return []

    imports = sg_result.get("imports", [])
    if not isinstance(imports, list):
        logger.warning("[PKG_EX] sg_result.imports is not a list: %s", type(imports))
        return []

    return extract_third_party_packages(imports)


def format_packages_for_intel_fusion(packages: list[str]) -> str:
    """
    將套件列表格式化為 Intel Fusion 可以直接使用的字串。

    例如：["requests", "flask"] → "requests, flask"

    Args:
        packages: 套件名稱列表

    Returns:
        逗號分隔的套件字串
    """
    return ", ".join(packages) if packages else ""
