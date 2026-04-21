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

# Go 標準庫黑名單（不應視為第三方套件查詢 NVD）
# 來源：https://pkg.go.dev/std (Go 1.22)
# 格式：Go import path 的頂層 + 完整路徑（因為 Go 用 / 不用 .）
GO_STDLIB_BLACKLIST: frozenset[str] = frozenset({
    # 頂層模組名（經過 _normalize_package_name 後的結果）
    "fmt", "log", "os", "io", "net", "sync", "time", "math",
    "sort", "strings", "strconv", "bytes", "errors", "context",
    "flag", "regexp", "reflect", "runtime", "unsafe", "builtin",
    "testing", "debug", "embed", "encoding", "archive", "compress",
    "crypto", "database", "image", "index", "mime", "path",
    "plugin", "text", "unicode", "html", "hash", "container",
    "expvar", "go", "internal", "maps", "slices", "cmp", "iter",
    # 常見完整路徑（_normalize_package_name 只取 / 前第一段，
    # 但若 Go import regex 保留完整路徑則需要匹配）
    "net/http", "net/url", "os/exec", "os/signal", "io/ioutil",
    "encoding/json", "encoding/xml", "encoding/csv", "encoding/base64",
    "crypto/tls", "crypto/sha256", "crypto/md5", "crypto/rand",
    "database/sql", "html/template", "text/template", "path/filepath",
    "log/slog", "sync/atomic", "testing/fstest",
})

# Java JDK 標準庫黑名單（不應視為第三方套件查詢 NVD）
# import java.io.ObjectInputStream、import java.sql.Statement 均是 JDK 內建
# 對這些套件查詢 NVD 只會得到雜訊，或導致 Intel Fusion forceRun 失敗
JAVA_STDLIB_BLACKLIST: frozenset[str] = frozenset({
    # 頂層前綴：java.* 和 javax.*
    "java", "javax",
    # 常見完整子套件（防止 module_raw 直接比對）
    "java.io", "java.sql", "java.lang", "java.util",
    "java.net", "java.nio", "java.security", "java.math",
    "java.time", "java.text", "java.beans", "java.rmi",
    "java.awt", "java.applet", "javax.swing", "java.swing",
    "java.management", "javax.sql", "javax.net",
    "javax.security", "javax.crypto", "javax.xml", "javax.naming",
    # Android / Kotlin 內建
    "android", "dalvik", "kotlin",
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

            # 過濾 Go 標準庫（完整路徑 + 頂層模組）
            if module_raw.strip() in GO_STDLIB_BLACKLIST or top_level in GO_STDLIB_BLACKLIST:
                logger.debug("[PKG_EX] Filtered Go stdlib: %s (raw: %s)", top_level, module_raw)
                continue

            # 過濾 Java JDK 標準庫（java.io, java.sql, java.lang 等均為 JDK 內建）
            if top_level in JAVA_STDLIB_BLACKLIST or module_raw.strip() in JAVA_STDLIB_BLACKLIST:
                logger.debug("[PKG_EX] Filtered Java stdlib: %s (raw: %s)", top_level, module_raw)
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


# ══════════════════════════════════════════════════════════════════
# 版本感知提取（v5.3 新增）
# ══════════════════════════════════════════════════════════════════

def extract_packages_with_versions(source_text: str, filename: str = "") -> list[dict]:
    """
    從依賴文件（requirements.txt / package.json / pom.xml / Pipfile）
    提取套件名稱 + 版本號。

    若版本未知（例如直接從 import 提取），
    回傳 version=None, version_known=False。

    Args:
        source_text: 文件內容
        filename: 文件名稱（用於判斷格式）

    Returns:
        list[dict]: [{"package": "requests", "version": "2.28.0", "version_known": True}, ...]
    """
    results = []
    fname = filename.lower()

    # ── requirements.txt ──────────────────────────────────────────
    if "requirements" in fname or fname.endswith(".txt"):
        for line in source_text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # requests==2.28.0 / requests>=2.28.0 / requests~=2.28.0
            m = re.match(r"^([a-zA-Z0-9_.-]+)\s*(?:==|>=|<=|~=|!=|>|<)\s*([^\s;]+)", line)
            if m:
                pkg, ver = m.group(1), m.group(2)
                results.append({"package": pkg.lower(), "version": ver, "version_known": True})
            else:
                # 無版本號的行（如 requests）
                m2 = re.match(r"^([a-zA-Z0-9_.-]+)\s*$", line)
                if m2:
                    results.append({"package": m2.group(1).lower(), "version": None, "version_known": False})

    # ── package.json ──────────────────────────────────────────────
    elif fname.endswith("package.json"):
        import json as _json
        try:
            data = _json.loads(source_text)
            for section in ["dependencies", "devDependencies"]:
                for pkg, ver in data.get(section, {}).items():
                    # 清除 ^, ~, >= 前綴
                    clean_ver = re.sub(r"^[^0-9]*", "", ver) if ver else None
                    known = bool(clean_ver and re.match(r"^\d", clean_ver))
                    results.append({"package": pkg.lower(), "version": clean_ver if known else ver, "version_known": known})
        except Exception:
            pass

    # ── pom.xml（Maven）──────────────────────────────────────────
    elif fname.endswith("pom.xml"):
        # 簡單提取 <artifactId> + 對應 <version>
        deps = re.findall(
            r"<dependency>.*?<artifactId>([^<]+)</artifactId>.*?(?:<version>([^<]+)</version>)?.*?</dependency>",
            source_text,
            re.DOTALL,
        )
        for art, ver in deps:
            if art.strip() and not art.strip().startswith("$"):
                results.append({
                    "package": art.strip().lower(),
                    "version": ver.strip() if ver and not ver.strip().startswith("$") else None,
                    "version_known": bool(ver and not ver.strip().startswith("$")),
                })

    # ── Pipfile ────────────────────────────────────────────────────
    elif fname == "pipfile" or fname.endswith("pipfile"):
        for line in source_text.splitlines():
            m = re.match(r'''(?x)^([a-zA-Z0-9_.\-]+)\s*=\s*["\']?([^"\' \t]+)["\']?''', line.strip())
            if m:
                pkg, ver = m.group(1), m.group(2)
                clean = re.sub(r"^[^0-9]*", "", ver)
                known = bool(clean and re.match(r"^\d", clean))
                results.append({"package": pkg.lower(), "version": clean if known else ver, "version_known": known})

    return results


def build_version_disclaimer(package: str, version: str | None) -> str:
    """
    為 Intel Fusion 的 CVE 輸出生成版本免責聲明。

    Args:
        package: 套件名稱
        version: 版本號（None 表示未知）

    Returns:
        免責聲明字串（若版本已知則為空字串）
    """
    if version:
        return ""  # 版本已知，無需免責聲明
    return (
        f"[版本未知] 無法確認 {package} 的確切版本。"
        f"以下 CVE 為該套件的所有已知漏洞，請確認你的版本是否落在受影響範圍內再採取行動。"
    )
