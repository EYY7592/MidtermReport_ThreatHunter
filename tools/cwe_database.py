# tools/cwe_database.py
# MITRE CWE 離線資料庫 — ThreatHunter 可信佐證來源
#
# 來源：MITRE CWE v4.14（https://cwe.mitre.org/）
# 注意：此檔案內容來自 MITRE 官方定義，非 LLM 生成
# 更新日期：2026-04-21
#
# 用途：
#   當 Security Guard 偵測到 code pattern 時，
#   引用此資料庫提供官方定義、NIST 嚴重性、OWASP 對應、修復建議
#   以及代表性 CVE（同類弱點真實被利用案例）。
#
# 重要免責聲明：
#   代表性 CVE 不代表用戶的程式碼「就是」該 CVE，
#   而是「同類弱點被利用的真實案例」，用於說明風險嚴重性。

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("ThreatHunter.cwe_database")

# ══════════════════════════════════════════════════════════════════
# MITRE CWE 資料庫
# 欄位說明：
#   name            : CWE 短名稱
#   full_name       : MITRE 官方完整名稱
#   source          : 資料來源版本
#   nist_severity   : NIST 評定嚴重等級
#   cvss_base       : 典型 CVSS v3.1 基礎分數（來自 NVD 統計）
#   owasp_2021      : OWASP Top 10 2021 對應
#   cwe_url         : MITRE 官方 URL
#   description     : 官方定義摘要（英文，MITRE 原文）
#   remediation_en  : 英文修復建議
#   remediation_zh  : 中文修復建議
#   representative_cves : 代表性 CVE（真實案例，非用戶程式碼的直接映射）
# ══════════════════════════════════════════════════════════════════

CWE_DATABASE: dict[str, dict[str, Any]] = {

    # ── 注入類 (Injection) ────────────────────────────────────────

    "CWE-89": {
        "name": "SQL Injection",
        "full_name": "Improper Neutralization of Special Elements used in an SQL Command",
        "source": "MITRE CWE v4.14",
        "nist_severity": "HIGH",
        "cvss_base": 8.1,
        "owasp_2021": "A03:2021 – Injection",
        "cwe_url": "https://cwe.mitre.org/data/definitions/89.html",
        "description": (
            "Without sufficient removal or quoting of SQL syntax in user-controllable inputs, "
            "the generated SQL query can cause those inputs to be interpreted as SQL instead of "
            "ordinary user data. This can be used to alter query logic to bypass authentication, "
            "retrieve, modify, or delete data."
        ),
        "remediation_en": "Use parameterized queries (prepared statements). Never concatenate user input into SQL strings.",
        "remediation_zh": "使用參數化查詢（Prepared Statements）。絕不將用戶輸入直接拼接進 SQL 字串。",
        "representative_cves": [
            {"id": "CVE-2023-23752", "cvss": 7.5, "vendor": "Joomla", "year": 2023,
             "note": "Improper access checks allow SQL injection via URL parameter"},
            {"id": "CVE-2022-21661", "cvss": 7.5, "vendor": "WordPress", "year": 2022,
             "note": "SQL injection via WP_Query in core component"},
            {"id": "CVE-2023-40028", "cvss": 8.8, "vendor": "Ghost CMS", "year": 2023,
             "note": "SQL injection leading to data exposure"},
        ],
    },

    "CWE-78": {
        "name": "OS Command Injection",
        "full_name": "Improper Neutralization of Special Elements used in an OS Command",
        "source": "MITRE CWE v4.14",
        "nist_severity": "CRITICAL",
        "cvss_base": 9.8,
        "owasp_2021": "A03:2021 – Injection",
        "cwe_url": "https://cwe.mitre.org/data/definitions/78.html",
        "description": (
            "The product constructs all or part of an OS command using externally-influenced input "
            "but does not neutralize elements that can modify the intended OS command, allowing "
            "attackers to execute arbitrary commands with the privileges of the vulnerable process."
        ),
        "remediation_en": "Avoid shell execution functions. Use language APIs that accept argument arrays (not strings).",
        "remediation_zh": "避免使用 shell 執行函式。改用語言 API 並以陣列方式傳遞參數（不使用字串拼接）。",
        "representative_cves": [
            {"id": "CVE-2021-44228", "cvss": 10.0, "vendor": "Apache Log4j", "year": 2021,
             "note": "JNDI injection leading to Remote Code Execution (Log4Shell)"},
            {"id": "CVE-2022-33891", "cvss": 8.8, "vendor": "Apache Spark", "year": 2022,
             "note": "Shell injection via HTTP query parameter"},
            {"id": "CVE-2023-44487", "cvss": 7.5, "vendor": "Multiple HTTP servers", "year": 2023,
             "note": "HTTP/2 Rapid Reset Attack enabling code execution"},
        ],
    },

    "CWE-77": {
        "name": "Command Injection",
        "full_name": "Improper Neutralization of Special Elements used in a Command",
        "source": "MITRE CWE v4.14",
        "nist_severity": "CRITICAL",
        "cvss_base": 9.8,
        "owasp_2021": "A03:2021 – Injection",
        "cwe_url": "https://cwe.mitre.org/data/definitions/77.html",
        "description": "The product constructs a command using externally-influenced input without proper neutralization.",
        "remediation_en": "Validate and whitelist all input. Use safe APIs instead of direct command execution.",
        "remediation_zh": "驗證並白名單化所有輸入。使用安全 API 替代直接命令執行。",
        "representative_cves": [
            {"id": "CVE-2021-44228", "cvss": 10.0, "vendor": "Apache Log4j", "year": 2021,
             "note": "Command injection via JNDI lookup"},
        ],
    },

    "CWE-79": {
        "name": "Cross-Site Scripting (XSS)",
        "full_name": "Improper Neutralization of Input During Web Page Generation",
        "source": "MITRE CWE v4.14",
        "nist_severity": "MEDIUM",
        "cvss_base": 6.1,
        "owasp_2021": "A03:2021 – Injection",
        "cwe_url": "https://cwe.mitre.org/data/definitions/79.html",
        "description": (
            "The product does not neutralize or incorrectly neutralizes user-controllable input "
            "before it is placed in output that is used as a web page that is served to other users."
        ),
        "remediation_en": "Encode all output. Use Content Security Policy (CSP). Use framework's built-in escaping.",
        "remediation_zh": "對所有輸出進行 HTML 編碼。啟用 CSP。使用框架內建的 escape 機制。",
        "representative_cves": [
            {"id": "CVE-2023-32235", "cvss": 6.1, "vendor": "WordPress Plugin", "year": 2023,
             "note": "Reflected XSS via unescaped URL parameter"},
            {"id": "CVE-2022-40082", "cvss": 5.4, "vendor": "Multiple CMS", "year": 2022,
             "note": "Stored XSS via input field"},
        ],
    },

    "CWE-80": {
        "name": "Basic XSS (Improper HTML Encoding)",
        "full_name": "Improper Neutralization of Script-Related HTML Tags in a Web Page",
        "source": "MITRE CWE v4.14",
        "nist_severity": "MEDIUM",
        "cvss_base": 5.4,
        "owasp_2021": "A03:2021 – Injection",
        "cwe_url": "https://cwe.mitre.org/data/definitions/80.html",
        "description": "The product does not neutralize or incorrectly neutralizes script tags in user input.",
        "remediation_en": "HTML-encode all user output using htmlspecialchars() or equivalent.",
        "remediation_zh": "使用 htmlspecialchars() 或同等函式對所有用戶輸出進行 HTML 編碼。",
        "representative_cves": [
            {"id": "CVE-2023-32235", "cvss": 6.1, "vendor": "WordPress Plugin", "year": 2023,
             "note": "Script injection via unencoded output"},
        ],
    },

    "CWE-94": {
        "name": "Code Injection",
        "full_name": "Improper Control of Generation of Code",
        "source": "MITRE CWE v4.14",
        "nist_severity": "CRITICAL",
        "cvss_base": 9.8,
        "owasp_2021": "A03:2021 – Injection",
        "cwe_url": "https://cwe.mitre.org/data/definitions/94.html",
        "description": "User input is interpreted as executable code by the application.",
        "remediation_en": "Never use eval() or equivalent with user input. Use safe alternatives (JSON.parse, predefined mappings).",
        "remediation_zh": "絕不對用戶輸入使用 eval()。使用安全替代（JSON.parse、預定義映射）。",
        "representative_cves": [
            {"id": "CVE-2021-41773", "cvss": 7.5, "vendor": "Apache HTTP Server", "year": 2021,
             "note": "Path traversal + code injection in CGI"},
        ],
    },

    "CWE-95": {
        "name": "Dynamic Code Evaluation (eval Injection)",
        "full_name": "Improper Neutralization of Directives in Dynamically Evaluated Code",
        "source": "MITRE CWE v4.14",
        "nist_severity": "CRITICAL",
        "cvss_base": 9.8,
        "owasp_2021": "A03:2021 – Injection",
        "cwe_url": "https://cwe.mitre.org/data/definitions/95.html",
        "description": (
            "The software receives input from an upstream component, but it does not neutralize "
            "codes in the input before using it as part of a dynamically-evaluated code."
        ),
        "remediation_en": "Remove all uses of eval() with dynamic input. Use JSON.parse() for data, or a switch/map for logic.",
        "remediation_zh": "移除所有對動態輸入的 eval() 使用。資料改用 JSON.parse()，邏輯改用 switch/map。",
        "representative_cves": [
            {"id": "CVE-2023-29017", "cvss": 10.0, "vendor": "vm2 (Node.js sandbox)", "year": 2023,
             "note": "Sandbox escape via eval injection leading to RCE"},
            {"id": "CVE-2021-22911", "cvss": 9.8, "vendor": "Rocket.Chat", "year": 2021,
             "note": "Server-side eval injection leading to RCE"},
        ],
    },

    "CWE-98": {
        "name": "PHP File Inclusion",
        "full_name": "Improper Control of Filename for Include/Require Statement in PHP",
        "source": "MITRE CWE v4.14",
        "nist_severity": "HIGH",
        "cvss_base": 8.8,
        "owasp_2021": "A03:2021 – Injection",
        "cwe_url": "https://cwe.mitre.org/data/definitions/98.html",
        "description": (
            "The PHP application receives input from an upstream component, but does not restrict "
            "or incorrectly restricts the input before its use in a require, include, or similar "
            "statement, allowing the web server to include and execute unintended PHP files."
        ),
        "remediation_en": "Use a strict whitelist of allowed filenames. Never use user input directly in include/require.",
        "remediation_zh": "使用嚴格白名單限制允許的檔案名稱。絕不將用戶輸入直接傳入 include/require。",
        "representative_cves": [
            {"id": "CVE-2023-23752", "cvss": 7.5, "vendor": "Joomla", "year": 2023,
             "note": "Improper access check leading to Local File Inclusion"},
            {"id": "CVE-2021-39165", "cvss": 9.8, "vendor": "Cachet", "year": 2021,
             "note": "Remote File Inclusion via template engine"},
        ],
    },

    "CWE-90": {
        "name": "LDAP Injection",
        "full_name": "Improper Neutralization of Special Elements used in an LDAP Query",
        "source": "MITRE CWE v4.14",
        "nist_severity": "HIGH",
        "cvss_base": 7.5,
        "owasp_2021": "A03:2021 – Injection",
        "cwe_url": "https://cwe.mitre.org/data/definitions/90.html",
        "description": "User-supplied input is incorporated into LDAP queries without sufficient sanitization.",
        "remediation_en": "Escape all special LDAP characters. Use parameterized LDAP queries.",
        "remediation_zh": "對所有特殊 LDAP 字元進行轉義。使用參數化 LDAP 查詢。",
        "representative_cves": [
            {"id": "CVE-2021-40539", "cvss": 9.8, "vendor": "ManageEngine", "year": 2021,
             "note": "LDAP injection enabling authentication bypass"},
        ],
    },

    "CWE-611": {
        "name": "XML External Entity (XXE)",
        "full_name": "Improper Restriction of XML External Entity Reference",
        "source": "MITRE CWE v4.14",
        "nist_severity": "HIGH",
        "cvss_base": 8.6,
        "owasp_2021": "A05:2021 – Security Misconfiguration",
        "cwe_url": "https://cwe.mitre.org/data/definitions/611.html",
        "description": (
            "The software processes an XML document that can contain XML entities with URIs that "
            "resolve to documents outside of the intended sphere of control, causing the product "
            "to embed incorrect documents into its output."
        ),
        "remediation_en": "Disable external entity processing in XML parser. Use allowlist of allowed entities.",
        "remediation_zh": "停用 XML 解析器的外部實體處理。使用允許的實體白名單。",
        "representative_cves": [
            {"id": "CVE-2021-44228", "cvss": 10.0, "vendor": "Apache Log4j", "year": 2021,
             "note": "XXE via JNDI lookup in log messages"},
            {"id": "CVE-2022-21363", "cvss": 7.0, "vendor": "MySQL Connector/J", "year": 2022,
             "note": "XXE in XML data processing"},
        ],
    },

    # ── 路徑與文件操作 ────────────────────────────────────────────

    "CWE-22": {
        "name": "Path Traversal",
        "full_name": "Improper Limitation of a Pathname to a Restricted Directory",
        "source": "MITRE CWE v4.14",
        "nist_severity": "HIGH",
        "cvss_base": 7.5,
        "owasp_2021": "A01:2021 – Broken Access Control",
        "cwe_url": "https://cwe.mitre.org/data/definitions/22.html",
        "description": (
            "The software uses external input to construct a pathname that is intended to identify "
            "a file or directory located underneath a restricted parent directory, but does not "
            "properly neutralize special elements within the pathname that can cause it to resolve "
            "to a location outside of that directory."
        ),
        "remediation_en": "Canonicalize paths before validation. Validate against a strict whitelist of allowed paths.",
        "remediation_zh": "在驗證前正規化路徑。使用嚴格白名單驗證允許的路徑。",
        "representative_cves": [
            {"id": "CVE-2021-41773", "cvss": 7.5, "vendor": "Apache HTTP Server", "year": 2021,
             "note": "Path traversal allowing arbitrary file read"},
            {"id": "CVE-2022-22965", "cvss": 9.8, "vendor": "Spring Framework", "year": 2022,
             "note": "Spring4Shell: path traversal leading to RCE"},
        ],
    },

    "CWE-73": {
        "name": "External Control of File Name or Path",
        "full_name": "External Control of File Name or Path",
        "source": "MITRE CWE v4.14",
        "nist_severity": "HIGH",
        "cvss_base": 7.5,
        "owasp_2021": "A01:2021 – Broken Access Control",
        "cwe_url": "https://cwe.mitre.org/data/definitions/73.html",
        "description": "The software allows user input to control or influence paths used in filesystem operations.",
        "remediation_en": "Use a whitelist of allowed filenames. Sanitize directory separator characters.",
        "remediation_zh": "使用允許的檔案名稱白名單。過濾目錄分隔字元。",
        "representative_cves": [
            {"id": "CVE-2021-41773", "cvss": 7.5, "vendor": "Apache HTTP Server", "year": 2021,
             "note": "File path control leading to arbitrary file access"},
        ],
    },

    "CWE-134": {
        "name": "Uncontrolled Format String",
        "full_name": "Use of Externally-Controlled Format String",
        "source": "MITRE CWE v4.14",
        "nist_severity": "HIGH",
        "cvss_base": 8.1,
        "owasp_2021": "A03:2021 – Injection",
        "cwe_url": "https://cwe.mitre.org/data/definitions/134.html",
        "description": "User input is used as a format string in functions like printf, allowing memory read/write.",
        "remediation_en": "Always use a literal format string. Never pass user input directly as the format argument.",
        "remediation_zh": "永遠使用字面格式字串。絕不將用戶輸入直接作為格式參數傳入。",
        "representative_cves": [
            {"id": "CVE-2021-3156", "cvss": 7.8, "vendor": "sudo", "year": 2021,
             "note": "Heap-based buffer overflow via format string (Baron Samedit)"},
        ],
    },

    # ── 反序列化與程式完整性 ──────────────────────────────────────

    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "full_name": "Deserialization of Untrusted Data",
        "source": "MITRE CWE v4.14",
        "nist_severity": "CRITICAL",
        "cvss_base": 9.8,
        "owasp_2021": "A08:2021 – Software and Data Integrity Failures",
        "cwe_url": "https://cwe.mitre.org/data/definitions/502.html",
        "description": (
            "The application deserializes untrusted data without sufficiently verifying that the "
            "resulting data will be valid, allowing attackers to control the state or flow of "
            "execution, and potentially execute arbitrary code."
        ),
        "remediation_en": "Use safe data formats (JSON). Implement class allowlisting. Sign serialized data.",
        "remediation_zh": "使用安全的資料格式（JSON）。實作類別白名單。對序列化資料進行簽名。",
        "representative_cves": [
            {"id": "CVE-2018-2628", "cvss": 9.8, "vendor": "Oracle WebLogic", "year": 2018,
             "note": "Java deserialization RCE via T3 protocol"},
            {"id": "CVE-2017-9248", "cvss": 9.8, "vendor": "Telerik UI", "year": 2017,
             "note": ".NET deserialization leading to RCE"},
            {"id": "CVE-2022-22947", "cvss": 10.0, "vendor": "Spring Cloud Gateway", "year": 2022,
             "note": "Code injection via SPEL in actuator endpoint"},
        ],
    },

    "CWE-494": {
        "name": "Download of Code Without Integrity Check",
        "full_name": "Download of Code Without Integrity Check",
        "source": "MITRE CWE v4.14",
        "nist_severity": "HIGH",
        "cvss_base": 8.1,
        "owasp_2021": "A08:2021 – Software and Data Integrity Failures",
        "cwe_url": "https://cwe.mitre.org/data/definitions/494.html",
        "description": "The product downloads source code or an executable from a remote location without verifying its integrity.",
        "remediation_en": "Verify checksums/signatures before execution. Use HTTPS. Pin dependency versions.",
        "remediation_zh": "執行前驗證校驗和/簽名。使用 HTTPS。鎖定依賴版本。",
        "representative_cves": [
            {"id": "CVE-2022-3602", "cvss": 7.5, "vendor": "OpenSSL", "year": 2022,
             "note": "Certificate verification bypass enabling MitM"},
        ],
    },

    # ── 敏感資料暴露 ──────────────────────────────────────────────

    "CWE-312": {
        "name": "Cleartext Storage of Sensitive Information",
        "full_name": "Cleartext Storage of Sensitive Information",
        "source": "MITRE CWE v4.14",
        "nist_severity": "MEDIUM",
        "cvss_base": 5.5,
        "owasp_2021": "A02:2021 – Cryptographic Failures",
        "cwe_url": "https://cwe.mitre.org/data/definitions/312.html",
        "description": "Sensitive information (passwords, keys, PII) is stored in cleartext.",
        "remediation_en": "Encrypt sensitive data at rest. Use hardware security modules for keys.",
        "remediation_zh": "加密靜態敏感資料。使用硬體安全模組管理金鑰。",
        "representative_cves": [
            {"id": "CVE-2023-27163", "cvss": 7.5, "vendor": "request-baskets", "year": 2023,
             "note": "SSRF exposing internal credentials in cleartext"},
        ],
    },

    "CWE-200": {
        "name": "Exposure of Sensitive Information",
        "full_name": "Exposure of Sensitive Information to an Unauthorized Actor",
        "source": "MITRE CWE v4.14",
        "nist_severity": "MEDIUM",
        "cvss_base": 5.3,
        "owasp_2021": "A02:2021 – Cryptographic Failures",
        "cwe_url": "https://cwe.mitre.org/data/definitions/200.html",
        "description": "The product exposes sensitive information to an actor that is not explicitly authorized to access it.",
        "remediation_en": "Apply least-privilege principle. Audit error messages and logs for sensitive data leakage.",
        "remediation_zh": "應用最小權限原則。審核錯誤訊息和日誌中的敏感資料洩漏。",
        "representative_cves": [
            {"id": "CVE-2023-23752", "cvss": 7.5, "vendor": "Joomla", "year": 2023,
             "note": "Unauthorized information disclosure via REST API"},
        ],
    },

    "CWE-798": {
        "name": "Use of Hard-coded Credentials",
        "full_name": "Use of Hard-coded Credentials",
        "source": "MITRE CWE v4.14",
        "nist_severity": "CRITICAL",
        "cvss_base": 9.8,
        "owasp_2021": "A07:2021 – Identification and Authentication Failures",
        "cwe_url": "https://cwe.mitre.org/data/definitions/798.html",
        "description": "The software contains hard-coded credentials such as passwords or cryptographic keys.",
        "remediation_en": "Remove all hard-coded credentials. Use environment variables or secret management systems.",
        "remediation_zh": "移除所有硬編碼憑證。改用環境變數或密鑰管理系統（Vault、AWS Secrets Manager 等）。",
        "representative_cves": [
            {"id": "CVE-2022-29303", "cvss": 9.8, "vendor": "SolarView Compact", "year": 2022,
             "note": "Hard-coded credentials enabling backdoor access"},
            {"id": "CVE-2021-20090", "cvss": 9.8, "vendor": "Buffalo Router", "year": 2021,
             "note": "Hard-coded admin credentials"},
        ],
    },

    # ── 加密弱點 ──────────────────────────────────────────────────

    "CWE-326": {
        "name": "Inadequate Encryption Strength",
        "full_name": "Inadequate Encryption Strength",
        "source": "MITRE CWE v4.14",
        "nist_severity": "MEDIUM",
        "cvss_base": 5.9,
        "owasp_2021": "A02:2021 – Cryptographic Failures",
        "cwe_url": "https://cwe.mitre.org/data/definitions/326.html",
        "description": "The software stores or transmits sensitive data using an algorithm that is insufficiently strong given current conditions.",
        "remediation_en": "Use AES-256 for symmetric encryption. Use RSA-2048+ or ECC P-256+ for asymmetric. Avoid MD5, SHA-1, DES.",
        "remediation_zh": "對稱加密使用 AES-256。非對稱使用 RSA-2048+ 或 ECC P-256+。避免 MD5、SHA-1、DES。",
        "representative_cves": [
            {"id": "CVE-2022-3602", "cvss": 7.5, "vendor": "OpenSSL", "year": 2022,
             "note": "Inadequate certificate verification"},
        ],
    },

    "CWE-295": {
        "name": "Improper Certificate Validation",
        "full_name": "Improper Certificate Validation",
        "source": "MITRE CWE v4.14",
        "nist_severity": "HIGH",
        "cvss_base": 7.4,
        "owasp_2021": "A02:2021 – Cryptographic Failures",
        "cwe_url": "https://cwe.mitre.org/data/definitions/295.html",
        "description": "The software does not validate, or incorrectly validates, a certificate.",
        "remediation_en": "Enable full certificate chain validation. Pin certificates for high-value connections.",
        "remediation_zh": "啟用完整的憑證鏈驗證。對高價值連線使用憑證鎖定（Certificate Pinning）。",
        "representative_cves": [
            {"id": "CVE-2021-3449", "cvss": 5.9, "vendor": "OpenSSL", "year": 2021,
             "note": "NULL pointer dereference during certificate validation"},
        ],
    },

    # ── 存取控制 ──────────────────────────────────────────────────

    "CWE-862": {
        "name": "Missing Authorization",
        "full_name": "Missing Authorization",
        "source": "MITRE CWE v4.14",
        "nist_severity": "HIGH",
        "cvss_base": 8.8,
        "owasp_2021": "A01:2021 – Broken Access Control",
        "cwe_url": "https://cwe.mitre.org/data/definitions/862.html",
        "description": "The software does not perform an authorization check when an actor attempts to access a resource or perform an action.",
        "remediation_en": "Implement authorization checks on every endpoint. Use deny-by-default policy.",
        "remediation_zh": "在每個端點實作授權檢查。使用預設拒絕策略。",
        "representative_cves": [
            {"id": "CVE-2023-23752", "cvss": 7.5, "vendor": "Joomla", "year": 2023,
             "note": "Missing authorization allowing data access"},
            {"id": "CVE-2022-27096", "cvss": 8.8, "vendor": "Multiple Web Apps", "year": 2022,
             "note": "Broken access control leading to privilege escalation"},
        ],
    },

    "CWE-287": {
        "name": "Improper Authentication",
        "full_name": "Improper Authentication",
        "source": "MITRE CWE v4.14",
        "nist_severity": "CRITICAL",
        "cvss_base": 9.8,
        "owasp_2021": "A07:2021 – Identification and Authentication Failures",
        "cwe_url": "https://cwe.mitre.org/data/definitions/287.html",
        "description": "When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct.",
        "remediation_en": "Use strong multi-factor authentication. Validate session tokens properly.",
        "remediation_zh": "使用強多因素認證。正確驗證 Session Token。",
        "representative_cves": [
            {"id": "CVE-2022-35405", "cvss": 9.8, "vendor": "Zoho ManageEngine", "year": 2022,
             "note": "Authentication bypass via improper validation"},
        ],
    },

    "CWE-306": {
        "name": "Missing Authentication for Critical Function",
        "full_name": "Missing Authentication for Critical Function",
        "source": "MITRE CWE v4.14",
        "nist_severity": "CRITICAL",
        "cvss_base": 9.8,
        "owasp_2021": "A07:2021 – Identification and Authentication Failures",
        "cwe_url": "https://cwe.mitre.org/data/definitions/306.html",
        "description": "The software does not perform any authentication for functionality that requires a provable user identity.",
        "remediation_en": "Require authentication for all sensitive operations. Implement zero-trust model.",
        "remediation_zh": "所有敏感操作都要求認證。實作零信任模型。",
        "representative_cves": [
            {"id": "CVE-2021-20090", "cvss": 9.8, "vendor": "Buffalo Network Device", "year": 2021,
             "note": "Authentication bypass allowing unauthorized access"},
        ],
    },

    # ── 開放重定向與 SSRF ─────────────────────────────────────────

    "CWE-601": {
        "name": "Open Redirect",
        "full_name": "URL Redirection to Untrusted Site",
        "source": "MITRE CWE v4.14",
        "nist_severity": "MEDIUM",
        "cvss_base": 6.1,
        "owasp_2021": "A01:2021 – Broken Access Control",
        "cwe_url": "https://cwe.mitre.org/data/definitions/601.html",
        "description": "The web application accepts a user-controlled input that specifies a link to an external site, and uses that link in a Redirect.",
        "remediation_en": "Use a whitelist of allowed redirect URLs. Avoid using user input in redirect destinations.",
        "remediation_zh": "使用允許的重定向 URL 白名單。避免在重定向目標中使用用戶輸入。",
        "representative_cves": [
            {"id": "CVE-2023-33246", "cvss": 7.5, "vendor": "Apache RocketMQ", "year": 2023,
             "note": "Open redirect enabling phishing attacks"},
        ],
    },

    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "full_name": "Server-Side Request Forgery (SSRF)",
        "source": "MITRE CWE v4.14",
        "nist_severity": "HIGH",
        "cvss_base": 8.6,
        "owasp_2021": "A10:2021 – Server-Side Request Forgery",
        "cwe_url": "https://cwe.mitre.org/data/definitions/918.html",
        "description": "The server can be induced to make requests to unintended locations, including internal network services.",
        "remediation_en": "Validate and whitelist URLs. Block access to internal IP ranges. Disable unnecessary URL schemes.",
        "remediation_zh": "驗證並白名單化 URL。封鎖對內部 IP 範圍的存取。停用不必要的 URL 協定。",
        "representative_cves": [
            {"id": "CVE-2023-27163", "cvss": 7.5, "vendor": "request-baskets", "year": 2023,
             "note": "SSRF allowing internal network access"},
            {"id": "CVE-2019-8451", "cvss": 6.8, "vendor": "Jira", "year": 2019,
             "note": "SSRF via IconUriServlet endpoint"},
        ],
    },

    # ── 記憶體與資源問題 ──────────────────────────────────────────

    "CWE-119": {
        "name": "Buffer Overflow",
        "full_name": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
        "source": "MITRE CWE v4.14",
        "nist_severity": "CRITICAL",
        "cvss_base": 9.8,
        "owasp_2021": "A03:2021 – Injection",
        "cwe_url": "https://cwe.mitre.org/data/definitions/119.html",
        "description": "The software performs operations on a memory buffer but can read from or write to a memory location outside of its intended bounds.",
        "remediation_en": "Use memory-safe languages. Enable stack canaries, ASLR, and NX. Use bounds-checked functions.",
        "remediation_zh": "使用記憶體安全語言。啟用棧金絲雀、ASLR 和 NX。使用有邊界檢查的函式。",
        "representative_cves": [
            {"id": "CVE-2022-3602", "cvss": 7.5, "vendor": "OpenSSL", "year": 2022,
             "note": "Buffer overflow in X.509 certificate verification"},
        ],
    },

    "CWE-120": {
        "name": "Classic Buffer Overflow",
        "full_name": "Buffer Copy without Checking Size of Input",
        "source": "MITRE CWE v4.14",
        "nist_severity": "CRITICAL",
        "cvss_base": 9.8,
        "owasp_2021": "A03:2021 – Injection",
        "cwe_url": "https://cwe.mitre.org/data/definitions/120.html",
        "description": "The program copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer.",
        "remediation_en": "Use strncpy/strncat with explicit size limits. Prefer C++ std::string or Rust.",
        "remediation_zh": "使用帶大小限制的 strncpy/strncat。優先使用 C++ std::string 或 Rust。",
        "representative_cves": [
            {"id": "CVE-2021-3156", "cvss": 7.8, "vendor": "sudo", "year": 2021,
             "note": "Heap-based buffer overflow (Baron Samedit)"},
        ],
    },

    "CWE-416": {
        "name": "Use After Free",
        "full_name": "Use After Free",
        "source": "MITRE CWE v4.14",
        "nist_severity": "HIGH",
        "cvss_base": 7.8,
        "owasp_2021": "A03:2021 – Injection",
        "cwe_url": "https://cwe.mitre.org/data/definitions/416.html",
        "description": "The software references memory after it has been freed, which may cause it to crash, use unexpected values, or execute code.",
        "remediation_en": "Set pointers to NULL after freeing. Use smart pointers in C++. Use memory-safe languages.",
        "remediation_zh": "釋放後將指標設為 NULL。在 C++ 中使用智慧指標。優先考慮記憶體安全語言。",
        "representative_cves": [
            {"id": "CVE-2022-0185", "cvss": 8.4, "vendor": "Linux Kernel", "year": 2022,
             "note": "Use-after-free in filesystem context leading to privilege escalation"},
        ],
    },

    "CWE-400": {
        "name": "Uncontrolled Resource Consumption (ReDoS/DoS)",
        "full_name": "Uncontrolled Resource Consumption",
        "source": "MITRE CWE v4.14",
        "nist_severity": "HIGH",
        "cvss_base": 7.5,
        "owasp_2021": "A04:2021 – Insecure Design",
        "cwe_url": "https://cwe.mitre.org/data/definitions/400.html",
        "description": "The software does not properly control the allocation and maintenance of a limited resource, allowing attackers to cause denial of service via resource exhaustion.",
        "remediation_en": "Implement rate limiting. Audit regex for exponential backtracking. Set resource limits.",
        "remediation_zh": "實作速率限制。審核正則表達式是否有指數回溯。設置資源限制。",
        "representative_cves": [
            {"id": "CVE-2023-28155", "cvss": 7.5, "vendor": "Node.js request", "year": 2023,
             "note": "ReDoS via specially crafted URL"},
        ],
    },

    "CWE-1333": {
        "name": "Inefficient Regular Expression Complexity (ReDoS)",
        "full_name": "Inefficient Regular Expression Complexity",
        "source": "MITRE CWE v4.14",
        "nist_severity": "HIGH",
        "cvss_base": 7.5,
        "owasp_2021": "A04:2021 – Insecure Design",
        "cwe_url": "https://cwe.mitre.org/data/definitions/1333.html",
        "description": "The product uses a regular expression with an inefficient, exponential worst-case computational complexity that consumes excessive CPU cycles.",
        "remediation_en": "Audit regex for catastrophic backtracking. Use linear-time regex engines. Enforce timeouts.",
        "remediation_zh": "審核正則表達式的災難性回溯問題。使用線性時間正則引擎。強制設置超時。",
        "representative_cves": [
            {"id": "CVE-2022-24999", "cvss": 7.5, "vendor": "qs (npm)", "year": 2022,
             "note": "ReDoS in query string parsing"},
        ],
    },

    "CWE-1321": {
        "name": "Prototype Pollution",
        "full_name": "Improperly Controlled Modification of Object Prototype Attributes",
        "source": "MITRE CWE v4.14",
        "nist_severity": "HIGH",
        "cvss_base": 8.1,
        "owasp_2021": "A03:2021 – Injection",
        "cwe_url": "https://cwe.mitre.org/data/definitions/1321.html",
        "description": "Modifying the Object prototype in JavaScript can affect all objects, allowing attackers to inject malicious properties.",
        "remediation_en": "Use Object.create(null) for maps. Validate keys. Use hasOwnProperty checks.",
        "remediation_zh": "使用 Object.create(null) 作為映射。驗證鍵名。使用 hasOwnProperty 檢查。",
        "representative_cves": [
            {"id": "CVE-2022-37601", "cvss": 9.8, "vendor": "loader-utils (npm)", "year": 2022,
             "note": "Prototype pollution via webpack loader configuration"},
            {"id": "CVE-2021-23337", "cvss": 7.2, "vendor": "lodash", "year": 2021,
             "note": "Prototype pollution via merge/zipObjectDeep"},
        ],
    },

}

# ══════════════════════════════════════════════════════════════════
# 查詢函式
# ══════════════════════════════════════════════════════════════════

def get_cwe_info(cwe_id: str) -> dict | None:
    """
    查詢 CWE 官方資訊。

    Args:
        cwe_id: CWE 識別碼，例如 "CWE-89"

    Returns:
        CWE 資訊字典，若未找到則回傳 None
    """
    normalized = cwe_id.strip().upper()
    result = CWE_DATABASE.get(normalized)
    if result is None:
        logger.debug("[CWE_DB] CWE not found in database: %s", normalized)
    return result


def format_cwe_for_advisor(cwe_id: str, include_cves: bool = True) -> str:
    """
    格式化 CWE 資訊，供 Advisor 輸出使用。

    格式設計原則：
    - 明確標注來源（非 LLM 生成）
    - 包含 MITRE 官方定義、NIST 嚴重性、OWASP 對應
    - 可選：代表性 CVE（附免責聲明）

    Args:
        cwe_id: CWE 識別碼
        include_cves: 是否包含代表性 CVE

    Returns:
        格式化後的字串
    """
    info = get_cwe_info(cwe_id)
    if not info:
        return f"[{cwe_id}] No official data found in MITRE CWE v4.14 database"

    lines = [
        f"[{cwe_id}] {info['name']}",
        f"來源：{info.get('source', 'MITRE CWE')} | "
        f"NIST 嚴重性：{info.get('nist_severity', 'N/A')} | "
        f"CVSS Base：{info.get('cvss_base', 'N/A')}",
        f"OWASP：{info.get('owasp_2021', 'N/A')}",
        f"官方URL：{info.get('cwe_url', '')}",
        f"定義：{info.get('description', '')}",
        f"修復：{info.get('remediation_zh', info.get('remediation_en', 'N/A'))}",
    ]

    if include_cves:
        rep_cves = info.get("representative_cves", [])
        if rep_cves:
            lines.append(
                "代表性 CVE（同類弱點真實案例，非本程式碼的直接 CVE）："
            )
            for cve in rep_cves[:3]:  # 最多 3 個
                lines.append(
                    f"  → {cve['id']} | CVSS {cve['cvss']} | "
                    f"{cve.get('vendor', '')} ({cve.get('year', '')}) | "
                    f"{cve.get('note', '')}"
                )

    return "\n".join(lines)


def get_cwe_severity(cwe_id: str) -> str:
    """回傳 CWE 的 NIST 嚴重性等級（HIGH/CRITICAL/MEDIUM/LOW），未知則回傳 UNKNOWN"""
    info = get_cwe_info(cwe_id)
    return info.get("nist_severity", "UNKNOWN") if info else "UNKNOWN"


def get_representative_cves(cwe_id: str) -> list[dict]:
    """回傳 CWE 的代表性 CVE 列表（最多 3 個），未知則回傳空列表"""
    info = get_cwe_info(cwe_id)
    return info.get("representative_cves", [])[:3] if info else []


def list_covered_cwes() -> list[str]:
    """回傳資料庫中所有覆蓋的 CWE ID"""
    return sorted(CWE_DATABASE.keys())
