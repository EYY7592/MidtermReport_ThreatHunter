# tools/attck_tool.py
# 功能：CWE → CAPEC → MITRE ATT&CK Technique 映射
# 架構定位：補全 Intel Fusion 六維分析的 ATT&CK 維度（權重 10%）
#
# 為什麼用靜態映射（不用 API）：
#   - MITRE ATT&CK 官方 TAXII 伺服器沒有 CVE→Technique 直接查詢端點
#   - 研究：CAPEC 是 CWE 和 ATT&CK 之間最結構化的橋接
#   - 路徑：CVE description → CWE → CAPEC → ATT&CK Technique
#   - 來源：NIST NVD 提供 CWE，MITRE 官方提供 CAPEC→ATT&CK 對應
#
# 佐證：
#   - Center for Threat-Informed Defense (CTID) Mappings Explorer
#   - https://mappings-explorer.mitre.org/
#   - NopSec (2024): "CWE→CAPEC→ATT&CK is the most structured mapping path"
#   - GitHub: threatsurfer/cve-attack-mapper（參考實作）
#
# 使用方式：
#   from tools.attck_tool import lookup_attck_technique

import json
import logging
import re

logger = logging.getLogger("ThreatHunter.attck_tool")

# ══════════════════════════════════════════════════════════════
# CWE → ATT&CK Technique 和 CAPEC 映射表
# 來源：MITRE ATT&CK v14 + CAPEC 3.9
# 涵蓋最常見的 Web/系統漏洞 CWE
# ══════════════════════════════════════════════════════════════

CWE_TO_ATTCK: dict[str, dict] = {
    # ── 注入類 ──────────────────────────────────────────────
    "CWE-89": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "capec": "CAPEC-66",
        "capec_name": "SQL Injection",
        "description": "SQL injection allows attackers to manipulate DB queries",
    },
    "CWE-78": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "capec": "CAPEC-88",
        "capec_name": "OS Command Injection",
        "description": "OS command injection via improper input neutralization",
    },
    "CWE-77": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "capec": "CAPEC-88",
        "capec_name": "Command Injection",
        "description": "Command injection in shell-invoked functions",
    },
    # ── XSS / 客戶端注入 ─────────────────────────────────────
    "CWE-79": {
        "technique_id": "T1059.007",
        "technique_name": "JavaScript",
        "tactic": "Execution",
        "capec": "CAPEC-86",
        "capec_name": "XSS via HTTP Query Strings",
        "description": "Cross-site scripting enables malicious script injection",
    },
    "CWE-80": {
        "technique_id": "T1059.007",
        "technique_name": "JavaScript",
        "tactic": "Execution",
        "capec": "CAPEC-198",
        "capec_name": "XSS via HTTP Headers",
        "description": "Basic XSS through unescaped HTML",
    },
    # ── 路徑遍歷 / 檔案操作 ──────────────────────────────────
    "CWE-22": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "Discovery",
        "capec": "CAPEC-126",
        "capec_name": "Path Traversal",
        "description": "Path traversal grants unauthorized file access",
    },
    "CWE-73": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "Discovery",
        "capec": "CAPEC-126",
        "capec_name": "External Control of File Name",
        "description": "Externally controlled file name leads to traversal",
    },
    # ── 認證 / 授權 ──────────────────────────────────────────
    "CWE-287": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Initial Access",
        "capec": "CAPEC-115",
        "capec_name": "Authentication Bypass",
        "description": "Authentication bypass allows unauthorized access",
    },
    "CWE-306": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Initial Access",
        "capec": "CAPEC-115",
        "capec_name": "Missing Authentication",
        "description": "Missing authentication for critical function",
    },
    "CWE-798": {
        "technique_id": "T1552.001",
        "technique_name": "Credentials In Files",
        "tactic": "Credential Access",
        "capec": "CAPEC-191",
        "capec_name": "Hardcoded Credentials",
        "description": "Hardcoded credentials expose authentication secrets",
    },
    # ── 暴露敏感資訊 ─────────────────────────────────────────
    "CWE-200": {
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage",
        "tactic": "Collection",
        "capec": "CAPEC-118",
        "capec_name": "Collect and Analyze Information",
        "description": "Exposure of sensitive information to unauthorized actors",
    },
    "CWE-312": {
        "technique_id": "T1552.004",
        "technique_name": "Private Keys",
        "tactic": "Credential Access",
        "capec": "CAPEC-37",
        "capec_name": "Unencrypted Storage",
        "description": "Cleartext storage of sensitive information",
    },
    # ── 序列化 / 反序列化 ─────────────────────────────────────
    "CWE-502": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "capec": "CAPEC-586",
        "capec_name": "Object Injection",
        "description": "Deserialization of untrusted data enables code execution",
    },
    # ── SSRF / 請求偽造 ──────────────────────────────────────
    "CWE-918": {
        "technique_id": "T1090",
        "technique_name": "Proxy",
        "tactic": "Command and Control",
        "capec": "CAPEC-664",
        "capec_name": "Server-Side Request Forgery",
        "description": "SSRF allows reaching internal services via the server",
    },
    # ── 快取 / 中間人 ─────────────────────────────────────────
    "CWE-295": {
        "technique_id": "T1557",
        "technique_name": "Adversary-in-the-Middle",
        "tactic": "Collection",
        "capec": "CAPEC-94",
        "capec_name": "Man-in-the-Browser",
        "description": "Improper certificate validation enables MITM",
    },
    # ── Buffer Overflow / 記憶體安全 ─────────────────────────
    "CWE-120": {
        "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution",
        "tactic": "Execution",
        "capec": "CAPEC-100",
        "capec_name": "Overflow Buffers",
        "description": "Buffer overflow can lead to arbitrary code execution",
    },
    "CWE-119": {
        "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution",
        "tactic": "Execution",
        "capec": "CAPEC-100",
        "capec_name": "Memory Buffer Overflow",
        "description": "Improper restriction of buffer operations",
    },
    # ── Use-After-Free / 記憶體管理 ───────────────────────────
    "CWE-416": {
        "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution",
        "tactic": "Execution",
        "capec": "CAPEC-46",
        "capec_name": "Overflow Variables and Tags",
        "description": "Use-after-free enables heap manipulation attacks",
    },
    # ── 供應鏈 ───────────────────────────────────────────────
    "CWE-494": {
        "technique_id": "T1195.002",
        "technique_name": "Compromise Software Supply Chain",
        "tactic": "Initial Access",
        "capec": "CAPEC-538",
        "capec_name": "Open-Source Library Manipulation",
        "description": "Download of code without integrity check",
    },
    # ── LDAP 注入 ─────────────────────────────────────────────
    "CWE-90": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "capec": "CAPEC-136",
        "capec_name": "LDAP Injection",
        "description": "LDAP injection via improper LDAP query neutralization",
    },
    # ── XXE ───────────────────────────────────────────────────
    "CWE-611": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "capec": "CAPEC-221",
        "capec_name": "DTD Injection",
        "description": "XML External Entity injection enables file disclosure",
    },
    # ── Prototype Pollution (Node.js) ─────────────────────────
    "CWE-1321": {
        "technique_id": "T1059.007",
        "technique_name": "JavaScript",
        "tactic": "Execution",
        "capec": "CAPEC-1",
        "capec_name": "Accessing Functionality Not Properly Constrained",
        "description": "Prototype pollution via __proto__ manipulation",
    },
    # ── ReDoS ─────────────────────────────────────────────────
    "CWE-1333": {
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "capec": "CAPEC-492",
        "capec_name": "Regular Expression Exponential Blowup",
        "description": "Inefficient regular expression causes ReDoS",
    },
    # ── DoS ───────────────────────────────────────────────────
    "CWE-400": {
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "capec": "CAPEC-147",
        "capec_name": "XML Routing Detour Attacks",
        "description": "Uncontrolled resource consumption leads to DoS",
    },
    # ── Open Redirect ─────────────────────────────────────────
    "CWE-601": {
        "technique_id": "T1204.001",
        "technique_name": "Malicious Link",
        "tactic": "Execution",
        "capec": "CAPEC-194",
        "capec_name": "Fake the Source of Data",
        "description": "URL redirection to untrusted sites",
    },
}

# Keyword → CWE 快速映射（從 CVE 描述中提取）
KEYWORD_TO_CWE: dict[str, str] = {
    "sql injection": "CWE-89",
    "sqli": "CWE-89",
    "command injection": "CWE-78",
    "os command": "CWE-78",
    "xss": "CWE-79",
    "cross-site scripting": "CWE-79",
    "cross site scripting": "CWE-79",
    "path traversal": "CWE-22",
    "directory traversal": "CWE-22",
    "authentication bypass": "CWE-287",
    "hardcoded": "CWE-798",
    "hard-coded": "CWE-798",
    "ssrf": "CWE-918",
    "server-side request forgery": "CWE-918",
    "deserialization": "CWE-502",
    "prototype pollution": "CWE-1321",
    "redos": "CWE-1333",
    "denial of service": "CWE-400",
    "open redirect": "CWE-601",
    "xxe": "CWE-611",
    "xml external entity": "CWE-611",
    "buffer overflow": "CWE-120",
    "use after free": "CWE-416",
    "use-after-free": "CWE-416",
    "supply chain": "CWE-494",
    "ldap injection": "CWE-90",
}


def lookup_attck_by_cwe(cwe_id: str) -> dict | None:
    """
    根據 CWE ID 查詢對應的 ATT&CK Technique。

    Args:
        cwe_id: 格式 "CWE-79" 或 "79"

    Returns:
        {technique_id, technique_name, tactic, capec, ...} 或 None
    """
    norm = cwe_id.strip().upper()
    if not norm.startswith("CWE-"):
        norm = f"CWE-{norm}"
    result = CWE_TO_ATTCK.get(norm)
    if result:
        logger.info("[ATTCK] CWE %s -> %s (%s)", norm, result["technique_id"], result["technique_name"])
    return result


def lookup_attck_by_description(description: str) -> dict | None:
    """
    從 CVE 描述文字中提取可能的 CWE，再查詢 ATT&CK。

    優先精確 CWE，其次關鍵字匹配。
    """
    text = description.lower()

    # 1. 從描述中提取明確的 CWE 編號（如 "CWE-79"）
    cwe_match = re.search(r"cwe-(\d+)", text)
    if cwe_match:
        result = lookup_attck_by_cwe(f"CWE-{cwe_match.group(1)}")
        if result:
            return result

    # 2. 關鍵字匹配
    for keyword, cwe in KEYWORD_TO_CWE.items():
        if keyword in text:
            result = lookup_attck_by_cwe(cwe)
            if result:
                return result

    return None


def get_attck_for_cve(cve_id: str, description: str = "", cwe_ids: list[str] | None = None) -> dict:
    """
    程式碼層呼叫：給定 CVE ID + 描述 + CWE 列表，返回最匹配的 ATT&CK Technique。

    供 Intel Fusion _verify_and_recalculate 使用。

    Returns:
        {
            "technique_id": "T1059.007",
            "technique_name": "JavaScript",
            "tactic": "Execution",
            "capec": "CAPEC-86",
            "source": "CWE->ATTCK_MAP",
            "matched_by": "CWE-79" | "keyword:xss" | None,
        }
    """
    # 優先使用明確的 CWE 列表
    if cwe_ids:
        for cwe in cwe_ids:
            result = lookup_attck_by_cwe(cwe)
            if result:
                return {**result, "source": "CWE->ATTCK_MAP", "matched_by": cwe}

    # 降級：從描述文字推斷
    if description:
        result = lookup_attck_by_description(description)
        if result:
            # 找出是哪個關鍵字觸發的
            text = description.lower()
            matched_kw = next((kw for kw in KEYWORD_TO_CWE if kw in text), "keyword")
            return {**result, "source": "CWE->ATTCK_MAP", "matched_by": f"keyword:{matched_kw}"}

    # 無法對應：返回通用 T1190（最常見的漏洞利用 Technique）
    return {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "capec": "CAPEC-1",
        "capec_name": "Unknown",
        "description": "No specific ATT&CK mapping found; defaulting to general exploitation",
        "source": "CWE->ATTCK_MAP",
        "matched_by": None,
    }
