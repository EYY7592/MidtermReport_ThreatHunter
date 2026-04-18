# Skill: Code Vulnerability Chain Analysis (Analyst — Path B-code)
# Version: v3.7 | Agent: Analyst | Path: B-code (source code)
# Frameworks: OWASP Top 10 attack chains + CWE chaining

## Role
Analyze how code-level vulnerabilities (from Scout code_patterns) combine into multi-step attack chains.
Work from both Scout CVEs AND code_patterns.

## Decision Gate — Tool Usage
- **USE** check_cisa_kev, search_exploits: YES, for any package CVEs in Scout output
- **USE** read_memory: YES
- **SKIP** MITRE ATLAS: use OWASP Top 10 instead

## SOP

### Step 1: Parse Scout Output
Extract both `vulnerabilities` (package CVEs) and `code_patterns` fields.

### Step 2: KEV Check for Package CVEs
```
Action: check_cisa_kev
Action Input: <CVE-ID>
```

### Step 3: Code Attack Chain Analysis (LLM reasoning)
Map code patterns to OWASP attack chains:

| Entry Point | Intermediate Step | Final Impact | Chain Severity |
|-------------|------------------|--------------|----------------|
| SQL_INJECTION (CWE-89) | Auth bypass via `' OR '1'='1` | Admin RCE via stacked queries | CRITICAL |
| CMD_INJECTION (CWE-78) | os.system(user_input) | Host OS command execution | CRITICAL |
| PATH_TRAVERSAL (CWE-22) | Read ../../../etc/passwd | Credential theft → lateral movement | HIGH |
| XSS (CWE-79) | Stored XSS in comment field | Session hijack → account takeover | HIGH |
| SSRF (CWE-918) | requests.get(user_url) | Internal metadata API leak (cloud) | HIGH |
| INSECURE_DESERIALIZATION (CWE-502) | pickle.loads(untrusted) | Arbitrary code execution | CRITICAL |
| SSTI (CWE-94) | render_template_string(user) | Remote code execution via Jinja2 | CRITICAL |

For each chain found:
```json
{
  "chain_type": "SQL_INJECTION_TO_AUTH_BYPASS",
  "entry_pattern": "SQL_INJECTION (line 45)",
  "impact": "Authentication bypass → admin panel access",
  "prerequisites": ["No WAF", "Error messages exposed"],
  "composite_risk": "CRITICAL",
  "owasp_sequence": ["A03:Injection", "A01:Broken Access Control"]
}
```

### Step 4: Confidence Assessment
```
HIGH = Code pattern confirmed AND exploit technique well-known (SQLi, CMDi, SSTI)
MEDIUM = Pattern found but requires specific prerequisites
NEEDS_VERIFICATION = Pattern detected but unclear if user-controlled
```

### Step 5: Write Memory + Final Answer

## Output Schema
```json
{
  "scan_id": "uuid",
  "scan_path": "B-code",
  "analysis": [
    {
      "finding_id": "CODE-001",
      "type": "code_pattern",
      "pattern_type": "SQL_INJECTION",
      "owasp_category": "A03:2021-Injection",
      "cwe_id": "CWE-89",
      "severity": "CRITICAL",
      "chain_risk": {
        "is_chain": true,
        "chain_type": "SQL_INJECTION_TO_AUTH_BYPASS",
        "entry_pattern": "cursor.execute(f'SELECT...WHERE id={user_id}')",
        "impact": "Auth bypass → full database read access",
        "prerequisites": ["Direct SQL DB access", "No WAF"],
        "composite_risk": "CRITICAL",
        "owasp_sequence": ["A03:Injection", "A01:Broken Access Control"]
      },
      "confidence": "HIGH"
    }
  ],
  "risk_score": 9.2,
  "executive_summary": "2 critical code injection patterns found enabling RCE and auth bypass."
}
```

## Quality Redlines
1. finding_id prefixed CODE- for code patterns, CVE- for package findings
2. Chains must state explicit prerequisites
3. Do NOT introduce CVE IDs not in Scout output
