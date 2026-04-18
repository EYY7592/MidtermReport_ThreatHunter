# Skill: Code Security Action Report (Advisor — Path B-code)
# Version: v3.7 | Agent: Advisor | Path: B-code (source code)
# Purpose: Actionable code-level security remediation plan

## Role
Produce a developer-focused remediation plan for both package CVEs and code vulnerability patterns.
Give concrete code fix examples, not just "sanitize your inputs."

## Priority Framework
```
URGENT   = CODE pattern with CRITICAL severity + direct exploit path (SQLi, CMDi, SSTI, deserialization)
IMPORTANT = CODE pattern with HIGH severity OR package CVE in KEV
MONITOR  = MEDIUM severity patterns with mitigating controls
RESOLVED = Confirmed fixed by developer
```

## SOP

### Step 1: Read Memory
```
Action: read_memory
Action Input: advisor
```

### Step 2: Build Code Fix Actions per Finding

For code patterns — provide:
1. Vulnerable code snippet (from Analyst/Scout)
2. Fixed code replacement
3. Explanation of why the fix works
4. Testing recommendation

#### Standard Code Fixes

**SQL Injection (CWE-89)**
```python
# VULNERABLE
cursor.execute(f"SELECT * FROM users WHERE id={user_id}")
# FIXED
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

**Command Injection (CWE-78)**
```python
# VULNERABLE
os.system(f"ping {user_host}")
# FIXED
import subprocess, shlex
subprocess.run(["ping", user_host], capture_output=True, timeout=5)
```

**Path Traversal (CWE-22)**
```python
# VULNERABLE
open(f"/uploads/{filename}")
# FIXED
from pathlib import Path
safe_path = (Path("/uploads") / filename).resolve()
if not str(safe_path).startswith("/uploads"):
    raise ValueError("Path traversal detected")
```

**SSTI (CWE-94) — Flask/Jinja2**
```python
# VULNERABLE
render_template_string(user_content)
# FIXED
render_template("static_template.html", user_content=user_content)
```

**Hardcoded Secret (CWE-798)**
```python
# VULNERABLE
API_KEY = "sk-abc123..."
# FIXED
import os
API_KEY = os.environ["OPENAI_API_KEY"]  # Load from secrets manager
```

### Step 3: Remediation for Package CVEs
Same as Path A action_report.md format.

### Step 4: Write Memory + Final Answer

## Output Schema
```json
{
  "executive_summary": "2 critical code vulnerabilities found: SQL injection and command injection enabling RCE.",
  "risk_score": 9.2,
  "risk_trend": "+2.1",
  "actions": {
    "urgent": [
      {
        "finding_id": "CODE-001",
        "type": "code_pattern",
        "pattern_type": "SQL_INJECTION",
        "severity": "CRITICAL",
        "owasp_category": "A03:2021-Injection",
        "cwe_id": "CWE-89",
        "action": "Replace string-interpolated SQL with parameterized queries",
        "vulnerable_snippet": "cursor.execute(f\"SELECT * FROM users WHERE id={user_id}\")",
        "fixed_snippet": "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
        "why_this_works": "Parameterized queries separate SQL structure from data, preventing injection",
        "test_recommendation": "Run sqlmap against the endpoint to verify fix",
        "deadline": "TODAY"
      }
    ],
    "important": [],
    "resolved": []
  },
  "scan_path": "B-code"
}
```

## Quality Redlines
1. fixed_snippet MUST be syntactically correct Python/JS/Go (match detected language)
2. Do NOT use "escape user input" as a fix — provide specific parameterized/escape API
3. Each CRITICAL code fix must have a test_recommendation
