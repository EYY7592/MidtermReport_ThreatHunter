# Skill: Config Misconfiguration Chain Analysis (Analyst — Path C)
# Version: v3.7 | Agent: Analyst | Path: C (config)
# Frameworks: CIS Benchmarks attack chains + Cloud Security Alliance

## Role
Analyze how configuration misconfigurations chain into multi-step attack paths.
Work from Scout misconfigurations and hardcoded_secrets fields.

## Decision Gate — Tool Usage
- **SKIP** check_cisa_kev for config issues (CIS issues are not CVEs)
- **USE** check_cisa_kev ONLY for package_cves if Scout found versioned software CVEs
- **SKIP** search_exploits: config misconfigs are exploited via known techniques, not PoC binaries
- **USE** read_memory: YES

## Common Config Attack Chain Patterns

### Chain 1: Privileged Container → Host Escape
```
CIS-Docker-5.4 (privileged: true)
  → Container process has full host capabilities
  → nsenter / chroot to escape container
  → Full host OS access as root
Severity: CRITICAL
Prerequisites: Container privilege, runnable shell access
```

### Chain 2: Exposed Secret → Lateral Movement
```
Hardcoded API Key in .env
  → Attacker finds key via code repo, log leak, or container inspection
  → Key grants access to external service (DB, S3, API)
  → Lateral movement to cloud resources
Severity: CRITICAL
Prerequisites: Secret committed to repo or exposed in logs
```

### Chain 3: Debug Mode → Information Disclosure → Targeted Attack
```
DEBUG=True (Django/Flask)
  → Detailed error pages with stack traces, source code
  → Reveals internal structure, DB queries, API keys in environment
  → Targeted exploit constructed from leaked info
Severity: HIGH
Prerequisites: Debug mode accessible to external users
```

### Chain 4: Permissive Network + Weak Auth → Data Breach
```
Port 0.0.0.0 binding (all interfaces)
  → Internal service (Redis, Elasticsearch, MongoDB) exposed externally
  → No authentication configured (default)
  → Full data read/write access without credentials
Severity: CRITICAL
Prerequisites: No firewall, no authentication on service
```

### Chain 5: Latest Tag → Supply Chain Attack
```
image: latest (unpinned)
  → Automated rebuild pulls malicious image update
  → Compromised image contains backdoor
  → RCE on container startup
Severity: HIGH
Prerequisites: Malicious image in registry, auto-pull enabled
```

## SOP

### Step 1: Parse Scout Output
Extract `misconfigurations` and `hardcoded_secrets`.

### Step 2: Chain Analysis (LLM reasoning)
For each misconfiguration or secret:
1. Identify which chain pattern applies
2. Map prerequisites from actual config values
3. Assess composite risk

### Step 3: CIS Control Coverage Score
Calculate percentage of applicable CIS controls that are properly configured.

### Step 4: Write Memory + Final Answer

## Output Schema
```json
{
  "scan_id": "uuid",
  "scan_path": "C",
  "analysis": [
    {
      "chain_id": "CFG-CHAIN-001",
      "entry_issue": "Privileged container (CIS-Docker-5.4)",
      "chain_type": "PRIVILEGED_CONTAINER_TO_HOST_ESCAPE",
      "cis_controls_violated": ["CIS-Docker-5.4", "CIS-Docker-4.1"],
      "severity": "CRITICAL",
      "chain_risk": {
        "is_chain": true,
        "steps": [
          "Step 1: Container runs with privileged:true",
          "Step 2: Attacker gains code execution inside container (any method)",
          "Step 3: nsenter --target 1 --mount --pid -- chroot /proc/1/root",
          "Step 4: Full host OS access as root"
        ],
        "prerequisites": ["Code execution in container", "Linux kernel < 5.x (older risk)"],
        "composite_risk": "CRITICAL"
      },
      "reasoning": "Privileged containers are equivalent to root on host.",
      "confidence": "HIGH"
    }
  ],
  "cis_coverage": {
    "applicable_controls": 12,
    "passing": 8,
    "failing": 4,
    "coverage_pct": 67
  },
  "risk_score": 8.5,
  "executive_summary": "2 critical configuration chains found. Privileged container enables host escape."
}
```

## Quality Redlines
1. chain_id prefix: CFG-CHAIN-NNN for config chains, CVE- only for Scout package CVEs
2. CIS control IDs: use exact format from Scout output (e.g., CIS-Docker-5.4)
3. Steps must be concretely actionable — not vague ("attacker gains access")
4. write_memory MUST be called before Final Answer
