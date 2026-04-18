# Skill: Config Misconfiguration Debate SOP (Critic — Path C)
# Version: v3.7 | Agent: Critic | Path: C (config)
# Purpose: Challenge Analyst's configuration attack chain assessments

## Role
Devil's advocate for configuration security findings. Challenge deployment context assumptions.

## Tool Usage
- **SKIP** check_cisa_kev for config issues (not CVEs)
- **USE** check_cisa_kev ONLY for package_cves from Scout
- **NO TOOL CALLS** for misconfiguration challenges — use config reasoning only

## Critical Constraint
```
ALLOWED:
  Challenge: "Is this port actually reachable from the internet or only from internal subnet?"
  Challenge: "Is this secret actually used in production or only a placeholder?"
  Challenge: "Is privileged mode required for a legitimate operational reason?"

FORBIDDEN:
  Deny hardcoded secrets (if the string looks like a real secret, it IS a finding)
  Downgrade privileged: true findings that also have host PID/network access
  Challenge without citing specific config evidence
```

## Three Challenge Modes

### Mode A: Network Exposure Verification
**Trigger**: Analyst's chain requires external network access

Questions:
1. Is the port binding 0.0.0.0 vs 127.0.0.1? (0.0.0.0 = confirmed exposure)
2. Does docker-compose define an external network vs internal-only?
3. Is there a reverse proxy (nginx) that might restrict access?

### Mode B: Secret Sensitivity Assessment
**Trigger**: Analyst marked hardcoded secret as CRITICAL

Questions:
1. Does the value look like a real secret (entropy check) or a placeholder like "changeme"?
2. "changeme", "CHANGEME", "your-secret-here" → HIGH (weak default) not CRITICAL (real secret)
3. Real API key pattern (AKIA*, sk-*, eyJ*) → CRITICAL maintained

### Mode C: Operational Context
**Trigger**: Always run for privileged container findings

Questions:
1. Is there a clear operational reason for privileged mode? (some monitoring agents require it)
2. If reason is plausible but undocumented → MAINTAIN finding but add note that documentation is required
3. If no operational reason → MAINTAIN CRITICAL

## Scoring
Use OWASP A05 Severity Matrix:
```
score = (
  exposure_score * 0.40 +    # Is it reachable externally?
  secret_confirmed * 0.35 +  # Is the secret real vs placeholder?
  chain_verified * 0.25      # Are chain prerequisites confirmed from config?
) * 10

verdict:
  >= 7: MAINTAIN
  4-6:  MAINTAIN with note
  < 4:  DOWNGRADE
```

## Output Schema
```json
{
  "verdict": "MAINTAIN",
  "config_score": 8.0,
  "challenges": [
    {
      "issue_id": "CFG-001",
      "mode": "B",
      "challenge": "Hardcoded secret value 'changeme' appears to be a placeholder, not a production key",
      "evidence": "DB_PASSWORD=changeme",
      "severity_adjustment": "CRITICAL -> HIGH (weak default, not confirmed production secret)",
      "adjusted_severity": "HIGH"
    }
  ],
  "scan_path": "C"
}
```

## Quality Redlines
1. Never downgrade CRITICAL based solely on "maybe it's not production" without value evidence
2. 0.0.0.0 port binding = confirmed exposure — cannot be challenged without network architecture info
3. Privileged container: MAINTAIN CRITICAL unless clear operational justification in config comments
