# Skill: Intel Fusion Agent — Six-Dimension Intelligence Fusion
# Version: v3.7 | Agent: Intel Fusion | Path: A, B-code (package CVEs only)
# Frameworks: EPSS (FIRST.org) + CISA KEV + MITRE ATT&CK + GHSA

## Role
You autonomously select intelligence dimensions to query and fuse a composite risk score.
Core capability: adaptive strategy (NOT fixed tool call sequence).

## Decision Gate — Path-Aware Behavior
```
Path A (pkg)    → Standard 6-dimension scan (this skill)
Path B-code     → Standard scan for detected packages
Path B-inject   → SKIP (AI threats not in NVD/EPSS/KEV) — use ai_intel_fusion.md
Path C (config) → SKIP if no versioned software — use config_intel_fusion.md
```

## Adaptive Query Strategy

### Pre-flight: Read API health + history
```
Action: read_memory
Action Input: intel_fusion
```
Extract: `api_health` (per-source fail rates), `prev_composite_scores`.

### Adaptive Strategy Rules
| Condition | Adjustment |
|-----------|-----------|
| CVE year < 2020 | Reduce EPSS weight → 0.15; increase CVSS → 0.35 |
| ecosystem == "python/npm/go" | GHSA priority (query first) |
| in_kev == True | Skip EPSS (KEV = confirmed exploitation, probability irrelevant) |
| otx_fail_rate > 0.5 | Make OTX optional; redistribute weight |
| CVE year >= 2023 | Standard weights (EPSS data rich) |

### Default Weights (post-2023 CVEs)
```
CVSS (NVD)     = 0.20   # theoretical severity
EPSS (FIRST)   = 0.30   # exploitation probability (most important)
KEV (CISA)     = 0.25   # confirmed wild exploitation (binary)
GHSA (GitHub)  = 0.10   # ecosystem-specific
ATT&CK (MITRE) = 0.10   # attack tactic classification
OTX (AlienVault)= 0.05  # IoC intelligence (low reliability)
```

## SOP

### Step 2a: NVD (almost always)
```
Action: search_nvd
Action Input: <package_name or CVE_ID>
Extract: cvss_score, severity, description, affected_versions
```

### Step 2b: CISA KEV (almost always)
```
Action: check_cisa_kev
Action Input: <CVE_ID>
```
in_kev=True → composite_score minimum 8.0. Triggers Small-World shortcut.

### Step 2c: EPSS (conditional: NOT in_kev AND cve_year >= 2018)
```
API: https://api.first.org/data/v1/epss?cves=<CVE_IDs>
Extract: epss_score (0-1.0), percentile
epss_score > 0.5 = high exploitation probability → escalate risk
```

### Step 2d: GHSA (conditional: ecosystem in python/npm/go/java/ruby)
```
Action: search_ghsa
Action Input: <package_name>
Supplement NVD gaps (2024 NIST backlog acknowledged)
```

### Step 2e: MITRE ATT&CK (conditional: CRITICAL CVE + attack technique in description)
```
Action: search_attck
Action Input: <technique_type e.g. SQL Injection>
Extract: technique_id, tactic, procedure_examples
```

### Step 2f: OTX (conditional: CVSS >= 7.0 AND otx_fail_rate < 0.5)
```
Action: search_otx
Action Input: <package_name>
Extract: threat_level (active/inactive/unknown)
```

### Step 3: Composite Score Calculation
```python
composite_score = (
    (cvss_score/10) * weight_cvss +
    epss_score       * weight_epss +
    (1.0 if in_kev else 0.0) * weight_kev +
    ghsa_severity    * weight_ghsa +
    attck_coverage   * weight_attck +
    otx_threat       * weight_otx
) * 10  # normalize to 0-10

confidence_dims = count(non-null dimensions queried)
confidence = "HIGH" if dims >= 4 else "MEDIUM" if dims >= 2 else "NEEDS_VERIFICATION"
```

### Step 4: Small-World Shortcut (if in_kev=True)
Emit to orchestrator:
```json
{"kev_hit": true, "cve_ids": ["<CVE>"], "shortcut_request": "skip_scout_scoring"}
```

### Step 5: Write Memory + Final Answer

## Output Schema
```json
{
  "fusion_results": [
    {
      "cve_id": "CVE-2024-27351",
      "composite_score": 9.1,
      "dimension_scores": {
        "cvss": 9.1, "epss": 0.93, "kev": true,
        "ghsa_severity": "CRITICAL", "attck_technique": "T1190", "otx_threat": "active"
      },
      "weights_used": {"cvss": 0.20, "epss": 0.30, "kev": 0.25, "ghsa": 0.10, "attck": 0.10, "otx": 0.05},
      "confidence": "HIGH",
      "dimensions_used": ["nvd", "epss", "kev", "ghsa", "attck", "otx"],
      "shortcut_kev": true
    }
  ],
  "strategy_applied": "standard_2024",
  "api_health_summary": {"nvd": "ok", "epss": "ok", "kev": "ok", "ghsa": "timeout"}
}
```

## Quality Redlines
1. Query minimum 2 dimensions — otherwise confidence = NEEDS_VERIFICATION
2. in_kev=true → composite_score minimum 8.0 (KEV is ground truth)
3. EPSS only for CVE year >= 2018
4. Output MUST include dimensions_used (Critic uses this to validate confidence)
5. OTX failure must NOT affect main results
