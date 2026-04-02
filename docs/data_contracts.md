# ThreatHunter JSON 資料契約

> 定義每個 Agent 的輸入輸出 JSON 格式。
> 來源：FINAL_PLAN.md §八

---

## Scout → Analyst

```json
{
  "scan_id": "scan_20260401_001",
  "timestamp": "2026-04-01T10:00:00Z",
  "tech_stack": ["django 4.2", "redis 7.0"],
  "vulnerabilities": [
    {
      "cve_id": "CVE-2024-XXXX",
      "package": "django",
      "cvss_score": 7.5,
      "severity": "HIGH",
      "description": "...",
      "is_new": true
    }
  ],
  "summary": { "total": 8, "new": 2, "critical": 1, "high": 3 }
}
```

---

## Analyst → Advisor

```json
{
  "scan_id": "scan_20260401_001",
  "risk_score": 85,
  "risk_trend": "+7",
  "analysis": [
    {
      "cve_id": "CVE-2024-XXXX",
      "original_cvss": 6.5,
      "adjusted_risk": "CRITICAL",
      "in_cisa_kev": true,
      "exploit_available": true,
      "chain_risk": {
        "is_chain": true,
        "chain_with": ["CVE-2024-YYYY"],
        "chain_description": "SSRF → Redis → RCE",
        "confidence": "HIGH"
      },
      "reasoning": "In CISA KEV + public exploit + chains with Redis"
    }
  ]
}
```

---

## Advisor → UI

```json
{
  "executive_summary": "1 actively exploited chain. Risk increased.",
  "actions": {
    "urgent": [{ "cve_id": "...", "action": "...", "command": "..." }],
    "important": [{ "cve_id": "...", "action": "..." }],
    "resolved": [{ "cve_id": "...", "resolved_date": "..." }]
  },
  "risk_score": 85,
  "risk_trend": "+7",
  "scan_count": 2
}
```

---

## Critic 辯論結果

```json
{
  "debate_rounds": 2,
  "challenges": ["Redis 暴露前提未驗證"],
  "scorecard": {
    "evidence": 0.85,
    "chain_completeness": 0.80,
    "critique_quality": 0.75,
    "defense_quality": 0.70,
    "calibration": 0.90
  },
  "weighted_score": 80.5,
  "verdict": "MAINTAIN"
}
```
