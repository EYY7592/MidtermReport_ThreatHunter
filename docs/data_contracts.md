# ThreatHunter JSON 資料契約

> 定義每個 Agent 的輸入輸出 JSON 格式。  
> 來源：FINAL_PLAN.md §六  
> 版本：v3.1（新增 L0 淨化、Orchestrator 任務計畫、Security Guard、Intel Fusion 格式）


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
  "summary": {
    "total": 8,
    "new_since_last_scan": 2,
    "critical": 1,
    "high": 3,
    "medium": 3,
    "low": 1
  },
  "_degraded": false,
  "_error": null
}
```

**欄位說明：**

| 欄位 | 類型 | 必填 | 說明 |
|---|---|---|---|
| `scan_id` | string | ✅ | 掃描唯一識別符 |
| `timestamp` | string | ✅ | ISO 8601 時間戳 |
| `tech_stack` | string[] | ✅ | 技術堆疊清單 |
| `vulnerabilities` | array | ✅ | 漏洞清單 |
| `vulnerabilities[].cve_id` | string | ✅ | CVE 編號 |
| `vulnerabilities[].package` | string | ✅ | 套件名稱 |
| `vulnerabilities[].cvss_score` | number | ✅ | CVSS 分數（0-10） |
| `vulnerabilities[].severity` | string | ✅ | CRITICAL/HIGH/MEDIUM/LOW |
| `vulnerabilities[].description` | string | ✅ | 漏洞描述 |
| `vulnerabilities[].is_new` | bool | ✅ | 是否為新發現 |
| `summary.total` | number | ✅ | 漏洞總數 |
| `summary.new_since_last_scan` | number | ✅ | 新增漏洞數 |
| `summary.critical` | number | ✅ | CRITICAL 數量 |
| `summary.high` | number | ✅ | HIGH 數量 |
| `_degraded` | bool | ❌ | 是否為降級輸出 |
| `_error` | string/null | ❌ | 錯誤訊息（降級時） |

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
  ],
  "_degraded": false,
  "_error": null
}
```

**欄位說明：**

| 欄位 | 類型 | 必填 | 說明 |
|---|---|---|---|
| `scan_id` | string | ✅ | 掃描唯一識別符 |
| `risk_score` | number | ✅ | 風險分數（0-100） |
| `risk_trend` | string | ✅ | 風險趨勢（"+7", "-3", "+0"） |
| `analysis` | array | ✅ | 分析結果清單 |
| `analysis[].cve_id` | string | ✅ | CVE 編號 |
| `analysis[].original_cvss` | number | ✅ | 原始 CVSS 分數 |
| `analysis[].adjusted_risk` | string | ✅ | 調整後風險等級 |
| `analysis[].in_cisa_kev` | bool | ✅ | 是否在 CISA KEV 中 |
| `analysis[].exploit_available` | bool | ✅ | 是否有公開 Exploit |
| `analysis[].chain_risk` | object | ✅ | 連鎖風險 |
| `chain_risk.is_chain` | bool | ✅ | 是否形成連鎖 |
| `chain_risk.chain_with` | string[] | ✅ | 連鎖的 CVE 清單 |
| `chain_risk.chain_description` | string | ✅ | 連鎖描述 |
| `chain_risk.confidence` | string | ✅ | HIGH/MEDIUM/NEEDS_VERIFICATION |
| `analysis[].reasoning` | string | ✅ | 推理依據 |

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
  "verdict": "MAINTAIN",
  "reasoning": "Evidence is strong, chain analysis is well-supported.",
  "generated_at": "2026-04-01T10:05:00Z",
  "_harness_skipped": false
}
```

**欄位說明：**

| 欄位 | 類型 | 必填 | 說明 |
|---|---|---|---|
| `debate_rounds` | number | ✅ | 辯論輪數 |
| `challenges` | string[] | ✅ | 挑戰清單 |
| `scorecard` | object | ✅ | 5 維評分卡 |
| `scorecard.evidence` | number | ✅ | 證據支持度（0-1） |
| `scorecard.chain_completeness` | number | ✅ | 路徑完整性（0-1） |
| `scorecard.critique_quality` | number | ✅ | 反駁品質（0-1） |
| `scorecard.defense_quality` | number | ✅ | 回應品質（0-1） |
| `scorecard.calibration` | number | ✅ | 信心校準（0-1） |
| `weighted_score` | number | ✅ | 加權總分（0-100） |
| `verdict` | string | ✅ | MAINTAIN/DOWNGRADE/SKIPPED |
| `reasoning` | string | ✅ | 裁決理由 |
| `generated_at` | string | ✅ | ISO 8601 時間戳 |

**裁決規則：**
- weighted_score ≥ 50 → MAINTAIN
- weighted_score < 50 → DOWNGRADE
- 有 CVE 在 CISA KEV 中 → 禁止 DOWNGRADE

---

## Advisor → UI

```json
{
  "executive_summary": "1 actively exploited chain. Risk increased.",
  "actions": {
    "urgent": [
      {
        "cve_id": "CVE-2024-XXXX",
        "package": "django",
        "severity": "CRITICAL",
        "action": "Update Django to latest patched version.",
        "command": "pip install --upgrade django",
        "reason": "In CISA KEV with public exploit.",
        "is_repeated": false
      }
    ],
    "important": [
      {
        "cve_id": "CVE-2024-YYYY",
        "package": "redis",
        "severity": "HIGH",
        "action": "Update Redis and verify network exposure.",
        "reason": "Part of attack chain."
      }
    ],
    "resolved": []
  },
  "risk_score": 85,
  "risk_trend": "+7",
  "scan_count": 2,
  "generated_at": "2026-04-01T10:06:00Z"
}
```

**欄位說明：**

| 欄位 | 類型 | 必填 | 說明 |
|---|---|---|---|
| `executive_summary` | string | ✅ | 一句話摘要 |
| `actions` | object | ✅ | 行動清單 |
| `actions.urgent` | array | ✅ | 緊急行動 |
| `actions.urgent[].cve_id` | string | ✅ | CVE 編號 |
| `actions.urgent[].package` | string | ✅ | 套件名稱 |
| `actions.urgent[].severity` | string | ✅ | CRITICAL/HIGH |
| `actions.urgent[].action` | string | ✅ | 修補說明 |
| `actions.urgent[].command` | string | ✅ | 具體指令 |
| `actions.urgent[].reason` | string | ✅ | 為何標記為 URGENT |
| `actions.urgent[].is_repeated` | bool | ✅ | 是否重複未修補 |
| `actions.important` | array | ✅ | 重要行動 |
| `actions.resolved` | array | ✅ | 已修補項目 |
| `risk_score` | number | ✅ | 風險分數（0-100） |
| `risk_trend` | string | ✅ | 風險趨勢 |
| `scan_count` | number | ✅ | 掃描次數 |
| `generated_at` | string | ✅ | ISO 8601 時間戳 |

---

## Pipeline Meta（最終輸出附加欄位）

```json
{
  "pipeline_meta": {
    "pipeline_version": "3.0",
    "tech_stack": "Django 4.2, Redis 7.0",
    "stages_completed": 4,
    "stages_detail": {
      "scout": {
        "status": "SUCCESS",
        "vuln_count": 9,
        "duration_ms": 1200
      },
      "analyst": {
        "status": "SUCCESS",
        "risk_score": 85,
        "duration_ms": 800
      },
      "critic": {
        "status": "SUCCESS",
        "verdict": "MAINTAIN",
        "score": 80.5,
        "duration_ms": 600
      },
      "advisor": {
        "status": "SUCCESS",
        "urgent_count": 2,
        "duration_ms": 500
      }
    },
    "enable_critic": false,
    "critic_verdict": "SKIPPED",
    "critic_score": 0,
    "duration_seconds": 3.1,
    "degradation": {
      "level": 1,
      "label": "⚡ 全速運行",
      "degraded_components": [],
      "timestamp": "2026-04-01T10:06:00Z"
    },
    "generated_at": "2026-04-01T10:06:00Z"
  }
}
```

**欄位說明：**

| 欄位 | 類型 | 必填 | 說明 |
|---|---|---|---|
| `pipeline_version` | string | ✅ | Pipeline 版本（當前 3.0） |
| `tech_stack` | string | ✅ | 使用者輸入的技術堆疊 |
| `stages_completed` | number | ✅ | 完成的 Stage 數量 |
| `stages_detail` | object | ✅ | 每個 Stage 的詳細資訊 |
| `stages_detail.{stage}.status` | string | ✅ | SUCCESS/DEGRADED |
| `enable_critic` | bool | ✅ | Critic 是否啟用 |
| `critic_verdict` | string | ✅ | MAINTAIN/DOWNGRADE/SKIPPED |
| `critic_score` | number | ✅ | Critic 加權分數 |
| `duration_seconds` | number | ✅ | 總執行時間（秒） |
| `degradation` | object | ✅ | 降級狀態 |
| `degradation.level` | number | ✅ | 1-5（1=全速，5=最低生存） |
| `degradation.label` | string | ✅ | UI 顯示文字 |
| `degradation.degraded_components` | string[] | ✅ | 降級元件清單 |

**降級層級定義：**

| 層級 | 標籤 | 觸發條件 |
|---|---|---|
| 1 | ⚡ 全速運行 | 所有元件正常 |
| 2 | ⚠️ LLM 降級 | vLLM → OpenRouter → OpenAI |
| 3 | ⚠️ API 降級 | NVD/OTX → 離線快取 |
| 4 | 🔶 Agent 降級 | Analyst/Critic 跳過 |
| 5 | 🔶 最低生存模式 | 使用上次掃描結果 |

---

## v3.1 新增：L0 淨化報告（input_sanitizer → Pipeline）

```json
{
  "safe": true,
  "input_type": "source_code",
  "truncated": false,
  "input_hash": "a3f8b1c2d4e5f6a7",
  "blocked_reason": "",
  "l0_findings": [
    {
      "pattern": "hardcoded_secret",
      "description": "硬編碼憑證（Credential Exposure 風險）",
      "line_no": 42,
      "severity": "WARNING"
    }
  ],
  "l0_warning_count": 1
}
```

**`input_type` 枚舉**：`"package_list"` / `"source_code"` / `"config_file"` / `"blocked"`  
**`safe=false`** 時 Pipeline 直接返回錯誤，不進入任何 Agent

---

## v3.1 新增：Orchestrator 任務計畫（orchestrator → main.py）

```json
{
  "path": "B",
  "parallel_layer1": ["security_guard", "intel_fusion"],
  "agents_to_run": ["security_guard", "intel_fusion", "scout", "analyst", "debate", "advisor"],
  "shortcuts": [],
  "feedback_loop_count": 0,
  "l0_input_type": "source_code"
}
```

**`path` 枚舉**：`"A"` 套件 / `"B"` 完整程式碼 / `"C"` 配置文件 / `"D"` 回饋補充

---

## v3.1 新增：Security Guard 輸出（security_guard → scout）

```json
{
  "extraction_status": "success",
  "functions": [
    {"name": "execute_query", "args": ["sql"], "line_no": 15, "suspicious": true, "reason": "字串拼接"}
  ],
  "imports": [{"module": "os", "alias": null, "line_no": 1}],
  "patterns": [{"type": "sql_concat", "pattern": "f\"SELECT...\"", "line_no": 23, "severity": "HIGH"}],
  "hardcoded": [{"type": "api_key", "key_name": "AWS_SECRET", "line_no": 8}],
  "stats": {"total_lines": 150, "functions_found": 12, "patterns_found": 3}
}
```

---

## v3.1 新增：Intel Fusion 輸出（intel_fusion → scout）

```json
{
  "fusion_results": [
    {
      "cve_id": "CVE-2024-42005",
      "composite_score": 9.1,
      "confidence": "HIGH",
      "dimensions": {
        "nvd_cvss": 9.8, "epss_score": 0.97,
        "in_kev": true, "ghsa_hits": 3,
        "attack_techniques": 2, "otx_pulse_count": 5
      },
      "weights_used": {"nvd": 0.20, "epss": 0.00, "kev": 0.55, "ghsa": 0.10, "attack": 0.10, "otx": 0.05},
      "kev_shortcut": true,
      "cve_year": 2024
    }
  ],
  "api_health": {"epss": "ok", "ghsa": "ok", "otx": "degraded"},
  "degraded": false
}
```

**動態加權規則**：
- `in_kev=true` → `epss_weight=0.00`，`kev_weight` 增至 0.55
- `cve_year < 2020` → `epss_weight=0.10`
- `otx_fail_rate > 0.5` → `otx_weight=0.01`

---

## v3.1 更新：Pipeline Meta 完整欄位

```json
{
  "pipeline_meta": {
    "pipeline_version": "3.1",
    "tech_stack": "Django 4.2, Redis 7.0",
    "stages_completed": 7,
    "stages_detail": {
      "orchestrator": {"status": "SUCCESS", "scan_path": "B", "l0_input_type": "source_code"},
      "security_guard": {"status": "SUCCESS", "functions_found": 12},
      "intel_fusion": {"status": "SUCCESS", "cves_scored": 2},
      "scout": {"status": "SUCCESS", "vuln_count": 2},
      "analyst": {"status": "SUCCESS", "risk_score": 85},
      "critic": {"status": "SUCCESS", "verdict": "MAINTAIN"},
      "advisor": {"status": "SUCCESS", "urgent_count": 1}
    },
    "enable_critic": true,
    "critic_verdict": "MAINTAIN",
    "critic_score": 80.5,
    "duration_seconds": 45.2,
    "degradation": {"level": 1, "label": "FULL_SPEED"},
    "generated_at": "2026-04-10T00:02:00Z",
    "l0_report": {"safe": true, "input_type": "source_code", "l0_warning_count": 0}
  }
}
```

| v3.1 新增欄位 | 說明 |
|---|---|
| `stages_detail.orchestrator` | Orchestrator 路徑 + L0 類型 |
| `stages_detail.security_guard` | Security Guard 提取統計 |
| `stages_detail.intel_fusion` | Intel Fusion 計分統計 |
| `stages_completed` | 現在包含 orchestrator + 4 主 Stage（≥ 5）|
| `l0_report` | L0 淨化報告摘要 |
