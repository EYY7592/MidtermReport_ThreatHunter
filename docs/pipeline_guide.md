# ThreatHunter Pipeline 執行手冊

> **版本**：v1.0  
> **日期**：2026-04-06  
> **適用對象**：開發者、維運人員

---

## 一、Pipeline 架構

### 1.1 整體流程

```
使用者輸入
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  main.py: run_pipeline(tech_stack)                   │
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐          │
│  │  Scout   │─▶│ Analyst  │─▶│  Critic  │──┐       │
│  │(事實收集) │  │(推理判斷) │  │(可插拔)  │  │       │
│  └──────────┘  └──────────┘  └──────────┘  │       │
│                              ┌──────────────▼──┐    │
│                              │    Advisor      │    │
│                              │  (最終裁決報告)  │    │
│                              └─────────────────┘    │
└─────────────────────────────────────────────────────┘
    │
    ▼
最終 JSON 報告 + pipeline_meta
```

### 1.2 設計哲學

**為什麼不用純 CrewAI Sequential？**

根據 CrewAI 官方文檔：*"For any production-ready application, start with a Flow."*

本專案採用 **Pipeline + Crew 內部化** 架構：
- 每個 Stage 內部使用 CrewAI Crew（Agent 自主推理）
- Stage 之間由 Python 程式碼串接（精確控制、錯誤隔離）
- 保留 17 層 Harness 保障層（程式碼層驗證）

詳細分析請參考 `.opencode/plans/integration_plan.md`。

---

## 二、各 Stage 詳細說明

### Stage 1：Scout Agent（事實收集）

**職責**：從公開漏洞資料庫收集指定技術堆疊的已知漏洞。

| 項目 | 說明 |
|---|---|
| 輸入 | `tech_stack`（字串，如 "Django 4.2, Redis 7.0"） |
| 輸出 | Scout JSON（scan_id, vulnerabilities[], summary） |
| Tools | search_nvd, search_otx, read_memory, write_memory, history_search |
| Skill | `skills/threat_intel.md` |
| Harness | 5 層（強制 write_memory、Schema 驗證、CVE 真實性、package 補全、is_new 校正） |

**執行流程**：
1. 讀取歷史記憶（read_memory）
2. 對每個套件查詢 NVD（search_nvd）
3. 對高危 CVE 查詢 OTX 威脅情報（search_otx）
4. 比對歷史標記 is_new
5. 寫入記憶（write_memory）
6. 程式碼層 CVE 真實性驗證（反查 NVD API）
7. 校正 is_new 標記
8. 輸出 JSON

**Graceful Degradation**：
- NVD API 失敗 → 使用離線快取（data/nvd_cache/）
- 全部失敗 → 回傳空 vulnerabilities 清單，管線繼續

---

### Stage 2：Analyst Agent（推理判斷）

**職責**：驗證 KEV 和 Exploit 狀態，分析漏洞連鎖攻擊路徑。

| 項目 | 說明 |
|---|---|
| 輸入 | Scout 輸出（dict） |
| 輸出 | Analyst JSON（scan_id, risk_score, risk_trend, analysis[]） |
| Tools | check_cisa_kev, search_exploits, read_memory, write_memory, history_search |
| Skill | `skills/chain_analysis.md` |
| Harness | 4 層（強制 write_memory、Schema 驗證、chain_risk 邏輯、風險禁止降級） |

**執行流程**（3-Task 拆分架構）：
1. **Collector**：讀取歷史 + 解析 Scout JSON
2. **Verifier**：KEV 驗證 + Exploit 搜尋 + Chain 分析
3. **Scorer**：風險計算 + 寫入記憶 + 輸出 JSON

**風險計算公式**：
```
risk_score = min(100, Σ(cvss_score × weight))
weight: CRITICAL=3, HIGH=2, MEDIUM=1, LOW=0.5
```

**風險禁止降級規則**：
- adjusted_risk 只能升級，不能降級
- 如果 Agent 試圖降級，Harness Layer 4 強制修正

**Graceful Degradation**：
- LLM 輸出無法解析 → 使用 Fallback 輸出
- chain_risk 欄位缺失 → 自動補充預設值

---

### Stage 3：Critic Agent（質疑挑戰，可插拔）

**職責**：對抗式辯論，挑戰 Analyst 的主觀判斷。

| 項目 | 說明 |
|---|---|
| 輸入 | Analyst 輸出（dict） |
| 輸出 | Critic JSON（debate_rounds, challenges[], scorecard, verdict） |
| 開關 | `ENABLE_CRITIC` 環境變數（預設 false） |
| Tools | check_cisa_kev, search_exploits, read_memory |
| Skill | `skills/debate_sop.md` |
| Harness | 3 層（SKIPPED/fallback、Schema+scorecard 修復、verdict 枚舉+型別安全） |

**辯論流程**（參考李宏毅論文 LLM Discussion Framework）：
1. 挑戰 Analyst 的連鎖推理前提
2. 使用 Tool 驗證前提條件
3. 計算 5 維評分卡（證據 30%、路徑完整性 25%、反駁品質 20%、回應品質 15%、信心校準 10%）
4. 裁決：MAINTAIN（≥50 分）或 DOWNGRADE（<50 分）

**裁決規則**：
- weighted_score ≥ 50 → MAINTAIN
- weighted_score < 50 → DOWNGRADE
- 有 CVE 在 CISA KEV 中 → 禁止 DOWNGRADE

**為什麼可插拔？**
- 辯論是「增強項」，不是「核心依賴」
- Demo 時可展示完整辯論，平時關閉節省 Token

---

### Stage 4：Advisor Agent（最終裁決）

**職責**：產出可執行的資安行動報告。

| 項目 | 說明 |
|---|---|
| 輸入 | Analyst 輸出 + Critic 裁決（dict） |
| 輸出 | Advisor JSON（executive_summary, actions{}, risk_score, risk_trend） |
| Tools | read_memory, write_memory, history_search |
| Skill | `skills/action_report.md` |
| Harness | 5 層（強制 write_memory、Schema 驗證、SOP 邏輯、risk_score 範圍、command 確保、歷史比對） |

**分級規則**：
- **URGENT**：CVSS ≥ 9.0 或在 CISA KEV 中或有公開 PoC
- **IMPORTANT**：CVSS ≥ 7.0 或有攻擊鏈風險
- **RESOLVED**：已修補的歷史漏洞

**每個 URGENT 項目必須附帶**：
- `command`：具體修補指令（如 `pip install --upgrade django`）
- `reason`：為何標記為 URGENT
- `is_repeated`：是否為重複未修補項目

**歷史比對（Harness Layer 5）**：
- 讀取 advisor_memory.json
- 如果 CVE 曾在歷史中出現且未 resolved → is_repeated=True
- 語氣遞升："[REPEATED — STILL NOT PATCHED] ..."

---

## 三、錯誤處理機制

### 3.1 每個 Stage 的獨立 try-except

```python
try:
    result = run_*_pipeline(input)
    return result, sl  # 成功
except Exception as e:
    degradation_status.degrade("StageName", str(e))
    return fallback_output, sl  # 降級
```

### 3.2 降級狀態追蹤

```python
degradation_status.to_dict()
# {
#   "level": 1,           # 1=全速, 2=LLM降級, 3=API降級, 4=Agent降級, 5=最低生存
#   "label": "⚡ 全速運行",
#   "degraded_components": ["Scout: NVD API timeout"],
#   "timestamp": "2026-04-06T..."
# }
```

### 3.3 五層降級瀑布

| 層級 | 狀態 | 觸發條件 |
|---|---|---|
| 1 | ⚡ 全速運行 | 所有元件正常 |
| 2 | ⚠️ LLM 降級 | vLLM → OpenRouter → OpenAI |
| 3 | ⚠️ API 降級 | NVD/OTX → 離線快取 |
| 4 | 🔶 Agent 降級 | Analyst/Critic 跳過 |
| 5 | 🔶 最低生存模式 | 使用上次掃描結果 |

---

## 四、Observability 日誌

### 4.1 StepLogger 原子步驟

每個 Stage 的執行都會記錄：

```json
{
  "step": "COMPLETE",
  "agent": "scout",
  "timestamp": "2026-04-06T10:00:00Z",
  "status": "SUCCESS",
  "detail": "found 9 vulnerabilities",
  "duration_ms": 1200
}
```

### 4.2 pipeline_meta 完整資訊

最終輸出的 `pipeline_meta` 包含：

```json
{
  "pipeline_version": "3.0",
  "tech_stack": "Django 4.2, Redis 7.0",
  "stages_completed": 4,
  "stages_detail": {
    "scout": {"status": "SUCCESS", "vuln_count": 9, "duration_ms": 1200},
    "analyst": {"status": "SUCCESS", "risk_score": 85, "duration_ms": 800},
    "critic": {"status": "SUCCESS", "verdict": "MAINTAIN", "score": 80.5, "duration_ms": 600},
    "advisor": {"status": "SUCCESS", "urgent_count": 2, "duration_ms": 500}
  },
  "enable_critic": false,
  "critic_verdict": "SKIPPED",
  "critic_score": 0,
  "duration_seconds": 3.1,
  "degradation": {"level": 1, "label": "⚡ 全速運行"},
  "generated_at": "2026-04-06T..."
}
```

---

## 五、資料契約

### 5.1 Scout → Analyst

```json
{
  "scan_id": "scan_20260406_001",
  "timestamp": "ISO 8601",
  "tech_stack": ["django 4.2", "redis 7.0"],
  "vulnerabilities": [{"cve_id", "package", "cvss_score", "severity", "description", "is_new"}],
  "summary": {"total", "new_since_last_scan", "critical", "high", "medium", "low"}
}
```

### 5.2 Analyst → Advisor

```json
{
  "scan_id": "scan_20260406_001",
  "risk_score": 85,
  "risk_trend": "+10",
  "analysis": [{"cve_id", "original_cvss", "adjusted_risk", "in_cisa_kev", "exploit_available", "chain_risk", "reasoning"}]
}
```

### 5.3 Advisor → UI

```json
{
  "executive_summary": "...",
  "actions": {
    "urgent": [{"cve_id", "package", "severity", "action", "command", "reason", "is_repeated"}],
    "important": [{"cve_id", "package", "severity", "action", "reason"}],
    "resolved": []
  },
  "risk_score": 85,
  "risk_trend": "+10",
  "scan_count": 1,
  "generated_at": "ISO 8601"
}
```

---

## 六、記憶系統

### 6.1 雙層記憶架構

| 層級 | 儲存方式 | 用途 | 冷啟動 |
|---|---|---|---|
| Layer 1 | JSON 檔案 | 精確取得上次結果 | 回傳 {}，不崩潰 |
| Layer 2 | LlamaIndex 向量索引 | 語義搜尋歷史案例 | 0 文件時跳過 |

### 6.2 記憶檔案位置

```
memory/
├── scout_memory.json      # Scout 的掃描歷史
├── analyst_memory.json    # Analyst 的分析歷史
├── advisor_memory.json    # Advisor 的建議歷史
└── vector_store/          # LlamaIndex 向量索引
```

### 6.3 寫入時機

每個 Agent 在給出 Final Answer 之前，必須先呼叫 `write_memory`。
如果 Agent 忘記呼叫，Harness Layer 1 會強制代為執行。

---

*本文件與 `docs/quickstart.md` 搭配使用。*

## 7. 向量資料庫使用邊界

本專案目前不把向量資料庫作為漏洞判斷的主要來源。比賽展示與修復建議必須能回溯到本次掃描的 JSON、Checkpoint、工具輸出與程式碼行號；這些資料是 deterministic evidence，可直接驗證與重跑。

LlamaIndex/vector_store 只保留為歷史案例語義搜尋與輔助回憶用途，不可覆蓋本次掃描結果，也不可在缺少掃描證據時自行補出 CWE/CVE 結論。原因如下：

- 可審計性：JSON 與 checkpoint 能指出哪個 Agent、哪個工具、哪一行 code 產生結論。
- 比賽可重現性：同一份輸入重跑時，主結論應來自目前 pipeline，而不是相似歷史案例。
- 避免污染：向量檢索可能召回舊專案或相似但不相同的漏洞，若直接作為主證據會造成誤報。
- 成本控制：目前資料量小，JSON + checkpoint 已足以支撐 UI、Thinking Path 與修復建議。

未來若要啟用向量資料庫作為 RAG，需要新增 evidence provenance 欄位，並在 UI 標記「retrieved historical context」，不得標記成 verified finding。

---
