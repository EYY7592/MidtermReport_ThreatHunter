# ThreatHunter Agent 本質說明書

> **版本**：v1.0 | **更新日期**：2026-04-23  
> **用途**：給團隊成員理解每個 Agent 本質上在做什麼

---

## 總覽：Pipeline 資料流

```
使用者輸入（程式碼 / 套件 / 設定檔）
       │
       ▼
┌──────────────────┐
│   Orchestrator   │ ← 指揮官：決定走哪條路（A/B/C/D）、誰要上場
└──────┬───────────┘
       │ 並行 Layer 1
       ▼
┌──────────────┐  ┌───────────────┐  ┌──────────────────┐
│Security Guard│  │ Intel Fusion  │  │ L0/L1 Scanner    │
│（程式碼消毒） │  │（六維情報融合）│  │（正則預掃描）     │
└──────┬───────┘  └───────┬───────┘  └────────┬─────────┘
       │                  │                   │
       └──────────┬───────┘───────────────────┘
                  ▼
          ┌──────────────┐
          │    Scout     │ ← 偵察兵：組裝最終漏洞清單，重用 Intel Fusion 情報
          └──────┬───────┘
                 ▼
          ┌──────────────┐
          │   Analyst    │ ← 分析師：KEV 驗證 + 連鎖攻擊分析
          └──────┬───────┘
                 ▼
          ┌──────────────┐
          │ Debate Engine│ ← 辯論：Analyst vs Critic（最多 3 輪）
          │  + Critic    │
          │  + Judge     │
          └──────┬───────┘
                 ▼
          ┌──────────────┐
          │   Advisor    │ ← 顧問：產出可執行的行動報告
          └──────────────┘
                 │
                 ▼
              UI 顯示
```

---

## 1. Orchestrator（指揮官）

| 項目 | 說明 |
|------|------|
| **檔案** | `agents/orchestrator.py` (518 行) |
| **本質** | **不用 LLM 做推理的確定性路由器**。根據輸入類型決定走哪條路、跳過哪些 Agent、走哪些捷徑 |
| **LLM 使用** | 幾乎不用。路由邏輯全是 if/else 確定性程式碼 |
| **核心函式** | `classify_input()` → 決定 Path A/B/C/D |
| | `check_shortcuts()` → MacNet Small-World 捷徑 |
| | `review_worker_output()` → 審閱各 Agent 輸出品質 |

### 四條掃描路徑

| 路徑 | 觸發條件 | 啟動的 Agent |
|------|---------|-------------|
| **A** 套件掃描 | 輸入只有 `package==version` | Intel Fusion → Scout → Analyst → Debate → Judge |
| **B** 完整程式碼 | 有 `def`/`class` 等程式碼 | Security Guard + Intel Fusion + L0 → Scout → Analyst → Debate → Judge |
| **C** 文件掃描 | `.env`/`.yaml` 等設定檔 | Doc Scanner + Intel Fusion → Scout → Judge |
| **D** 回饋迴路 | Judge 信心不足時觸發 | Intel Fusion → Analyst → Debate → Judge（最多 2 次） |

### Small-World 捷徑（省 Token 機制）

| 捷徑 | 觸發條件 | 效果 |
|------|---------|------|
| `kev_to_analyst_direct` | CISA KEV 命中 | 跳過 Scout 重新評分 |
| `skip_l2_llm` | L0 正則零發現 | 跳過 L2 LLM 分析 |
| `debate_phase2_skipped` | 辯論第一輪就共識 | 省 6 次 LLM 呼叫 |
| `skip_debate_all_low` | 全部 CVSS < 4.0 | 跳過整個辯論 |

---

## 2. Security Guard（程式碼消毒員）

| 項目 | 說明 |
|------|------|
| **檔案** | `agents/security_guard.py` (1174 行) |
| **本質** | **完全確定性的靜態分析引擎**。用正則 + AST 從使用者程式碼中提取函式、危險模式、硬編碼密碼。**絕不使用 LLM 判斷** |
| **LLM 使用** | **零**。這是唯一完全不依賴 LLM 的 Agent |
| **設計依據** | Dual LLM Pattern (Simon Willison 2024) + OWASP LLM01:2025 |

### 核心函式：`extract_code_surface(code: str)`

**輸入**：使用者提交的原始程式碼（任何語言）  
**輸出**：結構化 JSON，包含：

```json
{
  "functions": ["eval", "exec", "os.system"],    // AST 提取的函式呼叫
  "patterns": [                                   // 正則匹配的危險模式
    {"type": "CMD_INJECTION", "cwe": "CWE-78", "severity": "CRITICAL", "snippet": "os.system(cmd)"}
  ],
  "hardcoded": [                                  // 硬編碼密碼/金鑰
    {"type": "HARDCODED_SECRET", "snippet": "api_key = 'sk-xxx'"}
  ],
  "language": "python",                           // 偵測到的語言
  "stats": {"loc": 150, "function_count": 12}
}
```

### 三層偵測架構

| 層級 | 機制 | 覆蓋範圍 |
|------|------|---------|
| **L0 通用正則** | `_DANGER_UNIVERSAL` | SQL Injection、CMD Injection、Path Traversal、XXE、Hardcoded Secret、**Log4Shell JNDI** |
| **L1 語言特化** | `_DANGER_LANG[language]` | Python: Pickle/YAML/Eval/SSRF/SSTI；JS: Prototype Pollution/innerHTML；Java: Deserialization；C#: Process.Start/SqlCommand/BinaryFormatter 等 |
| **L2 AST 分析** | Python `ast.parse()` | 精確函式呼叫提取（不被字串/註解干擾） |

### 支援語言（15 種）

Python、JavaScript、TypeScript、Java、C#、PHP、Ruby、Go、Rust、C/C++、Kotlin、Swift、Scala、Bash、SQL

### 關鍵設計決策

- **為何不用 LLM？** → 防 Prompt Injection。使用者程式碼可能包含 `# Ignore all previous instructions`，如果讓 LLM 分析程式碼，LLM 可能被注入。確定性正則不受此影響。
- **Word Boundary 修補** → `(?<!\w)` lookbehind 防止 `ecosystem` 誤觸 `system\s*\(` 模式。

---

## 3. Intel Fusion（六維情報融合師）

| 項目 | 說明 |
|------|------|
| **檔案** | `agents/intel_fusion.py` (792 行) |
| **本質** | **用 LLM 自主決策要查哪些情報源**，然後用**確定性公式**計算複合風險分數 |
| **LLM 使用** | 用於決定查詢順序和解析 API 回傳；**分數計算由程式碼執行** |
| **Tools** | search_nvd、search_osv、check_cisa_kev、search_otx、fetch_epss_score、query_ghsa、read/write_memory |

### 六維評分公式

```
composite_score = (cvss×0.20 + epss×0.30 + kev×0.25 + ghsa×0.10 + attck×0.10 + otx×0.05) × 10
```

| 維度 | 來源 | 權重 | 說明 |
|------|------|------|------|
| CVSS | NVD API | 20% | 理論嚴重性（0-10） |
| EPSS | FIRST.org | 30% | 30 天內被利用的機率（0-1） |
| KEV | CISA | 25% | 已確認在野利用（二元） |
| GHSA | GitHub Advisory | 10% | 生態系專屬告警 |
| ATT&CK | MITRE | 10% | 攻擊戰術分類 |
| OTX | AlienVault | 5% | IoC 威脅情報 |

### 動態加權規則（確定性程式碼）

| 條件 | 調整 |
|------|------|
| `in_kev == True` | EPSS 降至 0（KEV 已是最高事實）→ 權重轉給 KEV |
| `cve_year < 2020` | EPSS 降至 0.10（舊漏洞 EPSS 不準）→ 權重轉給 CVSS |
| `otx_fail_rate > 0.5` | OTX 降至 0.01 → 權重轉給 CVSS |
| `in_kev && composite < 8.0` | 強制拉到 8.0（KEV 品質紅線） |

### Harness 保障

- **Layer 2**：`_verify_and_recalculate()` — LLM 算出的分數與程式碼計算差 >1.5 → 用程式碼的
- **Layer 2.5**：CVE 年份過濾 — `< 2005` 的遠古 CVE 一律濾除

---

## 4. Scout（威脅情報偵察兵）

| 項目 | 說明 |
|------|------|
| **檔案** | `agents/scout.py` (794 行) |
| **本質** | **Pipeline 第一個 LLM Agent**。彙整 OSV/NVD 與 Layer 1 情報，產出最終 `vulnerabilities[]` 與 scan-scoped 結果 |
| **LLM 使用** | 使用 LLM 決定查詢順序、解析 API 回傳、合併 Intel Fusion 證據並組裝 JSON 報告 |
| **Tools** | search_osv（主力）、search_nvd（備用）、read/write_memory、history_search |

### 工作流程（SOP 6 步）

1. `read_memory("scout")` — 讀取歷史掃描記錄
2. 對每個套件呼叫 `search_osv()`（OSV.dev ecosystem-aware）→ 無結果則 fallback `search_nvd()`
3. 若 Layer 1 已提供 `intel_fusion_result`，優先重用其 EPSS / OTX / KEV / GHSA 富化證據，不重複查詢
4. 組裝 JSON 報告（CVE ID 必須來自 API，絕不可編造）
5. `write_memory("scout")` — 儲存本次結果
6. 輸出 Final Answer（純 JSON）

### Path-Aware Skill Map

| Path | Skill 檔案 | 用途 |
|------|-----------|------|
| A (pkg) | `threat_intel.md` | NVD CVE 掃描 |
| B (code) | `source_code_audit.md` | OWASP Top10 + CWE |
| B (injection) | `ai_security_audit.md` | OWASP LLM Top10 |
| C (config) | `config_audit.md` | CIS Benchmark |

### Harness 保障（5 層）

| 層 | 功能 |
|----|------|
| **0** | OSV Batch 預熱：LLM 啟動前批量查所有套件，結果預存快取 |
| **1** | 強制 write_memory：LLM 沒寫 → 程式碼代寫 |
| **2** | Schema 驗證：缺少必要欄位 → 自動補全 |
| **2.5** | Cache 注入：LLM 輸出 0 CVE → 從 OSV/NVD 快取注入 |
| **3** | CVE 驗證：幻覺偵測 — 每個 CVE ID 回 NVD 精確查詢，不存在 → 移除 |
| **3.5** | 年份過濾：`< 2005` 的 CVE 一律移除 |
| **4** | Package 補全：CVE 沒有 package 欄位 → 從 description 推斷 |
| **5** | is_new 校正：比對歷史記憶，修正 LLM 的 is_new 標記 |

---

## 5. Analyst（漏洞連鎖分析師）

| 項目 | 說明 |
|------|------|
| **檔案** | `agents/analyst.py` (1045 行) |
| **本質** | **深度分析 + 連鎖攻擊路徑推理**。接收 Scout 的 CVE 清單，驗證 KEV/Exploit 狀態，分析漏洞間的連鎖關係 |
| **LLM 使用** | 重度使用。連鎖攻擊分析需要 LLM 推理 |
| **Tools** | check_cisa_kev、search_exploits、read/write_memory、history_search |

### 3-Task 拆分架構（降低弱模型認知負荷）

| Sub-Agent | 職責 | 擁有的 Tool |
|-----------|------|------------|
| **Collector** | 讀歷史記憶 + 解析 Scout JSON | `read_memory` |
| **Verifier** | KEV 驗證 + Exploit 搜尋 + Chain 分析 | `check_cisa_kev`、`search_exploits` |
| **Scorer** | 計算風險分數 + 寫記憶 + 輸出 JSON | `write_memory` |

### 連鎖攻擊分析規則

| 條件 | 風險調整 |
|------|---------|
| in_kev + exploit + chain | → CRITICAL |
| in_kev + exploit | → CRITICAL |
| chain alone | → 至少維持原始嚴重度 |
| **規則**：風險只能**升高**，絕不能降低 | |

### 風險分數計算

```
risk_score = min(100, Σ(cvss_score × weight))
weight: CRITICAL=3, HIGH=2, MEDIUM=1, LOW=0.5
```

### Harness 保障

| 層 | 功能 |
|----|------|
| **1** | 強制 write_memory |
| **2** | Schema 驗證（scan_id/risk_score/analysis 必須存在） |
| **3** | chain_risk 邏輯驗證（is_chain=true → 必須有 chain_with + chain_description） |
| **3.5** | CVE 年份標記（`< 2005` → confidence=NEEDS_VERIFICATION） |
| **Fallback** | LLM 完全失敗 → 用 Scout 資料建最小可行報告 |

---

## 6. Critic（魔鬼代言人）

| 項目 | 說明 |
|------|------|
| **檔案** | `agents/critic.py` (388 行) |
| **本質** | **對抗性審查者**。質疑 Analyst 的每個判斷，驗證假設，輸出 5 維記分卡 |
| **LLM 使用** | 用於生成質疑論點、驗證邏輯 |
| **Tools** | check_cisa_kev、search_exploits、read_memory |
| **可關閉** | `ENABLE_CRITIC=false` → 完全跳過，輸出 SKIPPED |

### 5 維記分卡

| 維度 | 權重 | 說明 |
|------|------|------|
| evidence | 30% | 證據充分度 |
| chain_completeness | 25% | 連鎖分析完整度 |
| critique_quality | 20% | 質疑品質 |
| defense_quality | 15% | 辯護品質 |
| calibration | 10% | 校準準確度 |

### 裁決規則

| 加權分數 | 裁決 |
|---------|------|
| ≥ 70 | **MAINTAIN**（維持 Analyst 判斷） |
| 50–69 | **MAINTAIN**（附帶挑戰筆記） |
| < 50 | **DOWNGRADE**（降級風險評估） |

### 關鍵限制

- **禁止降級 KEV 命中的 CVE**（in_cisa_kev=true → 不可 DOWNGRADE）
- 必須至少呼叫一個 Tool 才能下結論

---

## 7. Debate Engine（辯論引擎）

| 項目 | 說明 |
|------|------|
| **檔案** | `agents/debate_engine.py` (478 行) |
| **本質** | **多 Agent 辯論協調器**。讓 Analyst 和 Critic 進行最多 3 輪辯論，無共識時由 Judge 仲裁 |
| **論文依據** | Du et al. (2023) "Improving Factuality and Reasoning in LLMs through Multiagent Debate" (ICML 2023) |

### 辯論流程

```
Round 1: Analyst 提出初始立場 → Critic 質疑
Round 2: Analyst 更新立場（含 Critic 反饋）→ Critic 再評
Round 3: Analyst 最終立場 → Critic 最終評判
         ↓ 若 3 輪後仍無共識
Final:   Judge sub-agent 仲裁（獨立第三方）
```

### 共識判定

- Critic verdict = MAINTAIN → **直接共識**
- Critic verdict = DOWNGRADE 但 score ≥ 80 → **共識**（Analyst 立場強）
- 其他 → **繼續辯論**

### Judge Sub-Agent

- 獨立第三方，不是 Analyst 也不是 Critic
- 閱讀完整辯論紀錄，選擇最有邏輯支持的立場
- **安全性偏保守原則**：證據相當時，選更嚴重的評級

---

## 8. Advisor（資安顧問 / 最終裁決者）

| 項目 | 說明 |
|------|------|
| **檔案** | `agents/advisor.py` (812 行) |
| **本質** | **Pipeline 終點站**。接收所有前序 Agent 的分析結果，產出面向管理者的可執行行動報告 |
| **LLM 使用** | 使用 LLM 生成修補建議和 executive summary |
| **Tools** | read_memory、write_memory、history_search |

### 輸出格式（Advisor → UI 資料契約）

```json
{
  "executive_summary": "一句話風險摘要",
  "actions": {
    "urgent": [{"cve_id": "...", "command": "pip install --upgrade xxx", ...}],
    "important": [{"cve_id": "...", "action": "...", ...}],
    "resolved": []
  },
  "risk_score": 85,
  "risk_trend": "+12",
  "code_patterns_summary": [...]
}
```

### 三級分類規則

| 級別 | 條件 |
|------|------|
| **URGENT** | CVSS ≥ 9.0 或 in_cisa_kev=true 或有公開 PoC |
| **IMPORTANT** | CVSS ≥ 7.0 或有攻擊鏈風險 |
| **不列入** | MEDIUM/LOW 且無利用跡象 |

### Harness 保障（6.5 層）

| 層 | 功能 |
|----|------|
| **1** | LLM 輸出無法解析 → Fallback 最小可行報告 |
| **2** | Schema 驗證（executive_summary/actions/risk_score 必須存在） |
| **3** | risk_score 範圍驗證（強制 0-100） |
| **4** | URGENT 項目必須有 command（沒有 → 自動補 `pip install --upgrade`） |
| **5** | 歷史比對：重複未修補 CVE → `[REPEATED — STILL NOT PATCHED]` 語氣升級 |
| **6** | 憲法守衛：CODE-pattern（無真實 CVE ID）從 URGENT/IMPORTANT 移至 `code_patterns_summary` |
| **6.5** | CWE 佐證注入：為每個 code pattern 加入 MITRE CWE 官方定義、CVSS、代表性 CVE |

---

## Agent 間的資料契約總表

| 上游 | 下游 | 傳遞的 JSON 欄位 |
|------|------|-----------------|
| Orchestrator | 全部 | `scan_path`, `agents_to_run`, `shortcuts` |
| Security Guard | Scout/Analyst | `functions[]`, `patterns[]`, `hardcoded[]`, `language` |
| Intel Fusion | Scout | `fusion_results[]`, `composite_score`, `kev_hits` |
| Scout | Analyst | `vulnerabilities[]`, `code_patterns[]`, `summary` |
| Analyst | Critic/Debate | `analysis[]`, `risk_score`, `risk_trend` |
| Critic | Debate Engine | `scorecard`, `weighted_score`, `verdict`, `challenges[]` |
| Debate Engine | Advisor | 最終裁決 + `_debate_meta` |
| Advisor | UI | `executive_summary`, `actions{urgent/important/resolved}`, `risk_score` |

---

## 共通機制

### 429 自動輪替（所有 LLM Agent 共用）

```python
for attempt in range(MAX_LLM_RETRIES + 1):
    agent = create_xxx_agent(excluded_models)
    try:
        result = crew.kickoff()
        break
    except Exception as e:
        if "429" in str(e):
            mark_model_failed(current_model)
            excluded_models.append(current_model)
            rate_limiter.on_429(retry_after=...)
            continue
        raise
```

### Graceful Degradation（所有 Agent 共用）

每個 Agent 都有 `_build_fallback_output()` — LLM 完全失敗時，用前序 Agent 的資料建最小可行報告，確保 Pipeline 不中斷。

### CVE 年份過濾（三道防線）

| 位置 | 機制 |
|------|------|
| Scout Harness 3.5 | `< 2005` 的 CVE 從 vulnerabilities 移除 |
| Intel Fusion Harness 2.5 | `< 2005` 的 CVE 從 fusion_results 移除 |
| Advisor Harness 6 | `< 2005` 的 CVE 從 urgent/important 移除 |

---

*本文件僅供團隊內部參考，不需上傳至 Git。*
