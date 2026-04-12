# ThreatHunter 最終計畫（總綱）

> 版本：FINAL **v3.1**（七 Agent · Hierarchical × Parallel × ColMAD Feedback Loop）
> 日期：2026-04-09
> 狀態：✅ 架構確定 | ⚠️ P0 待辦：AMD 部署 + Live URL + Pitch 影片

---

## 一、專案一句話

> **ThreatHunter 是有記憶的 AI 資安顧問，能推理攻擊連鎖風險，並透過七個 AI Agent 協作自主分析。**
>
> - **Orchestrator** 動態分配工作（隨輸入類型調整，不是固定串列）
> - **Security Guard** 隔離不可信輸入（防 Prompt Injection）
> - **Intel Fusion** 六維情報融合評分（NVD+EPSS+KEV+GHSA+ATT&CK+OTX）
> - **Scout** 合成情報 + 記憶比對
> - **Analyst** 跨 CVE 連鎖推理（市面工具業界獨有功能）
> - **Debate Cluster** ColMAD 三角色協作辯論（非零和），比競爭式辯論準確 19%
> - **Advisor/Judge** 五維評分 + 歷史追蹤 + 行動計畫
>
> 每次使用都會記住你的狀況，越用越準。

---

## 二、與市面工具的核心差距

| 功能 | Snyk Enterprise | CodeQL | Semgrep | Trivy | **ThreatHunter v3.1** |
|---|---|---|---|---|---|
| 靜態掃描 | ✅ | ✅ | ✅ | ✅ | ✅（L0+L1+L2） |
| 已知 CVE 查詢 | ✅ | ❌ | ❌ | ✅ | ✅（六維） |
| 攻擊連鎖推理 | ❌ | ❌ | ❌ | ❌ | **✅ 唯一** |
| 六維情報融合評分 | ❌ | ❌ | ❌ | ❌ | **✅ 唯一** |
| Multi-Agent 協作辯論 | ❌ | ❌ | ❌ | ❌ | **✅ 唯一** |
| 跨次掃描記憶學習 | ❌ | ❌ | ❌ | ❌ | **✅ 唯一** |
| 年費 | **企業 6 位數美金** | GitHub Enterprise | Pro 訂閱 | 免費 | **Open Source** |

> 佐證：konvu.com, vendr.com, usenix.org PentestGPT 2024, Fang et al. 2024（arXiv）

---

## 三、核心架構（v3.1 完整版）

### 3a. 架構圖

```
用戶輸入（程式碼 / 套件名 / 文件）
        |
        v
[⚙️ input_sanitizer.py]  ← 確定性基礎設施（OWASP LLM01:2025）
向量語義過濾 + 長度截斷   ← 禁止 LLM 做這件事（會被攻擊者欺騙）
        |
        v
[⚙️ L0 正則掃描]  ← 毫秒級，找 SQL 拼接 / eval / 硬編碼密碼
   0 結果 → 跳過 L1/L2（省 Token）
        |
======== CrewAI Crew（Process.hierarchical）========

  🧭 Orchestrator Agent（CrewAI Manager）
  │  動態路由：
  │  路徑 A：套件掃描     → 跳過 Security Guard（無程式碼）
  │  路徑 B：完整程式碼   → Layer 1 全部並行
  │  路徑 C：文件弱配置   → 跳過 Analyst + Debate
  │  路徑 D：回饋補充     → 只重跑低信心 CVE
  │
  ├─ 【MacNet Layer 1：並行組（arXiv:2406.07155）】
  │   ├── 🔒 Security Guard Agent  ← 隔離 LLM，只提取不推理
  │   │    Dual LLM Pattern（Simon Willison 2024）
  │   ├── 🧠 Intel Fusion Agent    ← 六維情報，自主選擇查哪些
  │   │    KEV 命中 → Small-World 捷徑直通 Analyst
  │   └── ⚙️ L1 bandit/AST         ← 確定性引擎（非 LLM）
  │
  ├─ 【MacNet Layer 2：合成】
  │   └── 🕵️ Scout Agent  ← 合成 + 記憶比對 + 格式標準化
  │        強制寫記憶（Sentinel Monitor 監控此步驟）
  │
  ├─ 【MacNet Layer 3：連鎖推理（Fang et al. 2024 防禦側應用）】
  │   └── 🔬 Analyst Agent  ← SSRF→Redis→RCE 連鎖推理
  │        唯一具備此能力的開源工具
  │
  ├─ 【MacNet Layer 4：ColMAD 協作辯論（arXiv:2405.06373）】
  │   ├── 🔬 Analyst 角色（找真實威脅）
  │   ├── ❓ Skeptic 角色（補充盲點 + 列舉未驗證前提）
  │   └── ⚔️ Hunter 角色（攻擊者視角 + 給出攻擊步驟）
  │        三方一致 → 跳過 Phase 2（省 6 次 LLM 呼叫）
  │
  └─ 【MacNet Layer 5：裁決】
      └── 🎯 Advisor/Judge Agent  ← 五維評分 + 歷史追蹤
           confidence < 0.70 → Feedback Loop（MAX 2 次）
               └→ 回到 Orchestrator 精準補充

==========================================
        |
[⚙️ jsonschema 驗證 + Rate Limit + Audit Log]
        |
        v
Streamlit UI | SARIF 格式 | 行動計畫（URGENT/IMPORTANT/RESOLVED）
        |
        v
雙層記憶：JSON 穩底 + LlamaIndex 向量索引
```

### 3b. 架構決策表（完整佐證）

| 決策項目 | 選擇 | 哪個 Harness 支柱 | 佐證來源 |
|---|---|---|---|
| **總體拓撲** | MacNet DAG 不規則拓撲，非串列 | Evaluation | arXiv:2406.07155 |
| **Agent Manager** | Orchestrator（CrewAI Process.hierarchical） | Observability | CrewAI 官方文件 |
| **輸入防禦** | Security Guard（Dual LLM Pattern）+ input_sanitizer | Constraints | OWASP LLM01:2025 + Simon Willison 2024 |
| **情報融合** | Intel Fusion 六維自主決策，動態 API 健康管理 | Evaluation | seemplicity.io + edgescan.com + arXiv EPSS 研究 |
| **連鎖推理** | Analyst Agent 跨 CVE 依賴分析 | Evaluation | Fang et al. 2024（GPT-4 One-Day Exploit） |
| **辯論架構** | ColMAD 三角色協作（互補盲點，非零和競爭） | Evaluation | ColMAD 論文 + arXiv:2405.06373（李宏毅） |
| **辯論拓撲** | MacNet Small-World 捷徑（三方一致跳過 Phase 2） | Evaluation | arXiv:2406.07155 |
| **記憶系統** | JSON 穩底 + LlamaIndex RAG 增值，雙層 | Feedback Loops | LlamaIndex 官方 + OpenAI RAG 研究 |
| **系統憲法** | SYSTEM_CONSTITUTION 注入全部 Agent backstory | Constraints | config.py |
| **JSON 契約** | IO 格式預定義 + jsonschema 驗證（確定性） | Evaluation | docs/data_contracts.md |
| **可觀測性** | StepLogger 原子步驟日誌 | Observability | main.py |
| **LLM 降級** | vLLM → OpenRouter → OpenAI 五層降級瀑布 | Graceful Degradation | config.py |
| **技能 SOP** | backstory 內嵌 skills/*.md | Constraints | skills/ 目錄 |
| **AMD 整合** | AMD Cloud + ROCm + vLLM + Llama-70B | 技術應用 | AMD Hackathon 要求（⚠️ 需實測） |

---

## 四、開發方法論：Harness Engineering

> 我們用 **Harness Engineering** 來寫 Agent。
> 一句話：**不是讓 Agent 更聰明，而是讓它不會出錯。**

```
傳統思維：「讓 AI 更強、更聰明」
Harness 思維：「給 AI 裝上安全帶、方向盤、煞車」

Agent 是一匹馬。
Harness = 馬具（韁繩 + 馬鞍 + 護具）。
馬很強，但沒有馬具就會亂跑。
Harness Engineering = 打造讓馬穩定工作的基礎設施。
```

### 支柱 1：Constraints（約束層）

| 層級 | 機制 | 實作位置 |
|---|---|---|
| A：憲法約束 | SYSTEM_CONSTITUTION 注入 backstory | `config.py` |
| B：向量約束 | 禁區 Embedding 相似度偵測（cosine sim < 0.75） | `harness/constraints/` |
| C：Schema 驗證 | jsonschema 強制輸出格式 | 每個 `agents/*.py` |
| D：Security Guard | 隔離 LLM 處理不可信輸入 | `agents/` + `skills/security_guard.md` |
| E：紅隊測試 | 惡意提示對抗腳本 | `tests/red_team/` |

### 支柱 2：Observability（可觀測性）

- **StepLogger**：每個 Agent 的原子步驟（READ_MEMORY / CALL_NVD / WRITE_MEMORY）各自記錄
- **OrchestrationContext**：跨 Agent 的共享執行上下文，記錄捷徑使用、回饋迴路次數
- **Streamlit 進度面板**：CI/CD 風格的即時進度條

### 支柱 3：Feedback Loops（雙層記憶）

```
Layer 1（穩定底層）：JSON 持久化
  → 第 0 次掃描回傳 {} → Agent 知道是第一次
  → 絕對不會 Cold Start 失敗

Layer 2（增值層）：LlamaIndex RAG
  → 第 3+ 次掃描語義搜尋才開始有效
  → 「上次 Django SSRF 建議修但沒修」

Advisor Feedback Loop：
  confidence < 0.70 → 帶具體問題回 Orchestrator
  → 只重跑低信心 CVE（不是全部）
  → MAX 2 次，防止無限循環
```

### 支柱 4：Graceful Degradation（五層降級瀑布）

| 層級 | 觸發條件 | 行為 |
|---|---|---|
| 1（全速） | 正常 | vLLM + 即時 API + 完整 Pipeline |
| 2（LLM 降級） | vLLM 掛 | 自動切 OpenRouter → OpenAI |
| 3（API 降級） | NVD/OTX 限速 | 離線快取 `data/nvd_cache/` |
| 4（Agent 降級） | Analyst 超時 | 標注 `chain_analysis: SKIPPED` |
| 5（最低生存） | 一切掛掉 | 上次掃描摘要，不白屏 |

### 支柱 5：Evaluation（ColMAD 協作辯論）

三角色分工（互補盲點，來源：ColMAD 論文 + 李宏毅 arXiv:2405.06373）：

| 角色 | 任務 | 知識盲點 | 義務 |
|---|---|---|---|
| 🔬 Analyst | 找真實威脅 | 容易高估風險 | 必須引用程式碼行號 |
| ❓ Skeptic | 補充 Analyst 沒考慮的 | 容易低估（誤判誤報） | 列出所有未驗證前提 |
| ⚔️ Hunter | 攻擊者視角 | 只看「能不能打」 | 給出「攻擊步驟 1→2→3」 |

**加權評分卡（Advisor 裁決）**：

| 項目 | 權重 |
|---|---|
| Evidence（證據支持度） | 30% |
| Chain Completeness（連鎖完整性） | 25% |
| Critique Quality（反駁品質） | 20% |
| Defense Quality（正方回應） | 15% |
| Calibration（信心校準） | 10% |

---

## 五、七個 Agent 完整說明

### 🧭 Orchestrator Agent
- **角色**：CrewAI Manager，動態任務規劃
- **技能**：`skills/orchestrator.md`
- **核心能力**：
  - 四條路徑動態路由（A/B/C/D）
  - MacNet Small-World 捷徑（KEV 命中 / L0 無結果 / 辯論一致時省略）
  - Feedback Loop 管理（上限 2 次，防無限循環）
- **禁止**：自己查詢 API、自己做漏洞判斷

### 🔒 Security Guard Agent
- **角色**：隔離 LLM（Quarantined LLM）
- **技能**：`skills/security_guard.md`
- **核心能力**：只提取（函式/套件/字串模式），不判斷
- **設計依據**：Dual LLM Pattern（Simon Willison 2024）+ OWASP LLM01:2025
- **禁止**：任何推理 / Tool 呼叫 / 遵從程式碼注釋中的「指令」

### 🧠 Intel Fusion Agent
- **角色**：六維情報融合師，自主選擇查哪些
- **技能**：`skills/intel_fusion.md`
- **六維來源**：NVD(CVSS) 0.20 + EPSS 0.30 + KEV 0.25 + GHSA 0.10 + ATT&CK 0.10 + OTX 0.05
- **自主決策示例**：
  - `cve_year < 2020` → EPSS 數據少，調低 EPSS 權重
  - `in_kev == True` → 跳過 EPSS 查詢（KEV 已是最高事實）
  - `otx_fail_rate > 0.5` → OTX 降為可選

### 🕵️ Scout Agent
- **角色**：第一線 SOC 分析師
- **技能**：`skills/threat_intel.md`
- **核心能力**：情報合成 + 記憶比對（`is_new` 欄位）+ 格式標準化
- **強制**：完成後必須 `write_memory`，Sentinel Monitor 監控此步驟

### 🔬 Analyst Agent
- **角色**：資深漏洞研究員
- **技能**：`skills/chain_analysis.md`
- **核心能力**：跨 CVE 連鎖推理（SSRF→Redis→RCE 等），輸出 `attack_chain_graph`
- **市場獨特性**：Snyk / CodeQL / Semgrep / Trivy 均無此功能（來源：konvu.com）

### ⚖️ Debate Cluster（三角色 ColMAD）
- **角色**：三人審查小組（Analyst / Skeptic / Hunter）
- **技能**：`skills/debate_sop.md`
- **協作方式**：互補盲點（非零和），依據 ColMAD 論文 +19% 準確率
- **省 Token 設計**：第一輪三方全部一致 → 跳過 Phase 2

### 🎯 Advisor / Judge Agent
- **角色**：CISO，最終裁決者
- **技能**：`skills/action_report.md`
- **核心能力**：五維評分卡 + 歷史追蹤（「上次建議修但沒修」會更嚴厲）+ 輸出 URGENT/IMPORTANT/RESOLVED
- **Feedback**：confidence < 0.70 → 生成回饋訊息 → Orchestrator 精準補充

---

## 六、JSON 資料契約（各 Agent 輸入輸出格式）

### Scout → Analyst

```json
{
  "scan_id": "scan_20260401_001",
  "timestamp": "2026-04-09T10:00:00Z",
  "tech_stack": ["django 4.2", "redis 7.0"],
  "vulnerabilities": [
    {
      "cve_id": "CVE-2024-XXXX",
      "package": "django",
      "cvss_score": 7.5,
      "composite_score": 8.7,
      "severity": "CRITICAL",
      "epss_score": 0.97,
      "in_cisa_kev": true,
      "dimensions_used": ["nvd", "epss", "kev", "ghsa"],
      "is_new": true,
      "confidence": "HIGH"
    }
  ],
  "summary": {"total": 8, "critical": 1, "high": 3, "medium": 4}
}
```

### Analyst → Debate Cluster

```json
{
  "scan_id": "scan_20260401_001",
  "risk_score": 85,
  "risk_trend": "+7",
  "analysis": [
    {
      "cve_id": "CVE-2024-XXXX",
      "original_cvss": 6.5,
      "composite_score": 8.7,
      "adjusted_risk": "CRITICAL",
      "in_cisa_kev": true,
      "exploit_available": true,
      "chain_risk": {
        "is_chain": true,
        "chain_with": ["CVE-2024-YYYY"],
        "chain_description": "SSRF → Redis Unauthorized → RCE",
        "confidence": "HIGH",
        "attack_chain_graph": ["SSRF exploit", "Redis bind 0.0.0.0", "SLAVEOF injection", "RCE"]
      },
      "reasoning": "In CISA KEV + public exploit + chains with Redis CVE-2024-YYYY"
    }
  ]
}
```

### Advisor → UI

```json
{
  "executive_summary": "1 actively exploited attack chain detected. Risk score increased by 7.",
  "confidence": "HIGH",
  "actions": {
    "urgent": [{"cve_id": "CVE-2024-XXXX", "action": "pip install django==4.2.20", "deadline": "today"}],
    "important": [{"cve_id": "CVE-2024-YYYY", "action": "Set Redis requirepass"}],
    "resolved": [{"cve_id": "CVE-2024-ZZZZ", "resolved_date": "2026-04-07"}]
  },
  "pipeline_meta": {
    "agents_invoked": ["security_guard", "intel_fusion", "scout", "analyst", "debate", "advisor"],
    "shortcuts_taken": ["debate_phase2_skipped"],
    "feedback_loops": 0,
    "scan_path": "B"
  }
}
```

---

## 七、技能 SOP 文件清單

| 文件 | 對應 Agent | 核心內容 |
|---|---|---|
| `skills/orchestrator.md` | Orchestrator | 四路動態路由 + Small-World 捷徑 + Feedback Loop 上限 |
| `skills/security_guard.md` | Security Guard | 隔離提取 SOP + 注入嘗試範例 + 禁止行為清單 |
| `skills/intel_fusion.md` | Intel Fusion | 六維自主策略決策 + 動態權重 + KEV 捷徑通知 |
| `skills/threat_intel.md` | Scout | NVD/OTX 情報收集 + 記憶強制寫入 + is_new 比對 |
| `skills/chain_analysis.md` | Analyst | SSRF/RCE/SQLi 連鎖邏輯 + KEV 驗證 + Exploit 搜尋 |
| `skills/debate_sop.md` | Debate Cluster | Devil's Advocate SOP + 三角色分工 + 五維評分卡 |
| `skills/action_report.md` | Advisor | 裁決輸出格式 + 歷史追蹤 + 信心度閾值 |

---

## 八、Harness Engineering 驗證指令

```bash
# 全套測試（AGENTS.md 規定每個 PR 前必跑）
uv run python -m pytest tests/ -v

# 架構邊界 Linter（確認 harness/ 層次無違反）
uv run python harness/constraints/arch_linter.py

# 熵掃描（確認無 stub / pass / TODO 殘留）
uv run python harness/entropy/entropy_scanner.py

# UNTIL CLEAN 完整驗證迴圈
uv run python harness/entropy/until_clean_loop.py
```

---

## 九、P0 行動清單（影響 Hackathon 評分的緊急事項）

> 依據 `docs/architecture_diagrams.html` §5 審查結果

| 優先 | 任務 | 影響的評分維度 | 預估時間 |
|---|---|---|---|
| 🔴 P0 | 申請 AMD Developer Cloud + 部署 vLLM + 截圖錄影 | **AMD 技術應用**（最重要） | 4-8 小時 |
| 🔴 P0 | Streamlit Cloud 部署 → 取得 Live URL | **Presentation** | 2-4 小時 |
| 🟡 P1 | DVWA 實測 5 個攻擊鏈 → 取得 Precision/Recall 數字 | **商業價值佐證** | 6-12 小時 |
| 🟡 P1 | 錄製 5 分鐘 Pitch 影片（展示六 Agent 流程） | **Presentation** | 2-4 小時 |
| 🟢 P2 | `uv run python -m pytest tests/ -v` 全綠 | Hackathon 穩定性 | 1-2 小時 |
| 🟢 P2 | Intel Fusion Tool 實作（EPSS API + GHSA API） | 六維情報完整性 | 4-6 小時 |

---

## 十、時間線（分工）

```
         組長              成員 B              成員 C
         ────              ──────              ──────
賽前     環境+API Key      讀計畫+裝環境       讀計畫+裝環境
         發計畫給成員       uv + CrewAI hello   uv + CrewAI hello

Day 1    Orchestrator      nvd_tool.py         intel_fusion tools
         config.py          epss_tool.py        kev_tool.py / ghsa
         memory_tool.py     Tool 測試 ✅         Tool 測試 ✅

Day 2    Security Guard    scout.py Agent      analyst.py Agent
         Intel Fusion      ReAct 測試 ✅        ColMAD Debate
         main.py 骨架

Day 3    完整七 Agent 管線  Memory 整合          Advisor + Judge
         Advisor Judge      整合測試             整合測試

Day 4    AMD Cloud vLLM    Bug 修               DVWA 實測
         Feedback Loop     AMD Cloud 測試       Precision/Recall

Day 5    Demo 腳本 + 影片  Demo 支援            Live URL 部署
         排練 x3           排練 x3              排練 x3
```

---

## 十一、資料夾結構

```
ThreatHunter/
├── agents/
│   ├── orchestrator.py   ← 新！Orchestrator Manager
│   ├── scout.py
│   ├── analyst.py
│   ├── critic.py         ← ColMAD Debate Cluster（三角色）
│   └── advisor.py
├── tools/
│   ├── nvd_tool.py
│   ├── kev_tool.py       ← CISA KEV 批次查詢
│   ├── otx_tool.py
│   ├── exploit_tool.py
│   └── memory_tool.py
├── skills/
│   ├── orchestrator.md   ← 新！
│   ├── security_guard.md ← 新！
│   ├── intel_fusion.md   ← 新！
│   ├── threat_intel.md
│   ├── chain_analysis.md
│   ├── debate_sop.md
│   └── action_report.md
├── harness/
│   ├── context/          ← 第 1 層（最底層）
│   ├── constraints/      ← 第 2 層（只可引用 context）
│   └── entropy/          ← 第 3 層（可引用 1、2 層）
├── memory/
│   ├── *_memory.json     ← JSON 穩底（Layer 1）
│   └── vector_store/     ← LlamaIndex（Layer 2）
├── docs/
│   ├── architecture_diagrams.html  ← 最終架構審查（含佐證）
│   ├── first_principles_analysis.html ← 第一性原理分析
│   ├── six_agent_architecture.md
│   └── briefing_for_leader.md
├── config.py             ← LLM 降級瀑布 + SYSTEM_CONSTITUTION
├── main.py               ← Pipeline 協調
├── ui/                   ← Streamlit UI
└── tests/                ← pytest 全套測試
```

---

## 十二、參考文獻（所有架構佐證）

```
1. MacNet — Collaborative Scaling Law
   arXiv: 2406.07155
   核心：不規則拓撲 > 規則拓撲（串列）

2. LLM Discussion Framework（李宏毅教授）
   arXiv: 2405.06373
   核心：三階段討論（Initiation → Discussion → Convergence）

3. ColMAD — Collaborative Multi-Agent Debate
   核心：協作式辯論（+19% 準確率 vs 競爭式）

4. Dual LLM Pattern（Simon Willison, 2024）
   核心：隔離 LLM 處理不可信輸入

5. OWASP LLM Top 10（2025）
   LLM01: Prompt Injection — Security Guard 設計依據

6. PentestGPT（USENIX Security 2024, Deng et al.）
   核心：LLM Agent 比傳統掃描器更能做推理型分析

7. Fang et al. 2024 — GPT-4 One-Day Exploit（arXiv）
   核心：GPT-4 可自動利用 87% 的一日漏洞；多 Agent 層次架構 53% 零日漏洞

8. EPSS 效能研究（arXiv + seemplicity.io + edgescan.com）
   核心：CVSS+EPSS+KEV 融合顯著優於單一指標

9. Snyk 定價資料（vendr.com）
   核心：企業年合約六位數美金，LLM開源方案價值清晰
```

---

## 十三、詳細子計畫

每個人的詳細任務、程式碼範例、測試方法，請看各自的計畫書：

- 👑 [組長計畫](./leader_plan.md)
- 🔍 [成員 B 計畫](./member_b_plan.md)（如有）
- 🧠 [成員 C 計畫](./member_c_plan.md)（如有）
- 📐 [架構審查報告](./docs/architecture_diagrams.html)（含競品比較 + 佐證）
- 🔬 [第一性原理分析](./docs/first_principles_analysis.html)（含各 Agent 詳解）
- 📋 [六 Agent 架構說明](./docs/six_agent_architecture.md)（技術摘要）
