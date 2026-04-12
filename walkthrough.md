# ThreatHunter v3.1 — 下一個 Agent 的實作 Walkthrough

> 版本：2026-04-10 | 適用對象：接手實作的 AI Agent / 工程師
> 警告等級：🔴 任何偏離本文件描述的實作都可能破壞現有功能

---

## ⚠️ 最重要的三件事（先讀這個）

1. **在修改任何程式碼前，先執行**：
   ```bash
   cd d:\code\team-project\hackthon\ThreatHunter
   uv run python -m harness.constraints.arch_linter
   ```
   如果 Linter 不通過，**先修架構問題，再動功能**。

2. **不可虛構任何資訊**。如果不確定某個文件的路徑或函式名稱，**用 `list_dir` 或 `view_file` 確認**，不要猜。

3. **每次任務完成後執行**：
   ```bash
   uv run python -m pytest tests/ -v
   ```
   測試全綠才算完成。

---

## 一、目前已實作的完整清單（不需要再做）

### ✅ 已完成的 Python 模組

| 路徑 | 說明 |
|---|---|
| `main.py` | Pipeline 協調器，Orchestrator 驅動 → [Layer 1 並行] → Scout→Analyst→Critic→Advisor |
| `config.py` | LLM 降級瀑布、`SYSTEM_CONSTITUTION`、`SKILLS_DIR`、`get_llm()` |
| `input_sanitizer.py` | L0 確定性輸入淨化層（OWASP LLM01:2025），在 CrewAI 前執行 |
| `agents/orchestrator.py` | Orchestrator：`OrchestrationContext`、`run_orchestration()`、`classify_input()`、`check_shortcuts()` |
| `agents/scout.py` | Scout Agent：六維情報整合、記憶比對、`is_new` 欄位 |
| `agents/analyst.py` | Analyst Agent：連鎖推理、`attack_chain_graph` |
| `agents/critic.py` | Critic Agent（ColMAD Debate Cluster 三角色） |
| `agents/advisor.py` | Advisor/Judge Agent：五維評分、Feedback Loop 觸發 |
| `agents/security_guard.py` | Security Guard：隔離 LLM（Dual LLM Pattern），純提取不推理 |
| `agents/intel_fusion.py` | Intel Fusion：六維動態加權公式，計算 composite_score |
| `agents/__init__.py` | 懶載入所有 Agent 模組 |
| `tools/nvd_tool.py` | NVD API 查詢 + 離線快取 |
| `tools/kev_tool.py` | CISA KEV 批次查詢 |
| `tools/otx_tool.py` | OTX 威脅情報查詢 |
| `tools/exploit_tool.py` | exploit-db / GitHub PoC 搜尋 |
| `tools/epss_tool.py` | FIRST.org EPSS API 查詢 + 離線快取 |
| `tools/ghsa_tool.py` | GitHub Advisory DB 查詢 + 離線快取 |
| `tools/memory_tool.py` | JSON 雙層記憶（`read_memory`、`write_memory`） |
| `ui/server.py` | FastAPI + SSE 後端，`POST /api/scan`、`GET /api/stream/{id}` |
| `ui/static/index.html` | Vanilla HTML 前端（v3.1：七 Agent 卡片 + Orchestrator Pipeline Bar） |
| `ui/static/app.js` | 前端 SSE 事件處理邏輯（v3.1：支援全部七 Agent 事件） |
| `ui/static/style.css` | 前端樣式 |
| `harness/constraints/` | 架構邊界 Linter |
| `harness/entropy/` | 熵掃描器 / UNTIL CLEAN 迴圈 |
| `docs/data_contracts.md` | v3.1 JSON 資料契約（全部 Agent 間格式定義） |

### ✅ 已完成的技能 SOP 文件

| 路徑 | 對應 Agent |
|---|---|
| `skills/orchestrator.md` | Orchestrator Agent |
| `skills/security_guard.md` | Security Guard Agent |
| `skills/intel_fusion.md` | Intel Fusion Agent |
| `skills/threat_intel.md` | Scout Agent |
| `skills/chain_analysis.md` | Analyst Agent |
| `skills/debate_sop.md` | ColMAD Debate Cluster（實作在 `critic.py`） |
| `skills/action_report.md` | Advisor Agent |

### ✅ 已完成的文件（不需要再修改）

| 路徑 | 說明 |
|---|---|
| `docs/architecture_diagrams.html` | 架構審查報告（含競品佐證） |
| `docs/first_principles_analysis.html` | 第一性原理分析（含 Agent 白話說明） |
| `docs/six_agent_architecture.md` | 六 Agent 架構說明 |
| `docs/data_contracts.md` | v3.1 JSON 資料契約 |
| `docs/briefing_for_leader.md` | 領頭人簡報 |
| `FINAL_PLAN.md` | 總綱計畫（已更新至 v3.1） |
| `AGENTS.md` | Agent 實作規則（不要修改） |
| `project_CONSTITUTION.md` | 系統憲法（不可修改） |
| `HARNESS_ENGINEERING.md` | 工程方法論（不可修改） |

---

## 二、剩餘待辦事項

> 以下是尚未完成的工作，按優先級排序。

### 🔴 P0：部署（影響 Hackathon 分數最多）

#### 任務 P0-1：FastAPI 服務部署至雲端
- **目的**：取得可公開訪問的 Live URL，讓評審直接試用即時監控介面
- **啟動方式（本地測試）**：
  ```bash
  cd d:\code\team-project\hackthon\ThreatHunter
  uv run python ui/server.py
  # 開啟 http://localhost:1000
  ```
- **部署目標**：Railway、Render 或 AMD Developer Cloud（選一個）
- **注意**：`.env` 文件的 API Keys 不可上傳，要改用雲端環境變數設定

#### 任務 P0-2：申請 AMD Developer Cloud 並部署 vLLM
- **目的**：AMD Hackathon 評分的核心項目
- **步驟**：
  1. 前往 https://cloud.amd.com 申請帳號
  2. 選擇 MI300X GPU 執行個體
  3. 安裝 vLLM：`pip install vllm` + ROCm
  4. 啟動 Llama-70B：
     ```bash
     vllm serve meta-llama/Llama-3-70B-Instruct \
       --host 0.0.0.0 --port 8000 --tensor-parallel-size 2
     ```
  5. 修改 `config.py` 中的 `VLLM_BASE_URL` 指向 AMD 執行個體

---

### 🟢 P1：DVWA 實測（驗證攻擊連鎖準確率）

- **何處**：在本地或 Docker 部署 DVWA（Damn Vulnerable Web Application）
- **測試腳本位置**：`tests/stress_test_realworld.py`（已存在）
- **目標**：跑 5 個已知攻擊鏈，計算 ThreatHunter 的 Precision/Recall
- **輸出**：一份數字表（作為 Demo 時回答「準確率多少？」的佐證）

---

## 三、每次修改前必讀的三個邊界規則

### 規則 1：不可違反 Harness 層次架構
```
harness/context/       第 1 層：不可引用 constraints 或 entropy
harness/constraints/   第 2 層：只可引用 context
harness/entropy/       第 3 層：可引用 context 和 constraints
agents/ / tools/       應用層：可引用任何 harness 層
```

### 規則 2：輸出格式必須符合 JSON 契約
每個 Agent 的輸出都有預定格式。格式定義在：
- `docs/data_contracts.md`（v3.1，含 L0/Orchestrator/Security Guard/Intel Fusion）
- 或參考 `FINAL_PLAN.md` §六 的 JSON 範例

**驗證方式**：所有 `agents/*.py` 都要在輸出時呼叫 `jsonschema.validate()`

### 規則 3：Security Guard 的特殊限制
`agents/security_guard.py` 的 Agent 必須設定：
```python
Agent(
    ...
    allow_delegation=False,  # 禁止委派
    allow_code_execution=False,  # 禁止執行程式碼
    max_iter=3,  # 最多 3 次迭代
)
```

---

## 四、驗證指令（依序執行）

```bash
# 步驟 1：確認架構邊界合規
uv run python -m harness.constraints.arch_linter

# 步驟 2：確認無熵（無 stub/pass/TODO）
uv run python -m harness.entropy.entropy_scanner

# 步驟 3：跑全套測試
uv run python -m pytest tests/ -v

# 步驟 4：本機啟動 UI 確認 SSE 即時串流正常
uv run python ui/server.py
# 開啟 http://localhost:1000，輸入「Django 4.2, Redis 7.0」，確認七個 Agent 都有即時訊息

# 步驟 5（可選）：UNTIL CLEAN 完整驗證
uv run python -m harness.entropy.until_clean_loop
```

---

## 五、已知的問題和限制（不要試圖修復這些）

| 問題 | 狀態 | 說明 |
|---|---|---|
| ColMAD 三角色在同一個 LLM 扮演 | 接受 | 論文指出角色扮演仍有效，不是最優但可接受 |
| EPSS 對硬體漏洞預測不準 | 接受 | Intel Fusion 對 OTX 設低權重（0.05）作為緩解 |
| 攻擊連鎖精確度未量化 | P1 待辦 | 需 DVWA 實測，目前是已知缺口 |
| AMD vLLM 未實際測試 | P0 待辦 | 目前用 OpenRouter API，需部署至 AMD Cloud |

---

## 六、絕對禁止事項

```
❌ 禁止修改 project_CONSTITUTION.md
❌ 禁止修改 HARNESS_ENGINEERING.md
❌ 禁止使用 pass、# TODO、stub 函式交付功能
❌ 禁止在 Security Guard Agent 裡呼叫 Tool 或做推理
❌ 禁止偽造測試結果（測試必須真實執行）
❌ 禁止新增 requirements.txt 依賴項目而不通知工程師（AGENTS.md 規定）
❌ 禁止刪除現有的 Graceful Degradation try-except 結構
❌ 禁止在 agents/ 層引用 harness/entropy/ 的程式碼
```

---

## 七、問題排查（常見錯誤）

| 錯誤訊息 | 原因 | 解法 |
|---|---|---|
| `UnicodeEncodeError: 'charmap'` | Windows emoji 編碼問題 | `config.py` 的 `SafeStreamHandler` 應已處理，確認有被載入 |
| `NVD API rate limit` | NVD API 每日限流 | 使用 `data/` 離線快取，`tools/nvd_tool.py` 的 `read_nvd_cache` |
| `Arch Linter FAILED` | harness 層次違反 | 執行 `arch_linter.py` 看具體違規行，修正 import 路徑 |
| `jsonschema.ValidationError` | Agent 輸出格式不符 | 對照 `docs/data_contracts.md` 的 JSON 格式修正 Agent Prompt |
| SSE 連線中斷 | scan_id 不存在 | 確認 `POST /api/scan` 先成功返回 `scan_id` 再開 SSE 連線 |

---

## 八、檔案結構快照（截至 2026-04-10）

```
d:\code\team-project\hackthon\ThreatHunter\
├── agents/
│   ├── __init__.py         ✅ 懶載入（含 security_guard / intel_fusion）
│   ├── orchestrator.py     ✅ 完整實作（動態路由 A/B/C/D）
│   ├── scout.py            ✅ 完整實作
│   ├── analyst.py          ✅ 完整實作
│   ├── critic.py           ✅ ColMAD Debate Cluster
│   ├── advisor.py          ✅ Judge + Feedback Loop
│   ├── security_guard.py   ✅ 隔離 LLM（Dual LLM Pattern）
│   └── intel_fusion.py     ✅ 六維動態加權
├── tools/
│   ├── nvd_tool.py         ✅
│   ├── kev_tool.py         ✅
│   ├── otx_tool.py         ✅
│   ├── exploit_tool.py     ✅
│   ├── epss_tool.py        ✅ FIRST.org EPSS API
│   ├── ghsa_tool.py        ✅ GitHub Advisory DB
│   └── memory_tool.py      ✅
├── skills/
│   ├── orchestrator.md     ✅ SOP
│   ├── security_guard.md   ✅ SOP
│   ├── intel_fusion.md     ✅ SOP
│   ├── threat_intel.md     ✅
│   ├── chain_analysis.md   ✅
│   ├── debate_sop.md       ✅
│   └── action_report.md    ✅
├── ui/
│   ├── server.py           ✅ FastAPI + SSE
│   └── static/
│       ├── index.html      ✅ v3.1：七 Agent 卡片 + Orchestrator Pipeline Bar
│       ├── app.js          ✅ v3.1：全部七 Agent SSE 事件處理
│       └── style.css       ✅
├── harness/
│   ├── constraints/        ✅ Arch Linter
│   └── entropy/            ✅ 熵掃描 + UNTIL CLEAN
├── tests/                  ✅ 22 個測試文件（239+ 個測試案例）
├── input_sanitizer.py      ✅ L0 確定性安全淨化層（OWASP LLM01:2025）
├── main.py                 ✅ Orchestrator 驅動動態路由、L0 整合
├── config.py               ✅ LLM 降級瀑布
├── FINAL_PLAN.md           ✅ v3.1
├── docs/data_contracts.md  ✅ v3.1 JSON 資料契約
├── AGENTS.md               ✅（不可修改）
├── project_CONSTITUTION.md ✅（不可修改）
└── HARNESS_ENGINEERING.md  ✅（不可修改）
```

---

> 本文件由 Antigravity 基於 **實際掃描程式碼庫**生成，非虛構。
> 所有「✅」標記均對應已確認存在的文件。
> 最後更新：2026-04-10（v3.1 全部 P1 模組完成、UI 整合完成、L0 淨化器完成）
