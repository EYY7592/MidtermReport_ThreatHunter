# 👑 組長計畫書

> 角色：組長（架構師 + 串接 + 指揮 + Demo）
> 原則：code 由 vibe coding 完成，你的工作是**讓成員懂架構**。
> 方法論：**Harness Engineering**（讓 Agent 穩定可靠）

---

## 開發方法：Harness Engineering

```
你是 Harness 的總工程師。
你的工作不是讓 Agent 更聰明，
而是讓整個系統不會出錯。

Harness = 馬具。Agent = 馬。
你負責打造馬具，讓三匹馬穩定前進。
```

### 你的 Harness 職責

```
支柱 1: Constraints（向量約束 + 紅隊測試）→ 你的成果
  → 系統憲法 docs/system_constitution.md
  → JSON 契約 docs/data_contracts.md
  → 向量約束：Embedding 禁區偵測（防越獄攻擊）
  → Day 4 紅隊測試：慫恿 Agent 違規 → 驗證它會拒絕

支柱 2: Observability（原子化可觀測）→ 你的設定
  → verbose=True 在 Crew 層級開啟
  → 原子化日誌：每個 Agent 步驟產出結構化 JSON Log
  → Streamlit UI 展示 CI/CD 風格進度條

支柱 3: Feedback Loops（雙層記憶學習）→ 你的基礎建設
  → Layer 1: JSON 持久化（穩定保底，Day 1 起可用）
  → Layer 2: LlamaIndex RAG（語義搜尋，越用越好）
  → UI 的回饋按鈕：✅已修 / ❌未修 / 💬意見 → 雙寫

支柱 4: Graceful Degradation（五層降級瀑布）→ 你的備案
  → 層級 1：全速（vLLM + 即時 API）
  → 層級 2：LLM 降級（vLLM→OpenRouter→OpenAI）
  → 層級 3：API 降級（NVD/OTX 離線快取）
  → 層級 4：Agent 降級（跳過連鎖分析）
  → 層級 5：最低生存模式（離線摘要）

支柱 5: Evaluation（對抗式多智能體辯論）→ 你的驗收
  → Critic Agent（可插拔）：質疑 Analyst 的連鎖推理
  → 五維評分卡：證據 30% / 路徑 25% / 反駁 20% / 回應 15% / 校準 10%
  → Advisor 作為 Judge 裁決辯論結果
  → Day 4 加入，跑不通就拔掉
```

---

## 你的核心職責

```
你不是來寫 code 的。你是來確保：
  1. 成員 B 和 C 理解整體架構 + Harness Engineering
  2. 每個人知道自己做的東西在系統裡的位置
  3. 各部件的「馬具」到位（約束、驗證、降級）
  4. Demo 穩定可靠
```

---

## 你的交付清單

```
基礎建設（你負責）：
├── main.py              # CrewAI Crew 串接（含 Critic 辯論任務）
├── config.py            # API Keys + LLM endpoint + 向量約束
├── requirements.txt     # 鎖定版本
├── tools/memory_tool.py # 雙層記憶 Tool（JSON + LlamaIndex）
├── agents/advisor.py    # Advisor Agent（Judge 裁決者）
├── agents/critic.py     # Critic Agent（Day 4 可插拔）
└── ui/app.py            # Streamlit 介面（含原子化進度條）

Skill 文件（你負責）：
├── skills/action_report.md    # Advisor 的 SOP
└── skills/README.md           # Skill 系統說明

文件（你負責）：
├── docs/system_constitution.md
└── docs/data_contracts.md
```

---

## 記憶學習系統（你負責建造）

```
你是記憶學習系統的建造者。
成員 B 和 C 只是「用」它，你要「做」它。

記憶學習系統 = 雙層架構（JSON 穩底 + LlamaIndex 增值）

⚠️ 為什麼不能只用 LlamaIndex？
  → 向量搜尋 Cold Start 問題：
    - 0 份歷史 → 引擎報錯（致命！Demo 直接掛）
    - 1 份歷史 → 語義搜尋無統計意義
    - 向量搜尋永遠回傳 top_k，即使全不相關
  → Demo 前 2 次掃描 = 0-1 份歷史 = 最危險區間
  → 所以 JSON 必須保底！

架構：

  memory/
  ├── scout_memory.json     ← Layer 1: JSON（穩定保底）
  ├── analyst_memory.json   ← Layer 1: JSON（穩定保底）
  ├── advisor_memory.json   ← Layer 1: JSON（穩定保底）
  └── vector_store/         ← Layer 2: LlamaIndex（越用越好）

memory_tool.py 提供三個 Tool：

  Layer 1 — JSON（Day 1 起可用，絕不出錯）：
  ┌──────────────────────────────────────────────┐
  │ @tool("read_memory")                         │
  │ def read_memory(agent_name):                 │
  │     讀取 memory/{agent}_memory.json          │
  │     精確取得上次 risk_score、CVE 清單         │
  │     0 份歷史 → 回傳 {} → Agent 知道是第一次  │
  │                                               │
  │ @tool("write_memory")                        │
  │ def write_memory(agent_name, data):           │
  │     寫入 memory/{agent}_memory.json          │
  │     同時寫入 LlamaIndex（雙寫！）             │
  └──────────────────────────────────────────────┘

  Layer 2 — LlamaIndex RAG（Day 4 加上，越用越好）：
  ┌──────────────────────────────────────────────┐
  │ from llama_index.core import VectorStoreIndex│
  │ from crewai_tools import LlamaIndexTool      │
  │                                               │
  │ # 語義搜尋（帶安全閥）                        │
  │ def history_search(query):                   │
  │     if index.doc_count() == 0:               │
  │         return "No history"  # 安全閥        │
  │     results = query_engine.query(query)      │
  │     if results.score < THRESHOLD:            │
  │         return "No relevant history"         │
  │     return results                           │
  │                                               │
  │ HistorySearch = LlamaIndexTool(              │
  │     query_engine=index.as_query_engine(      │
  │         similarity_top_k=3),                 │
  │     name="HistorySearch",                    │
  │     description="語義搜尋歷史安全報告"       │
  │ )                                            │
  └──────────────────────────────────────────────┘

UI 回饋迴圈（Streamlit）：
  使用者看到報告後，按下：
    ✅ 已修復 CVE-XXX → 雙寫 JSON + 向量索引
    ❌ 暫不處理 → 雙寫，下次加強警告
    💬 報告太長 → 雙寫，下次輸出精簡版

  回饋 → 雙寫 → JSON 保底 + LlamaIndex 增值
  這就是「學習」的閉環
```

### 為什麼叫「學習系統」不是「記憶系統」

```
「記憶」= 記住上次的資料（被動）
「學習」= 根據歷史改變行為（主動）

雙層設計的好處：
  JSON（Layer 1）：精確比對 is_new、risk_trend
    → 第 1-2 次掃描就能穩定展示差異
  LlamaIndex（Layer 2）：語義搜尋歷史案例
    → 第 3+ 次掃描開始展示 RAG 能力
    → 「Django 安全問題？」→ 找到 SSRF 報告

Demo 時可以這樣說：
  「第一次掃描是全新的。第二次掃描，
    JSON 精確比對發現 2 筆新 CVE，風險 +13。
    第三次掃描，LlamaIndex 語義搜尋到
    上次的 SSRF 報告，Agent 據此加強警告。
    這是雙層記憶：JSON 穩底、RAG 增值。」
```




---

## 賽前任務 ⚡

```
⚡ 今天必做：
  □ 確認 AMD Cloud 帳號
  □ 註冊 OpenRouter + 儲值 $5（全員開發用）
  □ 通知成員 B：自己申請 NVD API Key + OTX 帳號
  □ 通知成員 C：自己申請 GitHub Token

📋 週末做：
  □ 建 GitHub repo（✅ 已完成）
  □ 本地跑通 CrewAI hello world
  □ 設定 config.py（OpenRouter + vLLM + OpenAI 三模式切換）
  □ 確認 OpenRouter 上 Llama 3.3 70B 能呼叫
  □ 把 OpenRouter API Key 發給 B 和 C
  □ 準備一場 30 分鐘的架構講解給 B 和 C：
     → 什麼是 Harness Engineering（五根支柱）
     → 什麼是 Agent（ReAct 思考迴圈）
     → 什麼是 Tool（@tool 裝飾器）
     → 什麼是 Skill（寫在 backstory 的 SOP）
     → 資料怎麼流（Scout → Analyst → Critic 辯論 → Advisor）
     → JSON 契約（每個 Agent 的輸入輸出格式）
     → LLM 策略（Day 1 不用 LLM → Day 2 用 OpenRouter）
```

### 架構講解重點（給 B 和 C 看的）

```
你需要讓他們理解的四件事：

0. Harness Engineering（方法論）

   我們的開發方法叫 Harness Engineering。
   核心理念：不是讓 Agent 更聰明，是讓它不出錯。
   
   五根支柱：
   ├── Constraints：約束（系統憲法、JSON 格式）
   ├── Observability：觀測（verbose=True）
   ├── Feedback Loops：回饋（Memory 系統）
   ├── Graceful Degradation：降級（try-except + 快取）
   └── Evaluation：驗證（驗收問題 + 信心度標記）
   
   你寫的每一段 code 和 Skill，
   都要想：「這是在讓 Agent 更穩嗎？」

1. ReAct 迴圈（Agent 的行為模式）
   
   Agent 不是function，它是一個思考迴圈：
   
   Thought: 我需要做什麼？
   Action: 用哪個 Tool？
   Action Input: 給 Tool 什麼參數？
   Observation: Tool 回傳了什麼？
   Thought: 根據結果，下一步？
   ...重複...
   Final Answer: 最終結果
   
   這就是「Agent」跟「腳本」的差別。
   Agent 自己決定下一步，腳本是寫死的。

2. Tool 的角色
   
   Tool = 一個 Python 函式 + @tool 裝飾器
   Agent 透過 ReAct 呼叫它
   Tool 只做一件事：呼叫 API，回傳結果
   Tool 不做判斷，判斷是 Agent（LLM）的事
   Tool 裡一定要有 try-except（Graceful Degradation）

3. Skill 的角色
   
   Skill = 寫在 backstory 裡的 SOP
   告訴 Agent「怎麼思考」，不是「怎麼呼叫 API」
   Skill 是一份 .md 文件，內容會被貼到 Agent 的 prompt
   Skill 裡的約束規則 = Constraints 支柱
   
   所以 Skill 的品質 = Agent 的推理品質
   這是成員最重要的產出
```

---

## Day 1-5 任務

### Day 1：建骨架 + 確認成員 Tool 能跑

```
□ 建專案結構（所有資料夾）
□ config.py / requirements.txt
□ memory_tool.py（記憶讀寫）
□ main.py 骨架（假 Agent 串通流程）
□ 確認成員 B 的 NVD Tool 回傳正確
□ 確認成員 C 的 KEV Tool 回傳正確
```

### Day 2：串接 + UI 基礎

```
□ 替換假 Agent → 成員 B 的 Scout
□ 替換假 Agent → 成員 C 的 Analyst
□ 寫 Advisor Agent（Judge 裁決者）+ skills/action_report.md
□ Streamlit UI 基礎（輸入框 + 報告 + 原子化進度條 + 回饋按鈕）
```

### Day 3：完整管線 + Memory

```
□ Scout → Analyst → Advisor 跑通（基礎管線）
□ Memory 整合（回饋寫入 → 下次讀取）
□ 跑兩次掃描，確認有差異（is_new, risk_trend）
□ 確認降級瀑布：拔掉 NVD Key → 系統自動切離線快取
```

### Day 4：AMD Cloud + Bug 修

```
□ 部署 vLLM
□ 加入 Critic Agent 辯論（可插拔，跑不通就拔掉）
□ 紅隊測試：用惡意 Prompt 慫恿 Agent 違規
□ 完整測試 3 次
□ 效能調整
```

### Day 5：Demo

```
□ Demo 腳本 + 排練 x3
□ 離線備案
□ 錄影
```

---

## Advisor Skill（你負責寫的）

### skills/action_report.md

```markdown
# Skill: 行動報告生成

## 目的
作為 Judge（裁決者），審閱 Analyst 和 Critic 的辯論結果，
產出非技術人員也能理解的行動方案。

## SOP
1. 讀取 Advisor 歷史建議（read_memory）
2. 比對歷史：哪些建議使用者做了？哪些還沒？
3. 對「建議過但沒做」的漏洞，加強警告語氣
4. 如果使用者回饋過「報告太長」→ 輸出精簡版
5. 每個行動項附帶具體修復指令（pip install, config 修改等）
6. 寫入本次建議到記憶

## 分級規則
🔴 URGENT — 在 CISA KEV + 有 exploit → 今天就要修
🟡 IMPORTANT — CVSS >= 7.0 但無 exploit → 本週修
🟢 RESOLVED — 使用者確認已修 → 標記完成

## 語氣規則
- 第一次建議：正常語氣
- 第二次建議（使用者沒做）：加強語氣 + 顯示天數
- 第三次以上：最強烈警告 + 標紅
```
