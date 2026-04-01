# AGENTS.md

ThreatHunter 是 CrewAI 多 Agent 資安威脅情報平台。Python 3.11+，Streamlit UI。

## 環境設定

- 安裝依賴：`pip install -r requirements.txt`
- 啟動 UI：`streamlit run ui/app.py`
- 執行掃描：`python main.py`
- 跑測試：`python -m pytest tests/ -v`
- 跑單一測試：`python -m pytest tests/test_memory_tool.py -v`

## 環境變數

```bash
LLM_PROVIDER=openrouter          # openrouter | vllm | openai
OPENROUTER_API_KEY=your-key
NVD_API_KEY=your-key             # 成員 B 負責
OTX_API_KEY=your-key             # 成員 B 負責
GITHUB_TOKEN=your-token          # 成員 C 負責
VLLM_BASE_URL=http://localhost:8000  # 比賽時才需要
```

## 專案結構與擁有者

```
main.py              # 組長：Crew 串接入口
config.py            # 組長：LLM 三模式切換
tools/memory_tool.py # 組長：記憶讀寫 Tool
agents/advisor.py    # 組長：Advisor Agent
skills/action_report.md  # 組長：Advisor SOP
ui/app.py            # 組長：Streamlit 介面

tools/nvd_tool.py    # 成員 B：NVD 查詢
tools/otx_tool.py    # 成員 B：OTX 情報
agents/scout.py      # 成員 B：Scout Agent
skills/threat_intel.md   # 成員 B：Scout SOP

tools/kev_tool.py    # 成員 C：CISA KEV 驗證
tools/exploit_tool.py    # 成員 C：Exploit 搜尋
agents/analyst.py    # 成員 C：Analyst Agent
skills/chain_analysis.md # 成員 C：Analyst SOP
```

## 程式碼風格

- 繁體中文（zh-TW）註解，英文變數名
- 所有 Tool 用 `@tool` 裝飾器（CrewAI 格式）
- 每個 Tool 裡必須有 `try-except`，失敗回傳空值或錯誤訊息，不拋例外
- Agent 設定 `max_iter=10, allow_delegation=False, verbose=True`
- LLM 輸出 JSON 時可能有多餘文字，用 `extract_json()` 清理

## 邊界（不能碰的東西）

- 不要修改其他成員擁有的檔案（擁有者見上方結構）
- 不要直接修改 `memory/*.json`，一律透過 `memory_tool.py`
- 不要在 Tool 裡做 LLM 推理，Tool 只做 API 呼叫和資料整理
- 不要編造 CVE 編號，所有 CVE 必須來自 Tool 回傳的真實 API 資料
- 不要把 API Key 寫死在程式碼裡，一律用 `os.getenv()`

## Agent 資料流

```
使用者輸入 → Scout（NVD+OTX）→ Analyst（KEV+Exploit）→ Advisor（純推理）→ UI
```

- Scout 輸出 JSON 包含 `vulnerabilities[]` 和 `summary`
- Analyst 輸出 JSON 包含 `risk_score`, `risk_trend`, `analysis[]` 含 `chain_risk`
- Advisor 輸出 JSON 包含 `actions.urgent[]`, `actions.important[]`, `actions.resolved[]`
- 每個分析結果必須有 `confidence` 和 `reasoning` 欄位

## 測試規範

- 每個模組對應 `tests/test_{module}.py`
- 測試覆蓋：基本功能、空輸入、API 失敗降級、JSON 格式驗證
- Tool 測試不需要 LLM，可離線跑
- Agent 測試需要 LLM（設 `LLM_PROVIDER=openrouter`）
- 測試全過才能合併

## LLM 設定

- 開發期用 OpenRouter `meta-llama/llama-3.3-70b-instruct`
- 比賽時切 vLLM，改環境變數 `LLM_PROVIDER=vllm`
- 備案用 `gpt-4o-mini`，自動降級
- 不支援 Function Calling，用文字解析 ReAct 格式

## 記憶系統

- `memory/scout_memory.json` — Scout 歷史 CVE 紀錄
- `memory/analyst_memory.json` — Analyst 歷史風險評分
- `memory/advisor_memory.json` — 使用者回饋 + 建議歷史
- 結構：`{"latest": {...}, "history": [...最近10次...]}`
- 讀取失敗回傳 `"{}"`，寫入失敗靜默不中斷
