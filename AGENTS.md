# AGENTS.md — ThreatHunter
# 任務地圖（Harness Engineering 格式，~100 行）
# 版本: v1.0.0 | 生效: 2026-04-03

## 你的角色（Your Role）

你是本專案的 AI 工程助理，在 **Harness Engineering** 框架內工作。
核心工作原則：**Constrain → Inform → Verify → Correct**

## 關鍵規則（Critical Rules）

- 如果資訊不在這個 repository 中，視作不存在
- 完成任何實作前，先查閱對應的 docs/ 文件
- 每完成一個模組，必須執行 `python -m pytest tests/ -v` 確認全數通過
- 禁止使用 `pass`、`# TODO`、stub 函式交付功能
- 所有 `.md` 報告使用繁體中文；程式碼註解使用繁體中文
- Agent 的 JSON 輸出使用英文

## 領域地圖（Domain Map）

| 領域 | 路徑 | 職責 |
|---|---|---|
| 配置 | `config.py` | LLM 切換 + API Key + 降級瀑布 |
| 工具 | `tools/` | CrewAI @tool 函式（NVD/OTX/KEV/Exploit/Memory） |
| Agent | `agents/` | Agent 定義（Scout/Analyst/Advisor/Critic） |
| Skill | `skills/` | Agent SOP 文件（.md） |
| 記憶 | `memory/` | 雙層持久化（JSON + LlamaIndex） |
| UI | `ui/` | Streamlit 介面 |
| Harness | `harness/` | 三柱架構基礎設施 |
| 測試 | `tests/` | pytest 測試 |

## 邊界規則（Boundary Rules — 嚴格模式）

本專案實施**嚴格層次架構**（定義於 `harness/constraints/boundary_rules.toml`）：

```
harness/context/    （第 1 層）← 不可引用 constraints 或 entropy
harness/constraints/（第 2 層）← 只可引用 context
harness/entropy/    （第 3 層）← 可引用 context 和 constraints
```

違反規則 → 執行 `python harness/constraints/arch_linter.py` 確認並修復

## 任務路由（Task Routing）

### 如果你的任務是「修改 Agent 行為」
→ 閱讀：`skills/*.md`（對應 Agent 的 SOP）
→ 參考：`docs/system_constitution.md`
→ 檢查：`docs/data_contracts.md`（JSON 格式）

### 如果你的任務是「修改或新增 Tool」
→ 參考：`tools/memory_tool.py`（範例格式）
→ 測試：`python -m pytest tests/test_memory_tool.py -v`

### 如果你的任務是「修改 Harness 基礎設施」
→ 閱讀：`HARNESS_ENGINEERING.md`
→ 確認邊界：`python harness/constraints/arch_linter.py`
→ 確認熵狀態：`python harness/entropy/entropy_scanner.py`

### 如果你的任務是「修復測試失敗」
→ 閱讀：`tests/` 下對應的 test 檔案
→ 參考：`docs/data_contracts.md`（輸出格式）

### 如果你的任務是「修改 UI」
→ 路徑：`ui/app.py`
→ 啟動：`streamlit run ui/app.py`

## 核心驗證指令（Verification Commands）

```bash
python -m pytest tests/ -v           # 全套測試
python harness/constraints/arch_linter.py  # 架構邊界 Linter
python harness/entropy/entropy_scanner.py  # 熵防掃描
python harness/entropy/until_clean_loop.py # UNTIL CLEAN 完整驗證
```

## 何時停止並通知工程師（Escalation）

立即停止並通知工程師，如果：
- 架構 linter 連續失敗超過 3 次
- 需要修改 `project_CONSTITUTION.md`
- 需要新增外部依賴（修改 `requirements.txt`）
- 測試失敗原因超出模組範圍
- UNTIL CLEAN 迴圈達到 10 次仍未通過
