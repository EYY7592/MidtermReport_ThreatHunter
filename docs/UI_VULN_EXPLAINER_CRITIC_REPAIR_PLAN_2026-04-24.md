# UI 漏洞說明與 Critic 多回合辯論修復計劃

> 狀態：待審批
> 日期：2026-04-24
> 範圍：UI 漏洞說明、URGENT 行號呈現、Unknown 顯示治理、Critic / Debate Engine 多回合修正

## 一、目標

本計劃要解決四個使用者可見問題：

1. UI 下方新增簡短漏洞詞彙說明，讓評審能一眼理解 CWE、CVSS、NVD，以及像 `CWE-78` 的本質意思。
2. `URGENT — Immediate Action Required` 內的程式碼類 finding 必須清楚顯示要修改的行號。
3. UI 報告不允許出現 `unknown`、`Unknown`、`UNKNOWN` 這類不友善字樣。
4. 查明 Critic Agent 為何看起來只有一回合，並改成可驗證的多回合辯論。
5. Thinking Path 必須顯示每個 Agent 的完整執行紀錄，而不是只顯示摘要 preview。
6. 說明為何目前不把向量資料庫作為主要資料來源，並保留未來可啟用 RAG 的位置。

## 二、目前觀察與根因

### 2.1 UI 漏洞說明不足

目前 UI 已經有 `codePatternsCWESection` 與 CWE inline evidence，但實際掃描結果主要把 CWE 資訊塞在每張 action card 裡。對第一次看 demo 的評審來說，`CWE-78`、`CVSS Base`、`NVD` 的概念仍不夠直覺。

根因：

- `ui/static/index.html` 沒有獨立的「漏洞詞彙速查」區塊。
- `ui/static/app.js` 有 CWE inline render，但缺少把 CWE 描述轉成一句話的固定摘要層。
- `tools/cwe_database.py` 已有 CWE description/remediation，但 UI 沒有使用「簡短白話版」。

### 2.2 URGENT 沒有明確顯示要改哪一行

畫面中的 code finding 目前會把 `package` 顯示成 `Code (Line X)`，但若 line metadata 缺失或 render fallback 失敗，就會出現類似 `[ ] Unknown`，不夠明確。

根因：

- `ui/static/app.js::codePatternToAction()` 只把行號包進 `package` 字串，沒有獨立欄位如 `line_no` / `source_location`。
- `renderActionList()` 沒有固定的 `Affected line` 顯示區。
- Advisor / Security Guard 的 code finding 欄位尚未被 UI 統一正規化。

### 2.3 UI 仍會出現 unknown

目前多處 fallback 會直接輸出：

- `item.package || 'unknown'`
- `item.cve_id || 'UNKNOWN'`
- `cweRef.name || p.pattern_type || 'Unknown'`
- `report_sources.vulnerability_detail || 'unknown'`

根因：

- 內部資料契約允許 `unknown` 表示工具查無資料或狀態未知。
- UI 沒有最後一道 display sanitizer。
- 對 demo 場景而言，`unknown` 應改成具體可讀狀態，例如 `Code finding`、`Line not provided`、`Evidence pending`、`No external CVE`。

注意：此處建議治理的是「UI 顯示層不出現 unknown」。部分工具資料契約仍可能需要保留 `unknown` 作為機器可讀狀態，例如 OTX threat level。

### 2.4 Critic 只有一回合的根因

目前有兩套相關實作：

- `main.py::stage_critic()` 呼叫 `agents.debate_engine.run_debate_pipeline()`，文件上是最多 3 輪。
- `agents/critic.py::run_critic_pipeline()` 本身仍是單次 Crew kickoff。

造成「看起來只有一回合」的根因有四個：

1. `agents/critic.py` 的 JSON 範例仍硬編碼 `"debate_rounds": 1`。
2. `agents/critic.py::_build_fallback_output()` 也硬編碼 `"debate_rounds": 1`。
3. `run_critic_pipeline()` 每次只執行一次 Critic task，`MAX_DEBATE_ROUNDS` 只出現在 prompt 文本，沒有在該函式內形成 loop。
4. `agents/debate_engine.py` 雖然有最多 3 輪，但 `_check_consensus()` 對 `verdict == "MAINTAIN"` 立即結束，所以只要第一輪 Critic 維持 Analyst 判斷，就會早停在 1 輪。

因此現況不是完全沒有 Debate Engine，而是「主流程可多輪，但共識條件太容易早停；底層 Critic contract 又仍保留單回合語意」。

### 2.5 Thinking Path 目前不是完整紀錄

Thinking Path 目前由 `ui/server.py::_build_thinking_path()` 讀取 `logs/checkpoints/*.jsonl`，再依 Agent 分組。它已經能顯示 `STAGE_ENTER`、`LLM_CALL`、`LLM_RESULT`、`TOOL_CALL`、`HARNESS_CHECK`、`DEGRADATION` 等事件，但多數內容仍是 preview 或部分欄位。

根因：

- `checkpoint.py` 的 `LLM_RESULT` 只保存 `thinking_preview`，沒有完整 raw output 或完整 final output。
- `TOOL_CALL` 只保存 input/output preview，無法完整重建每個 Agent 的工具查詢脈絡。
- `STAGE_EXIT` 目前主要保存狀態與 duration，沒有統一保存該 Agent 的完整輸入、完整輸出、資料來源、fallback/degraded 狀態。
- UI 的 Thinking Path drawer 目前以事件列表為主，缺少「每個 Agent 的完整紀錄」分頁或展開區。

### 2.6 為何目前不使用向量資料庫作為主資料源

本專案目前不是完全沒有向量資料庫能力。`tools/memory_tool.py` 已有 LlamaIndex RAG Layer 2，並由 `ENABLE_MEMORY_RAG=true` 條件式啟用；它會把 JSON memory 雙寫到 `memory/vector_store/`，並提供語義搜尋歷史案例。

但目前不把向量資料庫作為 UI / pipeline 的主資料源，原因如下：

- 比賽 demo 需要可重現與可審計；JSONL checkpoint 與 scan-scoped pipeline result 是 deterministic 的，能逐行追溯。
- 向量搜尋是相似度召回，適合歷史輔助，不適合承擔「本次漏洞結果」的唯一真相來源。
- RAG 依賴 embedding 套件與本機模型，環境不齊時會 graceful degradation，不能讓 UI 結果依賴它。
- Constitution 要求 CVE 與外部情報必須來自 tool-returned data；向量資料庫只能作為歷史記憶輔助，不能取代 NVD/OSV/GHSA/KEV/EPSS 等工具證據。
- 先前已修正 UI 避免從全域 `scout_memory.json` 污染本次 scan；若改用向量召回作主來源，會重新引入跨 scan 混淆風險。

結論：目前採用「scan-scoped JSON result + checkpoint JSONL」作為主資料源，LlamaIndex RAG 保留為 optional history assist，不作為最終報告的權威來源。

## 三、修復方案

### Phase 1：UI 漏洞詞彙速查區

修改檔案：

- `ui/static/index.html`
- `ui/static/app.js`
- `ui/static/style.css`

做法：

- 在結果區下方新增 `Vulnerability Glossary` 區塊。
- 固定顯示三個基礎概念：
  - `CWE`：弱點種類，例如「命令注入」「SQL 注入」。
  - `CVSS`：嚴重度分數，0.0 到 10.0。
  - `NVD`：美國 NIST 維護的 CVE 漏洞資料庫。
- 依本次掃描結果動態列出 CWE 條目，例如：
  - `CWE-78`：程式把使用者輸入組成系統命令，攻擊者可能執行任意指令。
  - `CWE-89`：程式把使用者輸入直接拼進 SQL，攻擊者可能改變查詢邏輯。
- 資料來源優先順序：
  - `code_patterns_summary[].cwe_reference.description`
  - `tools/cwe_database.py` 已知 CWE 對照
  - UI 內建短句 fallback

驗收標準：

- 掃描出 `CWE-78` 時，下方 glossary 必須出現 `CWE-78` 與一句白話說明。
- 沒有 code CWE 時，仍顯示 CWE / CVSS / NVD 的基礎說明。

### Phase 2：URGENT 明確顯示要修改的程式碼行

修改檔案：

- `ui/static/app.js`
- `ui/static/style.css`
- 視需要補強 `main.py::_build_code_patterns_summary()`
- 視需要補強 `agents/advisor.py`

做法：

- 在 `codePatternToAction()` 保留獨立欄位：
  - `line_no`
  - `source_location`
  - `vulnerable_snippet`
- `renderActionList()` 對 code finding 顯示固定區塊：
  - `Affected line: L12`
  - 若沒有行號：顯示 `Affected line: Not provided by scanner`
- URGENT code finding 不再用 `package` 承載行號。
- 若 Security Guard 已提供 `line_no`，UI 必須優先使用。

驗收標準：

- `CODE-001` 類型 finding 在 URGENT 裡必須看得到 `Affected line: L<number>`。
- 若缺 line metadata，不可顯示 `Unknown`，必須顯示 `Line not provided by scanner`。

### Phase 3：禁止 UI 出現 unknown

修改檔案：

- `ui/static/app.js`
- `ui/server.py`
- 視需要補測 `tests/test_ui_server.py`

做法：

- 新增 display sanitizer，例如：
  - `displayText(value, fallback)`
  - `normalizeDisplayLabel(value, fallback)`
- UI render 層禁止直接使用 `unknown` / `UNKNOWN` / `Unknown`。
- 替代表如下：

| 原始情況 | UI 顯示 |
|---|---|
| `package` 缺失 | `Code finding` 或 `Package not provided` |
| `cve_id` 缺失且是 code finding | `Code issue` |
| `cve_id` 缺失且是 package finding | `External ID pending` |
| `source` 缺失 | `Pipeline result` |
| `line_no` 缺失 | `Line not provided by scanner` |
| `cwe_name` 缺失 | `Security weakness` |

驗收標準：

- 完成掃描後，主要結果面板不可包含大小寫任一型態的 `unknown`。
- 測試要覆蓋 `Unknown`、`unknown`、`UNKNOWN` 三種輸入。

### Phase 4：Critic 多回合辯論修正

修改檔案：

- `agents/critic.py`
- `agents/debate_engine.py`
- `main.py`
- `docs/data_contracts.md`
- `tests/test_pipeline_integration.py`
- 新增或補強 `tests/test_debate_engine.py`

做法：

- 將 `agents/critic.py` 的輸出範例從單回合改為支援當輪上下文：
  - `debate_rounds` 必須反映目前 round number 或總 round count。
  - `challenges[]` 建議改成可接受 string 或 object，但 UI/Advisor 只依文字摘要使用。
- `_build_fallback_output()` 不再固定 `debate_rounds=1`，改讀 `_debate_round`。
- `run_critic_pipeline()` 回傳 `_critic_round`、`_max_rounds`、`_single_round=True`，讓 Debate Engine 能清楚知道這只是單輪 Critic 判斷。
- `agents/debate_engine.py::_check_consensus()` 收斂早停條件：
  - 第 1 輪即使 `MAINTAIN`，仍至少跑第 2 輪，除非 finding 數為 0 或 Critic 明確標記 `no_challenge=true`。
  - `MAX_DEBATE_ROUNDS=3` 時，預設至少跑 2 輪，必要時第 3 輪或 Judge。
- `_debate_meta` 補齊：
  - `total_rounds`
  - `consensus_round`
  - `early_stop_reason`
  - `judge_invoked`
  - `rounds[]`

驗收標準：

- 一般有 finding 的掃描，`_debate_meta.total_rounds >= 2`。
- 若無 finding，可允許 `total_rounds == 1`，但要有 `early_stop_reason: "no_findings"`。
- fallback 狀態不可假裝完成 3 輪，必須標示 degraded。

### Phase 5：Thinking Path 完整 Agent 紀錄

修改檔案：

- `checkpoint.py`
- `ui/server.py`
- `ui/static/app.js`
- `ui/static/style.css`
- `tests/test_thinking_path.py`
- 視需要補強 `main.py` 的 stage enter / exit payload

做法：

- 在 checkpoint 事件中補齊每個 Agent 的完整紀錄欄位：
  - `agent_input`
  - `agent_output`
  - `tool_calls[]`
  - `llm_calls[]`
  - `skill_file`
  - `input_type`
  - `duration_ms`
  - `status`
  - `degraded`
  - `degradation_reason`
- `_build_thinking_path()` 保留目前 steps timeline，同時新增 `agent_record`：

```json
{
  "agents": {
    "security_guard": {
      "agent_record": {
        "input": {},
        "output": {},
        "tool_calls": [],
        "llm_calls": [],
        "status": "SUCCESS",
        "duration_ms": 1234,
        "skill_file": "security_guard.md",
        "input_type": "code"
      },
      "steps": []
    }
  }
}
```

- 前端 Thinking Path drawer 新增每個 Agent 的完整紀錄區：
  - `Input`
  - `Output`
  - `Tools`
  - `LLM`
  - `Harness / Degradation`
- 對過長內容做 UI 摺疊與下載/複製友善顯示，但 checkpoint 原始 JSONL 仍保留可審計資料。
- 敏感資料仍由 `checkpoint.py` 既有 redaction 處理，不在 UI 顯示 token/API key。

驗收標準：

- 每個有執行的 Agent 都至少有一個 `agent_record`。
- Thinking Path 能顯示 `Security Guard`、`Intel Fusion`、`Scout`、`Analyst`、`Critic`、`Advisor` 的完整輸入/輸出摘要與完整 JSON 展開。
- 若某 Agent degraded，Thinking Path 必須顯示原因，不允許只顯示空白或 unknown。

### Phase 6：向量資料庫定位與 RAG 說明

修改檔案：

- `docs/UI_VULN_EXPLAINER_CRITIC_REPAIR_PLAN_2026-04-24.md`
- `docs/pipeline_guide.md`
- 視需要補充 `docs/data_contracts.md`

做法：

- 文件明確定義資料來源優先順序：
  1. 本次 scan 的 pipeline result。
  2. 本次 scan 的 checkpoint JSONL。
  3. JSON memory history。
  4. LlamaIndex vector store，只作歷史語義輔助。
- UI 不直接用 vector result 當漏洞主資料。
- 若未來啟用 `ENABLE_MEMORY_RAG=true`，RAG 回傳必須標記為 `historical_context`，不可混入 `vulnerability_detail` 當本次 finding。

驗收標準：

- 文件能回答「為什麼不用向量資料庫」。
- 報告來源標記能區分 `pipeline_result`、`checkpoint_jsonl`、`memory_history`、`rag_history_context`。

## 四、資料契約調整

建議新增或保證以下欄位：

```json
{
  "code_patterns_summary": [
    {
      "finding_id": "CODE-001",
      "cwe_id": "CWE-78",
      "line_no": 12,
      "source_location": "Line 12",
      "snippet": "os.system(user_input)",
      "cwe_reference": {
        "name": "OS Command Injection",
        "description_short": "User input is used to build an OS command, allowing arbitrary command execution.",
        "cvss_base": 9.8,
        "source": "MITRE CWE v4.14"
      }
    }
  ],
  "critic_output": {
    "debate_rounds": 2,
    "_debate_meta": {
      "total_rounds": 2,
      "early_stop_reason": "consensus_after_min_rounds",
      "judge_invoked": false
    }
  },
  "thinking_path": {
    "agents": {
      "advisor": {
        "agent_record": {
          "input": {},
          "output": {},
          "tool_calls": [],
          "llm_calls": [],
          "status": "SUCCESS",
          "degraded": false
        }
      }
    }
  }
}
```

## 五、測試計劃

必跑測試：

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_ui_server.py -v
.\.venv\Scripts\python.exe -m pytest tests\test_pipeline_integration.py -v
.\.venv\Scripts\python.exe -m pytest tests\test_sg_to_advisor_flow.py -v
.\.venv\Scripts\python.exe -m pytest tests\test_security_guard.py -v
.\.venv\Scripts\python.exe -m pytest tests\test_thinking_path.py -v
.\.venv\Scripts\python.exe -m pytest tests\ -q
```

必跑 Harness 檢查：

```powershell
$env:PYTHONPATH=(Get-Location).Path; $env:PYTHONIOENCODING='utf-8'; .\.venv\Scripts\python.exe harness\constraints\arch_linter.py
$env:PYTHONIOENCODING='utf-8'; .\.venv\Scripts\python.exe harness\entropy\entropy_scanner.py
```

建議新增測試：

- `tests/test_ui_server.py`
  - 驗證 UI server enrich 後不產生 `unknown` 顯示用欄位。
- `tests/test_sg_to_advisor_flow.py`
  - 驗證 `line_no` 從 Security Guard 保留到 action item。
- `tests/test_debate_engine.py`
  - 驗證有 finding 時至少 2 輪。
  - 驗證無 finding 時允許 1 輪但必須有 early stop reason。
- `tests/test_thinking_path.py`
  - 驗證每個 Agent 都有 `agent_record`。
  - 驗證 Agent 完整 input/output/tool/LLM/degradation 欄位可解析。
  - 驗證敏感資料 redaction 後才出現在 Thinking Path。

## 六、風險與取捨

- UI 禁止 `unknown` 不代表所有內部資料都不能用 unknown。若強行改掉工具層狀態，會破壞 OTX / GHSA / sanitizer 既有資料契約。
- Critic 至少 2 輪會增加 LLM 呼叫成本與時間；建議只對有 finding 的 scan 強制至少 2 輪。
- Thinking Path 完整紀錄會增加 checkpoint JSONL 體積；需要保留 redaction 與長內容摺疊，避免 UI 卡頓。
- 向量資料庫不作主資料源會犧牲部分語義回憶便利性，但可換取 demo 與審計所需的可重現性。
- 若比賽 demo 追求速度，可以用環境變數控制：
  - `MIN_DEBATE_ROUNDS=2`
  - `MAX_DEBATE_ROUNDS=3`
  - 無 finding 時允許早停。

## 七、建議實作順序

1. 先做 UI display sanitizer 與 URGENT 行號顯示，直接修掉截圖中的 `Unknown` 問題。
2. 加入漏洞 glossary，讓 CWE / CVSS / NVD 在 demo 中可立即理解。
3. 修正 Critic / Debate Engine 最少回合規則與 metadata。
4. 擴充 Thinking Path，補齊每個 Agent 的完整紀錄。
5. 補上向量資料庫定位說明，明確把 RAG 放在歷史輔助層。
6. 補測試與文件契約。
7. 跑全套測試與 Harness 檢查。

## 八、審批確認點

請確認是否同意以下決策：

1. `unknown` 禁止範圍先限定在 UI 與最終報告顯示層，內部工具資料契約暫不強行改名。
2. 有 finding 時 Critic 最少跑 2 輪；無 finding 時可 1 輪早停。
3. URGENT code finding 若沒有 line number，顯示 `Line not provided by scanner`，不阻塞整個報告。
4. CWE 說明先使用內建短句與 `tools/cwe_database.py`，不新增外部依賴。
5. Thinking Path 要新增每個 Agent 的完整紀錄，但仍需 redaction，不顯示 secrets。
6. 向量資料庫暫不作本次掃描結果的主資料源，只作 optional historical context。
