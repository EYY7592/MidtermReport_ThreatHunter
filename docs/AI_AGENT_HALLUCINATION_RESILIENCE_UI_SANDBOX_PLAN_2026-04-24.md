# AI Agent 幻覺防護、模型失效補償、UI 壓力測試與 Rust/Sandbox 強化計劃

> 日期：2026-04-24  
> 狀態：待審批  
> 適用範圍：ThreatHunter Agent Pipeline、UI、Harness、Rust crates、Sandbox  
> 遵守文件：`project_CONSTITUTION.md`、`AGENTS.md`、`code.md`

---

## 1. 目前防止 AI Agent 幻覺的措施

### 1.1 Constitution 與 Agent prompt 約束

目前 `config.py` 的 `SYSTEM_CONSTITUTION` 已明確要求：

- 所有 CVE ID 必須來自 Tool 回傳資料，禁止憑空捏造。
- Agent 必須使用指定 Tools，不可跳過查證。
- 輸出必須符合 JSON schema。
- 不確定的推理必須標記 `NEEDS_VERIFICATION`。
- 每個判斷都要有 reasoning。

這是第一層「語義約束」，可降低模型自由發揮，但不能單獨作為安全保證。

### 1.2 Tool-first evidence flow

目前 Scout / Intel Fusion / Advisor 透過 NVD、OTX、KEV、EPSS、Exploit、Memory tools 取得資料，並在測試中檢查：

- fake CVE 不應出現在 actions。
- pipeline 不應因 jailbreak/fabrication prompt 崩潰。
- CVE 格式需符合 `CVE-YYYY-NNNN...`。

相關測試包含 `tests/test_redteam.py`、`tests/test_nvd_tool.py`、`tests/test_scout_agent.py`。

### 1.3 Harness schema 與 fallback 驗證

Agent 端已存在多層 Harness：

- JSON extraction 容錯。
- schema validation。
- score/risk range clamp。
- fallback output。
- `_degraded` / `_error` metadata。
- checkpoint trace。

這能避免模型輸出格式錯誤時直接污染 UI 或 pipeline。

### 1.4 L0 Input Sanitizer 與 Memory Sanitizer

`input_sanitizer.py` 目前負責進入 pipeline 前的 L0 防線：

- prompt injection pattern detection。
- jailbreak pattern detection。
- SQL / command / path traversal / hardcoded secret pattern detection。
- input length 與 line count 限制。
- WASM sandbox 可用時先做 L0.5 檢查，不可用時降級為 Python L0。

`sandbox/memory_sanitizer.py` 目前負責 memory 寫入/讀取防護：

- 阻擋 secondary prompt injection。
- 阻擋 XSS / SQL / shell poison pattern。
- 阻擋不合理 CVE 年份。
- 限制單筆 memory 大小。

### 1.5 Deterministic Security Guard

Security Guard 目前不是讓 LLM 自由判斷 code vulnerability，而是用 AST / regex / deterministic pattern 抽取：

- command injection。
- SQL injection。
- XSS。
- SSRF。
- hardcoded secret。
- unsafe deserialization。

這是目前防止 code finding 幻覺最重要的一層，因為 findings 可以回溯到 snippet 與 line number。

### 1.6 Checkpoint / Thinking Path

目前 checkpoint 已記錄：

- `STAGE_ENTER`
- `STAGE_EXIT`
- `LLM_CALL`
- `LLM_RESULT`
- `LLM_RETRY`
- `LLM_ERROR`
- `TOOL_CALL`
- `HARNESS_CHECK`
- `DEGRADATION`

最新 UI Thinking Path 已加上 `agent_record`，可以追溯每個 Agent 的 input、output、LLM calls、tool calls 與 degradation reason。

---

## 2. 模型當掉時的補償機制現況

### 2.1 LLM provider waterfall

`config.py` 已建立 provider chain：

- Google AI primary / backup models。
- OpenRouter fallback。
- vLLM / OpenAI provider path。
- `LLM_TIMEOUT_SEC` timeout。
- model cooldown。
- `mark_model_failed()`。
- `retry_on_429()`。
- shared `rate_limiter` 與 429 retry-after wait。

這能處理 429、quota、timeout、部分 provider failure。

### 2.2 Agent-level fallback

目前各 stage 有 fallback：

- Scout 失敗時回傳空 vulnerabilities 與 `_degraded`。
- Analyst 失敗時保留 Scout vulnerabilities，並把 Security Guard deterministic code patterns 轉成 analysis。
- Critic / Debate Engine 失敗時 fallback 到 conservative `MAINTAIN` 與 `_degraded`。
- Advisor 失敗時依 Analyst analysis 產生 urgent / important / code pattern fallback actions。
- Sandbox / Docker 失敗時 fallback 到 in-process mode。

### 2.3 Degradation UI 與 pipeline_meta

`degradation_status` 會記錄 degraded components，`pipeline_meta` 會保存：

- stage status。
- critic verdict / score。
- degradation level。
- generated_at。
- l0_report。

這讓 UI 可以顯示「系統不是完全成功，而是 degraded success」。

---

## 3. UI 端測試現況與缺口

### 3.1 已有 UI 後端測試

目前存在 `tests/test_ui_server.py`，主要驗證：

- UI backend 優先使用本次 scan-scoped `vulnerability_detail`。
- 缺少 detail 時可從 Advisor actions fallback。
- fallback vulnerability 需標記 `source=ADVISOR_ACTIONS`。

這屬於 UI backend data enrichment 測試。

### 3.2 已有前端靜態檢查

目前已使用：

```bash
node --check ui/static/app.js
```

可確認 JS 語法不壞，但不能驗證 DOM render、SSE flow、按鈕互動、Thinking Path drawer、glossary、line number 顯示。

### 3.3 目前缺口

目前尚未看到完整 UI 端壓力測試：

- 沒有瀏覽器層級 e2e 測試。
- 沒有模擬 SSE 大量事件。
- 沒有測試 800+ vulnerabilities / code patterns 時 UI 是否卡住。
- 沒有測試 malformed API response 時 UI 是否保持可用。
- 沒有測試 unknown 顯示治理是否在 DOM 最終畫面消失。
- 沒有測試 Thinking Path 大 checkpoint 檔載入時間與 drawer render。

---

## 4. Rust 與 Sandbox 目前作用

### 4.1 Rust 目前作用

目前 repo 內有 `rust/` workspace 與 `build_rust_crates.py`，包含：

- `checkpoint_writer`：Rust BufWriter + Mutex，降低大量 checkpoint I/O 壓力。
- `prompt_sandbox`：WASM Runtime Sandbox Host。
- `prompt_sandbox_guest`：WASM guest prompt guard。
- `memory_validator`：預期作為 memory 驗證加速/強化。
- `json_validator`：預期作為 JSON / CVE validation。
- `sanitizer`：預期作為 sanitizer acceleration。
- `url_builder`：預期作為 URL validation/build helper。

目前 `checkpoint.py` 已優先嘗試 import `threathunter_checkpoint_writer`；不可用時自動降級 Python writer。

### 4.2 Rust 目前缺口

目前 Rust 的作用在 UI 與報告中不夠透明：

- UI 沒有顯示 checkpoint writer backend 是 Rust 還是 Python fallback。
- prompt sandbox 可用性沒有在 UI health / diagnostics 明確呈現。
- Rust crates 若未編譯，多數流程會靜默 fallback，demo 時不容易說明其作用。
- tests 會 skip 未編譯 Rust crate 的部分測試，但目前沒有「Rust disabled 時 UI 必須明確標示 fallback」的驗證。

### 4.3 Sandbox 目前作用

目前 Sandbox 分三類：

- Python AST Guard：防 AST bomb / parse timeout，保護 Security Guard。
- Memory Sanitizer：防 prompt injection / poison memory / fake CVE memory。
- Docker Sandbox：可用 `SANDBOX_ENABLED=true` 把 pipeline 放進 Docker，以 `--network none`、`--read-only`、non-root、seccomp、memory/cpu/pid limit 執行。
- WASM Prompt Sandbox：可用時在 input sanitizer 前段做 L0.5 prompt guard。

### 4.4 Sandbox 目前缺口

- Docker sandbox 預設未必啟用，UI 沒有清楚顯示目前是否 in-process / docker isolated。
- WASM sandbox 不可用時會 fallback，但 UI 沒有顯示 fallback reason。
- Sandbox selftest 尚未整合到 UI diagnostics。
- 缺少 UI 端展示「Sandbox 已保護哪些層」的可視化。

---

## 5. 修復與強化計劃

### Phase 1：建立防幻覺狀態總表

目標：讓 demo 評審一眼看到「每個結論是否有 evidence」。

任務：

- 在 `pipeline_meta` 新增 `evidence_integrity` 區塊。
- 記錄每個 CVE / CWE finding 的 source type：`TOOL_VERIFIED`、`DETERMINISTIC_CODE_PATTERN`、`ADVISOR_FALLBACK`、`NEEDS_VERIFICATION`。
- 在 UI report lineage 顯示 evidence integrity badges。
- 對沒有 source 的 finding 一律標成 `NEEDS_VERIFICATION`，不可靜默顯示為 verified。

驗證：

```bash
python -m pytest tests/test_ui_server.py -v
python -m pytest tests/test_pipeline_integration.py -v
python -m pytest tests/test_redteam.py -v -k "fabrication"
```

### Phase 2：強化 model failure 補償可觀測性

目標：模型當掉時，不只 fallback，還要讓 UI / Thinking Path 看得懂發生什麼事。

任務：

- 在每個 fallback output 補齊 `_fallback_strategy`、`_fallback_source`、`_confidence_floor`。
- 在 `checkpoint.py` 的 `DEGRADATION` event 補充 `recoverable=true/false`。
- UI 顯示「Model failed -> fallback path -> final confidence」。
- Critic/Debate fallback 需顯示是否有跑滿最低回合，若沒有要說明原因。

驗證：

```bash
python -m pytest tests/test_thinking_path.py -v
python -m pytest tests/test_debate_engine.py -v
python -m pytest tests/test_pipeline_integration.py -v
```

### Phase 3：新增 UI 端壓力測試

目標：補足目前只有 backend/JS syntax 測試、沒有 UI render 壓力測試的缺口。

任務：

- 新增 `tests/test_ui_static_render_contract.py`，以 fixture 驗證 `app.js` 必須包含 glossary、affected-line、Thinking Path agent record renderer。
- 新增 mock result JSON fixture：大量 CVEs、大量 code patterns、大量 checkpoint events。
- 新增輕量 DOM contract 測試，確認前端輸出不包含 visible `Unknown/unknown/UNKNOWN`。
- 若允許新增 dev dependency，再新增 Playwright e2e：
  - scan result render。
  - SSE event replay。
  - Thinking Path drawer open/close。
  - 1000 events render performance smoke test。

不新增 dependency 的替代方案：

- 使用現有 `node --check`。
- 加上純文字 contract tests。
- 用 FastAPI TestClient 測 API response。

驗證：

```bash
node --check ui/static/app.js
python -m pytest tests/test_ui_server.py -v
python -m pytest tests/test_ui_static_render_contract.py -v
```

### Phase 4：Rust / Sandbox 狀態顯示與自測

目標：讓 Rust 與 Sandbox 的作用在 demo 中可見、可驗證、可解釋。

任務：

- 新增 `/api/runtime-capabilities`：
  - checkpoint_writer_backend：`rust` / `python_fallback`
  - wasm_prompt_sandbox：`enabled` / `fallback`
  - docker_sandbox：`enabled` / `not_ready` / `disabled`
  - memory_sanitizer：`active`
  - ast_guard：`active`
- UI 新增 Runtime Protection panel。
- Thinking Path 顯示 checkpoint writer backend。
- Docker sandbox selftest 結果可從 UI diagnostics 查看。
- Rust crates 未編譯時，UI 顯示「fallback active」而不是沉默。

驗證：

```bash
python -m pytest tests/test_checkpoint_writer.py -v
python -m pytest tests/test_prompt_sandbox.py -v
python -m pytest tests/test_docker_sandbox.py -v
python -m pytest tests/test_sandbox.py -v
```

### Phase 5：建立 Demo-grade 故障注入測試

目標：在 hackathon demo 前證明「模型當掉、工具當掉、sandbox 不可用」都可安全降級。

任務：

- 新增 failure injection tests：
  - LLM timeout。
  - 429 rate limit。
  - NVD API unavailable。
  - malformed tool response。
  - Rust checkpoint writer unavailable。
  - Docker image missing。
  - WASM sandbox unavailable。
- 每個測試需驗證：
  - pipeline 不崩潰。
  - UI 有 degradation reason。
  - final output 不標成 fully verified。
  - Thinking Path 有完整紀錄。

驗證：

```bash
python -m pytest tests/test_failure_injection.py -v
python -m pytest tests/ -v
python harness/constraints/arch_linter.py
python harness/entropy/entropy_scanner.py
```

---

## 6. 優先順序建議

建議先做：

1. Phase 4 Runtime Protection panel，因為能直接回答「Rust 和 Sandbox 的作用」。
2. Phase 3 UI 壓力測試，因為目前這是最明顯缺口。
3. Phase 2 model failure 可觀測性，讓 fallback 不只是暗中發生。
4. Phase 1 evidence integrity badges，讓防幻覺能力更容易被評審理解。
5. Phase 5 failure injection，作為 demo 前最終保險。

---

## 7. 審批決策點

請審批以下方向：

- 是否允許新增 UI browser e2e dependency，例如 Playwright。
- Runtime Protection panel 是否放在主 dashboard，或獨立 `/diagnostics` 頁。
- Rust crates 若未編譯，demo 是否接受 fallback mode，還是必須先 build 成可用狀態。
- Docker sandbox 是否要在 hackathon demo 預設啟用，或只作為可選 isolation mode。

