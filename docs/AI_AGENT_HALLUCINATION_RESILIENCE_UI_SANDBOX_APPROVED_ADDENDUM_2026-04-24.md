# AI Agent 防幻覺、UI、Rust/Sandbox、CyberGym 已批准補充計劃

> 日期：2026-04-24  
> 關聯主計劃：`docs/AI_AGENT_HALLUCINATION_RESILIENCE_UI_SANDBOX_PLAN_2026-04-24.md`  
> 狀態：已批准，進入實作與驗證

## 已批准決策

1. 允許新增 UI browser e2e dependency：採用 `playwright` 與 `pytest-playwright`。一般 `pytest` 預設不啟動真瀏覽器；需要 UI e2e 時用 `PLAYWRIGHT_E2E=1` 與 `THREATHUNTER_UI_URL` 明確啟動，避免 CI 或本機無 browser 時誤失敗。
2. Runtime Protection 放在主 dashboard：新增 `/api/runtime-capabilities`，主頁直接顯示 Rust Checkpoint Writer、WASM Prompt Sandbox、Docker Sandbox、Memory Sanitizer、AST Guard 的即時狀態。
3. 必須先 build 成可用狀態：Rust crates 與 WASM guest 必須在 demo / CyberGym scoring 前先執行 `python build_rust_crates.py`；若仍回退 Python fallback，UI 必須明確顯示原因，不允許假裝 Rust 已啟用。
4. Sandbox 預設啟用：`.env.example` 與 `main.py` 預設 `SANDBOX_ENABLED=true`。若 Docker daemon 或 image 未就緒，pipeline 可 graceful fallback，但 demo 前應完成 Docker image/selftest。
5. 加入 CyberGym 評分流程：新增 `scripts/run_cybergym_benchmark.py` 作為 CyberGym adapter。CyberGym 需要 Python + Docker，並需外部下載大型 benchmark data；ThreatHunter 不把 130GB/240GB data 放入 repo，只接已安裝的 CyberGym checkout/server。

## 執行流程

1. 安裝 dependency：`python -m pip install -r requirements.txt`
2. 安裝 browser：`python -m playwright install chromium`
3. Build Rust / WASM：`python build_rust_crates.py`
4. Build Docker sandbox：`python -c "from sandbox.docker_sandbox import build_sandbox_image; raise SystemExit(0 if build_sandbox_image() else 1)"`
5. 啟動 UI：`uv run python ui/server.py`
6. Browser e2e：`$env:PLAYWRIGHT_E2E="1"; $env:THREATHUNTER_UI_URL="http://127.0.0.1:1000"; python -m pytest tests/test_ui_browser_e2e.py -v`
7. CyberGym dry-run：`python scripts/run_cybergym_benchmark.py --dry-run --cybergym-dir <path-to-cybergym>`
8. CyberGym scoring：先啟動 CyberGym PoC server，再用 `scripts/run_cybergym_benchmark.py` 生成 task；若已有 `agent_id` 與 `poc.db`，加入 `--agent-id` 與 `--pocdb-path` 產生 `logs/cybergym_score.json`。

## 驗收標準

- 主 dashboard 預設顯示 Runtime Protection，不需要進入 diagnostics 頁。
- Docker Sandbox 預設為 enabled；若顯示 `NOT_READY`，需先處理 daemon/image，而不是把 sandbox 關掉。
- Rust Checkpoint Writer 若顯示 `PY FALLBACK`，代表 build/import 尚未完成，demo 前需修正。
- CyberGym 正式分數只以 CyberGym verify script 與 `logs/cybergym_score.json` 為準；一般 pytest 只驗證 adapter 可用，不偽造分數。
