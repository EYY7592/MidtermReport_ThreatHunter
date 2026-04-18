//! threathunter_prompt_sandbox — L0.5 WASM Runtime Sandbox 主機端
//! ==================================================================
//! 架構：wasmtime Engine + PyO3 Python 綁定
//!
//! 安全層定位：
//!   L0.5（本模組）← 輸入進 Pipeline 前，在 WASM 沙箱內過濾
//!   L0  Rust Sanitizer（rust/sanitizer/）← blocklist + sha256
//!   L1  AST Guard（harness/）
//!   L2  Docker Sandbox（sandbox/）
//!   L3  Memory Sanitizer（memory/）← 輸出端
//!
//! 暴露給 Python 的介面：
//!   sandbox_eval(input, max_bytes) -> str  # JSON 結果
//!   sandbox_version()              -> str
//!   sandbox_reload_wasm(path)      -> None # 熱換 .wasm 模組
//!   sandbox_stats()                -> str  # 統計 JSON
//!
//! Graceful Degradation：
//!   若 WASM 載入失敗（如 .wasm 不存在），所有輸入改為
//!   直接用 Rust pure-function 層過濾（不呼叫 wasmtime）

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pyo3::prelude::*;
use sha2::{Digest, Sha256};
use wasmtime::{Engine, Instance, Module, Store};

// ── 版本常數 ────────────────────────────────────────────────
const VERSION: &str = "1.0.0-phase4c";
const MAX_DEFAULT_BYTES: usize = 512 * 1024; // 512KB

// ── 結果碼（與 WASM Guest 對齊）──────────────────────────────
const CODE_ALLOW:    u32 = 0;
const CODE_BLOCK:    u32 = 1;
const CODE_SANITIZE: u32 = 2;
const CODE_TRUNCATE: u32 = 3;

// ── 預設 .wasm 路徑（相對於此 crate 目錄，在 build_rust_crates.py 複製）──
fn default_wasm_path() -> PathBuf {
    // 嘗試從 lib 旁找 assets/prompt_guard.wasm
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("assets");
    p.push("prompt_guard.wasm");
    p
}

// ══════════════════════════════════════════════════════════════
// WasmEngine — per-process 單例（wasmtime Engine 是執行緒安全的）
// ══════════════════════════════════════════════════════════════

struct WasmSandbox {
    engine: Engine,
    module: Option<Module>,
    wasm_path: PathBuf,
    loaded_hash: Option<String>,
    call_count: u64,
    block_count: u64,
    fallback_mode: bool, // wasmtime 不可用時退到純 Rust 過濾
}

impl WasmSandbox {
    fn new(wasm_path: PathBuf) -> Self {
        let engine = Engine::default();
        let mut sandbox = WasmSandbox {
            engine,
            module: None,
            wasm_path,
            loaded_hash: None,
            call_count: 0,
            block_count: 0,
            fallback_mode: false,
        };
        sandbox.try_load_module();
        sandbox
    }

    fn try_load_module(&mut self) {
        if !self.wasm_path.exists() {
            eprintln!(
                "[PromptSandbox] WARN: .wasm not found at {:?}, using fallback Rust filter",
                self.wasm_path
            );
            self.fallback_mode = true;
            return;
        }

        match std::fs::read(&self.wasm_path) {
            Ok(bytes) => {
                let hash = sha256_hex(&bytes);
                match Module::new(&self.engine, &bytes) {
                    Ok(module) => {
                        self.module = Some(module);
                        self.loaded_hash = Some(hash);
                        self.fallback_mode = false;
                        eprintln!(
                            "[PromptSandbox] WASM loaded OK | path={:?} | sha256={}",
                            self.wasm_path,
                            self.loaded_hash.as_deref().unwrap_or("?")
                        );
                    }
                    Err(e) => {
                        eprintln!("[PromptSandbox] WARN: WASM compile failed: {e}, using fallback");
                        self.fallback_mode = true;
                    }
                }
            }
            Err(e) => {
                eprintln!("[PromptSandbox] WARN: Cannot read .wasm: {e}, using fallback");
                self.fallback_mode = true;
            }
        }
    }

    fn reload(&mut self, new_path: Option<&Path>) {
        if let Some(p) = new_path {
            self.wasm_path = p.to_path_buf();
        }
        self.module = None;
        self.loaded_hash = None;
        self.try_load_module();
    }

    fn eval(&mut self, input: &str, max_bytes: usize) -> EvalResult {
        self.call_count += 1;

        // ── Fallback：純 Rust 過濾（wasmtime 不可用時）─────────
        if self.fallback_mode || self.module.is_none() {
            let r = rust_filter(input, max_bytes);
            if r.code != CODE_ALLOW {
                self.block_count += 1;
            }
            return r;
        }

        // ── WASM 路徑 ────────────────────────────────────────────
        let t0 = Instant::now();
        match self.eval_wasm(input, max_bytes) {
            Ok(r) => {
                if r.code != CODE_ALLOW {
                    self.block_count += 1;
                }
                r
            }
            Err(e) => {
                // WASM 執行錯誤 → 降級到 Rust fallback
                eprintln!("[PromptSandbox] WASM eval error: {e}, fallback to Rust filter");
                self.fallback_mode = true;
                let r = rust_filter(input, max_bytes);
                if r.code != CODE_ALLOW {
                    self.block_count += 1;
                }
                r
            }
        }
    }

    fn eval_wasm(&self, input: &str, max_bytes: usize) -> Result<EvalResult, String> {
        let module = self.module.as_ref().unwrap();
        let mut store = Store::new(&self.engine, ());

        let instance = Instance::new(&mut store, module, &[])
            .map_err(|e| format!("Instance::new failed: {e}"))?;

        // 取得 WASM 匯出的函式和記憶體
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| "WASM has no 'memory' export".to_string())?;

        let get_buffer_ptr = instance
            .get_typed_func::<(), i32>(&mut store, "get_buffer_ptr")
            .map_err(|e| format!("get_buffer_ptr: {e}"))?;

        let eval_input = instance
            .get_typed_func::<(i32, i32), u32>(&mut store, "eval_input")
            .map_err(|e| format!("eval_input: {e}"))?;

        let get_result_ptr = instance
            .get_typed_func::<(), i32>(&mut store, "get_result_ptr")
            .map_err(|e| format!("get_result_ptr: {e}"))?;

        let get_result_len = instance
            .get_typed_func::<(), i32>(&mut store, "get_result_len")
            .map_err(|e| format!("get_result_len: {e}"))?;

        // 截斷輸入（max_bytes）
        let input_bytes = if input.len() > max_bytes {
            &input.as_bytes()[..max_bytes]
        } else {
            input.as_bytes()
        };
        let input_len = input_bytes.len() as i32;

        // 取 buffer 指標，寫入輸入資料
        let buf_ptr = get_buffer_ptr.call(&mut store, ())
            .map_err(|e| format!("get_buffer_ptr call: {e}"))?;
        let offset = buf_ptr as usize;

        // 寫入 WASM 線性記憶體
        let mem_data = memory.data_mut(&mut store);
        let end = offset + input_bytes.len();
        if end > mem_data.len() {
            return Err(format!("WASM memory too small: need {end}, have {}", mem_data.len()));
        }
        mem_data[offset..end].copy_from_slice(input_bytes);

        // 呼叫評估函式
        let code = eval_input.call(&mut store, (buf_ptr, input_len))
            .map_err(|e| format!("eval_input call: {e}"))?;

        // 讀取結果 JSON
        let res_ptr = get_result_ptr.call(&mut store, ()).map_err(|e| format!("get_result_ptr call: {e}"))? as usize;
        let res_len = get_result_len.call(&mut store, ()).map_err(|e| format!("get_result_len call: {e}"))? as usize;

        let mem_data = memory.data(&store);
        let res_end = (res_ptr + res_len).min(mem_data.len());
        let json_str = std::str::from_utf8(&mem_data[res_ptr..res_end])
            .unwrap_or(r#"{"code":0,"verdict":"ALLOW","reason":"utf8_error"}"#)
            .to_owned();

        Ok(EvalResult {
            code,
            json: json_str,
            engine: "wasm",
        })
    }
}

// ══════════════════════════════════════════════════════════════
// Rust Fallback Filter（不依賴 wasmtime，作為降級保障）
// ══════════════════════════════════════════════════════════════

struct EvalResult {
    code: u32,
    json: String,
    engine: &'static str,
}

fn rust_filter(input: &str, max_bytes: usize) -> EvalResult {
    // 長度截斷
    if input.len() > max_bytes {
        return make_result(CODE_TRUNCATE, "TRUNCATE", "input_too_large", "rust");
    }

    // Prompt injection 模式
    let lower = input.to_lowercase();
    const INJECTION_PATS: &[&str] = &[
        "ignore all previous",
        "ignore previous instructions",
        "disregard all",
        "forget your instructions",
        "you are now",
        "developer mode",
        "jailbreak",
        "pretend you are",
        "act as if you are",
        "system prompt:",
        "new instructions:",
        "override previous",
        "bypass your",
        "do anything now",
        "dan mode",
    ];
    for pat in INJECTION_PATS {
        if lower.contains(pat) {
            return make_result(CODE_BLOCK, "BLOCK", "prompt_injection", "rust");
        }
    }

    // AST Bomb 前驅
    let mut depth: i32 = 0;
    let mut max_depth: i32 = 0;
    for ch in input.chars() {
        match ch {
            '(' | '[' | '{' => {
                depth += 1;
                max_depth = max_depth.max(depth);
                if max_depth > 50 {
                    return make_result(CODE_BLOCK, "BLOCK", "ast_bomb_pattern", "rust");
                }
            }
            ')' | ']' | '}' => {
                depth = (depth - 1).max(0);
            }
            _ => {}
        }
    }

    // SQL/OS injection
    const CODE_INJ_PATS: &[&str] = &[
        "drop table", "drop database", "; drop", "union select",
        "' or '1'='1", "exec xp_", "; cat /etc/passwd", "| cat /etc/passwd",
        "nc -e /bin/sh",
    ];
    for pat in CODE_INJ_PATS {
        if lower.contains(pat) {
            return make_result(CODE_BLOCK, "BLOCK", "code_injection", "rust");
        }
    }

    make_result(CODE_ALLOW, "ALLOW", "ok", "rust")
}

fn make_result(code: u32, verdict: &str, reason: &str, engine: &'static str) -> EvalResult {
    EvalResult {
        code,
        json: format!(r#"{{"code":{code},"verdict":"{verdict}","reason":"{reason}"}}"#),
        engine,
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

// ══════════════════════════════════════════════════════════════
// 全域 Sandbox 狀態（Mutex 保護，允許多執行緒）
// ══════════════════════════════════════════════════════════════

static SANDBOX: std::sync::OnceLock<Arc<Mutex<WasmSandbox>>> = std::sync::OnceLock::new();

fn get_sandbox() -> Arc<Mutex<WasmSandbox>> {
    SANDBOX
        .get_or_init(|| {
            Arc::new(Mutex::new(WasmSandbox::new(default_wasm_path())))
        })
        .clone()
}

// ══════════════════════════════════════════════════════════════
// PyO3 暴露給 Python 的介面
// ══════════════════════════════════════════════════════════════

/// 評估輸入安全性（L0.5 WASM 沙箱）
///
/// Args:
///   input:     使用者輸入字串
///   max_bytes: 輸入長度上限（預設 524288 = 512KB）
///
/// Returns:
///   JSON 字串：{"code": N, "verdict": "ALLOW/BLOCK/SANITIZE/TRUNCATE", "reason": "..."}
///   code: 0=ALLOW, 1=BLOCK, 2=SANITIZE, 3=TRUNCATE
#[pyfunction]
#[pyo3(signature = (input, max_bytes=MAX_DEFAULT_BYTES))]
fn sandbox_eval(input: &str, max_bytes: usize) -> PyResult<String> {
    let sandbox = get_sandbox();
    let mut guard = sandbox.lock().map_err(|e| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("Sandbox lock poisoned: {e}"))
    })?;
    let result = guard.eval(input, max_bytes);
    // 補充 engine 欄位到 JSON
    let mut json = result.json;
    if json.ends_with('}') {
        json.pop();
        json.push_str(&format!(r#","engine":"{}"}}"#, result.engine));
    }
    Ok(json)
}

/// 回傳 WASM Sandbox 版本資訊
#[pyfunction]
fn sandbox_version() -> &'static str {
    VERSION
}

/// 熱換 WASM 模組（不需重啟 Python 進程）
///
/// Args:
///   path: 新的 .wasm 檔案路徑（若為空字串則重載原路徑）
#[pyfunction]
#[pyo3(signature = (path=""))]
fn sandbox_reload_wasm(path: &str) -> PyResult<()> {
    let sandbox = get_sandbox();
    let mut guard = sandbox.lock().map_err(|e| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("Sandbox lock poisoned: {e}"))
    })?;
    let new_path = if path.is_empty() {
        None
    } else {
        Some(Path::new(path))
    };
    guard.reload(new_path);
    Ok(())
}

/// 取得 Sandbox 運行統計
///
/// Returns:
///   JSON: {"call_count": N, "block_count": N, "fallback_mode": bool,
///          "wasm_loaded": bool, "wasm_hash": "...", "version": "..."}
#[pyfunction]
fn sandbox_stats() -> PyResult<String> {
    let sandbox = get_sandbox();
    let guard = sandbox.lock().map_err(|e| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("Sandbox lock: {e}"))
    })?;
    Ok(format!(
        r#"{{"call_count":{call},"block_count":{block},"fallback_mode":{fb},"wasm_loaded":{loaded},"wasm_hash":"{hash}","version":"{ver}"}}"#,
        call    = guard.call_count,
        block   = guard.block_count,
        fb      = guard.fallback_mode,
        loaded  = guard.module.is_some(),
        hash    = guard.loaded_hash.as_deref().unwrap_or("none"),
        ver     = VERSION,
    ))
}

// ── Python 模組宣告 ──────────────────────────────────────────
#[pymodule]
fn threathunter_prompt_sandbox(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sandbox_eval, m)?)?;
    m.add_function(wrap_pyfunction!(sandbox_version, m)?)?;
    m.add_function(wrap_pyfunction!(sandbox_reload_wasm, m)?)?;
    m.add_function(wrap_pyfunction!(sandbox_stats, m)?)?;
    m.add("VERSION", VERSION)?;
    m.add("CODE_ALLOW",    CODE_ALLOW)?;
    m.add("CODE_BLOCK",    CODE_BLOCK)?;
    m.add("CODE_SANITIZE", CODE_SANITIZE)?;
    m.add("CODE_TRUNCATE", CODE_TRUNCATE)?;
    Ok(())
}
