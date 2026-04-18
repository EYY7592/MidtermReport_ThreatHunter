// rust/json_validator/src/lib.rs
// A-2: LLM Output Parser Rust 加速層（最重要的防線）
// 功能：安全解析來自 LLM 的 JSON 輸出，防止 JSON Bomb + Secondary Injection
//
// 防禦的攻擊場景：
//   用戶貼入含惡意注釋的程式碼
//   → LLM 被 Secondary Prompt Injection 操控
//   → 輸出 JSON Bomb（巢狀深度 10000）或 schema bypass payload
//   → Python json.loads 無深度限制 → 記憶體耗盡
//
// 現有風險點（ui/server.py）：
//   line 109: scout_data = json.loads(raw)
//   line 114: inner = json.loads(inner)
//   line 389: evt = json.loads(line)
//   line 542: evt = json.loads(line)
//   line 616: events.append(json.loads(line))

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

const MAX_DEPTH: usize = 32;
const MAX_STRING_LEN: usize = 8_000;
const MAX_ARRAY_LEN: usize = 10_000;

// CVE 格式驗證
static CVE_REGEX: OnceLock<Regex> = OnceLock::new();
fn get_cve_regex() -> &'static Regex {
    CVE_REGEX.get_or_init(|| Regex::new(r"^\bCVE-(\d{4})-(\d{4,7})\b$").unwrap())
}

// ── 核心函式 ────────────────────────────────────────────────

/// 安全解析 JSON（深度限制 + 字串長度限制 + 陣列長度限制）
/// Returns: 淨化後的 JSON 字串（可直接 json.loads）
#[pyfunction]
fn safe_parse_json(json_str: &str) -> PyResult<String> {
    // 快速大小前置檢查
    if json_str.len() > 10_000_000 {
        return Err(PyValueError::new_err(
            "JSON input too large (> 10 MB)"
        ));
    }

    let value: Value = serde_json::from_str(json_str)
        .map_err(|e| PyValueError::new_err(format!("JSON parse error: {}", e)))?;

    // 深度 + 長度驗證
    validate_value(&value, 0)?;

    Ok(serde_json::to_string(&value).unwrap())
}

/// CVE ID 格式與年份驗證
#[pyfunction]
fn validate_cve_id(cve_id: &str) -> bool {
    let re = get_cve_regex();
    if let Some(cap) = re.captures(cve_id) {
        let year: u32 = cap[1].parse().unwrap_or(0);
        let seq_len = cap[2].len();
        year >= 1999 && year <= 2027 && seq_len >= 4 && seq_len <= 7
    } else {
        false
    }
}

/// 批量驗證 CVE ID 列表（用於 Scout 輸出的 vulnerabilities 陣列）
#[pyfunction]
fn validate_cve_list(cve_ids: Vec<String>) -> Vec<(String, bool)> {
    cve_ids.into_iter()
        .map(|id| {
            let valid = validate_cve_id(&id);
            (id, valid)
        })
        .collect()
}

// ── 內部驗證函式 ────────────────────────────────────────────

fn validate_value(value: &Value, depth: usize) -> PyResult<()> {
    if depth > MAX_DEPTH {
        return Err(PyValueError::new_err(format!(
            "JSON Bomb rejected: depth {} exceeds limit {}", depth, MAX_DEPTH
        )));
    }

    match value {
        Value::String(s) => {
            if s.len() > MAX_STRING_LEN {
                return Err(PyValueError::new_err(format!(
                    "String too long: {} chars > limit {}", s.len(), MAX_STRING_LEN
                )));
            }
        }
        Value::Object(map) => {
            for v in map.values() {
                validate_value(v, depth + 1)?;
            }
        }
        Value::Array(arr) => {
            if arr.len() > MAX_ARRAY_LEN {
                return Err(PyValueError::new_err(format!(
                    "Array too long: {} items > limit {}", arr.len(), MAX_ARRAY_LEN
                )));
            }
            for v in arr {
                validate_value(v, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

// ── PyO3 Module 定義 ────────────────────────────────────────

#[pymodule]
fn threathunter_json_validator(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(safe_parse_json, m)?)?;
    m.add_function(wrap_pyfunction!(validate_cve_id, m)?)?;
    m.add_function(wrap_pyfunction!(validate_cve_list, m)?)?;
    Ok(())
}
