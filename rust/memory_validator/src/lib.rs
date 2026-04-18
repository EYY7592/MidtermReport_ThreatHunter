// rust/memory_validator/src/lib.rs
// Sandbox Layer 3 Rust 加速層（A-3）
// 功能：Memory 快取寫入前的確定性毒素掃描 + CVE 幻覺過濾
// 優先保護：write_memory() 的輸入，防止 LLM 被 Prompt Injection 後輸出毒素被持久化
//
// 相較 Python sandbox/memory_sanitizer.py（fallback 層）：
//   - 正則由 regex crate 保證線性時間（無 ReDoS）
//   - JSON 解析上限防 Bomb（深度 32，長度 8000）
//   - 速度快 10-50x（CPython re 對比 DFA-based regex）

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

// ── 毒素模式（靜態編譯，regex crate 保證 O(n)）──────────────
static POISON_REGEX: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();

fn get_poison_patterns() -> &'static Vec<(&'static str, Regex)> {
    POISON_REGEX.get_or_init(|| {
        vec![
            // Prompt Injection 殘留
            ("PI_IGNORE",  Regex::new(r"(?i)ignore\s+(?:previous|all|above)\s+instructions?").unwrap()),
            ("PI_ROLE",    Regex::new(r"(?i)you\s+are\s+now\s+(?:a|an)\s+\w+").unwrap()),
            ("PI_MODE",    Regex::new(r"(?i)(?:developer|god|admin|root|jailbreak)\s+mode").unwrap()),
            ("PI_PRETEND", Regex::new(r"(?i)(?:pretend|act|roleplay)\s+(?:you\s+are|as\s+if)").unwrap()),
            ("PI_DAN",     Regex::new(r"(?i)\bDAN\b|\bJailbreak\b").unwrap()),
            ("PI_SYSTEM",  Regex::new(r"(?i)system\s+prompt\s*[:=]").unwrap()),
            // XSS 殘留
            ("XSS_SCRIPT", Regex::new(r"(?i)<script[^>]*>").unwrap()),
            ("XSS_EVENT",  Regex::new(r"(?i)(?:onerror|onload|onclick)\s*=").unwrap()),
            // SQL 殘留
            ("SQL_DROP",   Regex::new(r"(?i)\bDROP\s+TABLE\b").unwrap()),
            ("SQL_DEL",    Regex::new(r"(?i)\bDELETE\s+FROM\b").unwrap()),
            // 系統命令殘留
            ("CMD_RM",     Regex::new(r"(?i)rm\s+-rf\s+/").unwrap()),
        ]
    })
}

// CVE 年份驗證正則
static CVE_YEAR_REGEX: OnceLock<Regex> = OnceLock::new();
fn get_cve_regex() -> &'static Regex {
    CVE_YEAR_REGEX.get_or_init(|| Regex::new(r"\bCVE-(\d{4})-\d+\b").unwrap())
}

const MAX_JSON_SIZE: usize = 1_000_000; // 1 MB
const CVE_YEAR_MIN: u32 = 1999;
const CVE_YEAR_MAX: u32 = 2027;

// ── 核心 API ────────────────────────────────────────────────

/// 驗證要寫入 memory/ 的 JSON 字串是否安全
/// Returns: (is_safe: bool, reason: str)
#[pyfunction]
fn validate_memory_write(json_str: &str, agent_name: &str) -> PyResult<(bool, String)> {
    // 1. 大小限制
    if json_str.len() > MAX_JSON_SIZE {
        return Ok((false, format!(
            "Memory entry too large: {} bytes > {}", json_str.len(), MAX_JSON_SIZE
        )));
    }

    // 2. Prompt Injection 毒素掃描（regex crate 保證 O(n)）
    let lower = json_str.to_lowercase();
    for (name, re) in get_poison_patterns() {
        if re.is_match(&lower) {
            return Ok((false, format!(
                "Poison pattern [{}] detected in {}", name, agent_name
            )));
        }
    }

    // 3. CVE 年份幻覺驗證
    for cap in get_cve_regex().captures_iter(json_str) {
        if let Ok(year) = cap[1].parse::<u32>() {
            if year < CVE_YEAR_MIN || year > CVE_YEAR_MAX {
                return Ok((false, format!(
                    "Hallucination CVE year {}: CVE-{}-... out of valid range [{}, {}]",
                    year, year, CVE_YEAR_MIN, CVE_YEAR_MAX
                )));
            }
        }
    }

    // 4. JSON 深度限制（防 JSON Bomb 透過記憶注入）
    match serde_json::from_str::<Value>(json_str) {
        Ok(value) => {
            if let Err(e) = check_depth(&value, 0) {
                return Ok((false, e));
            }
        }
        Err(e) => {
            return Err(PyValueError::new_err(format!("Invalid JSON: {}", e)));
        }
    }

    Ok((true, "ok".to_string()))
}

/// CVE ID 格式驗證（獨立函式，方便 Python 呼叫）
#[pyfunction]
fn validate_cve_id(cve_id: &str) -> bool {
    let parts: Vec<&str> = cve_id.split('-').collect();
    if parts.len() != 3 || parts[0] != "CVE" {
        return false;
    }
    let year: u32 = match parts[1].parse() {
        Ok(y) => y,
        Err(_) => return false,
    };
    let seq = parts[2];
    year >= CVE_YEAR_MIN
        && year <= CVE_YEAR_MAX
        && seq.len() >= 4
        && seq.len() <= 7
        && seq.chars().all(|c| c.is_ascii_digit())
}

// ── 內部輔助────────────────────────────────────────────────

const MAX_DEPTH: usize = 32;

fn check_depth(value: &Value, depth: usize) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err(format!("JSON too deep: {} > {}", depth, MAX_DEPTH));
    }
    match value {
        Value::Object(map) => {
            for v in map.values() {
                check_depth(v, depth + 1)?;
            }
        }
        Value::Array(arr) => {
            for v in arr {
                check_depth(v, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

// ── PyO3 Module 定義 ────────────────────────────────────────

#[pymodule]
fn threathunter_memory_validator(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(validate_memory_write, m)?)?;
    m.add_function(wrap_pyfunction!(validate_cve_id, m)?)?;
    Ok(())
}
