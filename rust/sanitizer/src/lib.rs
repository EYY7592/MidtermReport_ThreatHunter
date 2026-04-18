// rust/sanitizer/src/lib.rs
// A-1: L0 Input Sanitizer Rust 加速層
// 功能：blocklist 掃描 + SHA256，使用 regex crate（O(n)，無 ReDoS）

use pyo3::prelude::*;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

// ── 靜態 Blocklist 模式（O(n) 保證）────────────────────────
static BLOCKLIST: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();

fn get_blocklist() -> &'static Vec<(&'static str, Regex)> {
    BLOCKLIST.get_or_init(|| {
        vec![
            // Command Injection
            ("CMD_SHELL",      Regex::new(r"(?:;|\||\|\||\&\&)\s*(?:bash|sh|cmd|powershell|python|perl|ruby|nc|ncat|netcat)").unwrap()),
            ("CMD_BACKTICK",   Regex::new(r"`[^`]+`").unwrap()),
            ("CMD_DOLLAR_SUB", Regex::new(r"\$\([^)]+\)").unwrap()),
            // Path Traversal
            ("PATH_TRAVERSE",  Regex::new(r"\.\.[/\\]").unwrap()),
            ("PATH_ABSOLUTE",  Regex::new(r"(?:/etc/passwd|/etc/shadow|/proc/\d+|C:\\Windows)").unwrap()),
            // Prompt Injection
            ("PI_IGNORE",      Regex::new(r"(?i)ignore\s+(?:previous|all|above)\s+instructions?").unwrap()),
            ("PI_JAILBREAK",   Regex::new(r"(?i)\b(?:DAN|jailbreak|developer\s+mode)\b").unwrap()),
            ("PI_ROLE",        Regex::new(r"(?i)you\s+are\s+now\s+(?:a|an)\s+\w+").unwrap()),
            // Script Injection
            ("XSS_SCRIPT",     Regex::new(r"(?i)<script[^>]*>").unwrap()),
            ("SQL_UNION",      Regex::new(r"(?i)\bUNION\s+(?:ALL\s+)?SELECT\b").unwrap()),
            ("SQL_DROP",       Regex::new(r"(?i)\bDROP\s+TABLE\b").unwrap()),
            // SSRF
            ("SSRF_INTERNAL",  Regex::new(r"(?i)(?:localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.\d+\.\d+)").unwrap()),
            ("URL_INJECT",     Regex::new(r"%0[dD]%0[aA]").unwrap()),
        ]
    })
}

// 輸入類型偵測模式
static TYPE_PATTERNS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();

fn get_type_patterns() -> &'static Vec<(&'static str, Regex)> {
    TYPE_PATTERNS.get_or_init(|| {
        vec![
            ("injection", Regex::new(r"(?i)(?:ignore\s+previous|jailbreak|you\s+are\s+now|DAN\b)").unwrap()),
            ("code",      Regex::new(r"(?:def\s+\w+\s*\(|class\s+\w+\s*[:(]|import\s+\w+|function\s+\w+\s*\()").unwrap()),
            ("config",    Regex::new(r#"(?:apiVersion:|version:\s+["']?\d)"#).unwrap()),
            ("pkg",       Regex::new(r"(?:\w[\w\-.]+(?:\s+\d+[\d.]+)?(?:,\s*\w[\w\-.]+)*\s*$)").unwrap()),
        ]
    })
}

// ── 核心函式 ────────────────────────────────────────────────

/// 掃描輸入是否包含 blocklist 模式（O(n) 保證，無 ReDoS）
#[pyfunction]
fn scan_blocklist(text: &str) -> Vec<(String, String)> {
    let text_limited = if text.len() > 500_000 {
        &text[..500_000]
    } else {
        text
    };

    let mut hits = Vec::new();
    for (name, re) in get_blocklist() {
        if let Some(m) = re.find(text_limited) {
            let snippet: String = m.as_str().chars().take(80).collect();
            hits.push((name.to_string(), snippet));
        }
    }
    hits
}

/// 偵測輸入類型（pkg / code / config / injection）
#[pyfunction]
fn infer_input_type(text: &str) -> String {
    let text_limited = if text.len() > 50_000 {
        &text[..50_000]
    } else {
        text
    };

    for (type_name, re) in get_type_patterns() {
        if re.is_match(text_limited) {
            return type_name.to_string();
        }
    }
    "pkg".to_string()
}

/// 計算 SHA-256（用於輸入去重與審計追蹤）
#[pyfunction]
fn sha256_hex(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// 長度限制檢查
#[pyfunction]
fn check_length_limit(text: &str, max_chars: usize) -> bool {
    text.len() <= max_chars
}

// ── PyO3 Module 定義 ────────────────────────────────────────

#[pymodule]
fn threathunter_sanitizer(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(scan_blocklist, m)?)?;
    m.add_function(wrap_pyfunction!(infer_input_type, m)?)?;
    m.add_function(wrap_pyfunction!(sha256_hex, m)?)?;
    m.add_function(wrap_pyfunction!(check_length_limit, m)?)?;
    Ok(())
}
