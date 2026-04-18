// rust/url_builder/src/lib.rs
// A-4: Tool URL Builder Rust 加速層
// 功能：強制 percent-encode + HTTPS-only + Host 白名單
//       防止用戶輸入被拼接進 NVD/OTX URL（URL 注入、SSRF）
//
// 現有風險點（tools/nvd_tool.py:254）：
//   "keywordSearch": keyword  ← keyword 是用戶原始輸入
//
// 攻擊：
//   keyword = "django%0d%0aX-Injected: evil"  → HTTP Header 注入
//   keyword = "127.0.0.1/../../../internal"   → SSRF
//   url crate 的 query_pairs_mut().append_pair() 自動 percent-encode，無法注入

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use url::Url;

// 受信任的 API Host 白名單
const ALLOWED_HOSTS: &[&str] = &[
    "services.nvd.nist.gov",
    "otx.alienvault.com",
    "api.first.org",
    "api.github.com",
    "www.cisa.gov",
    "cisa.gov",
];

// ── 核心函式 ────────────────────────────────────────────────

/// 安全建構 API URL（強制 encode + HTTPS + 白名單）
/// params: Vec<(key, value)> 要附加的 query 參數
#[pyfunction]
fn build_api_url(base: &str, params: Vec<(String, String)>) -> PyResult<String> {
    let mut url = Url::parse(base)
        .map_err(|e| PyValueError::new_err(format!("Invalid base URL '{}': {}", base, e)))?;

    // 強制 HTTPS（防止 plain HTTP 洩漏 API key）
    if url.scheme() != "https" {
        return Err(PyValueError::new_err(
            format!("Only HTTPS allowed, got: {}", url.scheme())
        ));
    }

    // Host 白名單驗證（防 SSRF）
    let host = url.host_str().unwrap_or("");
    if !ALLOWED_HOSTS.contains(&host) {
        return Err(PyValueError::new_err(
            format!("Host '{}' not in allowlist: {:?}", host, ALLOWED_HOSTS)
        ));
    }

    // 強制 percent-encode 所有參數（url crate 自動處理，無法注入）
    {
        let mut pairs = url.query_pairs_mut();
        for (k, v) in &params {
            pairs.append_pair(k, v);
        }
    }

    Ok(url.to_string())
}

/// 快速驗證 URL（不建構，只檢查）
#[pyfunction]
fn validate_url(raw_url: &str) -> (bool, String) {
    match Url::parse(raw_url) {
        Ok(url) => {
            if url.scheme() != "https" {
                return (false, format!("Not HTTPS: {}", url.scheme()));
            }
            let host = url.host_str().unwrap_or("");
            if !ALLOWED_HOSTS.contains(&host) {
                return (false, format!("Host not allowed: {}", host));
            }
            (true, "ok".to_string())
        }
        Err(e) => (false, e.to_string()),
    }
}

/// 安全 percent-encode 單一值（用於手動拼接場合）
#[pyfunction]
fn encode_query_value(raw: &str) -> String {
    url::form_urlencoded::byte_serialize(raw.as_bytes()).collect()
}

// ── PyO3 Module 定義 ────────────────────────────────────────

#[pymodule]
fn threathunter_url_builder(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(build_api_url, m)?)?;
    m.add_function(wrap_pyfunction!(validate_url, m)?)?;
    m.add_function(wrap_pyfunction!(encode_query_value, m)?)?;
    Ok(())
}
