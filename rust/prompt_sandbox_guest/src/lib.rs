// prompt_guard — ThreatHunter WASM Guest
// ========================================
// 在 wasmtime 沙箱內執行的輸入過濾引擎。
// 安全保證（WASM 規格層級，不依賴程式碼正確性）：
//   - 無法呼叫 OS syscall
//   - 無法存取主機檔案系統或網路
//   - 記憶體完全隔離在 WASM linear memory 內
//
// 介面（Host 透過 wasmtime 呼叫）：
//   get_buffer_ptr() -> i32       共享 IO 緩衝區起始位址
//   eval_input(offset, len) -> u32  評估輸入安全性
//   get_result_ptr() -> i32       結果 JSON 起始位址
//   get_result_len() -> i32       結果 JSON 長度
//
// 回傳碼：0=ALLOW, 1=BLOCK, 2=SANITIZE, 3=TRUNCATE

#![no_std]

use core::slice;
use core::str;

// no_std 需要 panic handler
#[panic_handler]
fn panic_handler(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

// ── 全域緩衝區定義 ──────────────────────────────────────────
const BUFFER_SIZE: usize = 1_048_576; // 1MB IO buffer
const RESULT_SIZE: usize = 4096;      // 4KB result buffer
const MAX_INPUT:   usize = 524_288;   // 512KB 輸入上限

static mut IO_BUFFER:     [u8; BUFFER_SIZE] = [0u8; BUFFER_SIZE];
static mut RESULT_BUFFER: [u8; RESULT_SIZE] = [0u8; RESULT_SIZE];
static mut RESULT_LEN:    i32 = 0;

// ══════════════════════════════════════════════════════════════
// 匯出給 Host 的介面函式
// ══════════════════════════════════════════════════════════════

#[no_mangle]
pub extern "C" fn get_buffer_ptr() -> i32 {
    unsafe { IO_BUFFER.as_mut_ptr() as i32 }
}

#[no_mangle]
pub extern "C" fn get_result_ptr() -> i32 {
    unsafe { RESULT_BUFFER.as_ptr() as i32 }
}

#[no_mangle]
pub extern "C" fn get_result_len() -> i32 {
    unsafe { RESULT_LEN }
}

#[no_mangle]
pub extern "C" fn eval_input(offset: i32, len: i32) -> u32 {
    if len <= 0 || offset < 0 {
        write_json(0, b"ALLOW", b"empty_input");
        return 0;
    }
    let len = len as usize;
    let offset = offset as usize;

    // 防護 1：輸入長度上限（防 OOM）
    if len > MAX_INPUT {
        write_json(3, b"TRUNCATE", b"input_too_large");
        return 3;
    }

    // 防護 2：邊界檢查
    if offset.saturating_add(len) > BUFFER_SIZE {
        write_json(1, b"BLOCK", b"buffer_overflow_attempt");
        return 1;
    }

    let raw = unsafe { slice::from_raw_parts(IO_BUFFER.as_ptr().add(offset), len) };

    // 防護 3：UTF-8 驗證
    let s = match str::from_utf8(raw) {
        Ok(s) => s,
        Err(_) => {
            write_json(2, b"SANITIZE", b"invalid_utf8");
            return 2;
        }
    };

    // 防護 4：危險 Unicode 控制字元
    if check_dangerous_unicode(s) {
        write_json(2, b"SANITIZE", b"dangerous_unicode");
        return 2;
    }

    // 防護 5：Prompt Injection 模式
    if check_prompt_injection(s) {
        write_json(1, b"BLOCK", b"prompt_injection");
        return 1;
    }

    // 防護 6：AST Bomb 前驅（深度巢狀括號）
    if check_ast_bomb(s) {
        write_json(1, b"BLOCK", b"ast_bomb_pattern");
        return 1;
    }

    // 防護 7：高信心 Code Injection
    if check_code_injection(s) {
        write_json(1, b"BLOCK", b"code_injection");
        return 1;
    }

    write_json(0, b"ALLOW", b"ok");
    0
}

// ══════════════════════════════════════════════════════════════
// 過濾邏輯（pure function, no alloc）
// ══════════════════════════════════════════════════════════════

fn check_dangerous_unicode(s: &str) -> bool {
    for ch in s.chars() {
        let cp = ch as u32;
        if (cp < 0x20 && cp != 9 && cp != 10 && cp != 13)
            || (cp >= 0x7F && cp <= 0x9F)
            || cp == 0x200B || cp == 0x200C || cp == 0x200D
            || cp == 0x2028 || cp == 0x2029
            || (cp >= 0x202A && cp <= 0x202E)
            || cp == 0xFEFF
        {
            return true;
        }
    }
    false
}

fn bytes_has_pattern(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

// 小寫比較（不 alloc，用固定大小 stack buffer 做滾動比對）
fn str_contains_lower(s: &str, needle: &[u8]) -> bool {
    let bytes = s.as_bytes();
    if needle.len() > bytes.len() {
        return false;
    }
    let mut lower_window = [0u8; 64];
    let nlen = needle.len().min(64);
    let needle = &needle[..nlen];

    for i in 0..=(bytes.len().saturating_sub(nlen)) {
        let window = &bytes[i..(i + nlen).min(bytes.len())];
        let wlen = window.len().min(64);
        for j in 0..wlen {
            lower_window[j] = window[j].to_ascii_lowercase();
        }
        if &lower_window[..wlen] == needle {
            return true;
        }
    }
    false
}

fn check_prompt_injection(s: &str) -> bool {
    let patterns: &[&[u8]] = &[
        b"ignore all previous",
        b"ignore previous instructions",
        b"disregard all",
        b"forget your instructions",
        b"you are now",
        b"developer mode",
        b"jailbreak",
        b"pretend you are",
        b"act as if you are",
        b"system prompt:",
        b"new instructions:",
        b"override previous",
        b"bypass your",
        b"disable your",
        b"unlock mode",
        b"simulation mode",
        b"do anything now",
        b"dan mode",
    ];
    patterns.iter().any(|p| str_contains_lower(s, p))
}

fn check_ast_bomb(s: &str) -> bool {
    // 巢狀括號深度 > 50 視為 AST Bomb 前驅
    let mut depth: i32 = 0;
    let mut max_depth: i32 = 0;
    for ch in s.chars() {
        match ch {
            '(' | '[' | '{' => {
                depth += 1;
                if depth > max_depth {
                    max_depth = depth;
                }
                if max_depth > 50 {
                    return true;
                }
            }
            ')' | ']' | '}' => {
                depth -= 1;
                if depth < 0 {
                    depth = 0;
                }
            }
            _ => {}
        }
    }
    false
}

fn check_code_injection(s: &str) -> bool {
    // SQL injection 高信心模式（大小寫不敏感）
    let sql_patterns: &[&[u8]] = &[
        b"drop table",
        b"drop database",
        b"; drop",
        b"union select",
        b"' or '1'='1",
        b"\" or \"1\"=\"1",
        b"exec xp_",
        b"execute xp_",
    ];
    // OS command injection
    let cmd_patterns: &[&[u8]] = &[
        b"; cat /etc/passwd",
        b"| cat /etc/passwd",
        b"&& cat /etc/passwd",
        b"; rm -rf",
        b"$(rm",
        b"`rm",
        b"nc -e /bin/sh",
    ];
    let all: &[&[&[u8]]] = &[&sql_patterns, &cmd_patterns];
    for group in all {
        for p in *group {
            if str_contains_lower(s, p) {
                return true;
            }
        }
    }
    false
}

// ══════════════════════════════════════════════════════════════
// 結果寫入（寫入 RESULT_BUFFER，格式為 JSON）
// ══════════════════════════════════════════════════════════════

fn write_json(code: u32, verdict: &[u8], reason: &[u8]) {
    // 手動組裝 JSON（no_std，無 format! 宏）
    // {"code":N,"verdict":"...","reason":"..."}
    let mut pos = 0usize;

    unsafe {
        let buf = &mut RESULT_BUFFER[..];

        // {"code":
        put_bytes(buf, &mut pos, b"{\"code\":");
        // N（0-9 單字元）
        if pos < RESULT_SIZE {
            buf[pos] = b'0' + (code as u8 % 10);
            pos += 1;
        }
        // ,"verdict":"
        put_bytes(buf, &mut pos, b",\"verdict\":\"");
        put_bytes(buf, &mut pos, verdict);
        // ","reason":"
        put_bytes(buf, &mut pos, b"\",\"reason\":\"");
        put_bytes(buf, &mut pos, reason);
        // "}
        put_bytes(buf, &mut pos, b"\"}");

        RESULT_LEN = pos as i32;
    }
}

fn put_bytes(buf: &mut [u8], pos: &mut usize, data: &[u8]) {
    for &b in data {
        if *pos < buf.len() {
            buf[*pos] = b;
            *pos += 1;
        }
    }
}
