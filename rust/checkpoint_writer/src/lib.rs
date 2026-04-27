// rust/checkpoint_writer/src/lib.rs
// Phase 4A: Rust 高效能 Checkpoint Writer
// ==========================================
//
// 設計目標：
//   - 取代 Python threading.Lock + file.write + file.flush 的高頻 I/O 瓶頸
//   - 使用 tokio::sync::Mutex<BufWriter<File>> 達到 async-friendly 共享寫入
//   - parking_lot::Mutex 包裝為同步 PyO3 介面（Python 呼叫方不需要 async）
//   - 所有函式絕不 panic：所有錯誤轉為 PyErr 回傳
//
// PyO3 暴露介面：
//   open_writer(path: str) -> None
//   write_line(line: str) -> None
//   flush_writer() -> None
//   close_writer() -> None
//   is_open() -> bool
//   get_lines_written() -> int
//
// 遵守：project_CONSTITUTION.md + HARNESS_ENGINEERING.md

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::OnceLock;

use parking_lot::Mutex;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;

// ── 全域 Writer 狀態（單例，模擬 checkpoint.py 的 _file）────────
struct WriterState {
    writer: Option<BufWriter<File>>,
    path:   Option<PathBuf>,
    lines:  u64,
}

impl WriterState {
    fn new() -> Self {
        Self {
            writer: None,
            path:   None,
            lines:  0,
        }
    }
}

static WRITER: OnceLock<Mutex<WriterState>> = OnceLock::new();

fn get_writer() -> &'static Mutex<WriterState> {
    WRITER.get_or_init(|| Mutex::new(WriterState::new()))
}

// ── 核心函式 ────────────────────────────────────────────────────

/// 開啟（或覆蓋開啟）指定路徑的檔案，以 append 模式 + BufWriter 加速
/// 若已開啟則先 flush + close 再重新開啟
#[pyfunction]
fn open_writer(path: &str) -> PyResult<()> {
    let p = PathBuf::from(path);

    // 確保父目錄存在
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            PyRuntimeError::new_err(format!(
                "[CheckpointWriter] 無法建立目錄 {}: {}",
                parent.display(),
                e
            ))
        })?;
    }

    // 開啟檔案（append 模式，不清除既有內容）
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&p)
        .map_err(|e| {
            PyRuntimeError::new_err(format!(
                "[CheckpointWriter] 無法開啟檔案 {}: {}",
                p.display(),
                e
            ))
        })?;

    // BufWriter 緩衝區 64KiB（平衡延遲與吞吐量）
    let buf_writer = BufWriter::with_capacity(65536, file);

    let mut state = get_writer().lock();
    // 先 flush 過去的 writer（若有）
    if let Some(ref mut old_w) = state.writer {
        let _ = old_w.flush();
    }
    state.writer = Some(buf_writer);
    state.path   = Some(p);
    state.lines  = 0;

    Ok(())
}

/// 寫入一行 JSON（自動追加 '\n'），執行緒安全
#[pyfunction]
fn write_line(line: &str) -> PyResult<()> {
    let mut state = get_writer().lock();
    match state.writer {
        None => Err(PyRuntimeError::new_err(
            "[CheckpointWriter] writer 尚未開啟，請先呼叫 open_writer()",
        )),
        Some(ref mut w) => {
            w.write_all(line.as_bytes()).map_err(|e| {
                PyRuntimeError::new_err(format!("[CheckpointWriter] 寫入失敗: {}", e))
            })?;
            w.write_all(b"\n").map_err(|e| {
                PyRuntimeError::new_err(format!("[CheckpointWriter] 寫入換行失敗: {}", e))
            })?;
            let _ = w;
            state.lines += 1;
            Ok(())
        }
    }
}

/// 手動觸發 flush（通常由 Python 在 high-priority 事件後呼叫）
#[pyfunction]
fn flush_writer() -> PyResult<()> {
    let mut state = get_writer().lock();
    match state.writer {
        None => Ok(()), // writer 未開啟時 flush 是 no-op（非錯誤）
        Some(ref mut w) => w.flush().map_err(|e| {
            PyRuntimeError::new_err(format!("[CheckpointWriter] flush 失敗: {}", e))
        }),
    }
}

/// 關閉 writer（flush + drop），釋放檔案鎖
#[pyfunction]
fn close_writer() -> PyResult<()> {
    let mut state = get_writer().lock();
    if let Some(mut w) = state.writer.take() {
        let _ = w.flush(); // 最後一次 flush，忽略錯誤（已關閉）
    }
    state.path = None;
    Ok(())
}

/// 回傳 writer 是否已開啟（供 Python fallback 判斷使用）
#[pyfunction]
fn is_open() -> bool {
    let state = get_writer().lock();
    state.writer.is_some()
}

/// 回傳本次已寫入的行數（用於統計與 benchmark）
#[pyfunction]
fn get_lines_written() -> u64 {
    let state = get_writer().lock();
    state.lines
}

/// 回傳當前已開啟的檔案路徑（供 Python 除錯使用）
#[pyfunction]
fn get_current_path() -> Option<String> {
    let state = get_writer().lock();
    state.path.as_ref().map(|p| p.to_string_lossy().into_owned())
}

/// 測試用：強制寫入並 flush，返回成功行數（壓力測試輔助）
#[pyfunction]
fn write_batch(lines: Vec<String>) -> PyResult<u64> {
    let mut state = get_writer().lock();
    match state.writer {
        None => Err(PyRuntimeError::new_err(
            "[CheckpointWriter] writer 尚未開啟",
        )),
        Some(ref mut w) => {
            let mut count = 0u64;
            for line in &lines {
                w.write_all(line.as_bytes()).map_err(|e| {
                    PyRuntimeError::new_err(format!("[CheckpointWriter] 批次寫入失敗: {}", e))
                })?;
                w.write_all(b"\n").map_err(|e| {
                    PyRuntimeError::new_err(format!("[CheckpointWriter] 批次換行失敗: {}", e))
                })?;
                count += 1;
            }
            // 批次寫入後自動 flush
            w.flush().map_err(|e| {
                PyRuntimeError::new_err(format!("[CheckpointWriter] 批次 flush 失敗: {}", e))
            })?;
            let _ = w;
            state.lines += count;
            Ok(count)
        }
    }
}

// ── PyO3 Module 定義 ────────────────────────────────────────────

#[pymodule]
fn threathunter_checkpoint_writer(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(open_writer, m)?)?;
    m.add_function(wrap_pyfunction!(write_line, m)?)?;
    m.add_function(wrap_pyfunction!(flush_writer, m)?)?;
    m.add_function(wrap_pyfunction!(close_writer, m)?)?;
    m.add_function(wrap_pyfunction!(is_open, m)?)?;
    m.add_function(wrap_pyfunction!(get_lines_written, m)?)?;
    m.add_function(wrap_pyfunction!(get_current_path, m)?)?;
    m.add_function(wrap_pyfunction!(write_batch, m)?)?;
    m.add("__version__", "0.1.0")?;
    Ok(())
}
