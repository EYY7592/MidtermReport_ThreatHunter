"""
checkpoint.py — Pipeline 執行檢查點記錄器
===========================================

設計原則：
  - 零阻塞：I/O 操作盡可能輕量（append-only JSONL）
  - 零失敗：任何記錄錯誤都被靜默吞噬，絕不影響 Pipeline
  - 結構化：每條記錄都是可查詢的 JSON
  - 執行緒安全：
      Phase 4A: 優先使用 Rust threathunter_checkpoint_writer
                （parking_lot::Mutex + BufWriter<File>，高頻 SSE 不競爭）
      Fallback:  Python threading.Lock + TextIO（原有實作）

輸出格式（JSONL）：
  logs/checkpoints/scan_{id}_{timestamp}.jsonl

事件類型：
  SCAN_START / SCAN_END
  STAGE_ENTER / STAGE_EXIT
  LLM_CALL / LLM_RESULT / LLM_RETRY / LLM_ERROR
  TOOL_CALL / HARNESS_CHECK / DEGRADATION

遵守：AGENTS.md + project_CONSTITUTION.md
"""

import hashlib
import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

logger = logging.getLogger("ThreatHunter.checkpoint")

# ── Phase 4A：Rust BufWriter 整合 ────────────────────────────
# 優先載入 Rust crate；不可用時（未編譯、非 Windows 等）自動降級
try:
    import threathunter_checkpoint_writer as _cw
    _RUST_WRITER_AVAILABLE = True
    logger.info("[CHECKPOINT] Phase 4A: Rust BufWriter 啟用 ✓")
except ImportError:
    _cw = None  # type: ignore[assignment]
    _RUST_WRITER_AVAILABLE = False
    logger.debug("[CHECKPOINT] Phase 4A: Rust BufWriter 不可用，使用 Python fallback")

# ── 環境變數開關（回滾策略第三級）──────────────────────────────
ENABLED = os.getenv("CHECKPOINT_ENABLED", "true").lower() != "false"

# ── 敏感資料遮罩模式 ──────────────────────────────────────────
_SENSITIVE_PATTERNS = [
    re.compile(r"(sk(?:-proj)?-[a-zA-Z0-9\-_]{10,})", re.IGNORECASE),  # OpenAI-style keys
    re.compile(r"(ghp_[a-zA-Z0-9]{36,})", re.IGNORECASE),        # GitHub Token
    re.compile(r"(api[_-]?key\s*[:=]\s*['\"]?)([^'\"\s,]{8,})", re.IGNORECASE),
    re.compile(r"(password\s*[:=]\s*['\"]?)([^'\"\s,]{4,})", re.IGNORECASE),
    re.compile(r"(secret\s*[:=]\s*['\"]?)([^'\"\s,]{8,})", re.IGNORECASE),
]

# ── 截斷上限 ──────────────────────────────────────────────────
MAX_DATA_LENGTH = 2000      # 單一欄位值最大長度
MAX_THINKING_LENGTH = 1000  # 思考過程摘要最大長度


def _redact(text: str) -> str:
    """遮罩敏感資料（API Key、密碼等）"""
    if not isinstance(text, str):
        return str(text)
    result = text
    for pattern in _SENSITIVE_PATTERNS:
        result = pattern.sub(lambda m: m.group(0)[:4] + "***REDACTED***", result)
    return result


def _truncate(value: Any, max_len: int = MAX_DATA_LENGTH) -> str:
    """截斷過長的值"""
    s = str(value) if not isinstance(value, str) else value
    if len(s) > max_len:
        return s[:max_len] + f"...[truncated, total={len(s)}]"
    return s


def _safe_hash(text: str) -> str:
    """計算輸入的短 hash（用於追蹤同一輸入的多次執行）"""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:12]


class CheckpointRecorder:
    """
    Pipeline 執行檢查點記錄器。

    每次掃描呼叫 start_scan() 初始化一個 JSONL 檔案，
    後續所有 checkpoint() 呼叫追加一行 JSON。
    掃描結束呼叫 end_scan() 關閉檔案。

    所有公開方法都是「靜默模式」：
      - 任何內部錯誤被 try-except 捕捉
      - 僅記錄到 logger.debug，不拋出例外
      - Pipeline 主流程完全不受影響
    """

    def __init__(self, logs_dir: Path | str | None = None):
        if logs_dir is None:
            logs_dir = Path(__file__).parent / "logs"
        self._logs_dir = Path(logs_dir)
        self._checkpoints_dir = self._logs_dir / "checkpoints"
        self._errors_dir = self._logs_dir / "errors"
        self._scan_id: str = "unknown"
        self._seq: int = 0
        self._file: TextIO | None = None        # Python fallback writer
        self._lock = threading.Lock()            # Python fallback lock
        self._event_counts: dict[str, int] = {}
        self._scan_start_time: float = 0.0
        self._current_filename: str = ""        # v3.6: Thinking Path API 使用
        # Phase 4A：追蹤 Rust writer 是否對本次掃描開啟
        self._rust_writer_active: bool = False

    @property
    def current_filename(self) -> str:
        """回傳本次掃描的 JSONL 檔名（供 server.py Thinking Path API 使用）"""
        return self._current_filename

    # ══════════════════════════════════════════════════════════
    # 掃描生命週期
    # ══════════════════════════════════════════════════════════

    def start_scan(self, scan_id: str) -> None:
        """初始化新掃描的 checkpoint 檔案"""
        if not ENABLED:
            return
        try:
            self._checkpoints_dir.mkdir(parents=True, exist_ok=True)
            self._errors_dir.mkdir(parents=True, exist_ok=True)

            self._scan_id = scan_id
            self._seq = 0
            self._event_counts = {}
            self._scan_start_time = time.time()
            self._rust_writer_active = False

            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_{scan_id[:8]}_{ts}.jsonl"
            filepath = self._checkpoints_dir / filename
            self._current_filename = filename  # v3.6: 供 Thinking Path API 查詢

            # ── Phase 4A：優先嘗試 Rust BufWriter ──────────────────
            if _RUST_WRITER_AVAILABLE:
                try:
                    _cw.open_writer(str(filepath))
                    self._rust_writer_active = True
                    logger.info(
                        "[CHECKPOINT] Phase 4A: Rust BufWriter 開啟: %s", filepath.name
                    )
                except Exception as rust_err:
                    logger.warning(
                        "[CHECKPOINT] Phase 4A: Rust BufWriter 開啟失敗，回退 Python: %s", rust_err
                    )
                    self._rust_writer_active = False

            # ── Fallback：Python TextIO ─────────────────────────────
            if not self._rust_writer_active:
                if self._file and not self._file.closed:
                    try:
                        self._file.close()
                    except Exception:
                        pass
                self._file = open(filepath, "a", encoding="utf-8")

            self.checkpoint("SCAN_START", "pipeline", {
                "scan_id": scan_id,
                "writer_backend": "rust_bufwriter" if self._rust_writer_active else "python_lock",
            })
            logger.info("[CHECKPOINT] 掃描記錄開始: %s", filepath.name)

        except Exception as e:
            logger.debug("[CHECKPOINT] start_scan failed: %s", e)

    def end_scan(self, final_status: str, total_duration: float) -> None:
        """掃描結束，寫入摘要並關閉檔案"""
        if not ENABLED:
            return
        try:
            self.checkpoint("SCAN_END", "pipeline", {
                "final_status": final_status,
                "total_duration_seconds": round(total_duration, 2),
                "total_checkpoints": self._seq,
                "event_summary": dict(self._event_counts),
                "writer_backend": "rust_bufwriter" if self._rust_writer_active else "python_lock",
            })
            # ── Phase 4A：關閉 Rust writer ──────────────────────────
            if self._rust_writer_active and _RUST_WRITER_AVAILABLE:
                try:
                    _cw.flush_writer()
                    _cw.close_writer()
                    logger.debug(
                        "[CHECKPOINT] Phase 4A: Rust BufWriter 已關閉，共寫入 %d 行",
                        _cw.get_lines_written(),
                    )
                except Exception as e:
                    logger.debug("[CHECKPOINT] Phase 4A: Rust close 失敗: %s", e)
                finally:
                    self._rust_writer_active = False
            # ── Fallback：Python TextIO 關閉 ────────────────────────
            if self._file and not self._file.closed:
                self._file.close()
                self._file = None
            logger.info(
                "[CHECKPOINT] 掃描記錄結束: %d 條 checkpoint | %.1fs",
                self._seq, total_duration,
            )
        except Exception as e:
            logger.debug("[CHECKPOINT] end_scan failed: %s", e)

    # ══════════════════════════════════════════════════════════
    # 核心寫入
    # ══════════════════════════════════════════════════════════

    def checkpoint(self, event: str, agent: str, data: dict | None = None) -> None:
        """
        寫入一條 checkpoint 記錄（執行緒安全）。

        Phase 4A：優先使用 Rust BufWriter（parking_lot::Mutex，無 GIL 競爭）。
        Fallback：Python threading.Lock + TextIO（原有實作，完全等效）。

        Args:
            event: 事件類型（如 STAGE_ENTER, LLM_CALL 等）
            agent: Agent 名稱（如 scout, security_guard）
            data: 附加資料字典
        """
        if not ENABLED:
            return
        try:
            with self._lock:
                self._seq += 1
                self._event_counts[event] = self._event_counts.get(event, 0) + 1

                record = {
                    "seq": self._seq,
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "scan_id": self._scan_id,
                    "event": event,
                    "agent": agent,
                    "data": self._sanitize_data(data or {}),
                }

                line = json.dumps(record, ensure_ascii=False, default=str)

                # ── Phase 4A：Rust BufWriter 寫入路徑 ──────────────
                if self._rust_writer_active and _RUST_WRITER_AVAILABLE:
                    try:
                        _cw.write_line(line)
                        # 高優先級事件（LLM 錯誤 / 掃描邊界）立即 flush
                        if event in (
                            "SCAN_START",
                            "SCAN_END",
                            "STAGE_ENTER",
                            "STAGE_EXIT",
                            "LLM_ERROR",
                            "DEGRADATION",
                        ):
                            _cw.flush_writer()
                        return
                    except Exception as rust_err:
                        # Rust 寫入失敗 → 回退，並禁用 Rust writer 避免後續重試
                        logger.warning(
                            "[CHECKPOINT] Phase 4A Rust write 失敗，切換 Python: %s", rust_err
                        )
                        self._rust_writer_active = False

                # ── Fallback：Python TextIO ─────────────────────────
                if self._file and not self._file.closed:
                    self._file.write(line + "\n")
                    self._file.flush()  # 即時寫入，debug 時更易追蹤

        except Exception as e:
            logger.debug("[CHECKPOINT] write failed: %s", e)

    def _sanitize_data(self, data: dict) -> dict:
        """清洗資料：截斷 + 遮罩敏感資訊"""
        sanitized = {}
        for key, value in data.items():
            if isinstance(value, dict):
                sanitized[key] = self._sanitize_data(value)
            elif isinstance(value, (list, tuple)):
                sanitized[key] = _truncate(str(value))
            elif isinstance(value, str):
                sanitized[key] = _redact(_truncate(value))
            elif isinstance(value, (int, float, bool)):
                sanitized[key] = value
            else:
                sanitized[key] = _truncate(str(value))
        return sanitized

    # ══════════════════════════════════════════════════════════
    # Stage 層便捷方法
    # ══════════════════════════════════════════════════════════

    def stage_enter(
        self,
        agent: str,
        input_data: Any = None,
        skill_file: str = "",
        input_type: str = "",
    ) -> None:
        """Stage 進入點 checkpoint — v3.7: 加入 skill_file / input_type 欄位供 Thinking Path UI 使用"""
        try:
            data: dict[str, Any] = {}
            # v3.7: Path-Aware Skills 追蹤資料
            if skill_file:
                data["skill_file"] = skill_file
            if input_type:
                data["input_type"] = input_type
            # 輸入摘要
            if isinstance(input_data, dict):
                data["input_keys"] = list(input_data.keys())[:20]
                if "tech_stack" in input_data:
                    data["tech_stack_preview"] = _truncate(
                        str(input_data["tech_stack"]), 200
                    )
                if "vulnerabilities" in input_data:
                    data["vuln_count"] = len(input_data.get("vulnerabilities", []))
                data["input_hash"] = _safe_hash(json.dumps(input_data, default=str))
            elif isinstance(input_data, str):
                data["input_preview"] = _truncate(input_data, 200)
                data["input_hash"] = _safe_hash(input_data)
                data["input_length"] = len(input_data)
            self.checkpoint("STAGE_ENTER", agent, data)
        except Exception:
            pass

    def stage_exit(
        self,
        agent: str,
        status: str,
        output_data: Any = None,
        duration_ms: int = 0,
    ) -> None:
        """Stage 離開點 checkpoint"""
        try:
            data: dict[str, Any] = {
                "status": status,
                "duration_ms": duration_ms,
            }
            if isinstance(output_data, dict):
                data["output_keys"] = list(output_data.keys())[:20]
                if "vulnerabilities" in output_data:
                    data["vuln_count"] = len(output_data.get("vulnerabilities", []))
                if "risk_score" in output_data:
                    data["risk_score"] = output_data["risk_score"]
                if "verdict" in output_data:
                    data["verdict"] = output_data["verdict"]
                if output_data.get("_degraded"):
                    data["degraded"] = True
                if "scan_path" in output_data:
                    data["scan_path"] = output_data["scan_path"]
            self.checkpoint("STAGE_EXIT", agent, data)

            # ── 自動注入 DEGRADATION checkpoint ──────────────────────────
            # 當 stage 輸出包含 _degraded=True 時，立即補寫一條 DEGRADATION
            # 事件，讓 Thinking Path 面板能正確顯示降級原因，不讓開發者瞎猜
            if isinstance(output_data, dict) and output_data.get("_degraded"):
                error_msg  = str(output_data.get("_error", "Unknown degradation reason"))
                strategy   = f"status={status}, duration={duration_ms}ms"
                self.checkpoint("DEGRADATION", agent, {
                    "reason":            _truncate(error_msg, 400),
                    "fallback_strategy": strategy,
                    "error":             _truncate(error_msg, 400),   # 供前端 tp-error-text 使用
                    "source":            "stage_exit_auto",
                })
        except Exception:
            pass

    # ══════════════════════════════════════════════════════════
    # LLM 層便捷方法
    # ══════════════════════════════════════════════════════════

    def llm_call(
        self,
        agent: str,
        model: str,
        provider: str = "openrouter",
        task_preview: str = "",
    ) -> None:
        """LLM 呼叫前 checkpoint"""
        try:
            self.checkpoint("LLM_CALL", agent, {
                "model": model,
                "provider": provider,
                "task_preview": _truncate(task_preview, 300),
            })
        except Exception:
            pass

    def llm_result(
        self,
        agent: str,
        model: str,
        status: str,
        output_len: int,
        duration_ms: int,
        thinking: str = "",
    ) -> None:
        """LLM 呼叫後 checkpoint（含思考過程摘要）"""
        try:
            data: dict[str, Any] = {
                "model": model,
                "status": status,
                "output_length": output_len,
                "duration_ms": duration_ms,
            }
            if thinking:
                data["thinking_preview"] = _redact(
                    _truncate(thinking, MAX_THINKING_LENGTH)
                )
            self.checkpoint("LLM_RESULT", agent, data)
        except Exception:
            pass

    def llm_retry(
        self,
        agent: str,
        model: str,
        error: str,
        retry_count: int,
        next_model: str,
    ) -> None:
        """LLM 重試 checkpoint"""
        try:
            self.checkpoint("LLM_RETRY", agent, {
                "failed_model": model,
                "error": _truncate(error, 300),
                "retry_count": retry_count,
                "next_model": next_model,
            })
        except Exception:
            pass

    def llm_error(self, agent: str, model: str, error: str) -> None:
        """LLM 失敗 checkpoint（同時寫入 error log）"""
        try:
            self.checkpoint("LLM_ERROR", agent, {
                "model": model,
                "error": _truncate(error, 500),
            })
            # 同步寫入 error log
            self._write_error_log(agent, model, error)
        except Exception:
            pass

    def _write_error_log(self, agent: str, model: str, error: str) -> None:
        """將 LLM 錯誤寫入獨立的 error log 檔案"""
        try:
            self._errors_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d")
            error_file = self._errors_dir / f"errors_{ts}.log"
            with open(error_file, "a", encoding="utf-8") as f:
                now = datetime.now(timezone.utc).isoformat()
                f.write(
                    f"[{now}] scan={self._scan_id} agent={agent} "
                    f"model={model} error={error[:300]}\n"
                )
        except Exception:
            pass

    # ══════════════════════════════════════════════════════════
    # 工具 / Harness 層便捷方法
    # ══════════════════════════════════════════════════════════

    def tool_call(
        self,
        agent: str,
        tool_name: str,
        tool_input: str,
        tool_output: str,
        status: str = "SUCCESS",
    ) -> None:
        """工具呼叫 checkpoint"""
        try:
            self.checkpoint("TOOL_CALL", agent, {
                "tool_name": tool_name,
                "input": _truncate(tool_input, 500),
                "output_preview": _truncate(tool_output, 500),
                "status": status,
            })
        except Exception:
            pass

    def harness_check(
        self,
        agent: str,
        layer: str,
        check_name: str,
        result: str,
        action: str = "",
        details: dict | None = None,
    ) -> None:
        """Harness 保障層觸發 checkpoint"""
        try:
            data: dict[str, Any] = {
                "layer": layer,
                "check_name": check_name,
                "result": result,
            }
            if action:
                data["corrective_action"] = action
            if details:
                data.update(details)
            self.checkpoint("HARNESS_CHECK", agent, data)
        except Exception:
            pass

    def degradation(
        self,
        agent: str,
        reason: str,
        fallback_strategy: str = "",
    ) -> None:
        """降級觸發 checkpoint"""
        try:
            self.checkpoint("DEGRADATION", agent, {
                "reason": _truncate(reason, 300),
                "fallback_strategy": fallback_strategy,
            })
        except Exception:
            pass

    # ══════════════════════════════════════════════════════════
    # 統計
    # ══════════════════════════════════════════════════════════

    def get_summary(self) -> dict:
        """回傳當前掃描的統計摘要"""
        try:
            elapsed = time.time() - self._scan_start_time if self._scan_start_time else 0
            return {
                "scan_id": self._scan_id,
                "total_checkpoints": self._seq,
                "event_counts": dict(self._event_counts),
                "elapsed_seconds": round(elapsed, 2),
                "enabled": ENABLED,
            }
        except Exception:
            return {"error": "summary unavailable"}


# ══════════════════════════════════════════════════════════════
# 全域實例（單例模式）
# ══════════════════════════════════════════════════════════════

_project_root = Path(__file__).parent
recorder = CheckpointRecorder(logs_dir=_project_root / "logs")


def get_checkpoint_writer_status() -> dict[str, Any]:
    """回傳 checkpoint writer 後端狀態，供 UI diagnostics 使用。"""
    rust_active = bool(getattr(recorder, "_rust_writer_active", False))
    return {
        "available": _RUST_WRITER_AVAILABLE,
        "active": rust_active,
        "preferred_backend": "rust_bufwriter",
        "current_backend": "rust_bufwriter" if rust_active else "python_lock",
        "fallback_backend": "python_lock",
    }
