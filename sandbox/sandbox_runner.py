"""
sandbox/sandbox_runner.py
Docker 容器內的 ThreatHunter Pipeline 執行器
=========================================================
設計：
  - 進入點：ENTRYPOINT ["python", "-m", "sandbox.sandbox_runner"]
  - stdin  → JSON 任務（tech_stack, input_type, scan_id）
  - stdout → JSON 結果（vulnerabilities, summary, metadata）
  - stderr → 結構化日誌（不影響 JSON 輸出）

安全保證（容器層級）：
  - --network none     → 無法發送網路請求（NVD/OTX 結果來自掛載的 /app/data cache）
  - --read-only        → 除 tmpfs /tmp 外，所有 FS 唯讀
  - USER sandbox       → 非 root 執行
  - seccomp            → syscall 白名單

Graceful Degradation：
  - 若 pipeline 失敗，返回 {"error": "...","fallback": true}
  - 主機端 docker_sandbox.py 收到 fallback=true 時自動降級 in-process 模式
"""

import json
import logging
import os
import sys
import traceback
from datetime import datetime, timezone

# ── 日誌設定（輸出到 stderr，不汙染 JSON stdout）────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SANDBOX] %(levelname)s %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("threathunter.sandbox_runner")

# ── 執行路徑設定 ──────────────────────────────────────────────

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read_task_from_stdin() -> dict:
    """從 stdin 讀取 JSON 任務，帶有 schema 驗證"""
    try:
        raw = sys.stdin.read(1_000_000)  # 最多讀 1MB，防止 input flood
        if not raw.strip():
            raise ValueError("Empty stdin — no task received")
        task = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON task from stdin: {e}") from e

    # Schema 驗證
    if "tech_stack" not in task:
        raise ValueError("Missing required field: tech_stack")

    return task


def _run_pipeline(task: dict) -> dict:
    """在容器內執行 ThreatHunter Pipeline"""
    tech_stack = task["tech_stack"]
    input_type = task.get("input_type", "pkg")
    scan_id = task.get("scan_id", f"sandbox-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}")

    logger.info("Starting sandbox scan | scan_id=%s | input_type=%s", scan_id, input_type)
    logger.info("Tech stack: %s", tech_stack[:200])

    # 動態 import（避免頂層 import 因容器環境缺少依賴而崩潰）
    sys.path.insert(0, APP_DIR)

    try:
        from main import run_pipeline_sync  # type: ignore[import]
    except ImportError as e:
        logger.error("Cannot import main.run_pipeline_sync: %s", e)
        return {
            "error": "IMPORT_ERROR",
            "message": str(e),
            "fallback": True,
            "scan_id": scan_id,
        }

    try:
        result = run_pipeline_sync(
            tech_stack=tech_stack,
            input_type=input_type,
        )
    except Exception as e:  # noqa: BLE001
        logger.error("Pipeline failed: %s\n%s", e, traceback.format_exc())
        return {
            "error": "PIPELINE_ERROR",
            "message": str(e)[:500],
            "fallback": True,
            "scan_id": scan_id,
        }

    # 確保結果有基本 schema
    if not isinstance(result, dict):
        result = {"raw_result": str(result)}

    result.setdefault("scan_id", scan_id)
    result.setdefault("sandbox_mode", True)
    result.setdefault("timestamp", datetime.now(timezone.utc).isoformat())

    logger.info("Sandbox scan complete | scan_id=%s", scan_id)
    return result


def _selftest() -> int:
    """--selftest 模式：驗證容器環境是否正確（不執行 LLM）"""
    print(json.dumps({
        "status": "ok",
        "python": sys.version,
        "platform": sys.platform,
        "sandbox_user": os.getenv("USER", "unknown"),
        "network_none": not _can_reach_internet(),
        "filesystem_readonly": _is_readonly("/app"),
        "tmp_writable": _is_writable("/tmp"),
    }, indent=2))
    return 0


def _can_reach_internet() -> bool:
    try:
        import socket
        socket.setdefaulttimeout(2)
        socket.socket().connect(("8.8.8.8", 53))
        return True
    except OSError:
        return False


def _is_readonly(path: str) -> bool:
    try:
        test_file = os.path.join(path, ".readonly_test")
        open(test_file, "w").close()  # noqa: WPS515
        os.remove(test_file)
        return False
    except OSError:
        return True


def _is_writable(path: str) -> bool:
    try:
        test_file = os.path.join(path, ".write_test")
        with open(test_file, "w") as f:
            f.write("test")
        os.remove(test_file)
        return True
    except OSError:
        return False


def main() -> int:
    # selftest 模式（無 stdin，直接驗證環境）
    if "--selftest" in sys.argv:
        return _selftest()

    try:
        task = _read_task_from_stdin()
        result = _run_pipeline(task)
        print(json.dumps(result, ensure_ascii=False, default=str))
        return 0 if not result.get("fallback") else 1
    except Exception as e:  # noqa: BLE001
        error_resp = {
            "error": "RUNNER_ERROR",
            "message": str(e)[:500],
            "fallback": True,
        }
        print(json.dumps(error_resp, ensure_ascii=False))
        logger.critical("Runner fatal error: %s\n%s", e, traceback.format_exc())
        return 2


if __name__ == "__main__":
    sys.exit(main())
