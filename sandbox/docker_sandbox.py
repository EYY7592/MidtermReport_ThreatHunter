"""
sandbox/docker_sandbox.py
ThreatHunter Docker Sandbox — Layer 2 隔離層
=========================================================
功能：
  - 在 Docker 容器內執行 Pipeline（完整隔離）
  - --network none / --read-only / non-root / seccomp
  - Graceful Degradation：Docker 不可用時自動降級 in-process
  - SANDBOX_ENABLED 環境變數控制開關

使用：
  # 啟用：在 .env 設置 SANDBOX_ENABLED=true
  # 手動測試：
  python -c "from sandbox.docker_sandbox import run_in_sandbox; print(run_in_sandbox('django==4.2'))"
"""

import json
import logging
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("ThreatHunter.sandbox")

# ── 設定常數 ──────────────────────────────────────────────────
SANDBOX_IMAGE   = os.getenv("SANDBOX_IMAGE",   "threathunter-sandbox:latest")
SANDBOX_TIMEOUT = int(os.getenv("SANDBOX_TIMEOUT", "300"))   # 秒（5 分鐘）
SANDBOX_MEMORY  = os.getenv("SANDBOX_MEMORY",  "512m")
SANDBOX_CPUS    = os.getenv("SANDBOX_CPUS",    "1.0")

# seccomp profile 路徑（容器隔離 syscall 白名單）
_HERE = Path(__file__).parent
SECCOMP_PROFILE = str(_HERE / "seccomp-profile.json")

# 專案根目錄（掛載用）
_PROJECT_ROOT = str(Path(__file__).parent.parent.resolve())

# ── 核心 API ──────────────────────────────────────────────────

def run_in_sandbox(
    tech_stack: str,
    input_type: str = "pkg",
    scan_id: str | None = None,
) -> dict[str, Any]:
    """
    在 Docker 容器內執行 ThreatHunter Pipeline。

    Args:
        tech_stack: 掃描目標（套件清單 / 程式碼字串 / config 字串）
        input_type: "pkg" | "code" | "config"
        scan_id:    可選的追蹤 ID

    Returns:
        Pipeline 結果 dict，包含 vulnerabilities / summary / error 等欄位
    """
    if not is_sandbox_image_ready():
        logger.warning("[SANDBOX] Image '%s' not found — triggering fallback", SANDBOX_IMAGE)
        return {
            "error": "SANDBOX_IMAGE_NOT_FOUND",
            "image": SANDBOX_IMAGE,
            "hint": "Run: docker build -t threathunter-sandbox:latest -f sandbox/Dockerfile .",
            "fallback": True,
        }

    task = {
        "tech_stack": tech_stack,
        "input_type": input_type,
        "scan_id": scan_id or f"sandbox-{int(time.time())}",
    }
    task_json = json.dumps(task, ensure_ascii=False)

    cmd = _build_docker_cmd()
    logger.info("[SANDBOX] Launching container | image=%s | timeout=%ds", SANDBOX_IMAGE, SANDBOX_TIMEOUT)
    logger.debug("[SANDBOX] Docker cmd: %s", " ".join(cmd))

    start_time = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            input=task_json,
            capture_output=True,
            text=True,
            timeout=SANDBOX_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - start_time
        logger.error("[SANDBOX] Container timeout after %.1fs", elapsed)
        return {
            "error": "SANDBOX_TIMEOUT",
            "timeout_seconds": SANDBOX_TIMEOUT,
            "fallback": True,
        }
    except FileNotFoundError:
        logger.error("[SANDBOX] Docker not found in PATH")
        return {"error": "DOCKER_NOT_FOUND", "fallback": True}
    except Exception as e:  # noqa: BLE001
        logger.error("[SANDBOX] Unexpected error: %s", e)
        return {"error": "SANDBOX_ERROR", "message": str(e), "fallback": True}

    elapsed = time.monotonic() - start_time

    # stderr → 轉給 logger（容器內的日誌）
    if proc.stderr:
        for line in proc.stderr.strip().splitlines()[-20:]:  # 最後 20 行避免洗版
            logger.debug("[CONTAINER] %s", line)

    if proc.returncode not in (0, 1):
        logger.error(
            "[SANDBOX] Container exit %d | stderr: %s",
            proc.returncode,
            proc.stderr[-500:] if proc.stderr else "<empty>",
        )
        return {
            "error": "SANDBOX_CONTAINER_ERROR",
            "exit_code": proc.returncode,
            "stderr_tail": (proc.stderr or "")[-300:],
            "fallback": True,
        }

    # 解析 stdout → JSON result
    stdout = proc.stdout.strip()
    if not stdout:
        logger.error("[SANDBOX] Container returned empty stdout")
        return {"error": "SANDBOX_EMPTY_OUTPUT", "fallback": True}

    try:
        result = json.loads(stdout)
    except json.JSONDecodeError as e:
        logger.error("[SANDBOX] Cannot parse container output: %s | output: %s", e, stdout[:200])
        return {
            "error": "SANDBOX_OUTPUT_PARSE_ERROR",
            "raw": stdout[:300],
            "fallback": True,
        }

    result["_sandbox_elapsed_s"] = round(elapsed, 2)
    result["_sandbox_mode"] = True

    logger.info(
        "[SANDBOX] Scan complete | elapsed=%.2fs | vulns=%d",
        elapsed,
        len(result.get("vulnerabilities", [])),
    )
    return result


def is_docker_available() -> bool:
    """檢查 Docker daemon 是否可用（用於 Graceful Degradation 判斷）"""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def is_sandbox_image_ready() -> bool:
    """檢查 Docker 映像是否已建置"""
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", SANDBOX_IMAGE],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def build_sandbox_image(no_cache: bool = False) -> bool:
    """建置 sandbox Docker 映像（若不存在）"""
    dockerfile = str(_HERE / "Dockerfile")

    if not Path(dockerfile).exists():
        logger.error("[SANDBOX] Dockerfile not found: %s", dockerfile)
        return False

    cmd = ["docker", "build", "-t", SANDBOX_IMAGE, "-f", dockerfile, _PROJECT_ROOT]
    if no_cache:
        cmd.insert(2, "--no-cache")

    logger.info("[SANDBOX] Building image '%s'...", SANDBOX_IMAGE)
    try:
        result = subprocess.run(cmd, timeout=600)
        if result.returncode == 0:
            logger.info("[SANDBOX] Image built successfully: %s", SANDBOX_IMAGE)
            return True
        logger.error("[SANDBOX] Image build failed (exit %d)", result.returncode)
        return False
    except subprocess.TimeoutExpired:
        logger.error("[SANDBOX] Image build timeout (>600s)")
        return False


def run_sandbox_selftest() -> dict[str, Any]:
    """在容器內執行 selftest，驗證隔離設定是否正確"""
    cmd = _build_docker_cmd(selftest=True)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if proc.returncode == 0 and proc.stdout:
            return json.loads(proc.stdout)
        return {"error": "SELFTEST_FAILED", "stderr": proc.stderr[:300]}
    except Exception as e:  # noqa: BLE001
        return {"error": "SELFTEST_ERROR", "message": str(e)}


# ── 內部輔助 ──────────────────────────────────────────────────

def _build_docker_cmd(selftest: bool = False) -> list[str]:
    """
    建構完整的 docker run 指令。
    遵循計劃規格：--network none / --read-only / --memory / --cpus / seccomp
    """
    cmd = [
        "docker", "run",
        "--rm",                              # 結束後清理容器
        "--network", "none",                 # 完全隔離網路
        "--read-only",                       # Filesystem 唯讀
        "--tmpfs", "/tmp:noexec,nosuid,size=64m",  # 只有 /tmp 可寫，且 noexec
        "--memory", SANDBOX_MEMORY,          # 記憶體限制
        "--memory-swap", SANDBOX_MEMORY,     # 禁止 swap（避免無限增長）
        "--cpus", SANDBOX_CPUS,              # CPU 配額
        "--no-new-privileges",               # 禁止 setuid / capabilities 提權
        "--pids-limit", "256",               # 限制 PID 數量（防止 fork bomb）
        "--user", "sandbox",                 # 非 root 身分執行
    ]

    # seccomp profile（Linux only；Windows via WSL2）
    if Path(SECCOMP_PROFILE).exists():
        cmd += ["--security-opt", f"seccomp={SECCOMP_PROFILE}"]
    else:
        logger.warning("[SANDBOX] seccomp profile not found at %s — skipping", SECCOMP_PROFILE)

    # 掛載唯讀資料目錄（NVD cache / skills）
    data_dir = Path(_PROJECT_ROOT) / "data"
    skills_dir = Path(_PROJECT_ROOT) / "skills"
    memory_dir = Path(_PROJECT_ROOT) / "memory"

    if data_dir.exists():
        cmd += ["-v", f"{data_dir}:/app/data:ro"]
    if skills_dir.exists():
        cmd += ["-v", f"{skills_dir}:/app/skills:ro"]
    if memory_dir.exists():
        cmd += ["-v", f"{memory_dir}:/app/memory:ro"]

    # 傳入環境變數（API keys 等）
    env_file = Path(_PROJECT_ROOT) / ".env"
    if env_file.exists():
        cmd += ["--env-file", str(env_file)]

    # 映像名稱
    cmd.append(SANDBOX_IMAGE)

    # selftest 旗標
    if selftest:
        cmd.append("--selftest")

    return cmd


# ── 模組入口（cli 測試用）────────────────────────────────────
if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    print("=== ThreatHunter Docker Sandbox Diagnostics ===")
    print(f"Docker available:      {is_docker_available()}")
    print(f"Sandbox image ready:   {is_sandbox_image_ready()}")
    print(f"seccomp profile path:  {SECCOMP_PROFILE}")

    if "--selftest" in sys.argv:
        print("\nRunning container selftest...")
        result = run_sandbox_selftest()
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif "--build" in sys.argv:
        print("\nBuilding sandbox image...")
        ok = build_sandbox_image()
        sys.exit(0 if ok else 1)
    elif len(sys.argv) > 1:
        tech_stack = " ".join(sys.argv[1:])
        print(f"\nRunning sandbox scan: {tech_stack}")
        result = run_in_sandbox(tech_stack)
        print(json.dumps(result, indent=2, ensure_ascii=False))
