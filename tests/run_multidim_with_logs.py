"""
tests/run_multidim_with_logs.py
================================
多維度測試執行器 + 即時 Log 捕捉

功能：
  - 即時將 pytest 輸出寫入 logs/test_runs/YYYYMMDD_HHMMSS.log
  - 錯誤（FAILED / ERROR）單獨寫入 logs/errors/error_YYYYMMDD_HHMMSS.log
  - 即時監控摘要寫入 logs/monitor/monitor.jsonl（每秒更新）
  - 測試完成後输出結構化 JSON 報告

執行：
  uv run python tests/run_multidim_with_logs.py
"""

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ── 路徑設定 ──────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).parent.parent
LOGS_DIR = PROJECT_ROOT / "logs"
TEST_RUNS_DIR = LOGS_DIR / "test_runs"
ERRORS_DIR = LOGS_DIR / "errors"
MONITOR_DIR = LOGS_DIR / "monitor"

TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
MAIN_LOG = TEST_RUNS_DIR / f"multidim_{TIMESTAMP}.log"
ERROR_LOG = ERRORS_DIR / f"errors_{TIMESTAMP}.log"
MONITOR_LOG = MONITOR_DIR / "monitor.jsonl"
REPORT_FILE = LOGS_DIR / f"test_report_{TIMESTAMP}.json"

# ── 確保目錄存在 ────────────────────────────────────────────
for d in [TEST_RUNS_DIR, ERRORS_DIR, MONITOR_DIR]:
    d.mkdir(parents=True, exist_ok=True)


def write_log(path: Path, content: str, mode: str = "a") -> None:
    """安全寫入 log 檔案"""
    try:
        with open(path, mode, encoding="utf-8") as f:
            f.write(content)
    except OSError as e:
        print(f"[LOG ERROR] Cannot write to {path}: {e}", file=sys.stderr)


def write_monitor(event: dict) -> None:
    """寫入即時監控 JSONL"""
    event["ts"] = datetime.now(timezone.utc).isoformat()
    write_log(MONITOR_LOG, json.dumps(event, ensure_ascii=False) + "\n")


def parse_test_result(line: str) -> dict | None:
    """解析 pytest 輸出行，提取測試結果"""
    # 匹配：tests/xxx.py::TestClass::test_name PASSED/FAILED [ xx%]
    m = re.match(
        r"(tests/[\w/]+\.py)::(\w+)::(\w+)\s+(PASSED|FAILED|ERROR|SKIPPED)\s+\[\s*(\d+)%\]",
        line.strip()
    )
    if m:
        return {
            "file": m.group(1),
            "class": m.group(2),
            "test": m.group(3),
            "status": m.group(4),
            "progress": int(m.group(5)),
        }
    return None


def run_tests() -> dict:
    """執行多維度測試，捕捉並分析輸出"""

    cmd = [
        sys.executable, "-m", "pytest",
        "tests/test_multidim.py",
        "-v", "--tb=short", "-k", "not e2e",
        "--no-header",
    ]

    # 標頭行寫入主 log
    header = f"""
{'='*70}
  ThreatHunter Multi-Dimensional Test Run
  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
  Command : {' '.join(cmd)}
{'='*70}
"""
    write_log(MAIN_LOG, header, mode="w")
    write_monitor({"event": "run_started", "cmd": " ".join(cmd)})

    # 統計
    stats = {
        "total": 0, "passed": 0, "failed": 0,
        "errors": 0, "skipped": 0,
        "start_time": time.time(),
        "failures": [],
        "by_class": {},
        "by_dimension": {
            "D1_Clean": {"passed": 0, "failed": 0},
            "D2_Suspicious": {"passed": 0, "failed": 0},
            "D3_Vulnerable": {"passed": 0, "failed": 0},
            "D4_Injection": {"passed": 0, "failed": 0},
            "D5_Mixed": {"passed": 0, "failed": 0},
            "D6_Edge": {"passed": 0, "failed": 0},
        }
    }

    error_buffer = []  # 收集 FAILED 後的詳細訊息
    in_failure = False
    current_failure_lines = []

    print(f"\n{'='*60}")
    print(f"  ThreatHunter Multi-Dimensional Test Suite")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")
    print(f"  Main Log  : {MAIN_LOG}")
    print(f"  Error Log : {ERROR_LOG}")
    print(f"  Monitor   : {MONITOR_LOG}")
    print(f"{'='*60}\n")

    os.environ["PYTHONUTF8"] = "1"

    # 執行 pytest，即時捕捉輸出
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(PROJECT_ROOT),
        env=os.environ.copy()
    )

    for line in iter(process.stdout.readline, ""):
        # 即時顯示到終端
        print(line, end="", flush=True)

        # 寫入主 log
        ts_prefix = datetime.now().strftime("%H:%M:%S.%f")[:12]
        write_log(MAIN_LOG, f"[{ts_prefix}] {line}")

        # 偵測 FAILED 區段開始
        if line.strip().startswith("FAILED") or "_ FAILED _" in line:
            in_failure = True
            current_failure_lines = [line]
        elif in_failure:
            current_failure_lines.append(line)
            # 偵測 FAILED 區段結束（空行或下一個測試）
            stripped = line.strip()
            if stripped.startswith("tests/") and ("PASSED" in stripped or "FAILED" in stripped):
                in_failure = False
                failure_text = "".join(current_failure_lines)
                error_buffer.append(failure_text)
                write_log(ERROR_LOG, f"\n{'='*50}\n{failure_text}")
                current_failure_lines = []

        # 解析測試結果
        result = parse_test_result(line)
        if result:
            stats["total"] += 1
            status = result["status"]
            test_class = result["class"]
            test_name = result["test"]

            if status == "PASSED":
                stats["passed"] += 1
            elif status == "FAILED":
                stats["failed"] += 1
                stats["failures"].append(f"{test_class}::{test_name}")
                # 寫入 error log
                write_log(ERROR_LOG, f"[FAILED] {test_class}::{test_name}\n")
            elif status == "ERROR":
                stats["errors"] += 1
                write_log(ERROR_LOG, f"[ERROR] {test_class}::{test_name}\n")
            elif status == "SKIPPED":
                stats["skipped"] += 1

            # 按 class 統計
            if test_class not in stats["by_class"]:
                stats["by_class"][test_class] = {"passed": 0, "failed": 0}
            stats["by_class"][test_class][status.lower() if status in ("PASSED", "FAILED") else "passed"] += 1

            # 按維度統計
            def dim_key(name: str) -> str:
                n = name.lower()
                if "clean" in n or "no_danger" in n or "spring" in n or "express" in n:
                    return "D1_Clean"
                if "suspicious" in n:
                    return "D2_Suspicious"
                if "sqli" in n or "cmdi" in n or "xss" in n or "deserializ" in n or "secret" in n or "php" in n or "go" in n:
                    return "D3_Vulnerable"
                if "injection" in n or "pi_" in n or "jailbreak" in n or "chinese" in n or "exfil" in n:
                    return "D4_Injection"
                if "mixed" in n or "legit" in n or "multi_vuln" in n or "poison" in n:
                    return "D5_Mixed"
                if "empty" in n or "huge" in n or "minif" in n or "package_list" in n or "edge" in n:
                    return "D6_Edge"
                return "D3_Vulnerable"  # default

            dk = dim_key(test_name)
            if status == "PASSED":
                stats["by_dimension"][dk]["passed"] += 1
            elif status in ("FAILED", "ERROR"):
                stats["by_dimension"][dk]["failed"] += 1

            # 即時監控事件
            write_monitor({
                "event": "test_result",
                "status": status,
                "class": test_class,
                "test": test_name,
                "progress": result["progress"],
                "running_pass": stats["passed"],
                "running_fail": stats["failed"],
            })

    process.wait()
    stats["elapsed"] = time.time() - stats["start_time"]
    stats["exit_code"] = process.returncode

    write_monitor({"event": "run_completed", "stats": stats})
    return stats


def build_report(stats: dict) -> dict:
    """建立結構化測試報告"""

    # 計算每個維度的通過率
    dim_summary = {}
    for dim, counts in stats["by_dimension"].items():
        total = counts["passed"] + counts["failed"]
        rate = counts["passed"] / total * 100 if total > 0 else 0
        dim_summary[dim] = {
            "passed": counts["passed"],
            "failed": counts["failed"],
            "total": total,
            "pass_rate": f"{rate:.0f}%",
            "verdict": "✅ PASS" if counts["failed"] == 0 else "❌ FAIL",
        }

    # 計算每個測試類別通過率
    class_summary = {}
    for cls, counts in stats["by_class"].items():
        total = counts["passed"] + counts["failed"]
        rate = counts["passed"] / total * 100 if total > 0 else 0
        class_summary[cls] = {
            "passed": counts["passed"],
            "failed": counts["failed"],
            "pass_rate": f"{rate:.0f}%",
        }

    overall_rate = stats["passed"] / stats["total"] * 100 if stats["total"] > 0 else 0
    verdict = "✅ ALL PASSED — SYSTEM RESILIENT" if stats["failed"] == 0 and stats["errors"] == 0 \
              else f"⚠️ {stats['failed']} FAILED — REVIEW REQUIRED"

    report = {
        "report_meta": {
            "title": "ThreatHunter v3.1 Multi-Dimensional Test Report",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "timestamp": TIMESTAMP,
            "log_files": {
                "main_log": str(MAIN_LOG),
                "error_log": str(ERROR_LOG),
                "monitor_log": str(MONITOR_LOG),
            }
        },
        "overall": {
            "total": stats["total"],
            "passed": stats["passed"],
            "failed": stats["failed"],
            "errors": stats["errors"],
            "skipped": stats["skipped"],
            "pass_rate": f"{overall_rate:.1f}%",
            "elapsed_sec": round(stats["elapsed"], 2),
            "verdict": verdict,
            "failures": stats["failures"],
        },
        "by_dimension": dim_summary,
        "by_test_class": class_summary,
        "dimension_map": {
            "D1_Clean": "正常程式碼（Flask/Express/Spring）— 語言偵測 + 低誤報",
            "D2_Suspicious": "可疑但安全（eval 白名單/動態 SQL）— 不誤報",
            "D3_Vulnerable": "確實漏洞（SQLi/CMDi/XSS/Deserialize/Secrets）— 不漏報",
            "D4_Injection": "Prompt Injection 攻擊（4 種類型）— Agent 韌性",
            "D5_Mixed": "混合場景（正常夾帶攻擊/多重漏洞）— 全面偵測",
            "D6_Edge": "邊界條件（空檔/超大檔/壓縮 JS/套件清單）— 穩健性",
        }
    }
    return report


def print_report(report: dict) -> None:
    """漂亮列印報告到終端"""
    meta = report["report_meta"]
    overall = report["overall"]
    dims = report["by_dimension"]

    print(f"\n{'='*65}")
    print(f"  {meta['title']}")
    print(f"  Generated: {meta['generated_at'][:19].replace('T', ' ')} UTC")
    print(f"{'='*65}")
    print(f"\n  📊 OVERALL RESULTS")
    print(f"  {'─'*50}")
    print(f"  Total Tests  : {overall['total']}")
    print(f"  Passed       : {overall['passed']} ({overall['pass_rate']})")
    print(f"  Failed       : {overall['failed']}")
    print(f"  Errors       : {overall['errors']}")
    print(f"  Skipped      : {overall['skipped']}")
    print(f"  Elapsed      : {overall['elapsed_sec']}s")
    print(f"\n  Verdict: {overall['verdict']}")

    print(f"\n  📐 BY DIMENSION")
    print(f"  {'─'*50}")
    dim_names = report["dimension_map"]
    for dim, data in dims.items():
        label = dim_names.get(dim, dim)
        bar = "█" * data["passed"] + "░" * data["failed"]
        print(f"  {dim:20s} {data['verdict']}  {data['passed']}/{data['total']} ({data['pass_rate']})")
        print(f"    {label}")

    if overall["failures"]:
        print(f"\n  ❌ FAILED TESTS")
        print(f"  {'─'*50}")
        for f in overall["failures"]:
            print(f"  • {f}")

    print(f"\n  📁 LOG FILES")
    print(f"  {'─'*50}")
    for name, path in meta["log_files"].items():
        print(f"  {name:12s}: {path}")
    print(f"  report     : {REPORT_FILE}")
    print(f"{'='*65}\n")


def main():
    start_banner = f"""
╔══════════════════════════════════════════════════════════════╗
║  ThreatHunter v3.1 — Multi-Dimensional Test Suite           ║
║  Layer 1: Deterministic (49 tests, no LLM token)            ║
║  Dimensions: D1 Clean / D2 Suspicious / D3 Vuln /           ║
║              D4 Injection / D5 Mixed / D6 Edge              ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(start_banner)
    write_log(MAIN_LOG, start_banner, mode="w")
    write_log(ERROR_LOG, f"ThreatHunter Error Log — {TIMESTAMP}\n{'='*50}\n", mode="w")

    # 執行測試
    stats = run_tests()

    # 建立報告
    report = build_report(stats)

    # 儲存 JSON 報告
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    # 印出報告
    print_report(report)

    print(f"\n  JSON Report saved to: {REPORT_FILE}\n")

    return 0 if stats["failed"] == 0 and stats["errors"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
