"""
柱 3：熵防管理 — UNTIL CLEAN 閉環驗證迴圈
==========================================

以「終止條件」驅動，而非「步驟列表」驅動。
三道關卡：arch-lint → entropy-scan → pytest
重複執行直到全部通過，或達到最大迭代次數後升級給工程師。

層級邊界：L3（最高層）— 可引用 L1, L2
"""

import sys
import logging
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import Callable

# L3 可引用 L2
from harness.constraints.arch_linter import ArchLinter
from harness.entropy.entropy_scanner import EntropyScanner

logger = logging.getLogger("threathunter.harness.entropy")

MAX_ITERATIONS = 10  # 最大迭代次數


@dataclass
class GateResult:
    """單一關卡的執行結果"""
    name: str
    passed: bool
    message: str
    details: str = ""


@dataclass
class CleanStatus:
    """UNTIL CLEAN 迴圈的最終狀態"""
    is_clean: bool
    iterations: int
    gate_results: list[GateResult] = field(default_factory=list)
    escalation: bool = False

    def summary(self) -> str:
        status = "✅ CLEAN" if self.is_clean else "❌ DIRTY"
        esc = " (⚠️ ESCALATION)" if self.escalation else ""
        lines = [f"{status} — 迭代次數: {self.iterations}{esc}"]
        for gate in self.gate_results:
            icon = "✅" if gate.passed else "❌"
            lines.append(f"  {icon} {gate.name}: {gate.message}")
        return "\n".join(lines)


class UntilCleanLoop:
    """
    UNTIL CLEAN 閉環驗證迴圈

    三道關卡（依序執行）：
    1. arch-lint  → 邊界 Linter（零 error 違規）
    2. entropy-scan → 熵防掃描（零 critical 指標）
    3. pytest     → 測試套件（全通過）

    流程：
    REPEAT
      執行三道關卡
    UNTIL all_pass == True OR iterations >= MAX_ITERATIONS

    用法：
        loop = UntilCleanLoop(project_root)
        status = loop.run()
        if not status.is_clean:
            print("請工程師介入！")
    """

    def __init__(self, project_root: Path, max_iterations: int = MAX_ITERATIONS):
        self.project_root = project_root
        self.max_iterations = max_iterations
        self.linter = ArchLinter(project_root)
        self.scanner = EntropyScanner(project_root)

    def run(self, fix_callback: Callable[[list[GateResult]], None] | None = None) -> CleanStatus:
        """
        執行 UNTIL CLEAN 迴圈

        Args:
            fix_callback: 可選的修復回呼函式，接收失敗的關卡結果。
                          若提供，每次迭代失敗後會呼叫此函式嘗試修復。

        Returns:
            CleanStatus 最終狀態
        """
        for iteration in range(1, self.max_iterations + 1):
            logger.info(f"{'─' * 40}")
            logger.info(f"  UNTIL CLEAN 迭代 {iteration}/{self.max_iterations}")
            logger.info(f"{'─' * 40}")

            gate_results = self._run_all_gates()
            all_passed = all(g.passed for g in gate_results)

            if all_passed:
                logger.info(f"✅ SYSTEM STATUS: CLEAN（迭代 {iteration}）")
                return CleanStatus(
                    is_clean=True,
                    iterations=iteration,
                    gate_results=gate_results,
                )

            logger.warning(
                f"迭代 {iteration}: "
                f"{sum(1 for g in gate_results if not g.passed)} 道關卡未通過"
            )

            # 嘗試修復
            if fix_callback:
                failed_gates = [g for g in gate_results if not g.passed]
                try:
                    fix_callback(failed_gates)
                except Exception as e:
                    logger.error(f"修復回呼失敗：{e}")

        # 達到最大迭代次數
        logger.error(
            f"❌ SYSTEM STATUS: DIRTY\n"
            f"已達到最大迭代次數 ({self.max_iterations})，系統仍未 CLEAN。\n"
            f"請通知工程師介入處理。（Escalation）"
        )
        return CleanStatus(
            is_clean=False,
            iterations=self.max_iterations,
            gate_results=gate_results,
            escalation=True,
        )

    def _run_all_gates(self) -> list[GateResult]:
        """依序執行三道關卡"""
        results = []

        # 關卡 1：arch-lint
        results.append(self._gate_arch_lint())

        # 關卡 2：entropy-scan
        results.append(self._gate_entropy_scan())

        # 關卡 3：pytest
        results.append(self._gate_pytest())

        return results

    def _gate_arch_lint(self) -> GateResult:
        """關卡 1：邊界 Linter"""
        try:
            report = self.linter.lint_directory()
            if report.is_clean:
                return GateResult(
                    name="arch-lint",
                    passed=True,
                    message=f"CLEAN — {report.files_scanned} 檔案零違規",
                )
            else:
                details = "\n".join(
                    f"  {v.file_path}:{v.line_no} [{v.layer_name}] → {v.imported_module}"
                    for v in report.violations
                )
                return GateResult(
                    name="arch-lint",
                    passed=False,
                    message=f"{report.error_count} error, {report.warning_count} warning",
                    details=details,
                )
        except Exception as e:
            return GateResult(
                name="arch-lint",
                passed=False,
                message=f"執行失敗：{e}",
            )

    def _gate_entropy_scan(self) -> GateResult:
        """關卡 2：熵防掃描"""
        try:
            report = self.scanner.scan()
            if report.is_clean:
                return GateResult(
                    name="entropy-scan",
                    passed=True,
                    message=f"CLEAN — 熵分數: {report.entropy_score:.1f}",
                )
            else:
                critical_items = [
                    i for i in report.indicators if i.severity == "critical"
                ]
                details = "\n".join(f"  ❌ {i.message}" for i in critical_items)
                return GateResult(
                    name="entropy-scan",
                    passed=False,
                    message=f"熵分數: {report.entropy_score:.1f}",
                    details=details,
                )
        except Exception as e:
            return GateResult(
                name="entropy-scan",
                passed=False,
                message=f"執行失敗：{e}",
            )

    def _gate_pytest(self) -> GateResult:
        """關卡 3：測試套件（排除需要外部 LLM/API 的測試）"""
        tests_dir = self.project_root / "tests"
        if not tests_dir.exists() or not list(tests_dir.glob("test_*.py")):
            return GateResult(
                name="pytest",
                passed=True,
                message="無測試檔案，跳過（符合規範後應補測試）",
            )

        # 快速通道：排除需要外部 LLM 呼叫的測試（避免 rate limit 和超時）
        # 這些測試標記為 @pytest.mark.llm 或在 test_redteam.py（每個測試呼叫 LLM）
        fast_tests = [
            str(tests_dir / "test_epss_tool.py"),
            str(tests_dir / "test_security_guard.py"),
            str(tests_dir / "test_intel_fusion.py"),
            str(tests_dir / "test_memory_tool.py"),
            str(tests_dir / "test_nvd_tool.py"),
            str(tests_dir / "test_otx_tool.py"),
            str(tests_dir / "test_harness.py"),
            str(tests_dir / "test_pipeline_integration.py"),
        ]
        # 只跑「快速通道」中存在的測試
        existing_fast = [t for t in fast_tests if (self.project_root / t.lstrip(str(self.project_root))).exists() or Path(t).exists()]

        try:
            result = subprocess.run(
                [sys.executable, "-m", "pytest"] + existing_fast + ["-v", "--tb=short", "-q"],
                capture_output=True,
                text=True,
                cwd=str(self.project_root),
                timeout=600,  # 10 分鐘（排除 LLM 測試後，快速套件約需 5 分鐘）
                env={**__import__('os').environ, "PYTHONUTF8": "1"},
            )

            if result.returncode == 0:
                return GateResult(
                    name="pytest",
                    passed=True,
                    message="快速測試套件全部通過",
                )
            else:
                # 取最後 20 行作為摘要
                output_lines = (result.stdout + result.stderr).strip().split("\n")
                tail = "\n".join(output_lines[-20:])
                return GateResult(
                    name="pytest",
                    passed=False,
                    message=f"測試失敗（exit code: {result.returncode}）",
                    details=tail,
                )

        except subprocess.TimeoutExpired:
            return GateResult(
                name="pytest",
                passed=False,
                message="快速測試超時（300 秒），可能有無限等待",
            )
        except Exception as e:
            return GateResult(
                name="pytest",
                passed=False,
                message=f"執行失敗：{e}",
            )


def main() -> int:
    """CLI 入口點：until-clean"""
    project_root = Path(__file__).parent.parent.parent
    loop = UntilCleanLoop(project_root)
    status = loop.run()
    print(status.summary())
    return 0 if status.is_clean else 1


if __name__ == "__main__":
    sys.exit(main())
