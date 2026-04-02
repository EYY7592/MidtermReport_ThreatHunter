"""
柱 3：熵防管理 — 系統熵狀態掃描器
==================================

偵測四個維度的系統健康度：
1. 技術債（TODO/FIXME/HACK 密度）
2. 缺失測試（src/*.py 無對應 test_*.py）
3. 文件過期（docs/ 超過 N 天未更新）
4. 結構完整性（Harness 必要文件是否存在）

層級邊界：L3（最高層）— 可引用 L1, L2
"""

import re
import time
import logging
from pathlib import Path
from dataclasses import dataclass, field

logger = logging.getLogger("threathunter.harness.entropy")

# Harness Engineering 必要文件清單（缺失任一 = critical）
REQUIRED_HARNESS_FILES = [
    "AGENTS.md",
    "requirements.txt",
    "project_CONSTITUTION.md",
    "FINAL_PLAN.md",
]

# 技術債標記
DEBT_PATTERNS = re.compile(
    r"\b(TODO|FIXME|HACK|XXX|TEMP|WORKAROUND)\b", re.IGNORECASE
)

# 掃描排除的目錄
EXCLUDED_DIRS = {".git", "__pycache__", ".venv", "venv", ".pytest_cache", "node_modules"}


@dataclass
class EntropyIndicator:
    """單一熵指標"""
    dimension: str      # tech_debt / missing_tests / stale_docs / structure
    severity: str       # critical / warning / info
    message: str        # 描述
    detail: str = ""    # 詳細資訊


@dataclass
class EntropyReport:
    """熵掃描報告"""
    indicators: list[EntropyIndicator] = field(default_factory=list)
    todo_count: int = 0
    total_lines: int = 0
    missing_tests: list[str] = field(default_factory=list)
    stale_docs: list[str] = field(default_factory=list)
    missing_harness_files: list[str] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        """無 critical 指標 = 乾淨"""
        return not any(ind.severity == "critical" for ind in self.indicators)

    @property
    def entropy_score(self) -> float:
        """加權熵分數：critical×10 + warning×3 + info×1"""
        weights = {"critical": 10, "warning": 3, "info": 1}
        return sum(weights.get(ind.severity, 0) for ind in self.indicators)

    def summary(self) -> str:
        """產生摘要文字"""
        status = "✅ CLEAN" if self.is_clean else "❌ DIRTY"
        critical = sum(1 for i in self.indicators if i.severity == "critical")
        warning = sum(1 for i in self.indicators if i.severity == "warning")
        info = sum(1 for i in self.indicators if i.severity == "info")
        return (
            f"{status} — 熵分數: {self.entropy_score:.1f} "
            f"(critical:{critical} warning:{warning} info:{info})"
        )


class EntropyScanner:
    """
    系統熵狀態掃描器

    四維度觀測：
    1. 技術債密度 → ≥5.0 = critical, ≥2.0 = warning
    2. 缺失測試  → 每個缺失 = warning
    3. 文件過期  → 超過 30 天未更新 = warning
    4. 結構完整性 → 缺失必要文件 = critical

    用法：
        scanner = EntropyScanner(project_root)
        report = scanner.scan()
        print(report.summary())
    """

    def __init__(self, project_root: Path, stale_days: int = 30):
        self.project_root = project_root
        self.stale_days = stale_days

    def scan(self) -> EntropyReport:
        """執行完整四維度掃描"""
        report = EntropyReport()

        self._scan_tech_debt(report)
        self._scan_missing_tests(report)
        self._scan_stale_docs(report)
        self._scan_structural_integrity(report)

        if report.is_clean:
            logger.info(f"✅ entropy-scan {report.summary()}")
        else:
            logger.warning(f"❌ entropy-scan {report.summary()}")

        return report

    def _scan_tech_debt(self, report: EntropyReport) -> None:
        """掃描技術債標記密度"""
        total_lines = 0
        todo_count = 0

        for py_file in self._iter_python_files():
            try:
                lines = py_file.read_text(encoding="utf-8").split("\n")
                total_lines += len(lines)
                for line in lines:
                    if DEBT_PATTERNS.search(line):
                        todo_count += 1
            except (OSError, UnicodeDecodeError):
                continue

        report.todo_count = todo_count
        report.total_lines = total_lines

        if total_lines == 0:
            return

        density = (todo_count / total_lines) * 100

        if density >= 5.0:
            report.indicators.append(EntropyIndicator(
                dimension="tech_debt",
                severity="critical",
                message=f"技術債密度過高：{density:.1f}%（{todo_count}/{total_lines}）",
            ))
        elif density >= 2.0:
            report.indicators.append(EntropyIndicator(
                dimension="tech_debt",
                severity="warning",
                message=f"技術債密度偏高：{density:.1f}%（{todo_count}/{total_lines}）",
            ))
        else:
            report.indicators.append(EntropyIndicator(
                dimension="tech_debt",
                severity="info",
                message=f"技術債密度正常：{density:.1f}%（{todo_count}/{total_lines}）",
            ))

    def _scan_missing_tests(self, report: EntropyReport) -> None:
        """掃描缺失測試的模組"""
        # 收集所有需要測試的模組
        testable_modules = []
        for py_file in self._iter_python_files():
            if py_file.name.startswith("test_"):
                continue
            if py_file.name == "__init__.py":
                continue
            testable_modules.append(py_file)

        # 收集所有已有的測試檔案
        tests_dir = self.project_root / "tests"
        existing_tests = set()
        if tests_dir.exists():
            for test_file in tests_dir.rglob("test_*.py"):
                # 從 test_xxx.py 提取 xxx
                module_name = test_file.stem.replace("test_", "")
                existing_tests.add(module_name)

        # 比對
        for module_file in testable_modules:
            module_name = module_file.stem
            if module_name not in existing_tests:
                rel_path = str(module_file.relative_to(self.project_root))
                report.missing_tests.append(rel_path)
                report.indicators.append(EntropyIndicator(
                    dimension="missing_tests",
                    severity="warning",
                    message=f"缺失測試：{rel_path}",
                    detail=f"預期測試：tests/test_{module_name}.py",
                ))

    def _scan_stale_docs(self, report: EntropyReport) -> None:
        """掃描過期文件"""
        docs_dir = self.project_root / "docs"
        if not docs_dir.exists():
            return

        now = time.time()
        stale_threshold = self.stale_days * 86400  # 天 → 秒

        for md_file in docs_dir.rglob("*.md"):
            try:
                mtime = md_file.stat().st_mtime
                age_days = (now - mtime) / 86400
                if age_days > self.stale_days:
                    rel_path = str(md_file.relative_to(self.project_root))
                    report.stale_docs.append(rel_path)
                    report.indicators.append(EntropyIndicator(
                        dimension="stale_docs",
                        severity="warning",
                        message=f"文件過期：{rel_path}（{age_days:.0f} 天未更新）",
                    ))
            except OSError:
                continue

    def _scan_structural_integrity(self, report: EntropyReport) -> None:
        """掃描 Harness 必要文件完整性"""
        for required_file in REQUIRED_HARNESS_FILES:
            full_path = self.project_root / required_file
            if not full_path.exists():
                report.missing_harness_files.append(required_file)
                report.indicators.append(EntropyIndicator(
                    dimension="structure",
                    severity="critical",
                    message=f"缺失必要文件：{required_file}",
                ))

    def _iter_python_files(self):
        """迭代專案中所有 Python 檔案（排除排除目錄）"""
        for py_file in self.project_root.rglob("*.py"):
            if any(excluded in py_file.parts for excluded in EXCLUDED_DIRS):
                continue
            yield py_file


def main() -> int:
    """CLI 入口點：entropy-scan"""
    project_root = Path(__file__).parent.parent.parent
    scanner = EntropyScanner(project_root)
    report = scanner.scan()
    print(report.summary())
    return 0 if report.is_clean else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
