"""
柱 2：架構約束 — AST 靜態分析邊界 Linter
========================================

用 Python AST 解析 import 語句，偵測違反層次邊界的引用。
機械性約束：Agent 不是「不該」違反邊界，而是「不可能」違反。

層級邊界：L2 — 可引用 L1（harness.context）；不可引用 L3（harness.entropy）
"""

import ast
import sys
import logging
from pathlib import Path
from dataclasses import dataclass

# L2 可引用 L1
from harness.context.agent_map import AgentMap

logger = logging.getLogger("threathunter.harness.constraints")

# ── boundary_rules.toml 解析 ─────────────────────────────────
# 使用標準庫解析 TOML（Python 3.11+ 有 tomllib）
try:
    import tomllib
except ModuleNotFoundError:
    # Python < 3.11 fallback
    try:
        import tomli as tomllib  # type: ignore
    except ModuleNotFoundError:
        tomllib = None  # type: ignore


@dataclass
class Violation:
    """一筆邊界違規記錄"""
    file_path: str      # 違規的原始檔路徑
    line_no: int        # 行號
    layer_name: str     # 所屬層次
    imported_module: str  # 違規引用的模組
    forbidden_rule: str   # 觸發的禁止規則
    severity: str       # error / warning


@dataclass
class LintReport:
    """Linter 掃描報告"""
    violations: list[Violation]
    files_scanned: int
    layers_checked: int

    @property
    def is_clean(self) -> bool:
        """無 error 級違規 = 乾淨"""
        return not any(v.severity == "error" for v in self.violations)

    @property
    def error_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == "error")

    @property
    def warning_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == "warning")


class ArchLinter:
    """
    AST 靜態分析邊界 Linter

    核心演算法：
    1. 根據路徑判斷檔案所屬層次
    2. 查詢該層的禁止引用列表（boundary_rules.toml）
    3. 用 ast.parse 提取所有 import 語句
    4. 逐一比對

    用法：
        linter = ArchLinter(project_root)
        report = linter.lint_directory()
        if not report.is_clean:
            sys.exit(1)
    """

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.layers: list[dict] = []
        self.mode: str = "strict"
        self._load_rules()

    def _load_rules(self) -> None:
        """載入 boundary_rules.toml"""
        rules_path = self.project_root / "harness" / "constraints" / "boundary_rules.toml"

        if not rules_path.exists():
            logger.warning(f"邊界規則檔案不存在：{rules_path}")
            return

        if tomllib is None:
            logger.warning("tomllib/tomli 不可用，無法解析 TOML。Python 3.11+ 內建 tomllib。")
            return

        try:
            with open(rules_path, "rb") as f:
                data = tomllib.load(f)
            self.mode = data.get("meta", {}).get("mode", "strict")
            self.layers = data.get("layers", [])
            logger.info(
                f"✅ 邊界規則已載入：{len(self.layers)} 層，模式={self.mode}"
            )
        except Exception as e:
            logger.error(f"邊界規則載入失敗：{e}")

    def detect_layer(self, file_path: Path) -> dict | None:
        """根據路徑判斷檔案所屬層次"""
        rel_path = str(file_path.relative_to(self.project_root)).replace("\\", "/")
        for layer in self.layers:
            if layer["path_pattern"] in rel_path:
                return layer
        return None

    def extract_imports(self, file_path: Path) -> list[tuple[str, int]]:
        """用 AST 提取檔案中所有 import 的模組名稱和行號"""
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(file_path))
        except SyntaxError:
            logger.warning(f"語法錯誤，跳過：{file_path}")
            return []
        except (OSError, UnicodeDecodeError):
            return []

        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append((alias.name, node.lineno))
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.append((node.module, node.lineno))

        return imports

    def lint_file(self, file_path: Path) -> list[Violation]:
        """掃描單一檔案的邊界違規"""
        # 跳過 __init__.py（避免匯出模組的誤報）
        if file_path.name == "__init__.py":
            return []

        layer = self.detect_layer(file_path)
        if layer is None:
            return []  # 不屬於任何層次的檔案不檢查

        forbidden = layer.get("forbidden_imports_from", [])
        if not forbidden:
            return []

        imports = self.extract_imports(file_path)
        violations = []

        for module_name, line_no in imports:
            for forbidden_module in forbidden:
                if (module_name == forbidden_module or
                        module_name.startswith(forbidden_module + ".")):
                    violations.append(Violation(
                        file_path=str(file_path),
                        line_no=line_no,
                        layer_name=layer["name"],
                        imported_module=module_name,
                        forbidden_rule=forbidden_module,
                        severity=layer.get("severity", "error"),
                    ))

        return violations

    def lint_directory(self, directory: Path | None = None) -> LintReport:
        """
        掃描整個目錄的邊界違規

        Args:
            directory: 要掃描的目錄（預設為 harness/）

        Returns:
            LintReport 掃描報告
        """
        if directory is None:
            directory = self.project_root / "harness"

        if not directory.exists():
            return LintReport(violations=[], files_scanned=0, layers_checked=0)

        all_violations = []
        files_scanned = 0

        for py_file in directory.rglob("*.py"):
            files_scanned += 1
            violations = self.lint_file(py_file)
            all_violations.extend(violations)

        report = LintReport(
            violations=all_violations,
            files_scanned=files_scanned,
            layers_checked=len(self.layers),
        )

        if report.is_clean:
            logger.info(
                f"✅ arch-lint CLEAN：{files_scanned} 檔案，零違規"
            )
        else:
            logger.error(
                f"❌ arch-lint DIRTY：{report.error_count} error, "
                f"{report.warning_count} warning"
            )
            for v in all_violations:
                logger.error(
                    f"  {v.file_path}:{v.line_no} — "
                    f"[{v.layer_name}] 禁止引用 {v.imported_module} "
                    f"（規則: {v.forbidden_rule}）"
                )

        return report


def main() -> int:
    """CLI 入口點：arch-lint"""
    project_root = Path(__file__).parent.parent.parent
    linter = ArchLinter(project_root)
    report = linter.lint_directory()

    if report.is_clean:
        print(f"✅ CLEAN — {report.files_scanned} files scanned, 0 violations")
        return 0
    else:
        print(f"❌ DIRTY — {report.error_count} errors, {report.warning_count} warnings")
        return 1


if __name__ == "__main__":
    sys.exit(main())
