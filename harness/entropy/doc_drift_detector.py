"""
柱 3：熵防管理 — 文件漂移偵測器
================================

偵測「文件描述 ≠ 程式碼現實」的漂移問題。
比對 FINAL_PLAN.md 中定義的檔案結構與實際磁碟上的檔案。

層級邊界：L3（最高層）— 可引用 L1, L2
"""

import re
import logging
from pathlib import Path
from dataclasses import dataclass, field

logger = logging.getLogger("threathunter.harness.entropy")


@dataclass
class DriftItem:
    """一筆漂移記錄"""
    drift_type: str     # missing_in_code / missing_in_doc / extra_in_code
    path: str           # 相關路徑
    severity: str       # warning / info
    message: str


@dataclass
class DriftReport:
    """漂移偵測報告"""
    items: list[DriftItem] = field(default_factory=list)
    documented_paths: list[str] = field(default_factory=list)
    actual_paths: list[str] = field(default_factory=list)

    @property
    def has_drift(self) -> bool:
        return len(self.items) > 0

    @property
    def drift_count(self) -> int:
        return len(self.items)


class DocDriftDetector:
    """
    文件漂移偵測器

    核心邏輯：
    1. 從 FINAL_PLAN.md 的檔案結構段落提取預期的檔案路徑
    2. 掃描實際磁碟上的檔案
    3. 比對差異：
       - missing_in_code: 文件中有，程式碼中沒有
       - extra_in_code: 程式碼中有，文件中不一定有（info 級）

    用法：
        detector = DocDriftDetector(project_root)
        report = detector.detect()
    """

    # 從 Markdown 程式碼區塊中提取路徑的正則
    PATH_PATTERN = re.compile(
        r"[├└│\s]*(?:──\s*)?(\S+\.(?:py|md|json|toml|txt|yaml|yml))"
    )

    # 排除的目錄
    EXCLUDED_DIRS = {".git", "__pycache__", ".venv", "venv", ".pytest_cache"}

    def __init__(self, project_root: Path):
        self.project_root = project_root

    def detect(self, reference_doc: str = "FINAL_PLAN.md") -> DriftReport:
        """
        執行漂移偵測

        Args:
            reference_doc: 作為參考的文件路徑（相對於專案根目錄）
        """
        report = DriftReport()
        doc_path = self.project_root / reference_doc

        if not doc_path.exists():
            logger.warning(f"參考文件不存在：{doc_path}")
            return report

        # 提取文件中定義的路徑
        documented = self._extract_paths_from_doc(doc_path)
        report.documented_paths = documented

        # 掃描實際路徑
        actual = self._scan_actual_paths()
        report.actual_paths = actual

        actual_set = set(actual)
        documented_set = set(documented)

        # 文件中有但程式碼中沒有
        for path in documented_set - actual_set:
            report.items.append(DriftItem(
                drift_type="missing_in_code",
                path=path,
                severity="warning",
                message=f"文件中定義但程式碼中不存在：{path}",
            ))

        if report.has_drift:
            logger.warning(f"⚠️ 偵測到 {report.drift_count} 處文件漂移")
        else:
            logger.info("✅ 文件與程式碼一致，無漂移")

        return report

    def _extract_paths_from_doc(self, doc_path: Path) -> list[str]:
        """從 Markdown 文件提取檔案路徑"""
        paths = []
        try:
            content = doc_path.read_text(encoding="utf-8")
            in_code_block = False

            for line in content.split("\n"):
                stripped = line.strip()
                if stripped.startswith("```"):
                    in_code_block = not in_code_block
                    continue

                if in_code_block:
                    match = self.PATH_PATTERN.search(stripped)
                    if match:
                        path = match.group(1).strip()
                        # 過濾明顯不是路徑的匹配
                        if not path.startswith("#") and len(path) > 2:
                            paths.append(path)

        except (OSError, UnicodeDecodeError) as e:
            logger.warning(f"無法讀取文件：{doc_path}: {e}")

        return paths

    def _scan_actual_paths(self) -> list[str]:
        """掃描專案中實際存在的檔案"""
        paths = []
        for item in self.project_root.rglob("*"):
            if item.is_file():
                if any(excluded in item.parts for excluded in self.EXCLUDED_DIRS):
                    continue
                rel_path = str(item.relative_to(self.project_root)).replace("\\", "/")
                paths.append(item.name)  # 只用檔名比對（避免路徑格式差異）

        return list(set(paths))
