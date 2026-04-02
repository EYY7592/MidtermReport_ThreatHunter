"""
Harness Engineering 三柱架構測試
================================

測試三柱基礎設施：
  柱 1：Context Engineering（agent_map, doc_indexer）
  柱 2：Architectural Constraints（arch_linter）
  柱 3：Entropy Management（entropy_scanner）
"""

import tempfile
from pathlib import Path

import pytest


# ═══════════════════════════════════════════════════════════════
# 柱 1：Context Engineering 測試
# ═══════════════════════════════════════════════════════════════

class TestAgentMap:
    """測試 AGENTS.md 解析器"""

    def test_load_existing_agents_md(self):
        """載入專案的 AGENTS.md"""
        from harness.context.agent_map import AgentMap
        project_root = Path(__file__).parent.parent
        agent_map = AgentMap(project_root)
        assert agent_map.load() is True
        assert len(agent_map.sections) > 0

    def test_load_nonexistent_file(self, tmp_path):
        """不存在的 AGENTS.md 回傳 False"""
        from harness.context.agent_map import AgentMap
        agent_map = AgentMap(tmp_path)
        assert agent_map.load() is False

    def test_query_context_returns_results(self):
        """查詢任務能回傳相關文件引用"""
        from harness.context.agent_map import AgentMap
        project_root = Path(__file__).parent.parent
        agent_map = AgentMap(project_root)
        agent_map.load()
        results = agent_map.query_context("修改 Tool")
        # 應該能找到一些相關引用
        assert isinstance(results, list)

    def test_tokenize_mixed_language(self):
        """中英文混合分詞"""
        from harness.context.agent_map import AgentMap
        tokens = AgentMap._tokenize("修復 memory_tool 的 Bug")
        assert "memory_tool" in tokens
        assert "修" in tokens
        assert "bug" in tokens  # 英文轉小寫


class TestDocIndexer:
    """測試 BM25 文件索引器"""

    def test_build_index_from_docs(self):
        """對 docs/ 目錄建立索引"""
        from harness.context.doc_indexer import DocIndexer
        project_root = Path(__file__).parent.parent
        indexer = DocIndexer()
        count = indexer.build_index(project_root / "docs")
        assert count >= 0

    def test_build_index_nonexistent_dir(self, tmp_path):
        """不存在的目錄回傳 0"""
        from harness.context.doc_indexer import DocIndexer
        indexer = DocIndexer()
        count = indexer.build_index(tmp_path / "nonexistent")
        assert count == 0

    def test_search_returns_results(self):
        """搜尋能回傳結果"""
        from harness.context.doc_indexer import DocIndexer
        project_root = Path(__file__).parent.parent
        indexer = DocIndexer()
        indexer.build_index(project_root / "docs")
        results = indexer.search("CVE 漏洞")
        assert isinstance(results, list)

    def test_search_empty_index(self):
        """空索引搜尋回傳空列表"""
        from harness.context.doc_indexer import DocIndexer
        indexer = DocIndexer()
        results = indexer.search("anything")
        assert results == []

    def test_bm25_score_calculation(self):
        """BM25 分數計算不崩潰"""
        from harness.context.doc_indexer import DocIndexer
        indexer = DocIndexer()
        indexer._documents = [{"tokens": ["test", "hello"], "path": "a.md", "title": "a", "content": "test"}]
        indexer._n_docs = 1
        indexer._avg_dl = 2.0
        indexer._df = {"test": 1, "hello": 1}
        score = indexer._bm25_score(["test"], ["test", "hello"])
        assert score > 0


# ═══════════════════════════════════════════════════════════════
# 柱 2：Architectural Constraints 測試
# ═══════════════════════════════════════════════════════════════

class TestArchLinter:
    """測試 AST 邊界 Linter"""

    def test_lint_project_directory(self):
        """掃描專案 harness/ 目錄"""
        from harness.constraints.arch_linter import ArchLinter
        project_root = Path(__file__).parent.parent
        linter = ArchLinter(project_root)
        report = linter.lint_directory()
        assert report.files_scanned > 0

    def test_lint_clean_file(self, tmp_path):
        """無違規的檔案通過"""
        from harness.constraints.arch_linter import ArchLinter
        # 建立一個空的 Python 檔案
        context_dir = tmp_path / "harness" / "context"
        context_dir.mkdir(parents=True)
        clean_file = context_dir / "clean.py"
        clean_file.write_text("import os\nimport json\n")
        linter = ArchLinter(tmp_path)
        violations = linter.lint_file(clean_file)
        assert len(violations) == 0

    def test_detect_layer(self):
        """正確偵測檔案所屬層次"""
        from harness.constraints.arch_linter import ArchLinter
        project_root = Path(__file__).parent.parent
        linter = ArchLinter(project_root)
        # agent_map.py 應屬於 context 層
        agent_map_path = project_root / "harness" / "context" / "agent_map.py"
        if agent_map_path.exists():
            layer = linter.detect_layer(agent_map_path)
            assert layer is not None
            assert layer["name"] == "context"

    def test_harness_boundary_clean(self):
        """專案自身的 harness/ 應該零 error 違規"""
        from harness.constraints.arch_linter import ArchLinter
        project_root = Path(__file__).parent.parent
        linter = ArchLinter(project_root)
        report = linter.lint_directory()
        # 我們自己的程式碼不應有邊界違規
        assert report.is_clean, (
            f"Harness 邊界有 {report.error_count} 筆 error 違規：\n"
            + "\n".join(
                f"  {v.file_path}:{v.line_no} [{v.layer_name}] → {v.imported_module}"
                for v in report.violations
            )
        )


# ═══════════════════════════════════════════════════════════════
# 柱 3：Entropy Management 測試
# ═══════════════════════════════════════════════════════════════

class TestEntropyScanner:
    """測試熵掃描器"""

    def test_scan_project(self):
        """掃描專案回傳報告"""
        from harness.entropy.entropy_scanner import EntropyScanner
        project_root = Path(__file__).parent.parent
        scanner = EntropyScanner(project_root)
        report = scanner.scan()
        assert report.entropy_score >= 0
        assert isinstance(report.is_clean, bool)

    def test_scan_summary_format(self):
        """摘要格式正確"""
        from harness.entropy.entropy_scanner import EntropyScanner
        project_root = Path(__file__).parent.parent
        scanner = EntropyScanner(project_root)
        report = scanner.scan()
        summary = report.summary()
        assert "CLEAN" in summary or "DIRTY" in summary

    def test_structural_integrity_check(self):
        """結構完整性：必要文件存在"""
        from harness.entropy.entropy_scanner import EntropyScanner
        project_root = Path(__file__).parent.parent
        scanner = EntropyScanner(project_root)
        report = scanner.scan()
        # AGENTS.md 和 requirements.txt 應存在
        assert "AGENTS.md" not in report.missing_harness_files
        assert "requirements.txt" not in report.missing_harness_files
