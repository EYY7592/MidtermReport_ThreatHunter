"""
柱 1：情境工程 — AGENTS.md 解析器 + 任務路由引擎
================================================

漸進式情境披露（Progressive Disclosure）的核心元件。
根據任務描述的關鍵字，匹配 AGENTS.md 中的路由段落，
回傳最相關的文件引用列表。

層級邊界：L1（最底層）— 不可引用 harness.constraints 或 harness.entropy
"""

import re
import logging
from pathlib import Path
from dataclasses import dataclass, field

logger = logging.getLogger("threathunter.harness.context")


@dataclass
class DocReference:
    """文件引用"""
    path: str           # 檔案相對路徑
    section: str        # 所屬段落標題
    description: str    # 用途說明
    relevance: float    # 關鍵字重疊度（0.0 ~ 1.0）


@dataclass
class RouteSection:
    """AGENTS.md 中的一個路由段落"""
    title: str                          # 段落標題（例如「修復測試失敗」）
    keywords: list[str] = field(default_factory=list)  # 關鍵字
    references: list[str] = field(default_factory=list)  # 文件引用路徑
    description: str = ""               # 段落描述


class AgentMap:
    """
    AGENTS.md 解析器 + 任務路由引擎

    將 AGENTS.md 解析為結構化路由表，
    根據任務描述的關鍵字重疊度匹配，
    回傳最相關的文件引用。

    用法：
        agent_map = AgentMap(project_root)
        agent_map.load()
        refs = agent_map.query_context("修復 memory_tool 的測試失敗")
    """

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.agents_md_path = project_root / "AGENTS.md"
        self.sections: list[RouteSection] = []
        self.global_rules: list[str] = []
        self._loaded = False

    def load(self) -> bool:
        """
        載入並解析 AGENTS.md

        Returns:
            是否成功載入
        """
        if not self.agents_md_path.exists():
            logger.warning(f"AGENTS.md 不存在：{self.agents_md_path}")
            return False

        try:
            content = self.agents_md_path.read_text(encoding="utf-8")
            self._parse(content)
            self._loaded = True
            logger.info(
                f"✅ AGENTS.md 已載入："
                f"{len(self.sections)} 個路由段落，"
                f"{len(self.global_rules)} 條全域規則"
            )
            return True
        except Exception as e:
            logger.error(f"AGENTS.md 解析失敗：{e}")
            return False

    def _parse(self, content: str) -> None:
        """解析 AGENTS.md 的 Markdown 結構"""
        self.sections = []
        self.global_rules = []

        current_section: RouteSection | None = None
        in_rules_block = False

        for line in content.split("\n"):
            stripped = line.strip()

            # 偵測 ### 段落標題（任務路由段落）
            if stripped.startswith("### "):
                if current_section:
                    self.sections.append(current_section)
                title = stripped[4:].strip()
                # 從「如果你的任務是「XXX」」格式提取關鍵字
                keywords = re.findall(r"[「「](.+?)[」」]", title)
                current_section = RouteSection(
                    title=title,
                    keywords=keywords,
                )
                continue

            # 收集文件引用（→ 格式）
            if current_section and ("→" in stripped or "->" in stripped):
                # 提取路徑引用（反引號包裹的路徑）
                paths = re.findall(r"`([^`]+)`", stripped)
                for path in paths:
                    if "/" in path or path.endswith((".py", ".md", ".toml", ".json")):
                        current_section.references.append(path)
                # 提取描述
                desc = re.sub(r"`[^`]+`", "", stripped).strip("→-> ").strip()
                if desc:
                    current_section.description += desc + " "
                continue

            # 收集全域規則（- 開頭的列表）
            if not current_section and stripped.startswith("- "):
                self.global_rules.append(stripped[2:])

        # 最後一個段落
        if current_section:
            self.sections.append(current_section)

    def query_context(self, task: str, top_k: int = 5) -> list[DocReference]:
        """
        漸進披露的核心方法：根據任務描述匹配文件引用

        使用關鍵字重疊度進行匹配：
        overlap = len(task_tokens ∩ section_keywords) / len(section_keywords)

        Args:
            task: 使用者的任務描述
            top_k: 回傳最相關的前 N 個引用

        Returns:
            按相關性排序的 DocReference 列表
        """
        if not self._loaded:
            self.load()

        task_tokens = set(self._tokenize(task))
        results: list[DocReference] = []

        for section in self.sections:
            section_tokens = set()
            for kw in section.keywords:
                section_tokens.update(self._tokenize(kw))
            # 加上標題的 token
            section_tokens.update(self._tokenize(section.title))

            if not section_tokens:
                continue

            # 計算重疊度
            overlap = len(task_tokens & section_tokens)
            relevance = overlap / max(len(section_tokens), 1)

            if relevance > 0:
                for ref_path in section.references:
                    results.append(DocReference(
                        path=ref_path,
                        section=section.title,
                        description=section.description.strip(),
                        relevance=relevance,
                    ))

        # 按相關性排序，取 top_k
        results.sort(key=lambda r: r.relevance, reverse=True)
        return results[:top_k]

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        """
        簡易中英文分詞

        英文：按空白和標點拆分，轉小寫
        中文：逐字拆分（每個漢字作為獨立 token）
        """
        tokens = []
        # 英文 token
        english_tokens = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", text)
        tokens.extend(t.lower() for t in english_tokens)
        # 中文 token（逐字）
        chinese_chars = re.findall(r"[\u4e00-\u9fff]", text)
        tokens.extend(chinese_chars)
        return tokens
