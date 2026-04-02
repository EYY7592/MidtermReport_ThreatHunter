"""
柱 1：情境工程 — BM25 文件索引器
================================

對 docs/ 目錄建立離線 BM25 關鍵字搜尋索引，
支援中英文混合查詢。零外部依賴（僅使用標準庫）。

層級邊界：L1（最底層）— 不可引用 harness.constraints 或 harness.entropy
"""

import re
import math
import logging
from pathlib import Path
from dataclasses import dataclass

logger = logging.getLogger("threathunter.harness.context")


@dataclass
class SearchResult:
    """搜尋結果"""
    path: str       # 檔案路徑
    score: float    # BM25 分數
    snippet: str    # 匹配段落摘要（前 200 字）
    title: str      # 檔案標題（第一行 # 標題）


class DocIndexer:
    """
    BM25 文件索引器

    對指定目錄下的 .md 和 .txt 文件建立 BM25 索引，
    支援中英文混合查詢。

    BM25 參數：
      k1 = 1.5（詞頻飽和度）
      b  = 0.75（文件長度正規化）

    用法：
        indexer = DocIndexer()
        indexer.build_index(Path("docs/"))
        results = indexer.search("漏洞修復 Django")
    """

    # BM25 超參數
    K1 = 1.5
    B = 0.75

    def __init__(self):
        self._documents: list[dict] = []  # [{path, title, content, tokens}]
        self._avg_dl: float = 0.0         # 平均文件長度
        self._df: dict[str, int] = {}     # document frequency
        self._n_docs: int = 0

    def build_index(self, directory: Path) -> int:
        """
        掃描目錄下所有 .md / .txt 文件，建立 BM25 索引

        Args:
            directory: 要掃描的目錄路徑

        Returns:
            索引的文件數量
        """
        self._documents = []
        self._df = {}

        if not directory.exists():
            logger.warning(f"索引目錄不存在：{directory}")
            return 0

        # 掃描所有文件
        for ext in ("*.md", "*.txt"):
            for file_path in directory.rglob(ext):
                try:
                    content = file_path.read_text(encoding="utf-8")
                    tokens = self._tokenize(content)
                    title = self._extract_title(content, file_path.name)

                    self._documents.append({
                        "path": str(file_path),
                        "title": title,
                        "content": content,
                        "tokens": tokens,
                    })

                    # 更新 document frequency
                    unique_tokens = set(tokens)
                    for token in unique_tokens:
                        self._df[token] = self._df.get(token, 0) + 1

                except (OSError, UnicodeDecodeError) as e:
                    logger.warning(f"跳過無法讀取的文件 {file_path}: {e}")

        self._n_docs = len(self._documents)
        if self._n_docs > 0:
            self._avg_dl = sum(
                len(doc["tokens"]) for doc in self._documents
            ) / self._n_docs

        logger.info(f"✅ 文件索引已建立：{self._n_docs} 份文件")
        return self._n_docs

    def search(self, query: str, top_k: int = 5) -> list[SearchResult]:
        """
        BM25 關鍵字搜尋

        Args:
            query: 搜尋查詢（支援中英文混合）
            top_k: 回傳最相關的前 N 個結果

        Returns:
            按 BM25 分數排序的搜尋結果
        """
        if not self._documents:
            return []

        query_tokens = self._tokenize(query)
        if not query_tokens:
            return []

        scores: list[tuple[int, float]] = []

        for idx, doc in enumerate(self._documents):
            score = self._bm25_score(query_tokens, doc["tokens"])
            if score > 0:
                scores.append((idx, score))

        # 按分數排序
        scores.sort(key=lambda x: x[1], reverse=True)

        results = []
        for idx, score in scores[:top_k]:
            doc = self._documents[idx]
            snippet = doc["content"][:200].replace("\n", " ").strip()
            results.append(SearchResult(
                path=doc["path"],
                score=round(score, 4),
                snippet=snippet,
                title=doc["title"],
            ))

        return results

    def _bm25_score(self, query_tokens: list[str], doc_tokens: list[str]) -> float:
        """計算單一文件的 BM25 分數"""
        score = 0.0
        dl = len(doc_tokens)

        # 建立文件內的詞頻表
        tf_map: dict[str, int] = {}
        for token in doc_tokens:
            tf_map[token] = tf_map.get(token, 0) + 1

        for qt in query_tokens:
            if qt not in tf_map:
                continue

            tf = tf_map[qt]
            df = self._df.get(qt, 0)

            # IDF（逆文件頻率）
            idf = math.log(
                (self._n_docs - df + 0.5) / (df + 0.5) + 1
            )

            # BM25 詞頻正規化
            numerator = tf * (self.K1 + 1)
            denominator = tf + self.K1 * (
                1 - self.B + self.B * dl / max(self._avg_dl, 1)
            )

            score += idf * numerator / denominator

        return score

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        """中英文混合分詞"""
        tokens = []
        # 英文 token
        english = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", text)
        tokens.extend(t.lower() for t in english)
        # 中文 token（逐字）
        chinese = re.findall(r"[\u4e00-\u9fff]", text)
        tokens.extend(chinese)
        return tokens

    @staticmethod
    def _extract_title(content: str, fallback: str) -> str:
        """從 Markdown 內容提取第一個 # 標題"""
        for line in content.split("\n"):
            stripped = line.strip()
            if stripped.startswith("# "):
                return stripped[2:].strip()
        return fallback
