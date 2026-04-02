# tools/memory_tool.py
# 功能：雙層記憶學習系統（JSON 穩底 + LlamaIndex RAG 增值）
# Harness 支柱：Feedback Loops（回饋閉環）+ Graceful Degradation（降級）
# 擁有者：組長
#
# 使用方式（成員 B、C 直接 import）：
#   from tools.memory_tool import read_memory, write_memory
#
# 雙層設計原理（見 FINAL_PLAN.md 支柱 3）：
#   Layer 1: JSON 持久化 — Day 1 起可用，精確取值，絕不出錯
#   Layer 2: LlamaIndex RAG — 第 3+ 次掃描展示語義搜尋能力
#   寫入時「雙寫」：JSON + LlamaIndex 同時寫入
#   讀取時「JSON 保底」：即使 LlamaIndex 掛掉，JSON 一定有結果

import json
import os
import logging
from datetime import datetime

logger = logging.getLogger("ThreatHunter")

# ── 常數 ────────────────────────────────────────────────────
MEMORY_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "memory")
VECTOR_STORE_DIR = os.path.join(MEMORY_DIR, "vector_store")
MAX_HISTORY = 10  # 保留最近 10 次掃描記錄
RAG_SIMILARITY_THRESHOLD = 0.3  # 語義搜尋最低相關度閾值


def _get_memory_path(agent_name: str) -> str:
    """取得 memory 檔案路徑，同時確保目錄存在"""
    os.makedirs(MEMORY_DIR, exist_ok=True)
    return os.path.join(MEMORY_DIR, f"{agent_name}_memory.json")


# ══════════════════════════════════════════════════════════════
# Layer 1: JSON 持久化（穩定保底，Day 1 起可用）
# ══════════════════════════════════════════════════════════════

def _read_memory_impl(agent_name: str) -> str:
    """
    讀取指定 Agent 的歷史記憶（Layer 1: JSON），回傳 JSON 字串。

    保證：
      - 檔案不存在 → "{}"
      - 檔案損壞 → "{}"（Graceful Degradation）
      - 絕對不會拋出例外
    """
    path = _get_memory_path(agent_name)
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if not content:
                    return "{}"
                json.loads(content)  # 驗證合法 JSON
                return content
        return "{}"
    except (json.JSONDecodeError, IOError, PermissionError):
        return "{}"


def _write_memory_impl(agent_name: str, data: str) -> str:
    """
    寫入指定 Agent 的記憶（雙寫：JSON + LlamaIndex）。

    流程：
      1. 驗證 JSON 格式
      2. 寫入 Layer 1（JSON 檔案）← 保底，必須成功
      3. 寫入 Layer 2（LlamaIndex）← 增值，失敗不影響
    """
    path = _get_memory_path(agent_name)
    try:
        new_entry = json.loads(data)
        new_entry["timestamp"] = datetime.now().isoformat()
        new_entry["agent"] = agent_name

        # ── Layer 1: JSON 寫入（必須成功）──────────────────
        existing = {}
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except (json.JSONDecodeError, IOError):
                existing = {}  # 損壞 → 清空重建

        existing["latest"] = new_entry
        if "history" not in existing:
            existing["history"] = []
        existing["history"].append(new_entry)

        if len(existing["history"]) > MAX_HISTORY:
            existing["history"] = existing["history"][-MAX_HISTORY:]

        with open(path, "w", encoding="utf-8") as f:
            json.dump(existing, f, ensure_ascii=False, indent=2)

        # ── Layer 2: LlamaIndex 雙寫（增值，失敗不影響）────
        _write_to_vector_store(agent_name, new_entry)

        return "Memory saved successfully"

    except json.JSONDecodeError as e:
        return f"Memory save failed: invalid JSON - {e}"
    except (IOError, PermissionError) as e:
        return f"Memory save failed: file error - {e}"
    except Exception as e:
        return f"Memory save failed: {e}"


# ══════════════════════════════════════════════════════════════
# Layer 2: LlamaIndex RAG（增值層，越用越好）
# ══════════════════════════════════════════════════════════════
#
# 為什麼不能只用 LlamaIndex？（Cold Start 問題）
#   0 份歷史 → 引擎報錯或回傳空值（致命！Demo 直接掛）
#   1 份歷史 → 語義搜尋無統計意義
#   所以 JSON 必須保底，LlamaIndex 只是增值

_vector_indices = {}  # 快取：{agent_name: VectorStoreIndex}


def _get_vector_index(agent_name: str):
    """
    取得或建立指定 Agent 的 LlamaIndex 向量索引。

    安全閥：
      - LlamaIndex 未安裝 → 回傳 None
      - 索引建立失敗 → 回傳 None
      - 絕不影響 Layer 1 運作
    """
    if agent_name in _vector_indices:
        return _vector_indices[agent_name]

    try:
        from llama_index.core import (
            VectorStoreIndex,
            StorageContext,
            load_index_from_storage,
        )

        agent_store_dir = os.path.join(VECTOR_STORE_DIR, agent_name)

        if os.path.exists(os.path.join(agent_store_dir, "docstore.json")):
            # 已有持久化索引 → 載入
            storage_context = StorageContext.from_defaults(persist_dir=agent_store_dir)
            index = load_index_from_storage(storage_context)
            logger.info(f"✅ Layer 2: 載入 {agent_name} 向量索引")
        else:
            # 全新索引
            index = VectorStoreIndex([])
            os.makedirs(agent_store_dir, exist_ok=True)
            logger.info(f"✅ Layer 2: 建立 {agent_name} 新向量索引")

        _vector_indices[agent_name] = index
        return index

    except ImportError:
        logger.info("ℹ️ LlamaIndex 未安裝，Layer 2 停用（JSON 保底）")
        _vector_indices[agent_name] = None
        return None
    except Exception as e:
        logger.warning(f"⚠️ Layer 2 索引載入失敗：{e}（JSON 保底）")
        _vector_indices[agent_name] = None
        return None


def _write_to_vector_store(agent_name: str, entry: dict):
    """
    將記憶條目寫入 LlamaIndex 向量索引（雙寫的 Layer 2 部分）。
    失敗時靜默記錄 log，不影響主流程。
    """
    index = _get_vector_index(agent_name)
    if index is None:
        return  # Layer 2 停用，靜默跳過

    try:
        from llama_index.core import Document

        # 將 dict 轉成有意義的文件文字（Agent 語義搜尋用）
        text = json.dumps(entry, ensure_ascii=False, indent=2)
        doc = Document(
            text=text,
            metadata={
                "agent": agent_name,
                "timestamp": entry.get("timestamp", ""),
            },
        )
        index.insert(doc)

        # 持久化到磁碟
        agent_store_dir = os.path.join(VECTOR_STORE_DIR, agent_name)
        os.makedirs(agent_store_dir, exist_ok=True)
        index.storage_context.persist(persist_dir=agent_store_dir)

    except Exception as e:
        # Graceful Degradation：Layer 2 寫入失敗不影響主流程
        logger.warning(f"⚠️ Layer 2 寫入失敗（{agent_name}）：{e}")


def _search_history_impl(agent_name: str, query: str) -> str:
    """
    語義搜尋歷史報告（Layer 2: LlamaIndex RAG）。

    安全閥設計（避免 Cold Start）：
      - 0 份文件 → 回傳 "No history available"
      - 搜尋結果分數太低 → 回傳 "No relevant history found"
      - LlamaIndex 未安裝/掛掉 → 回傳 "History search unavailable"
    """
    index = _get_vector_index(agent_name)
    if index is None:
        return "History search unavailable (Layer 2 disabled)"

    try:
        # 安全閥 1：檢查文件數量（Cold Start 防護）
        doc_count = len(index.docstore.docs) if hasattr(index, 'docstore') else 0
        if doc_count == 0:
            return "No history available"

        # 執行語義搜尋
        query_engine = index.as_query_engine(similarity_top_k=3)
        response = query_engine.query(query)

        # 安全閥 2：檢查結果品質
        result_text = str(response).strip()
        if not result_text or result_text.lower() in ["empty response", "none", ""]:
            return "No relevant history found"

        return result_text

    except Exception as e:
        logger.warning(f"⚠️ Layer 2 搜尋失敗（{agent_name}）：{e}")
        return f"History search failed: {e}"


# ══════════════════════════════════════════════════════════════
# CrewAI @tool 包裝（Agent 呼叫用）
# ══════════════════════════════════════════════════════════════
# 延遲 import，避免在測試時拉入整個 CrewAI

def _create_tools():
    """延遲建立 CrewAI Tool，僅在 Agent 實際使用時才 import"""
    from crewai.tools import tool

    @tool("read_memory")
    def read_memory(agent_name: str) -> str:
        """讀取指定 Agent 的歷史記憶。agent_name 可選：scout、analyst、advisor。回傳 JSON 字串。"""
        return _read_memory_impl(agent_name)

    @tool("write_memory")
    def write_memory(agent_name: str, data: str) -> str:
        """寫入指定 Agent 的記憶並保留歷史（雙寫 JSON + 向量索引）。agent_name：scout、analyst、advisor。data：JSON 字串。"""
        return _write_memory_impl(agent_name)

    @tool("search_history")
    def search_history(agent_name: str, query: str) -> str:
        """語義搜尋歷史安全報告。用自然語言查問過去的掃描結果。agent_name：scout、analyst、advisor。query：搜尋問題。"""
        return _search_history_impl(agent_name, query)

    return read_memory, write_memory, search_history


class _LazyToolLoader:
    """延遲載入 CrewAI Tool 的包裝器"""
    def __init__(self):
        self._tools = None

    def _load(self):
        if self._tools is None:
            self._tools = _create_tools()

    @property
    def read_memory(self):
        self._load()
        return self._tools[0]

    @property
    def write_memory(self):
        self._load()
        return self._tools[1]

    @property
    def search_history(self):
        self._load()
        return self._tools[2]

_loader = _LazyToolLoader()

def __getattr__(name):
    """模組層級 __getattr__，支援 from tools.memory_tool import read_memory"""
    if name == "read_memory":
        return _loader.read_memory
    elif name == "write_memory":
        return _loader.write_memory
    elif name == "search_history":
        return _loader.search_history
    raise AttributeError(f"module 'tools.memory_tool' has no attribute {name!r}")
