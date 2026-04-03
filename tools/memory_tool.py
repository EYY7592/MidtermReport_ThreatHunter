"""
ThreatHunter 雙層記憶學習 Tool
==============================

Layer 1: JSON 持久化（穩定保底，Day 1 起可用）
Layer 2: LlamaIndex RAG（語義搜尋，ENABLE_MEMORY_RAG=true 啟用）

遵循文件：
  - FINAL_PLAN.md §支柱 3（Feedback Loops：雙層記憶學習系統）
  - leader_plan.md §記憶學習系統
"""

import json
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

from crewai.tools import tool

from config import MEMORY_DIR, ENABLE_MEMORY_RAG, SIMILARITY_THRESHOLD

logger = logging.getLogger("threathunter.memory")

# ── 常數 ─────────────────────────────────────────────────────
VALID_AGENT_NAMES = {"scout", "analyst", "advisor", "critic"}


# ── Layer 1: JSON 持久化工具函式 ─────────────────────────────
def _get_memory_path(agent_name: str) -> Path:
    """取得指定 Agent 的記憶 JSON 路徑"""
    return MEMORY_DIR / f"{agent_name}_memory.json"


def _load_json(path: Path) -> dict:
    """安全載入 JSON，檔案不存在或損壞時回傳空 dict"""
    if not path.exists():
        return {}
    try:
        content = path.read_text(encoding="utf-8")
        if not content.strip():
            return {}
        return json.loads(content)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"記憶檔案讀取失敗 {path}: {e}，回傳空記憶")
        return {}


def _save_json(path: Path, data: dict) -> None:
    """安全寫入 JSON（先寫臨時檔再 rename，防止寫入中斷導致損壞）"""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(".tmp")
    try:
        temp_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        temp_path.replace(path)
    except OSError as e:
        logger.error(f"記憶檔案寫入失敗 {path}: {e}")
        if temp_path.exists():
            temp_path.unlink()
        raise


# ── Layer 2: LlamaIndex RAG（條件性啟用）─────────────────────
_rag_index = None
_rag_query_engine = None


def _init_rag() -> None:
    """延遲初始化 LlamaIndex RAG（只在第一次呼叫時執行）"""
    global _rag_index, _rag_query_engine

    if not ENABLE_MEMORY_RAG:
        return
    if _rag_index is not None:
        return

    try:
        from llama_index.core import VectorStoreIndex, StorageContext, Settings
        from llama_index.core import load_index_from_storage

        # ── 設定 Free Local Embedding（不需要 OpenAI API Key）──
        # 使用 HuggingFace BAAI/bge-small-en-v1.5：輕量、快速、免費
        try:
            from llama_index.embeddings.huggingface import HuggingFaceEmbedding
            Settings.embed_model = HuggingFaceEmbedding(
                model_name="BAAI/bge-small-en-v1.5"
            )
            logger.info("✅ Embedding: HuggingFace BAAI/bge-small-en-v1.5（本地免費）")
        except ImportError:
            logger.warning("⚠️ HuggingFace embedding 未安裝，嘗試 OpenAI embedding")

        # 停用 LLM（RAG 記憶層只需要 embedding，不需要 LLM 生成）
        try:
            from llama_index.core.llms import MockLLM
            Settings.llm = MockLLM()
        except Exception:
            Settings.llm = None  # type: ignore

        vector_store_path = MEMORY_DIR / "vector_store"

        if (vector_store_path / "docstore.json").exists():
            storage_context = StorageContext.from_defaults(
                persist_dir=str(vector_store_path)
            )
            _rag_index = load_index_from_storage(storage_context)
            logger.info("✅ LlamaIndex 向量索引已載入")
            _rag_query_engine = _rag_index.as_query_engine(similarity_top_k=3)
        else:
            _rag_index = VectorStoreIndex([])
            logger.info("✅ LlamaIndex 向量索引已建立（空）")
            # 先設 query_engine，再回填（_backfill 需要 _rag_index 已就緒）
            _rag_query_engine = _rag_index.as_query_engine(similarity_top_k=3)
            _backfill_from_json_history()
            # 回填後重建 query_engine（索引已有資料）
            _rag_query_engine = _rag_index.as_query_engine(similarity_top_k=3)

    except ImportError:
        logger.warning("⚠️ LlamaIndex 未安裝，RAG 功能停用")
    except Exception as e:
        logger.warning(f"⚠️ LlamaIndex 初始化失敗：{e}")


def _backfill_from_json_history() -> None:
    """
    首次啟用 RAG 時，將所有已有的 *_memory.json 批次回填進 LlamaIndex。
    只在 vector_store 新建（非載入）時執行一次，之後透過 persist 保存。

    設計原則（Harness Engineering — Feedback Loops 支柱）：
    - 確保歷史掃描記錄不因 RAG 冷啟動而遺失語義感知
    - 失敗不阻塞（Graceful Degradation）
    """
    if _rag_index is None:
        return

    total_inserted = 0
    for agent_name in VALID_AGENT_NAMES:
        json_path = _get_memory_path(agent_name)
        if not json_path.exists():
            continue

        data = _load_json(json_path)
        if not data:
            continue

        # 回填 latest（最新掃描）
        _rag_insert(agent_name, data)
        total_inserted += 1

        # 回填 history[] 陣列中的每一筆歷史掃描
        for hist_scan in data.get("history", []):
            if isinstance(hist_scan, dict) and hist_scan:
                _rag_insert(agent_name, hist_scan)
                total_inserted += 1

    if total_inserted > 0:
        logger.info(f"✅ RAG 歷史回填完成：{total_inserted} 筆掃描記錄已向量化")
    else:
        logger.info("ℹ️ RAG 回填：無歷史 JSON 記憶可回填（首次掃描）")


def _rag_insert(agent_name: str, data: dict) -> None:
    """將資料插入 LlamaIndex 向量索引（雙寫的 Layer 2）"""
    if not ENABLE_MEMORY_RAG or _rag_index is None:
        return
    try:
        from llama_index.core import Document

        doc = Document(
            text=json.dumps(data, ensure_ascii=False),
            metadata={
                "agent": agent_name,
                "timestamp": data.get("timestamp", ""),
                "scan_id": data.get("scan_id", ""),
            },
        )
        _rag_index.insert(doc)
        vector_store_path = MEMORY_DIR / "vector_store"
        _rag_index.storage_context.persist(persist_dir=str(vector_store_path))
        logger.info(f"✅ RAG 索引已更新：{agent_name}")
    except Exception as e:
        logger.warning(f"⚠️ RAG 寫入失敗（不影響 JSON 層）：{e}")


def _rag_search(query: str) -> str:
    """語義搜尋（帶安全閥）"""
    if not ENABLE_MEMORY_RAG:
        return "RAG 功能未啟用（ENABLE_MEMORY_RAG=false）"

    _init_rag()
    if _rag_index is None:
        return "RAG 索引不可用"

    try:
        doc_count = len(_rag_index.docstore.docs) if hasattr(_rag_index, "docstore") else 0
        if doc_count == 0:
            return "No history available（向量索引為空）"

        response = _rag_query_engine.query(query)

        if hasattr(response, "source_nodes") and response.source_nodes:
            scores = [n.score for n in response.source_nodes if n.score is not None]
            max_score = max(scores) if scores else 0
            if max_score < SIMILARITY_THRESHOLD:
                return (
                    f"No relevant history found"
                    f"（最高相關性 {max_score:.2f} < 閾值 {SIMILARITY_THRESHOLD}）"
                )
        return str(response)

    except Exception as e:
        logger.warning(f"⚠️ RAG 搜尋失敗：{e}")
        return f"RAG 搜尋失敗：{e}"


# ── CrewAI Tool 定義 ─────────────────────────────────────────
@tool("read_memory")
def read_memory(agent_name: str) -> str:
    """
    讀取指定 Agent 的歷史記憶（JSON Layer 1：穩定保底）。
    0 份歷史回傳空 JSON，Agent 可據此判斷是否為第一次掃描。

    Args:
        agent_name: Agent 名稱（scout / analyst / advisor / critic）

    Returns:
        JSON 字串格式的歷史記憶
    """
    agent_name = agent_name.strip().lower()
    if agent_name not in VALID_AGENT_NAMES:
        logger.warning(f"非法的 agent 名稱：{agent_name}")
        return json.dumps({}, ensure_ascii=False)

    data = _load_json(_get_memory_path(agent_name))

    if not data:
        logger.info(f"📭 {agent_name} 無歷史記憶（第一次掃描）")
    else:
        logger.info(f"📬 {agent_name} 記憶已載入（scan_id: {data.get('scan_id', 'N/A')}）")

    return json.dumps(data, ensure_ascii=False, indent=2)


@tool("write_memory")
def write_memory(agent_name: str, data: str) -> str:
    """
    寫入 Agent 記憶（雙寫：JSON + LlamaIndex）。自動添加 timestamp。

    Args:
        agent_name: Agent 名稱（scout / analyst / advisor / critic）
        data: JSON 字串格式的記憶資料

    Returns:
        寫入結果訊息
    """
    agent_name = agent_name.strip().lower()
    if agent_name not in VALID_AGENT_NAMES:
        return f"❌ 非法的 agent 名稱：{agent_name}（允許：{VALID_AGENT_NAMES}）"

    try:
        memory_data = json.loads(data) if isinstance(data, str) else data
    except json.JSONDecodeError as e:
        return f"❌ JSON 格式錯誤：{e}"

    memory_data["timestamp"] = datetime.now(timezone.utc).isoformat()

    # Layer 1: JSON — 累積 history[] 陣列
    try:
        existing = _load_json(_get_memory_path(agent_name))
        history = existing.get("history", [])

        # 若已有舊的 latest，推入 history（最多保留 50 筆，防止無限增長）
        if existing and "scan_id" in existing:
            old_entry = {k: v for k, v in existing.items() if k != "history"}
            history.append(old_entry)
            if len(history) > 50:
                history = history[-50:]  # 保留最新 50 筆

        memory_data["history"] = history
        _save_json(_get_memory_path(agent_name), memory_data)
        logger.info(f"💾 {agent_name} 記憶已寫入 JSON（Layer 1｜history={len(history)} 筆）")
    except Exception as e:
        return f"❌ JSON 寫入失敗：{e}"
    # Layer 2: LlamaIndex（雙寫）
    _rag_insert(agent_name, memory_data)

    return f"✅ {agent_name} 記憶已寫入（timestamp: {memory_data['timestamp']}）"


@tool("history_search")
def history_search(query: str) -> str:
    """
    語義搜尋歷史安全報告（LlamaIndex RAG Layer 2）。
    帶安全閥：索引為空 / 分數太低 / RAG 未啟用 → 回傳提示。

    Args:
        query: 搜尋查詢（例如："Django SSRF 歷史"）

    Returns:
        搜尋結果或安全提示
    """
    return _rag_search(query)
