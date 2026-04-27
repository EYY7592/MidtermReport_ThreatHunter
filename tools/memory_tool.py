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

from config import MEMORY_DIR, ENABLE_MEMORY_RAG, SIMILARITY_THRESHOLD
from crewai.tools import tool

logger = logging.getLogger("threathunter.memory")

# Sandbox Layer 3: Memory cache sanitization
try:
    from sandbox.memory_sanitizer import sanitize_memory_write as _sanitize_write
    _MEM_SANITIZER_OK = True
except ImportError:
    def _sanitize_write(data, agent_name=''):  # type: ignore[misc]
        return True, data, 'ok'
    _MEM_SANITIZER_OK = False

# ── 常數 ─────────────────────────────────────────────────────
VALID_AGENT_NAMES = {"scout", "analyst", "advisor", "critic", "orchestrator"}


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
        logger.warning("[WARN] Memory file read failed %s: %s, returning empty", path, e)
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
        logger.error("[FAIL] Memory file write failed %s: %s", path, e)
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
            logger.info("[OK] Embedding: HuggingFace BAAI/bge-small-en-v1.5 (local free)")
        except ImportError:
            logger.warning("[WARN] HuggingFace embedding not installed, trying OpenAI embedding")

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
            logger.info("[OK] LlamaIndex vector index loaded")
            _rag_query_engine = _rag_index.as_query_engine(similarity_top_k=3)
        else:
            _rag_index = VectorStoreIndex([])
            logger.info("[OK] LlamaIndex vector index created (empty)")
            # 先設 query_engine，再回填（_backfill 需要 _rag_index 已就緒）
            _rag_query_engine = _rag_index.as_query_engine(similarity_top_k=3)
            _backfill_from_json_history()
            # 回填後重建 query_engine（索引已有資料）
            _rag_query_engine = _rag_index.as_query_engine(similarity_top_k=3)

    except ImportError:
        logger.warning("[WARN] LlamaIndex not installed, RAG disabled")
    except Exception as e:
        logger.warning("[WARN] LlamaIndex init failed: %s", e)


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
        logger.info("[OK] RAG history backfill done: %d scan records vectorized", total_inserted)
    else:
        logger.info("[INFO] RAG backfill: no historical JSON memory to backfill (first scan)")


def _extract_package_names(tech_stack: str) -> set[str]:
    """
    從技術棧字串中提取套件名稱（小寫、去版本號）。

    範例：
      'Django 4.2, Redis 7.0' -> {'django', 'redis'}
      'Spring Boot 3.1 和 Node.js 18' -> {'spring', 'boot', 'node.js'}
    """
    if not tech_stack:
        return set()
    names = set()
    for part in tech_stack.replace(",", " ").split():
        clean = part.strip().lower()
        # 跳過版本號（純數字或 x.y.z 格式）
        if clean and not clean.replace(".", "").replace("-", "").isdigit():
            names.add(clean)
    return names


def _rag_insert(agent_name: str, data: dict) -> None:
    """將資料插入 LlamaIndex 向量索引（雙寫的 Layer 2），含 tech_stack 元資料"""
    if not ENABLE_MEMORY_RAG or _rag_index is None:
        return
    try:
        from llama_index.core import Document

        # 提取 tech_stack：可能在 data 的不同欄位中
        tech_stack = (
            data.get("tech_stack", "")
            or data.get("tech_stack_input", "")
            or ""
        )
        # 如果 tech_stack 是 list，轉成字串
        if isinstance(tech_stack, list):
            tech_stack = ", ".join(str(t) for t in tech_stack)

        doc = Document(
            text=json.dumps(data, ensure_ascii=False),
            metadata={
                "agent": agent_name,
                "timestamp": data.get("timestamp", ""),
                "scan_id": data.get("scan_id", ""),
                "tech_stack": str(tech_stack),
            },
        )
        _rag_index.insert(doc)
        vector_store_path = MEMORY_DIR / "vector_store"
        _rag_index.storage_context.persist(persist_dir=str(vector_store_path))
        logger.info("[OK] RAG index updated: %s (tech_stack=%s)", agent_name, tech_stack[:50])
    except Exception as e:
        logger.warning("[WARN] RAG write failed (JSON layer unaffected): %s", e)


def _rag_search(query: str, tech_stack: str | None = None) -> str:
    """
    語義搜尋（帶安全閥 + 技術棧相關性過濾）。

    Args:
        query: 搜尋查詢
        tech_stack: 當前掃描的技術棧（用於過濾不相關歷史）
    """
    if not ENABLE_MEMORY_RAG:
        return "RAG disabled (ENABLE_MEMORY_RAG=false)"

    _init_rag()
    if _rag_index is None:
        return "RAG index unavailable"

    try:
        doc_count = len(_rag_index.docstore.docs) if hasattr(_rag_index, "docstore") else 0
        if doc_count == 0:
            return "No history available (vector index empty)"

        response = _rag_query_engine.query(query)

        # 相關性門檻過濾
        if hasattr(response, "source_nodes") and response.source_nodes:
            scores = [n.score for n in response.source_nodes if n.score is not None]
            max_score = max(scores) if scores else 0
            if max_score < SIMILARITY_THRESHOLD:
                return (
                    f"No relevant history found"
                    f" (max_similarity {max_score:.2f} < threshold {SIMILARITY_THRESHOLD})"
                )

            # 技術棧相關性過濾：只保留與當前掃描套件有交集的歷史
            if tech_stack:
                current_packages = _extract_package_names(tech_stack)
                if current_packages:
                    filtered_nodes = []
                    for node in response.source_nodes:
                        node_tech = node.metadata.get("tech_stack", "")
                        if not node_tech:
                            # 無 tech_stack 元資料的舊記錄，保守保留
                            filtered_nodes.append(node)
                            continue
                        node_packages = _extract_package_names(node_tech)
                        # 有套件名稱交集才保留
                        if current_packages & node_packages:
                            filtered_nodes.append(node)
                        else:
                            logger.info(
                                "[FILTER] Excluded history: %s (no overlap with %s)",
                                node_tech[:50], tech_stack[:50],
                            )

                    if not filtered_nodes:
                        return (
                            f"No relevant history for current tech stack"
                            f" (filtered {len(response.source_nodes)} results, 0 matched)"
                        )
                    response.source_nodes = filtered_nodes

        return str(response)

    except Exception as e:
        logger.warning("[WARN] RAG search failed: %s", e)
        return f"RAG search failed: {e}"


# ── CrewAI Tool 定義 ─────────────────────────────────────────
@tool("read_memory")
def read_memory(agent_name: str) -> str:
    """
    讀取指定 Agent 的歷史記憶（JSON Layer 1：穩定保底）。
    0 份歷史回傳空 JSON，Agent 可據此判斷是否為第一次掃描。

    Args:
        agent_name: Agent 名稱（scout / analyst / advisor / critic / orchestrator）

    Returns:
        JSON 字串格式的歷史記憶
    """
    agent_name = agent_name.strip().lower()
    if agent_name not in VALID_AGENT_NAMES:
        logger.warning("[WARN] Invalid agent name: %s", agent_name)
        return json.dumps({}, ensure_ascii=False)

    data = _load_json(_get_memory_path(agent_name))

    if not data:
        logger.info("[INFO] %s has no history (first scan)", agent_name)
    else:
        logger.info("[OK] %s memory loaded (scan_id: %s)", agent_name, data.get('scan_id', 'N/A'))

    return json.dumps(data, ensure_ascii=False, indent=2)


@tool("write_memory")
def write_memory(agent_name: str, data: str) -> str:
    """
    寫入 Agent 記憶（雙寫：JSON + LlamaIndex）。自動添加 timestamp。

    Args:
        agent_name: Agent 名稱（scout / analyst / advisor / critic / orchestrator）
        data: JSON 字串格式的記憶資料

    Returns:
        寫入結果訊息
    """
    agent_name = agent_name.strip().lower()
    if agent_name not in VALID_AGENT_NAMES:
        return f"[FAIL] Invalid agent name: {agent_name} (allowed: {VALID_AGENT_NAMES})"

    try:
        memory_data = json.loads(data) if isinstance(data, str) else data
    except json.JSONDecodeError as e:
        return f"[FAIL] JSON format error: {e}"

    # Sandbox Layer 3: poison filter before write
    is_safe, clean_data, reason = _sanitize_write(memory_data, agent_name)
    if not is_safe:
        logger.warning('[MEMORY][SANDBOX] Write BLOCKED: %s', reason)
        return '[BLOCKED] Memory write rejected by Sandbox: ' + reason
    memory_data = clean_data

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
        logger.info("[OK] %s memory saved to JSON (Layer 1 | history=%d records)", agent_name, len(history))
    except Exception as e:
        return f"[FAIL] JSON write failed: {e}"
    # Layer 2: LlamaIndex（雙寫）
    _rag_insert(agent_name, memory_data)

    return f"[OK] {agent_name} memory saved (timestamp: {memory_data['timestamp']})"


@tool("history_search")
def history_search(query: str, tech_stack: str = "") -> str:
    """
    語義搜尋歷史安全報告（帶技術棧過濾）。
    帶安全閥：索引為空 / 分數太低 / 技術棧不匹配 / RAG 未啟用 → 回傳提示。

    Args:
        query: 搜尋查詢（例如："Django SSRF 歷史"）
        tech_stack: 當前掃描的技術棧（例如："Django 4.2, Redis 7.0"），
                    用於過濾不相關的歷史記錄

    Returns:
        搜尋結果或安全提示
    """
    return _rag_search(query, tech_stack if tech_stack else None)
