# tools/memory_tool.py
# 功能：提供 Agent 讀寫 JSON 記憶的工具
# Harness 支柱：Feedback Loops（回饋閉環）
# 擁有者：組長
#
# 使用方式（成員 B、C 直接 import）：
#   from tools.memory_tool import read_memory, write_memory

import json
import os
from datetime import datetime

# ── 常數 ────────────────────────────────────────────────────
MEMORY_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "memory")
MAX_HISTORY = 10  # 保留最近 10 次掃描記錄


def _get_memory_path(agent_name: str) -> str:
    """取得 memory 檔案路徑，同時確保目錄存在"""
    os.makedirs(MEMORY_DIR, exist_ok=True)
    return os.path.join(MEMORY_DIR, f"{agent_name}_memory.json")


# ── 核心邏輯（不依賴 CrewAI，可獨立測試）───────────────────────

def _read_memory_impl(agent_name: str) -> str:
    """讀取指定 Agent 的歷史記憶，回傳 JSON 字串"""
    path = _get_memory_path(agent_name)
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if not content:
                    return "{}"
                # 驗證是合法 JSON（防止損壞檔案讓 Agent 崩潰）
                json.loads(content)
                return content
        return "{}"
    except (json.JSONDecodeError, IOError, PermissionError):
        # Harness：Graceful Degradation — 記憶損壞不中斷掃描
        return "{}"


def _write_memory_impl(agent_name: str, data: str) -> str:
    """寫入指定 Agent 的記憶並保留歷史"""
    path = _get_memory_path(agent_name)
    try:
        # 驗證傳入的 data 是合法 JSON
        new_entry = json.loads(data)
        new_entry["timestamp"] = datetime.now().isoformat()

        # 讀取現有記憶
        existing = {}
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except (json.JSONDecodeError, IOError):
                existing = {}  # 損壞的記憶直接清空重建

        # 更新 latest 和 history
        existing["latest"] = new_entry
        if "history" not in existing:
            existing["history"] = []
        existing["history"].append(new_entry)

        # 只保留最近 MAX_HISTORY 次
        if len(existing["history"]) > MAX_HISTORY:
            existing["history"] = existing["history"][-MAX_HISTORY:]

        with open(path, "w", encoding="utf-8") as f:
            json.dump(existing, f, ensure_ascii=False, indent=2)

        return "Memory saved successfully"

    except json.JSONDecodeError as e:
        return f"Memory save failed: invalid JSON - {e}"
    except (IOError, PermissionError) as e:
        return f"Memory save failed: file error - {e}"
    except Exception as e:
        return f"Memory save failed: {e}"


# ── CrewAI @tool 包裝（Agent 呼叫用）──────────────────────────
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
        """寫入指定 Agent 的記憶並保留歷史。agent_name：scout、analyst、advisor。data：JSON 字串。"""
        return _write_memory_impl(agent_name)

    return read_memory, write_memory


# 模組層級變數，Agent import 時使用：from tools.memory_tool import read_memory, write_memory
# 但只在真正需要時才觸發 CrewAI import
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

_loader = _LazyToolLoader()

def __getattr__(name):
    """模組層級的 __getattr__，支援 from tools.memory_tool import read_memory"""
    if name == "read_memory":
        return _loader.read_memory
    elif name == "write_memory":
        return _loader.write_memory
    raise AttributeError(f"module 'tools.memory_tool' has no attribute {name!r}")
