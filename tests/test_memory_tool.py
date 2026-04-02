"""
Memory Tool 測試
================

測試 tools/memory_tool.py 的核心功能。
符合 project_CONSTITUTION.md 第五條（子模組測試規範）。
"""

import json
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest


# ── 測試用的暫存目錄 ─────────────────────────────────────────
@pytest.fixture
def temp_memory_dir(tmp_path):
    """建立暫存記憶目錄，測試後自動清除"""
    memory_dir = tmp_path / "memory"
    memory_dir.mkdir()
    (memory_dir / "vector_store").mkdir()
    return memory_dir


@pytest.fixture(autouse=True)
def mock_memory_dir(temp_memory_dir):
    """將 memory_tool 的 MEMORY_DIR 指向暫存目錄"""
    with patch("tools.memory_tool.MEMORY_DIR", temp_memory_dir):
        yield temp_memory_dir


# ── Layer 1: JSON 內部函式測試 ───────────────────────────────
class TestJsonHelpers:
    """測試 JSON 讀寫工具函式"""

    def test_load_nonexistent_file(self, temp_memory_dir):
        """不存在的檔案回傳空 dict"""
        from tools.memory_tool import _load_json
        result = _load_json(temp_memory_dir / "nonexistent.json")
        assert result == {}

    def test_load_empty_file(self, temp_memory_dir):
        """空檔案回傳空 dict"""
        from tools.memory_tool import _load_json
        empty_file = temp_memory_dir / "empty.json"
        empty_file.write_text("")
        result = _load_json(empty_file)
        assert result == {}

    def test_load_corrupted_file(self, temp_memory_dir):
        """損壞的 JSON 回傳空 dict（不崩潰）"""
        from tools.memory_tool import _load_json
        bad_file = temp_memory_dir / "bad.json"
        bad_file.write_text("{invalid json!!!")
        result = _load_json(bad_file)
        assert result == {}

    def test_save_and_load_roundtrip(self, temp_memory_dir):
        """寫入後能正確讀取"""
        from tools.memory_tool import _save_json, _load_json
        test_path = temp_memory_dir / "test.json"
        test_data = {"scan_id": "scan_001", "risk_score": 85}
        _save_json(test_path, test_data)
        loaded = _load_json(test_path)
        assert loaded == test_data

    def test_save_atomic_write(self, temp_memory_dir):
        """寫入使用原子操作（先寫 .tmp 再 rename）"""
        from tools.memory_tool import _save_json
        test_path = temp_memory_dir / "atomic.json"
        _save_json(test_path, {"key": "value"})
        # .tmp 應該已經被 rename，不應存在
        assert not test_path.with_suffix(".tmp").exists()
        assert test_path.exists()


# ── CrewAI Tool 測試 ─────────────────────────────────────────
class TestReadMemory:
    """測試 read_memory Tool"""

    def test_read_empty_memory(self):
        """空記憶回傳 {} 不崩潰"""
        from tools.memory_tool import read_memory
        result = read_memory.run(agent_name="scout")
        parsed = json.loads(result)
        assert parsed == {}

    def test_read_invalid_agent_name(self):
        """非法 agent 名稱回傳空 dict"""
        from tools.memory_tool import read_memory
        result = read_memory.run(agent_name="invalid_agent")
        parsed = json.loads(result)
        assert parsed == {}

    def test_read_strips_whitespace(self):
        """agent 名稱前後空白自動處理"""
        from tools.memory_tool import read_memory
        result = read_memory.run(agent_name="  Scout  ")
        parsed = json.loads(result)
        assert parsed == {}  # 空記憶，但不崩潰

    def test_read_case_insensitive(self):
        """agent 名稱大小寫不敏感"""
        from tools.memory_tool import read_memory
        result = read_memory.run(agent_name="SCOUT")
        parsed = json.loads(result)
        assert parsed == {}


class TestWriteMemory:
    """測試 write_memory Tool"""

    def test_write_and_read_roundtrip(self):
        """寫入後能透過 read_memory 讀取"""
        from tools.memory_tool import read_memory, write_memory
        test_data = {"scan_id": "scan_001", "risk_score": 85}
        write_result = write_memory.run(
            agent_name="scout",
            data=json.dumps(test_data),
        )
        assert "✅" in write_result

        read_result = read_memory.run(agent_name="scout")
        parsed = json.loads(read_result)
        assert parsed["scan_id"] == "scan_001"
        assert parsed["risk_score"] == 85

    def test_write_adds_timestamp(self):
        """自動添加 timestamp"""
        from tools.memory_tool import write_memory, read_memory
        write_memory.run(
            agent_name="analyst",
            data=json.dumps({"test": True}),
        )
        result = json.loads(read_memory.run(agent_name="analyst"))
        assert "timestamp" in result

    def test_write_invalid_agent(self):
        """非法 agent 名稱回傳錯誤訊息"""
        from tools.memory_tool import write_memory
        result = write_memory.run(
            agent_name="hacker",
            data=json.dumps({"evil": True}),
        )
        assert "❌" in result

    def test_write_invalid_json(self):
        """無效 JSON 輸入回傳錯誤訊息"""
        from tools.memory_tool import write_memory
        result = write_memory.run(
            agent_name="scout",
            data="{invalid json!!!",
        )
        assert "❌" in result

    def test_write_overwrite(self):
        """重複寫入覆蓋舊資料"""
        from tools.memory_tool import write_memory, read_memory
        write_memory.run(agent_name="scout", data=json.dumps({"version": 1}))
        write_memory.run(agent_name="scout", data=json.dumps({"version": 2}))
        result = json.loads(read_memory.run(agent_name="scout"))
        assert result["version"] == 2


class TestHistorySearch:
    """測試 history_search Tool"""

    def test_search_rag_disabled(self):
        """RAG 未啟用時回傳提示"""
        from tools.memory_tool import history_search
        result = history_search.run(query="Django SSRF")
        assert "RAG" in result
