"""
tests/test_thinking_path.py — Thinking Path API 測試
=======================================================
測試範圍：
  ✅ _build_thinking_path: 正確解析 JSONL checkpoint
  ✅ 依 Agent 分組：各 Agent 有 steps 陣列
  ✅ LLM 統計：llm_calls / tool_calls 計數正確
  ✅ skill_applied: 有 LLM_RESULT(SUCCESS) 時為 True
  ✅ Graceful Degradation: 空 JSONL 不崩潰
  ✅ 損壞行跳過：部分損壞 JSONL 仍能解析

遵守：project_CONSTITUTION.md 第五條（測試規範）
"""

import json
import sys
import tempfile
from pathlib import Path

import pytest

# ── 確保 project root 在 sys.path ──────────────────────────────
_ROOT = Path(__file__).parent.parent
_UI   = _ROOT / "ui"
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_UI))


# ── 載入待測函式（不啟動 FastAPI）──────────────────────────────
from server import _build_thinking_path  # noqa: E402


# ── 測試用 JSONL fixture ────────────────────────────────────────

SAMPLE_JSONL = [
    {"seq": 1, "ts": "2026-04-13T01:00:00Z", "scan_id": "test", "event": "SCAN_START", "agent": "pipeline", "data": {"scan_id": "test"}},
    {"seq": 2, "ts": "2026-04-13T01:00:01Z", "scan_id": "test", "event": "STAGE_ENTER",  "agent": "scout", "data": {"tech_stack_preview": "Django 4.2"}},
    {"seq": 3, "ts": "2026-04-13T01:00:02Z", "scan_id": "test", "event": "LLM_CALL",    "agent": "scout", "data": {"model": "gemini-3-flash-preview", "task_preview": "分析 Django 4.2"}},
    {"seq": 4, "ts": "2026-04-13T01:00:06Z", "scan_id": "test", "event": "LLM_RESULT",  "agent": "scout", "data": {"model": "gemini-3-flash-preview", "status": "SUCCESS", "output_length": 512, "duration_ms": 4200}},
    {"seq": 5, "ts": "2026-04-13T01:00:06Z", "scan_id": "test", "event": "TOOL_CALL",   "agent": "scout", "data": {"tool_name": "search_nvd", "input": "Django 4.2", "output_preview": "[{CVE-...}]", "status": "SUCCESS"}},
    {"seq": 6, "ts": "2026-04-13T01:00:07Z", "scan_id": "test", "event": "STAGE_EXIT",  "agent": "scout", "data": {"status": "SUCCESS", "duration_ms": 6100}},
    {"seq": 7, "ts": "2026-04-13T01:00:08Z", "scan_id": "test", "event": "LLM_CALL",    "agent": "analyst", "data": {"model": "gemini-3-flash-preview", "task_preview": "分析漏洞"}},
    {"seq": 8, "ts": "2026-04-13T01:00:12Z", "scan_id": "test", "event": "LLM_RESULT",  "agent": "analyst", "data": {"model": "gemini-3-flash-preview", "status": "SUCCESS", "output_length": 384, "duration_ms": 3800, "thinking_preview": "此漏洞屬於 SQL Injection..."}},
    {"seq": 9, "ts": "2026-04-13T01:00:13Z", "scan_id": "test", "event": "LLM_ERROR",   "agent": "advisor", "data": {"model": "gemini-3-flash-preview", "error": "429 Too Many Requests"}},
    {"seq": 10, "ts": "2026-04-13T01:00:14Z", "scan_id": "test", "event": "LLM_RETRY",  "agent": "advisor", "data": {"failed_model": "gemini-3-flash-preview", "error": "429", "retry_count": 1, "next_model": "gemini-2.0-flash"}},
    {"seq": 11, "ts": "2026-04-13T01:00:18Z", "scan_id": "test", "event": "SCAN_END",   "agent": "pipeline", "data": {"final_status": "COMPLETE", "total_duration_seconds": 18.2, "total_checkpoints": 11, "event_summary": {"STAGE_ENTER": 2, "LLM_CALL": 2}}},
]


def _make_jsonl(records: list, tmp_path: Path) -> Path:
    """將記錄列表寫入臨時 JSONL 檔案，回傳 Path"""
    p = tmp_path / "scan_test_20260413_010000.jsonl"
    with open(p, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return p


# ══════════════════════════════════════════════════════════════
# 測試案例
# ══════════════════════════════════════════════════════════════

class TestBuildThinkingPath:
    """_build_thinking_path 解析 JSONL 邏輯測試"""

    def test_returns_dict_with_agents_and_scan_meta(self, tmp_path):
        """Happy Path: 正確回傳結構"""
        cp = _make_jsonl(SAMPLE_JSONL, tmp_path)
        result = _build_thinking_path(cp)

        assert isinstance(result, dict)
        assert "agents" in result
        assert "scan_meta" in result

    def test_agents_grouped_by_agent_name(self, tmp_path):
        """各 Agent 有獨立的 steps 陣列"""
        cp = _make_jsonl(SAMPLE_JSONL, tmp_path)
        result = _build_thinking_path(cp)

        agents = result["agents"]
        assert "scout" in agents
        assert "analyst" in agents
        assert "advisor" in agents
        # pipeline（SCAN_START/END）不應出現（SCAN_START 不是 DISPLAY_EVENTS）
        # pipeline 事件類型是 SCAN_START/SCAN_END，不在 DISPLAY_EVENTS 中

    def test_llm_call_count(self, tmp_path):
        """llm_calls 計數正確（LLM_RETRY 不算 LLM_CALL，需要有實際 LLM_CALL 事件）"""
        cp = _make_jsonl(SAMPLE_JSONL, tmp_path)
        result = _build_thinking_path(cp)

        assert result["agents"]["scout"]["llm_calls"] == 1
        assert result["agents"]["analyst"]["llm_calls"] == 1
        # advisor SAMPLE 只有 LLM_ERROR + LLM_RETRY，沒有 LLM_CALL
        assert result["agents"]["advisor"]["llm_calls"] == 0

    def test_tool_call_count(self, tmp_path):
        """tool_calls 計數正確"""
        cp = _make_jsonl(SAMPLE_JSONL, tmp_path)
        result = _build_thinking_path(cp)

        assert result["agents"]["scout"]["tool_calls"] == 1
        assert result["agents"]["analyst"].get("tool_calls", 0) == 0

    def test_skill_applied_true_when_llm_result_success(self, tmp_path):
        """skill_applied 在 LLM_RESULT SUCCESS 時為 True"""
        cp = _make_jsonl(SAMPLE_JSONL, tmp_path)
        result = _build_thinking_path(cp)

        assert result["agents"]["scout"]["skill_applied"] is True
        assert result["agents"]["analyst"]["skill_applied"] is True

    def test_skill_applied_false_when_only_error(self, tmp_path):
        """advisor 只有 LLM_ERROR，skill_applied 應為 False（初始值）"""
        cp = _make_jsonl(SAMPLE_JSONL, tmp_path)
        result = _build_thinking_path(cp)

        # advisor 有 LLM_ERROR 和 LLM_RETRY，但無 LLM_RESULT SUCCESS
        assert result["agents"]["advisor"]["skill_applied"] is False

    def test_has_error_flag_correct(self, tmp_path):
        """LLM_ERROR 事件要能被前端偵測（steps 包含 event=LLM_ERROR）"""
        cp = _make_jsonl(SAMPLE_JSONL, tmp_path)
        result = _build_thinking_path(cp)

        advisor_steps = result["agents"]["advisor"]["steps"]
        error_steps = [s for s in advisor_steps if s["event"] == "LLM_ERROR"]
        assert len(error_steps) == 1
        assert error_steps[0]["data"]["error"] == "429 Too Many Requests"

    def test_scan_meta_populated(self, tmp_path):
        """scan_meta 正確提取 SCAN_START/SCAN_END 資料"""
        cp = _make_jsonl(SAMPLE_JSONL, tmp_path)
        result = _build_thinking_path(cp)

        meta = result["scan_meta"]
        assert meta["scan_id"] == "test"
        assert meta["duration_seconds"] == 18.2
        assert meta["total_events"] == 11

    def test_empty_jsonl(self, tmp_path):
        """Graceful Degradation: 空 JSONL 不崩潰"""
        cp = _make_jsonl([], tmp_path)
        result = _build_thinking_path(cp)

        assert result["agents"] == {}
        assert result["scan_meta"] == {}

    def test_corrupted_lines_skipped(self, tmp_path):
        """部分損壞行跳過，仍能解析其餘正常行"""
        mixed = [
            SAMPLE_JSONL[0],  # SCAN_START
            "THIS IS NOT JSON !!!",
            SAMPLE_JSONL[1],  # STAGE_ENTER scout
            SAMPLE_JSONL[2],  # LLM_CALL scout
            SAMPLE_JSONL[3],  # LLM_RESULT scout
        ]
        # 混合正常 JSON 和壞行
        p = tmp_path / "corrupted.jsonl"
        with open(p, "w", encoding="utf-8") as f:
            for item in mixed:
                if isinstance(item, dict):
                    f.write(json.dumps(item) + "\n")
                else:
                    f.write(item + "\n")
        result = _build_thinking_path(p)

        # scout 的事件應該正確解析
        assert "scout" in result["agents"]
        assert result["agents"]["scout"]["llm_calls"] == 1

    def test_agent_order(self, tmp_path):
        """Agent 依預設 Pipeline 順序排列"""
        cp = _make_jsonl(SAMPLE_JSONL, tmp_path)
        result = _build_thinking_path(cp)

        agent_keys = list(result["agents"].keys())
        # scout 應該在 analyst 前
        if "scout" in agent_keys and "analyst" in agent_keys:
            assert agent_keys.index("scout") < agent_keys.index("analyst")

    def test_steps_contain_expected_events(self, tmp_path):
        """Scout 的 steps 應包含 STAGE_ENTER, LLM_CALL, LLM_RESULT, TOOL_CALL"""
        cp = _make_jsonl(SAMPLE_JSONL, tmp_path)
        result = _build_thinking_path(cp)

        scout_events = {s["event"] for s in result["agents"]["scout"]["steps"]}
        assert "STAGE_ENTER" in scout_events
        assert "LLM_CALL"    in scout_events
        assert "LLM_RESULT"  in scout_events
        assert "TOOL_CALL"   in scout_events

    def test_thinking_preview_preserved(self, tmp_path):
        """LLM_RESULT 中的 thinking_preview 被正確保留"""
        cp = _make_jsonl(SAMPLE_JSONL, tmp_path)
        result = _build_thinking_path(cp)

        analyst_steps = result["agents"]["analyst"]["steps"]
        llm_result_steps = [s for s in analyst_steps if s["event"] == "LLM_RESULT"]
        assert len(llm_result_steps) == 1
        assert llm_result_steps[0]["data"]["thinking_preview"] == "此漏洞屬於 SQL Injection..."

    def test_total_duration_ms_accumulation(self, tmp_path):
        """total_duration_ms 正確累加多個 LLM_RESULT duration_ms"""
        cp = _make_jsonl(SAMPLE_JSONL, tmp_path)
        result = _build_thinking_path(cp)

        # Scout: 4200ms
        assert result["agents"]["scout"]["total_duration_ms"] == 4200
        # Analyst: 3800ms
        assert result["agents"]["analyst"]["total_duration_ms"] == 3800
