"""
tests/test_checkpoint.py — Checkpoint 記錄器測試
=================================================

14 個測試案例，驗證 CheckpointRecorder 的完整功能：
  - 檔案建立與 JSONL 寫入
  - Stage / LLM / Tool / Harness 便捷方法
  - 執行緒安全
  - 零失敗保障
  - 敏感資料遮罩
  - 截斷上限

遵守：AGENTS.md + project_CONSTITUTION.md
"""

import json
import os
import tempfile
import threading
from pathlib import Path

import pytest

from checkpoint import CheckpointRecorder, _redact, _truncate, ENABLED


@pytest.fixture
def tmp_logs(tmp_path):
    """建立臨時 logs 目錄"""
    return tmp_path / "logs"


@pytest.fixture
def rec(tmp_logs):
    """建立測試用 CheckpointRecorder"""
    return CheckpointRecorder(logs_dir=tmp_logs)


def _read_jsonl(logs_dir: Path) -> list[dict]:
    """讀取 checkpoints 目錄下的所有 JSONL 行"""
    cp_dir = logs_dir / "checkpoints"
    if not cp_dir.exists():
        return []
    lines = []
    for f in cp_dir.glob("*.jsonl"):
        for line in f.read_text(encoding="utf-8").strip().splitlines():
            if line.strip():
                lines.append(json.loads(line))
    return lines


# ══════════════════════════════════════════════════════════════
# 1. 檔案建立
# ══════════════════════════════════════════════════════════════

class TestFileCreation:
    """測試 start_scan 建立檔案和基礎結構"""

    def test_start_scan_creates_file(self, rec, tmp_logs):
        """呼叫 start_scan() 後在 checkpoints/ 建立 JSONL 檔案"""
        rec.start_scan("test-scan-001")
        rec.end_scan("COMPLETE", 1.0)

        cp_dir = tmp_logs / "checkpoints"
        assert cp_dir.exists(), "checkpoints 目錄應該存在"
        files = list(cp_dir.glob("*.jsonl"))
        assert len(files) == 1, f"應有 1 個 JSONL 檔案，但有 {len(files)}"
        assert "test-sca" in files[0].name  # scan_id[:8] 截斷

    def test_checkpoint_writes_jsonl(self, rec, tmp_logs):
        """每次 checkpoint() 寫入一行有效 JSON"""
        rec.start_scan("test-jsonl-001")
        rec.checkpoint("TEST_EVENT", "test_agent", {"key": "value"})
        rec.checkpoint("TEST_EVENT_2", "test_agent", {"num": 42})
        rec.end_scan("COMPLETE", 2.0)

        records = _read_jsonl(tmp_logs)
        # SCAN_START + 2 個自定義 + SCAN_END = 4
        assert len(records) == 4, f"應有 4 行 JSONL，但有 {len(records)}"

        # 驗證第二條記錄的結構
        r = records[1]
        assert r["event"] == "TEST_EVENT"
        assert r["agent"] == "test_agent"
        assert r["data"]["key"] == "value"
        assert r["seq"] == 2  # SCAN_START 是 seq=1
        assert "ts" in r
        assert "scan_id" in r


# ══════════════════════════════════════════════════════════════
# 2. Stage 層
# ══════════════════════════════════════════════════════════════

class TestStageMethods:
    """測試 Stage 進出 checkpoint"""

    def test_stage_enter_exit_pair(self, rec, tmp_logs):
        """stage_enter + stage_exit 配對完整"""
        rec.start_scan("test-stage-001")
        rec.stage_enter("scout", {"tech_stack": "Django 4.2", "vulnerabilities": [1, 2]})
        rec.stage_exit("scout", "SUCCESS", {"risk_score": 75, "vulnerabilities": [1, 2]}, 1500)
        rec.end_scan("COMPLETE", 1.5)

        records = _read_jsonl(tmp_logs)
        events = [r["event"] for r in records]
        assert "STAGE_ENTER" in events
        assert "STAGE_EXIT" in events

        enter = [r for r in records if r["event"] == "STAGE_ENTER"][0]
        assert enter["agent"] == "scout"
        assert "input_hash" in enter["data"]
        assert enter["data"]["vuln_count"] == 2

        exit_r = [r for r in records if r["event"] == "STAGE_EXIT"][0]
        assert exit_r["data"]["status"] == "SUCCESS"
        assert exit_r["data"]["duration_ms"] == 1500
        assert exit_r["data"]["risk_score"] == 75


# ══════════════════════════════════════════════════════════════
# 3. LLM 層
# ══════════════════════════════════════════════════════════════

class TestLLMMethods:
    """測試 LLM 呼叫 checkpoint"""

    def test_llm_call_result_pair(self, rec, tmp_logs):
        """llm_call + llm_result 配對完整"""
        rec.start_scan("test-llm-001")
        rec.llm_call("scout", "llama-3.3-70b:free", "openrouter", "分析技術堆疊...")
        rec.llm_result("scout", "llama-3.3-70b:free", "SUCCESS", 1200, 5000,
                       thinking="scan_id: scan_123, vulnerabilities: [...]")
        rec.end_scan("COMPLETE", 5.0)

        records = _read_jsonl(tmp_logs)
        llm_call = [r for r in records if r["event"] == "LLM_CALL"]
        llm_result = [r for r in records if r["event"] == "LLM_RESULT"]

        assert len(llm_call) == 1
        assert llm_call[0]["data"]["model"] == "llama-3.3-70b:free"

        assert len(llm_result) == 1
        assert llm_result[0]["data"]["status"] == "SUCCESS"
        assert llm_result[0]["data"]["output_length"] == 1200
        assert "thinking_preview" in llm_result[0]["data"]

    def test_llm_retry_records_model_switch(self, rec, tmp_logs):
        """重試時記錄舊模型和新模型"""
        rec.start_scan("test-retry-001")
        rec.llm_retry("scout", "llama-3.3-70b:free", "429 rate limit", 1, "hermes-3-405b:free")
        rec.end_scan("COMPLETE", 1.0)

        records = _read_jsonl(tmp_logs)
        retry = [r for r in records if r["event"] == "LLM_RETRY"]
        assert len(retry) == 1
        assert retry[0]["data"]["failed_model"] == "llama-3.3-70b:free"
        assert retry[0]["data"]["next_model"] == "hermes-3-405b:free"
        assert retry[0]["data"]["retry_count"] == 1
        assert "429" in retry[0]["data"]["error"]

    def test_llm_error_writes_to_error_log(self, rec, tmp_logs):
        """llm_error 同時寫入 error log"""
        rec.start_scan("test-error-001")
        rec.llm_error("analyst", "llama-3.3-70b:free", "Connection timeout after 30s")
        rec.end_scan("ERROR", 30.0)

        # 驗證 checkpoint 記錄
        records = _read_jsonl(tmp_logs)
        errors = [r for r in records if r["event"] == "LLM_ERROR"]
        assert len(errors) == 1

        # 驗證 error log 檔案
        err_dir = tmp_logs / "errors"
        assert err_dir.exists()
        err_files = list(err_dir.glob("errors_*.log"))
        assert len(err_files) >= 1
        content = err_files[0].read_text(encoding="utf-8")
        assert "analyst" in content
        assert "Connection timeout" in content


# ══════════════════════════════════════════════════════════════
# 4. 工具 / Harness 層
# ══════════════════════════════════════════════════════════════

class TestToolAndHarness:
    """測試工具呼叫和 Harness 保障 checkpoint"""

    def test_tool_call_captures_io(self, rec, tmp_logs):
        """工具呼叫記錄輸入輸出"""
        rec.start_scan("test-tool-001")
        rec.tool_call("scout", "search_nvd", "Django", '{"cves": ["CVE-2024-1234"]}', "SUCCESS")
        rec.end_scan("COMPLETE", 1.0)

        records = _read_jsonl(tmp_logs)
        tools = [r for r in records if r["event"] == "TOOL_CALL"]
        assert len(tools) == 1
        assert tools[0]["data"]["tool_name"] == "search_nvd"
        assert tools[0]["data"]["input"] == "Django"
        assert "CVE-2024-1234" in tools[0]["data"]["output_preview"]

    def test_harness_check_records_action(self, rec, tmp_logs):
        """Harness 修正行為被記錄"""
        rec.start_scan("test-harness-001")
        rec.harness_check(
            "security_guard", "L1", "deterministic_extraction", "PASS",
            details={"functions": 3, "patterns": 2}
        )
        rec.end_scan("COMPLETE", 1.0)

        records = _read_jsonl(tmp_logs)
        harness = [r for r in records if r["event"] == "HARNESS_CHECK"]
        assert len(harness) == 1
        assert harness[0]["data"]["layer"] == "L1"
        assert harness[0]["data"]["check_name"] == "deterministic_extraction"
        assert harness[0]["data"]["functions"] == 3


# ══════════════════════════════════════════════════════════════
# 5. 安全性與健壯性
# ══════════════════════════════════════════════════════════════

class TestSafetyAndRobustness:
    """測試零失敗保障和安全性"""

    def test_thread_safety(self, rec, tmp_logs):
        """兩個 Thread 同時寫入不衝突"""
        rec.start_scan("test-thread-001")
        errors = []

        def write_events(agent_name: str, count: int):
            try:
                for i in range(count):
                    rec.checkpoint(f"THREAD_TEST", agent_name, {"i": i})
            except Exception as e:
                errors.append(str(e))

        t1 = threading.Thread(target=write_events, args=("agent_a", 50))
        t2 = threading.Thread(target=write_events, args=("agent_b", 50))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        rec.end_scan("COMPLETE", 1.0)

        assert len(errors) == 0, f"Thread 寫入發生錯誤: {errors}"

        records = _read_jsonl(tmp_logs)
        # SCAN_START + 100 THREAD_TEST + SCAN_END = 102
        assert len(records) == 102, f"應有 102 條記錄，但有 {len(records)}"

        # 驗證 seq 唯一性
        seqs = [r["seq"] for r in records]
        assert len(seqs) == len(set(seqs)), "seq 應該是唯一的"

    def test_checkpoint_never_raises(self, rec, tmp_logs):
        """任何異常輸入（None/巨大字串）不拋出例外"""
        # 未初始化就呼叫
        fresh = CheckpointRecorder(logs_dir=tmp_logs)
        fresh.checkpoint("TEST", "agent", None)  # data=None
        fresh.stage_enter("agent", None)
        fresh.stage_exit("agent", "SUCCESS", None, 0)
        fresh.llm_call("agent", None, None, None)
        fresh.llm_result("agent", None, None, 0, 0)
        fresh.llm_retry("agent", None, None, 0, None)
        fresh.llm_error("agent", None, None)
        fresh.tool_call("agent", None, None, None)
        fresh.harness_check("agent", None, None, None)
        fresh.end_scan("DONE", 0)
        # 如果到這裡沒拋出例外就通過

    def test_input_truncation(self, rec, tmp_logs):
        """超過 2000 字元的輸入被截斷"""
        rec.start_scan("test-truncate-001")
        huge_input = "A" * 10000
        rec.checkpoint("BIG_DATA", "agent", {"huge": huge_input})
        rec.end_scan("COMPLETE", 1.0)

        records = _read_jsonl(tmp_logs)
        big = [r for r in records if r["event"] == "BIG_DATA"]
        assert len(big) == 1
        assert len(big[0]["data"]["huge"]) < 3000  # 截斷後應小於 3000
        assert "truncated" in big[0]["data"]["huge"]

    def test_sensitive_data_redaction(self, rec, tmp_logs):
        """API Key / 密碼不出現在 checkpoint"""
        rec.start_scan("test-redact-001")
        rec.checkpoint("SENSITIVE", "agent", {
            "api_key": "sk-proj-1234567890abcdefghijklmnopqrst",
            "password": "my_secret_password_123",
            "normal": "This is fine",
        })
        rec.end_scan("COMPLETE", 1.0)

        records = _read_jsonl(tmp_logs)
        sensitive = [r for r in records if r["event"] == "SENSITIVE"]
        assert len(sensitive) == 1
        data = sensitive[0]["data"]
        # sk-proj-xxxx 會被 _redact 遮罩（前 4 字保留 + REDACTED）
        assert "REDACTED" in data["api_key"]
        assert data["normal"] == "This is fine"


# ══════════════════════════════════════════════════════════════
# 6. 統計摘要
# ══════════════════════════════════════════════════════════════

class TestSummary:
    """測試統計摘要功能"""

    def test_end_scan_writes_summary(self, rec, tmp_logs):
        """end_scan() 寫入掃描摘要"""
        rec.start_scan("test-summary-001")
        rec.checkpoint("A", "x", {})
        rec.checkpoint("B", "y", {})
        rec.checkpoint("A", "z", {})
        rec.end_scan("COMPLETE", 3.5)

        records = _read_jsonl(tmp_logs)
        scan_end = [r for r in records if r["event"] == "SCAN_END"]
        assert len(scan_end) == 1
        data = scan_end[0]["data"]
        assert data["final_status"] == "COMPLETE"
        assert data["total_duration_seconds"] == 3.5
        assert data["total_checkpoints"] >= 4  # SCAN_START + 3 + SCAN_END

    def test_get_summary_counts(self, rec, tmp_logs):
        """統計摘要正確計算各事件類型數量"""
        rec.start_scan("test-counts-001")
        rec.checkpoint("LLM_CALL", "scout", {})
        rec.checkpoint("LLM_CALL", "analyst", {})
        rec.checkpoint("LLM_RESULT", "scout", {})
        rec.checkpoint("TOOL_CALL", "scout", {})

        summary = rec.get_summary()
        assert summary["scan_id"] == "test-counts-001"
        assert summary["total_checkpoints"] >= 5  # SCAN_START + 4
        assert summary["event_counts"]["LLM_CALL"] == 2
        assert summary["event_counts"]["LLM_RESULT"] == 1
        assert summary["event_counts"]["TOOL_CALL"] == 1
