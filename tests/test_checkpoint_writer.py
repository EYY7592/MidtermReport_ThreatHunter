"""
tests/test_checkpoint_writer.py
Phase 4A：Rust checkpoint_writer crate 單元測試
============================================================
測試策略：
  - 雙軌測試：若 Rust crate 可用 → 直接測試 Rust 介面
               若不可用 → 測試 Python fallback 路徑
  - 測試 checkpoint.py 整合層（Rust + Python 兩個路徑都跑）
  - 壓力測試：多執行緒同時寫入，驗證無資料競爭

執行：uv run python -m pytest tests/test_checkpoint_writer.py -v
"""

import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

# 確保 project root 在 sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── 偵測 Rust crate 是否可用 ────────────────────────────────────
try:
    import threathunter_checkpoint_writer as _cw
    _RUST_AVAILABLE = True
except ImportError:
    _cw = None
    _RUST_AVAILABLE = False


# ════════════════════════════════════════════════════════════════
# 測試集 1：Rust crate 直接介面測試（若 crate 已建置）
# ════════════════════════════════════════════════════════════════

@unittest.skipUnless(_RUST_AVAILABLE, "threathunter_checkpoint_writer 尚未編譯")
class TestRustCheckpointWriterDirect(unittest.TestCase):
    """直接測試 Rust crate 的所有 PyO3 函式"""

    def setUp(self):
        """每個測試前確保 writer 已關閉"""
        self.tmpdir = tempfile.mkdtemp()
        try:
            _cw.close_writer()
        except Exception:
            pass

    def tearDown(self):
        """每個測試後清理"""
        try:
            _cw.close_writer()
        except Exception:
            pass

    def _make_path(self, name: str = "test.jsonl") -> str:
        return str(Path(self.tmpdir) / name)

    # ── 基本 API 驗證 ──────────────────────────────────────────

    def test_module_has_version(self):
        """crate 應含有 __version__ 屬性"""
        self.assertTrue(hasattr(_cw, "__version__"))
        self.assertIsInstance(_cw.__version__, str)

    def test_is_open_false_before_open(self):
        """開啟前 is_open() 應為 False"""
        # 確保已關閉
        _cw.close_writer()
        self.assertFalse(_cw.is_open())

    def test_open_writer_creates_file(self):
        """open_writer() 應建立檔案"""
        path = self._make_path("create_test.jsonl")
        _cw.open_writer(path)
        self.assertTrue(_cw.is_open())
        _cw.close_writer()
        self.assertTrue(Path(path).exists())

    def test_open_writer_creates_parent_dir(self):
        """open_writer() 應自動建立父目錄"""
        nested = str(Path(self.tmpdir) / "a" / "b" / "c" / "test.jsonl")
        _cw.open_writer(nested)
        self.assertTrue(_cw.is_open())
        _cw.close_writer()
        self.assertTrue(Path(nested).parent.exists())

    def test_write_line_basic(self):
        """write_line() 寫入一行，關閉後可讀回"""
        path = self._make_path("write_basic.jsonl")
        _cw.open_writer(path)
        _cw.write_line('{"event": "TEST", "seq": 1}')
        _cw.flush_writer()
        _cw.close_writer()

        content = Path(path).read_text(encoding="utf-8").strip()
        self.assertEqual(content, '{"event": "TEST", "seq": 1}')

    def test_write_line_multiple(self):
        """write_line() 寫入多行，每行獨立"""
        path = self._make_path("write_multi.jsonl")
        _cw.open_writer(path)
        for i in range(10):
            _cw.write_line(f'{{"seq": {i}}}')
        _cw.close_writer()

        lines = Path(path).read_text(encoding="utf-8").strip().split("\n")
        self.assertEqual(len(lines), 10)
        for i, line in enumerate(lines):
            data = json.loads(line)
            self.assertEqual(data["seq"], i)

    def test_write_line_auto_appended_newline(self):
        """write_line() 應自動追加換行符"""
        path = self._make_path("newline_test.jsonl")
        _cw.open_writer(path)
        _cw.write_line("line1")
        _cw.write_line("line2")
        _cw.close_writer()

        raw = Path(path).read_bytes()
        self.assertEqual(raw.count(b"\n"), 2)

    def test_get_lines_written_counter(self):
        """get_lines_written() 應準確計數寫入行數"""
        path = self._make_path("counter_test.jsonl")
        _cw.open_writer(path)
        for i in range(7):
            _cw.write_line(f"line {i}")
        count = _cw.get_lines_written()
        _cw.close_writer()
        self.assertEqual(count, 7)

    def test_get_current_path_returns_path(self):
        """get_current_path() 應回傳已開啟的檔案路徑"""
        path = self._make_path("path_test.jsonl")
        _cw.open_writer(path)
        result = _cw.get_current_path()
        _cw.close_writer()
        self.assertIsNotNone(result)
        self.assertIn("path_test.jsonl", result)

    def test_get_current_path_none_when_closed(self):
        """writer 未開啟時 get_current_path() 應回傳 None"""
        _cw.close_writer()
        result = _cw.get_current_path()
        # None 或 空字串，依實作而定
        self.assertTrue(result is None or result == "")

    def test_flush_writer_no_error_when_closed(self):
        """writer 未開啟時 flush_writer() 應為 no-op（不 raise）"""
        _cw.close_writer()
        try:
            _cw.flush_writer()  # 不應拋出例外
        except Exception as e:
            self.fail(f"flush_writer() 當 writer 未開啟時不應 raise：{e}")

    def test_close_writer_idempotent(self):
        """多次呼叫 close_writer() 不應 crash"""
        path = self._make_path("idempotent.jsonl")
        _cw.open_writer(path)
        _cw.close_writer()
        _cw.close_writer()  # 第二次 close 不應拋出

    def test_write_batch_writes_all_lines(self):
        """write_batch() 應寫入所有行並回傳計數"""
        path = self._make_path("batch_test.jsonl")
        _cw.open_writer(path)
        lines = [f'{{"batch": {i}}}' for i in range(20)]
        written = _cw.write_batch(lines)
        _cw.close_writer()

        self.assertEqual(written, 20)
        read_lines = Path(path).read_text(encoding="utf-8").strip().split("\n")
        self.assertEqual(len(read_lines), 20)

    def test_write_line_unicode(self):
        """write_line() 應正確處理繁體中文 Unicode"""
        path = self._make_path("unicode_test.jsonl")
        text = '{"msg": "威脅掃描完成，發現 3 個 CVE 漏洞"}'
        _cw.open_writer(path)
        _cw.write_line(text)
        _cw.close_writer()

        content = Path(path).read_text(encoding="utf-8").strip()
        self.assertEqual(content, text)

    def test_write_large_line(self):
        """write_line() 應能處理接近 BufWriter 緩衝區大小（64KiB）的行"""
        path = self._make_path("large_line.jsonl")
        _cw.open_writer(path)
        large_line = "x" * 50_000  # 50KiB
        _cw.write_line(large_line)
        _cw.close_writer()

        content = Path(path).read_text(encoding="utf-8").strip()
        self.assertEqual(len(content), 50_000)

    # ── 多執行緒壓力測試 ────────────────────────────────────────

    def test_concurrent_writes_no_race_condition(self):
        """多執行緒同時呼叫 write_line()，結果必須完整且無混行"""
        path = self._make_path("concurrent.jsonl")
        _cw.open_writer(path)

        N_THREADS = 8
        N_LINES_PER_THREAD = 50
        errors = []

        def worker(tid: int):
            for i in range(N_LINES_PER_THREAD):
                try:
                    line = json.dumps({"tid": tid, "seq": i})
                    _cw.write_line(line)
                except Exception as e:
                    errors.append(f"tid={tid} seq={i}: {e}")

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(N_THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        _cw.flush_writer()
        _cw.close_writer()

        self.assertEqual(errors, [], f"寫入錯誤: {errors}")

        # 驗證每行都是合法 JSON
        all_lines = [
            l for l in Path(path).read_text(encoding="utf-8").strip().split("\n") if l
        ]
        self.assertEqual(len(all_lines), N_THREADS * N_LINES_PER_THREAD)
        for raw in all_lines:
            obj = json.loads(raw)  # 若混行，此處會拋 JSONDecodeError
            self.assertIn("tid", obj)
            self.assertIn("seq", obj)


# ════════════════════════════════════════════════════════════════
# 測試集 2：checkpoint.py 整合測試（Python + Rust 路徑）
# ════════════════════════════════════════════════════════════════

class TestCheckpointIntegration(unittest.TestCase):
    """測試 checkpoint.py 的完整整合行為（含 Phase 4A 雙路徑）"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def _make_recorder(self):
        from checkpoint import CheckpointRecorder
        return CheckpointRecorder(logs_dir=Path(self.tmpdir))

    # ── 基本功能：scan 生命週期 ──────────────────────────────────

    def test_start_scan_creates_jsonl_file(self):
        """start_scan() 應建立 JSONL 檔案（不論 Rust 是否可用）"""
        rec = self._make_recorder()
        rec.start_scan("test_001")
        rec.end_scan("OK", 1.0)

        cp_dir = Path(self.tmpdir) / "checkpoints"
        files = list(cp_dir.glob("*.jsonl"))
        self.assertEqual(len(files), 1)

    def test_checkpoint_writes_valid_json(self):
        """每條 checkpoint 記錄必須是合法 JSON，含必要欄位"""
        rec = self._make_recorder()
        rec.start_scan("test_002")
        rec.checkpoint("TEST_EVENT", "test_agent", {"key": "value"})
        rec.end_scan("OK", 0.1)

        cp_dir = Path(self.tmpdir) / "checkpoints"
        lines = [l for f in cp_dir.glob("*.jsonl")
                 for l in f.read_text(encoding="utf-8").strip().split("\n") if l]
        self.assertGreaterEqual(len(lines), 1)

        for raw in lines:
            ev = json.loads(raw)
            self.assertIn("seq", ev)
            self.assertIn("ts", ev)
            self.assertIn("event", ev)
            self.assertIn("agent", ev)

    def test_scan_start_contains_writer_backend(self):
        """SCAN_START 事件資料應含有 writer_backend 欄位（Phase 4A 新增）"""
        rec = self._make_recorder()
        rec.start_scan("test_003")
        rec.end_scan("OK", 0.1)

        cp_dir = Path(self.tmpdir) / "checkpoints"
        file = list(cp_dir.glob("*.jsonl"))[0]
        lines = [json.loads(l) for l in file.read_text(encoding="utf-8").strip().split("\n") if l]
        scan_start = next((e for e in lines if e["event"] == "SCAN_START"), None)
        self.assertIsNotNone(scan_start)
        self.assertIn("writer_backend", scan_start["data"])
        # 值必須是 'rust_bufwriter' 或 'python_lock'
        self.assertIn(scan_start["data"]["writer_backend"], ["rust_bufwriter", "python_lock"])

    def test_checkpoint_redacts_api_keys(self):
        """checkpoint 應遮罩 API Key（敏感資料遮罩功能）"""
        rec = self._make_recorder()
        rec.start_scan("test_004")
        rec.checkpoint("LLM_CALL", "scout", {"api_key": "sk-proj-abcdef123456"})
        rec.end_scan("OK", 0.1)

        cp_dir = Path(self.tmpdir) / "checkpoints"
        content = list(cp_dir.glob("*.jsonl"))[0].read_text(encoding="utf-8")
        # API key 必須被遮罩
        self.assertNotIn("sk-proj-abcdef123456", content)

    def test_end_scan_writes_event_summary(self):
        """SCAN_END 事件應含有 event_summary 統計"""
        rec = self._make_recorder()
        rec.start_scan("test_005")
        rec.checkpoint("LLM_CALL", "scout", {})
        rec.checkpoint("LLM_CALL", "analyst", {})
        rec.checkpoint("TOOL_CALL", "scout", {})
        rec.end_scan("OK", 5.0)

        cp_dir = Path(self.tmpdir) / "checkpoints"
        file = list(cp_dir.glob("*.jsonl"))[0]
        lines = [json.loads(l) for l in file.read_text(encoding="utf-8").strip().split("\n") if l]
        scan_end = next((e for e in lines if e["event"] == "SCAN_END"), None)
        self.assertIsNotNone(scan_end)
        summary = scan_end["data"]["event_summary"]
        self.assertEqual(summary.get("LLM_CALL", 0), 2)
        self.assertEqual(summary.get("TOOL_CALL", 0), 1)

    def test_get_summary_correctness(self):
        """get_summary() 應回傳正確的統計資訊"""
        rec = self._make_recorder()
        rec.start_scan("test_006")
        for _ in range(5):
            rec.checkpoint("LLM_CALL", "scout", {})
        summary = rec.get_summary()
        self.assertEqual(summary["event_counts"].get("LLM_CALL", 0), 5)
        rec.end_scan("OK", 1.0)

    def test_disabled_checkpoint_does_not_write(self):
        """CHECKPOINT_ENABLED=false 時不寫入任何檔案"""
        import checkpoint as cp_module
        original = cp_module.ENABLED
        cp_module.ENABLED = False
        try:
            rec = self._make_recorder()
            rec.start_scan("test_007")
            rec.checkpoint("TEST", "agent", {})
            rec.end_scan("OK", 0.1)
            cp_dir = Path(self.tmpdir) / "checkpoints"
            files = list(cp_dir.glob("*.jsonl")) if cp_dir.exists() else []
            self.assertEqual(files, [])
        finally:
            cp_module.ENABLED = original

    def test_silent_on_internal_error(self):
        """checkpoint() 內部錯誤不應拋出例外（靜默模式）"""
        rec = self._make_recorder()
        rec.start_scan("test_008")
        # 故意損壞內部狀態
        rec._file = None
        rec._rust_writer_active = False
        try:
            rec.checkpoint("TEST", "agent", {"data": "ok"})  # 不應 raise
        except Exception as e:
            self.fail(f"checkpoint() 不應拋出例外: {e}")
        rec.end_scan("OK", 0.1)

    # ── Rust Fallback 路徑驗證 ───────────────────────────────────

    def test_python_fallback_path_works(self):
        """強制禁用 Rust writer → Python fallback 仍正常寫入"""
        import checkpoint as cp_mod
        original = cp_mod._RUST_WRITER_AVAILABLE

        cp_mod._RUST_WRITER_AVAILABLE = False
        try:
            rec = self._make_recorder()
            rec.start_scan("test_fallback")
            for i in range(5):
                rec.checkpoint("STAGE_ENTER", f"agent_{i}", {"step": i})
            rec.end_scan("OK", 0.5)

            cp_dir = Path(self.tmpdir) / "checkpoints"
            files = list(cp_dir.glob("*.jsonl"))
            self.assertEqual(len(files), 1)
            lines = [
                l for l in files[0].read_text(encoding="utf-8").strip().split("\n") if l
            ]
            # SCAN_START + 5 STAGE_ENTER + SCAN_END = 7
            self.assertEqual(len(lines), 7)
        finally:
            cp_mod._RUST_WRITER_AVAILABLE = original

    # ── 多執行緒整合壓力測試 ────────────────────────────────────

    def test_concurrent_checkpoint_writes(self):
        """Layer-1 並行（security_guard + intel_fusion 同時 checkpoint），結果完整"""
        rec = self._make_recorder()
        rec.start_scan("test_concurrent")

        N_THREADS = 4
        N_WRITES_EACH = 25
        errors = []

        def writer_thread(agent_name: str):
            for i in range(N_WRITES_EACH):
                try:
                    rec.checkpoint("LLM_CALL", agent_name, {"seq": i})
                except Exception as e:
                    errors.append(f"{agent_name}[{i}]: {e}")

        threads = [
            threading.Thread(target=writer_thread, args=(f"agent_{t}",))
            for t in range(N_THREADS)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        rec.end_scan("OK", 1.0)

        self.assertEqual(errors, [], f"並行寫入錯誤: {errors}")

        cp_dir = Path(self.tmpdir) / "checkpoints"
        files = list(cp_dir.glob("*.jsonl"))
        self.assertEqual(len(files), 1)
        all_lines = [
            l for l in files[0].read_text(encoding="utf-8").strip().split("\n") if l
        ]
        # 每行必須是合法 JSON
        for raw in all_lines:
            try:
                json.loads(raw)
            except json.JSONDecodeError as e:
                self.fail(f"並行寫入產生損壞 JSON: {e}\n原始行: {raw[:200]}")

        # 總行數：SCAN_START + N_THREADS*N_WRITES_EACH + SCAN_END
        expected_min = N_THREADS * N_WRITES_EACH
        llm_calls = [l for l in all_lines if '"LLM_CALL"' in l]
        self.assertGreaterEqual(len(llm_calls), expected_min)


# ════════════════════════════════════════════════════════════════
# 測試集 3：edge case 與邊界情況
# ════════════════════════════════════════════════════════════════

class TestCheckpointEdgeCases(unittest.TestCase):
    """邊界情況與例外處理測試"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def _make_recorder(self):
        from checkpoint import CheckpointRecorder
        return CheckpointRecorder(logs_dir=Path(self.tmpdir))

    def test_stage_enter_with_all_fields(self):
        """stage_enter() 完整欄位測試（v3.7 Path-Aware）"""
        rec = self._make_recorder()
        rec.start_scan("edge_001")
        rec.stage_enter(
            "scout",
            input_data={"tech_stack": "django==4.2", "vulnerabilities": []},
            skill_file="threat_intel.md",
            input_type="pkg",
        )
        rec.end_scan("OK", 0.1)

        cp_dir = Path(self.tmpdir) / "checkpoints"
        content = list(cp_dir.glob("*.jsonl"))[0].read_text(encoding="utf-8")
        self.assertIn("threat_intel.md", content)
        self.assertIn("pkg", content)

    def test_llm_retry_checkpoint(self):
        """llm_retry() 應寫入正確欄位"""
        rec = self._make_recorder()
        rec.start_scan("edge_002")
        rec.llm_retry("scout", "gemini-pro", "Rate limited", 1, "gemini-flash")
        rec.end_scan("OK", 0.1)

        cp_dir = Path(self.tmpdir) / "checkpoints"
        content = list(cp_dir.glob("*.jsonl"))[0].read_text(encoding="utf-8")
        self.assertIn("LLM_RETRY", content)
        self.assertIn("gemini-flash", content)

    def test_degradation_checkpoint(self):
        """degradation() 應寫入正確欄位"""
        rec = self._make_recorder()
        rec.start_scan("edge_003")
        rec.degradation("intel_fusion", "OTX API timeout", "use_cache")
        rec.end_scan("OK", 0.1)

        cp_dir = Path(self.tmpdir) / "checkpoints"
        content = list(cp_dir.glob("*.jsonl"))[0].read_text(encoding="utf-8")
        self.assertIn("DEGRADATION", content)
        self.assertIn("use_cache", content)

    def test_current_filename_property(self):
        """current_filename 屬性應在 start_scan 後回傳可用的檔名"""
        rec = self._make_recorder()
        rec.start_scan("edge_004")
        fname = rec.current_filename
        self.assertNotEqual(fname, "")
        self.assertTrue(fname.endswith(".jsonl"))
        rec.end_scan("OK", 0.1)

    def test_harness_check_checkpoint(self):
        """harness_check() 應寫入完整欄位"""
        rec = self._make_recorder()
        rec.start_scan("edge_005")
        rec.harness_check(
            "scout", "L1", "CVE_VALIDATION",
            "PASS", action="none",
            details={"cve_count": 3},
        )
        rec.end_scan("OK", 0.1)

        cp_dir = Path(self.tmpdir) / "checkpoints"
        content = list(cp_dir.glob("*.jsonl"))[0].read_text(encoding="utf-8")
        self.assertIn("HARNESS_CHECK", content)
        self.assertIn("CVE_VALIDATION", content)

    def test_empty_data_dict(self):
        """空 data dict 不應 crash"""
        rec = self._make_recorder()
        rec.start_scan("edge_006")
        rec.checkpoint("STAGE_ENTER", "orchestrator", {})
        rec.checkpoint("STAGE_EXIT", "orchestrator", {"status": "OK", "duration_ms": 100})
        rec.end_scan("OK", 0.1)

    def test_seq_increments_correctly(self):
        """seq 計數器應正確遞增"""
        rec = self._make_recorder()
        rec.start_scan("edge_007")
        for _ in range(10):
            rec.checkpoint("TOOL_CALL", "scout", {})
        rec.end_scan("OK", 0.1)

        cp_dir = Path(self.tmpdir) / "checkpoints"
        file = list(cp_dir.glob("*.jsonl"))[0]
        lines = [json.loads(l) for l in file.read_text(encoding="utf-8").strip().split("\n") if l]
        seqs = [e["seq"] for e in lines]
        # seq 必須嚴格遞增，從 1 開始
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
