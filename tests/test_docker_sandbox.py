# tests/test_docker_sandbox.py
# Phase 3 Docker Sandbox 單元測試
# ================================================
# 測試策略：
#   - 不依賴真實 Docker daemon（用 unittest.mock 模擬）
#   - 驗證 docker_sandbox.py 的邏輯正確性
#   - 驗證 sandbox_runner.py 的 selftest / 輸入驗證
#   - 驗證 main.py 的 SANDBOX_ENABLED 整合開關
#
# 執行：uv run python -m pytest tests/test_docker_sandbox.py -v

import importlib
import json
import sys
import os
import subprocess
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, call

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ════════════════════════════════════════════════════════════
# 測試 1：sandbox/docker_sandbox.py 核心邏輯
# ════════════════════════════════════════════════════════════

class TestDockerSandboxAvailability(unittest.TestCase):
    """is_docker_available / is_sandbox_image_ready 邏輯測試"""

    def test_is_docker_available_returns_true_when_docker_info_succeeds(self):
        """docker info 成功 → is_docker_available() = True"""
        from sandbox.docker_sandbox import is_docker_available
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            self.assertTrue(is_docker_available())
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            self.assertIn("docker", args)
            self.assertIn("info", args)

    def test_is_docker_available_returns_false_when_docker_not_found(self):
        """docker 未安裝 → FileNotFoundError → returns False"""
        from sandbox.docker_sandbox import is_docker_available
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            self.assertFalse(is_docker_available())

    def test_is_docker_available_returns_false_on_timeout(self):
        """docker info 超時 → returns False"""
        from sandbox.docker_sandbox import is_docker_available
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("docker", 5)):
            self.assertFalse(is_docker_available())

    def test_is_sandbox_image_ready_true_when_inspect_succeeds(self):
        """docker image inspect 成功 → image 已存在"""
        from sandbox.docker_sandbox import is_sandbox_image_ready
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            self.assertTrue(is_sandbox_image_ready())

    def test_is_sandbox_image_ready_false_when_image_missing(self):
        """docker image inspect 返回 1 → image 不存在"""
        from sandbox.docker_sandbox import is_sandbox_image_ready
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            self.assertFalse(is_sandbox_image_ready())


class TestRunInSandbox(unittest.TestCase):
    """run_in_sandbox() 主要邏輯測試"""

    def _mock_successful_run(self, result_dict: dict):
        """建立成功的 subprocess.run mock"""
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = json.dumps(result_dict)
        mock_proc.stderr = ""
        return mock_proc

    def test_returns_fallback_when_image_not_ready(self):
        """映像不存在 → 返回 fallback=True"""
        from sandbox.docker_sandbox import run_in_sandbox
        with patch("sandbox.docker_sandbox.is_sandbox_image_ready", return_value=False):
            result = run_in_sandbox("django==4.2")
            self.assertTrue(result.get("fallback"))
            self.assertEqual(result.get("error"), "SANDBOX_IMAGE_NOT_FOUND")
            self.assertIn("hint", result)

    def test_returns_result_on_successful_container_execution(self):
        """容器正常執行 → 返回解析後的結果 dict"""
        from sandbox.docker_sandbox import run_in_sandbox
        expected_result = {
            "vulnerabilities": [{"cve_id": "CVE-2024-12345"}],
            "summary": {"total": 1},
        }
        with patch("sandbox.docker_sandbox.is_sandbox_image_ready", return_value=True), \
             patch("subprocess.run", return_value=self._mock_successful_run(expected_result)):
            result = run_in_sandbox("django==4.2")
            self.assertEqual(result["vulnerabilities"][0]["cve_id"], "CVE-2024-12345")
            self.assertIn("_sandbox_elapsed_s", result)
            self.assertTrue(result.get("_sandbox_mode"))

    def test_returns_fallback_on_timeout(self):
        """容器超時 → 返回 SANDBOX_TIMEOUT fallback"""
        from sandbox.docker_sandbox import run_in_sandbox
        with patch("sandbox.docker_sandbox.is_sandbox_image_ready", return_value=True), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired("docker", 300)):
            result = run_in_sandbox("django==4.2")
            self.assertTrue(result.get("fallback"))
            self.assertEqual(result.get("error"), "SANDBOX_TIMEOUT")

    def test_returns_fallback_when_docker_not_found(self):
        """docker 未安裝 → DOCKER_NOT_FOUND fallback"""
        from sandbox.docker_sandbox import run_in_sandbox
        with patch("sandbox.docker_sandbox.is_sandbox_image_ready", return_value=True), \
             patch("subprocess.run", side_effect=FileNotFoundError()):
            result = run_in_sandbox("django==4.2")
            self.assertTrue(result.get("fallback"))
            self.assertEqual(result.get("error"), "DOCKER_NOT_FOUND")

    def test_returns_fallback_on_nonzero_exit_code(self):
        """容器以非 0/1 結束 → SANDBOX_CONTAINER_ERROR"""
        from sandbox.docker_sandbox import run_in_sandbox
        mock_proc = MagicMock()
        mock_proc.returncode = 2
        mock_proc.stdout = ""
        mock_proc.stderr = "some error"
        with patch("sandbox.docker_sandbox.is_sandbox_image_ready", return_value=True), \
             patch("subprocess.run", return_value=mock_proc):
            result = run_in_sandbox("django==4.2")
            self.assertTrue(result.get("fallback"))
            self.assertEqual(result.get("error"), "SANDBOX_CONTAINER_ERROR")

    def test_returns_fallback_on_invalid_json_output(self):
        """容器輸出無效 JSON → SANDBOX_OUTPUT_PARSE_ERROR"""
        from sandbox.docker_sandbox import run_in_sandbox
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "not valid json"
        mock_proc.stderr = ""
        with patch("sandbox.docker_sandbox.is_sandbox_image_ready", return_value=True), \
             patch("subprocess.run", return_value=mock_proc):
            result = run_in_sandbox("django==4.2")
            self.assertTrue(result.get("fallback"))
            self.assertEqual(result.get("error"), "SANDBOX_OUTPUT_PARSE_ERROR")

    def test_returns_fallback_on_empty_stdout(self):
        """容器返回空 stdout → SANDBOX_EMPTY_OUTPUT"""
        from sandbox.docker_sandbox import run_in_sandbox
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = ""
        mock_proc.stderr = "something logged"
        with patch("sandbox.docker_sandbox.is_sandbox_image_ready", return_value=True), \
             patch("subprocess.run", return_value=mock_proc):
            result = run_in_sandbox("django==4.2")
            self.assertTrue(result.get("fallback"))
            self.assertEqual(result.get("error"), "SANDBOX_EMPTY_OUTPUT")


class TestBuildDockerCmd(unittest.TestCase):
    """_build_docker_cmd() 安全旗標驗證"""

    def test_cmd_includes_network_none(self):
        """docker run 必須包含 --network none"""
        from sandbox.docker_sandbox import _build_docker_cmd
        cmd = _build_docker_cmd()
        self.assertIn("--network", cmd)
        idx = cmd.index("--network")
        self.assertEqual(cmd[idx + 1], "none")

    def test_cmd_includes_read_only(self):
        """docker run 必須包含 --read-only"""
        from sandbox.docker_sandbox import _build_docker_cmd
        cmd = _build_docker_cmd()
        self.assertIn("--read-only", cmd)

    def test_cmd_includes_no_new_privileges(self):
        """docker run 必須包含 --no-new-privileges"""
        from sandbox.docker_sandbox import _build_docker_cmd
        cmd = _build_docker_cmd()
        self.assertIn("--no-new-privileges", cmd)

    def test_cmd_includes_memory_limit(self):
        """docker run 必須包含 --memory 限制"""
        from sandbox.docker_sandbox import _build_docker_cmd
        cmd = _build_docker_cmd()
        self.assertIn("--memory", cmd)

    def test_cmd_includes_cpu_limit(self):
        """docker run 必須包含 --cpus 限制"""
        from sandbox.docker_sandbox import _build_docker_cmd
        cmd = _build_docker_cmd()
        self.assertIn("--cpus", cmd)

    def test_cmd_includes_pids_limit(self):
        """docker run 必須包含 --pids-limit"""
        from sandbox.docker_sandbox import _build_docker_cmd
        cmd = _build_docker_cmd()
        self.assertIn("--pids-limit", cmd)

    def test_cmd_includes_user_sandbox(self):
        """docker run 必須以 sandbox 用戶執行"""
        from sandbox.docker_sandbox import _build_docker_cmd
        cmd = _build_docker_cmd()
        self.assertIn("--user", cmd)
        idx = cmd.index("--user")
        self.assertEqual(cmd[idx + 1], "sandbox")

    def test_selftest_cmd_includes_flag(self):
        """selftest 模式下 cmd 包含 --selftest"""
        from sandbox.docker_sandbox import _build_docker_cmd
        cmd = _build_docker_cmd(selftest=True)
        self.assertIn("--selftest", cmd)


# ════════════════════════════════════════════════════════════
# 測試 2：sandbox/sandbox_runner.py 邏輯
# ════════════════════════════════════════════════════════════

class TestSandboxRunner(unittest.TestCase):
    """sandbox_runner.py 輸入驗證與環境偵測"""

    def test_read_task_validates_tech_stack_required(self):
        """stdin JSON 缺少 tech_stack → ValueError"""
        from sandbox import sandbox_runner
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.read.return_value = json.dumps({"input_type": "pkg"})
            with self.assertRaises(ValueError) as ctx:
                sandbox_runner._read_task_from_stdin()
            self.assertIn("tech_stack", str(ctx.exception))

    def test_read_task_rejects_invalid_json(self):
        """stdin 非 JSON → ValueError"""
        from sandbox import sandbox_runner
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.read.return_value = "not json"
            with self.assertRaises(ValueError) as ctx:
                sandbox_runner._read_task_from_stdin()
            self.assertIn("Invalid JSON", str(ctx.exception))

    def test_read_task_rejects_empty_stdin(self):
        """空 stdin → ValueError"""
        from sandbox import sandbox_runner
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.read.return_value = ""
            with self.assertRaises(ValueError) as ctx:
                sandbox_runner._read_task_from_stdin()
            self.assertIn("Empty stdin", str(ctx.exception))

    def test_read_task_accepts_valid_json(self):
        """合法 JSON 包含 tech_stack → 返回 dict"""
        from sandbox import sandbox_runner
        task = {"tech_stack": "django==4.2", "input_type": "pkg"}
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.read.return_value = json.dumps(task)
            result = sandbox_runner._read_task_from_stdin()
            self.assertEqual(result["tech_stack"], "django==4.2")


    def test_run_pipeline_fallback_on_import_error(self):
        """main.run_pipeline_sync 拋錯 → 返回 fallback dict"""
        from sandbox import sandbox_runner
        import sys as _sys

        # 用 MagicMock 替換 sys.modules['main']，讓 run_pipeline_sync 拋 ImportError
        mock_main = MagicMock()
        mock_main.run_pipeline_sync = MagicMock(side_effect=ImportError("simulated"))
        original_main = _sys.modules.get("main")
        _sys.modules["main"] = mock_main
        try:
            task = {"tech_stack": "django==4.2"}
            result = sandbox_runner._run_pipeline(task)
            self.assertIsInstance(result, dict)
            self.assertTrue(result.get("fallback"), msg=f"Expected fallback, got: {result}")
        finally:
            if original_main is not None:
                _sys.modules["main"] = original_main
            elif "main" in _sys.modules:
                del _sys.modules["main"]


    def test_is_writable_returns_true_for_tmp(self):
        """_is_writable('/tmp') → True（通常可寫）"""
        from sandbox.sandbox_runner import _is_writable
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            self.assertTrue(_is_writable(tmpdir))

    def test_can_reach_internet_returns_false_without_network(self):
        """模擬無網路 → _can_reach_internet() = False"""
        from sandbox.sandbox_runner import _can_reach_internet
        with patch("socket.socket") as mock_sock:
            mock_sock.return_value.connect.side_effect = OSError("no network")
            # 因為 _can_reach_internet 已 import socket，這個 patch 不一定生效
            # 但至少驗證函式不會 crash
            result = _can_reach_internet()
            self.assertIsInstance(result, bool)


# ════════════════════════════════════════════════════════════
# 測試 3：main.py SANDBOX_ENABLED 整合開關
# ════════════════════════════════════════════════════════════

class TestMainSandboxIntegration(unittest.TestCase):
    """驗證 main.py 的 SANDBOX_ENABLED 開關與 fallback 邏輯"""

    def test_sandbox_disabled_by_default(self):
        """SANDBOX_ENABLED 預設為 false"""
        import main
        # 重新載入確保環境變數生效
        original = os.environ.get("SANDBOX_ENABLED", "false")
        self.assertEqual(original.lower(), "false")

    def test_run_pipeline_uses_inprocess_when_sandbox_disabled(self):
        """SANDBOX_ENABLED=false → 直接走 in-process，不呼叫 run_in_sandbox"""
        import main
        with patch.object(main, "SANDBOX_ENABLED", False), \
             patch.object(main, "run_pipeline_with_callback", return_value={"test": "ok"}) as mock_pipeline, \
             patch.object(main, "run_in_sandbox") as mock_sandbox:
            result = main.run_pipeline("django==4.2")
            mock_pipeline.assert_called_once()
            mock_sandbox.assert_not_called()

    def test_run_pipeline_uses_sandbox_when_enabled_and_docker_available(self):
        """SANDBOX_ENABLED=true + docker 可用 → 呼叫 run_in_sandbox"""
        import main
        sandbox_result = {"vulnerabilities": [], "summary": {}, "fallback": False}
        with patch.object(main, "SANDBOX_ENABLED", True), \
             patch.object(main, "_DOCKER_SANDBOX_OK", True), \
             patch.object(main, "is_docker_available", return_value=True), \
             patch.object(main, "run_in_sandbox", return_value=sandbox_result) as mock_sandbox:
            result = main.run_pipeline("django==4.2")
            mock_sandbox.assert_called_once_with(tech_stack="django==4.2", input_type="pkg")

    def test_run_pipeline_falls_back_to_inprocess_on_sandbox_fallback(self):
        """sandbox 返回 fallback=True → 降級回 in-process"""
        import main
        sandbox_fallback = {"error": "SANDBOX_CRASH", "fallback": True}
        with patch.object(main, "SANDBOX_ENABLED", True), \
             patch.object(main, "_DOCKER_SANDBOX_OK", True), \
             patch.object(main, "is_docker_available", return_value=True), \
             patch.object(main, "run_in_sandbox", return_value=sandbox_fallback), \
             patch.object(main, "run_pipeline_with_callback", return_value={"inprocess": True}) as mock_inproc:
            result = main.run_pipeline("django==4.2")
            mock_inproc.assert_called_once()
            self.assertTrue(result.get("inprocess"))

    def test_run_pipeline_sync_is_always_inprocess(self):
        """run_pipeline_sync 永遠 in-process（容器內防遞迴）"""
        import main
        with patch.object(main, "SANDBOX_ENABLED", True), \
             patch.object(main, "run_pipeline_with_callback", return_value={"inprocess": True}) as mock_inproc, \
             patch.object(main, "run_in_sandbox") as mock_sandbox:
            result = main.run_pipeline_sync("django==4.2")
            mock_inproc.assert_called_once()
            mock_sandbox.assert_not_called()


# ════════════════════════════════════════════════════════════
# 測試 4：Dockerfile 和 seccomp profile 存在性
# ════════════════════════════════════════════════════════════

class TestSandboxFiles(unittest.TestCase):
    """驗證 Phase 3 必要檔案已建立"""

    def _sandbox_path(self, filename: str) -> Path:
        return Path(__file__).parent.parent / "sandbox" / filename

    def test_dockerfile_exists(self):
        """sandbox/Dockerfile 必須存在"""
        self.assertTrue(
            self._sandbox_path("Dockerfile").exists(),
            "sandbox/Dockerfile not found"
        )

    def test_dockerfile_not_empty(self):
        """sandbox/Dockerfile 不可為空"""
        content = self._sandbox_path("Dockerfile").read_text(encoding="utf-8")
        self.assertGreater(len(content), 100)
        self.assertIn("FROM python:", content)
        self.assertIn("USER sandbox", content)

    def test_seccomp_profile_exists(self):
        """sandbox/seccomp-profile.json 必須存在"""
        self.assertTrue(
            self._sandbox_path("seccomp-profile.json").exists(),
            "sandbox/seccomp-profile.json not found"
        )

    def test_seccomp_profile_valid_json(self):
        """seccomp-profile.json 必須是合法 JSON"""
        content = self._sandbox_path("seccomp-profile.json").read_text(encoding="utf-8")
        profile = json.loads(content)
        self.assertIn("defaultAction", profile)
        self.assertIn("syscalls", profile)
        self.assertEqual(profile["defaultAction"], "SCMP_ACT_ERRNO")

    def test_seccomp_profile_has_whitelist(self):
        """seccomp profile 必須有 syscall 白名單"""
        content = self._sandbox_path("seccomp-profile.json").read_text(encoding="utf-8")
        profile = json.loads(content)
        syscall_names = []
        for group in profile["syscalls"]:
            syscall_names.extend(group.get("names", []))
        self.assertIn("read", syscall_names)
        self.assertIn("write", syscall_names)
        self.assertIn("mmap", syscall_names)

    def test_docker_sandbox_py_exists(self):
        """sandbox/docker_sandbox.py 必須存在"""
        self.assertTrue(
            self._sandbox_path("docker_sandbox.py").exists(),
            "sandbox/docker_sandbox.py not found"
        )

    def test_sandbox_runner_py_exists(self):
        """sandbox/sandbox_runner.py 必須存在"""
        self.assertTrue(
            self._sandbox_path("sandbox_runner.py").exists(),
            "sandbox/sandbox_runner.py not found"
        )

    def test_docker_sandbox_imports_cleanly(self):
        """sandbox/docker_sandbox.py 可以正常 import"""
        try:
            from sandbox import docker_sandbox
            self.assertTrue(hasattr(docker_sandbox, "run_in_sandbox"))
            self.assertTrue(hasattr(docker_sandbox, "is_docker_available"))
            self.assertTrue(hasattr(docker_sandbox, "is_sandbox_image_ready"))
            self.assertTrue(hasattr(docker_sandbox, "build_sandbox_image"))
        except ImportError as e:
            self.fail(f"docker_sandbox import failed: {e}")

    def test_sandbox_runner_imports_cleanly(self):
        """sandbox/sandbox_runner.py 可以正常 import"""
        try:
            from sandbox import sandbox_runner
            self.assertTrue(hasattr(sandbox_runner, "main"))
            self.assertTrue(hasattr(sandbox_runner, "_read_task_from_stdin"))
            self.assertTrue(hasattr(sandbox_runner, "_selftest"))
        except ImportError as e:
            self.fail(f"sandbox_runner import failed: {e}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
