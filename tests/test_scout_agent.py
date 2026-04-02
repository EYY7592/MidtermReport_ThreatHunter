# tests/test_scout_agent.py
# Scout Agent 整合測試 — Day 2 需要 LLM
#
# 執行：
#   .venv\Scripts\python.exe -m pytest tests/test_scout_agent.py -v
#
# 前提：
#   1. 設定環境變數 OPENROUTER_API_KEY 或 LLM_PROVIDER
#   2. NVD API 可用（或有離線快取）
#
# 注意：
#   這些測試會實際呼叫 LLM（可能耗時 30-120 秒）
#   標記 @pytest.mark.llm，可跳過：pytest -m "not llm"

import json
import os
import re
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ══════════════════════════════════════════════════════════════
# 非 LLM 測試（單元測試，始終可執行）
# ══════════════════════════════════════════════════════════════

class TestScoutAgentCreation:
    """Scout Agent 建立測試（不需要 LLM 呼叫）"""

    def test_agent_creation_succeeds(self):
        """Agent 建立不會 crash"""
        from agents.scout import create_scout_agent
        agent = create_scout_agent()
        assert agent is not None

    def test_agent_has_correct_role(self):
        from agents.scout import create_scout_agent
        agent = create_scout_agent()
        assert "Scout" in agent.role or "偵察" in agent.role

    def test_agent_has_all_tools(self):
        """Agent 必須掛載 5 個 Tool"""
        from agents.scout import create_scout_agent
        agent = create_scout_agent()
        tool_names = {t.name for t in agent.tools}
        expected = {"search_nvd", "search_otx", "read_memory", "write_memory", "history_search"}
        assert expected == tool_names, f"Missing tools: {expected - tool_names}"

    def test_agent_max_iter(self):
        """max_iter 必須是 15（Harness Constraints）"""
        from agents.scout import create_scout_agent
        agent = create_scout_agent()
        assert agent.max_iter == 15

    def test_agent_verbose(self):
        """verbose 必須開啟（Harness Observability）"""
        from agents.scout import create_scout_agent
        agent = create_scout_agent()
        assert agent.verbose is True

    def test_agent_no_delegation(self):
        """Scout 不委派工作"""
        from agents.scout import create_scout_agent
        agent = create_scout_agent()
        assert agent.allow_delegation is False

    def test_backstory_contains_constitution(self):
        """backstory 必須包含系統憲法"""
        from agents.scout import create_scout_agent
        agent = create_scout_agent()
        assert "系統憲法" in agent.backstory
        assert "不可自行編造" in agent.backstory or "不可編造" in agent.backstory

    def test_backstory_contains_skill(self):
        """backstory 必須包含 Skill SOP"""
        from agents.scout import create_scout_agent
        agent = create_scout_agent()
        # 檢查 Skill 的關鍵步驟
        assert "read_memory" in agent.backstory
        assert "search_nvd" in agent.backstory
        assert "write_memory" in agent.backstory

    def test_skill_file_exists(self):
        """skills/threat_intel.md 必須存在"""
        from agents.scout import SKILL_PATH
        assert os.path.exists(SKILL_PATH), f"Skill file not found: {SKILL_PATH}"

    def test_skill_file_not_empty(self):
        """skills/threat_intel.md 不可為空"""
        from agents.scout import SKILL_PATH
        with open(SKILL_PATH, "r", encoding="utf-8") as f:
            content = f.read().strip()
        assert len(content) > 100, "Skill file is too short"


class TestScoutTaskCreation:
    """Scout Task 建立測試"""

    def test_task_creation(self):
        from agents.scout import create_scout_agent, create_scout_task
        agent = create_scout_agent()
        task = create_scout_task(agent, "Django 4.2, Redis 7.0")
        assert task is not None
        assert "Django 4.2" in task.description
        assert "Redis 7.0" in task.description

    def test_task_mentions_required_steps(self):
        from agents.scout import create_scout_agent, create_scout_task
        agent = create_scout_agent()
        task = create_scout_task(agent, "Django 4.2")
        desc = task.description
        assert "read_memory" in desc
        assert "search_nvd" in desc
        assert "write_memory" in desc


# ══════════════════════════════════════════════════════════════
# LLM 整合測試（需要 LLM + API）
# ══════════════════════════════════════════════════════════════

@pytest.mark.llm
class TestScoutAgentExecution:
    """
    Scout Agent 完整執行測試。
    需要 LLM（OPENROUTER_API_KEY）+ NVD API。
    執行：pytest tests/test_scout_agent.py -m llm -v --timeout=180
    耗時約 30-120 秒。
    """

    @pytest.fixture(autouse=True)
    def check_llm_available(self):
        """確認 LLM 可用"""
        api_key = os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            pytest.skip("OPENROUTER_API_KEY not set — LLM tests skipped")

    def test_full_pipeline_single_package(self):
        """單一套件完整 Pipeline 測試"""
        from agents.scout import create_scout_agent, create_scout_task
        from crewai import Crew, Process

        agent = create_scout_agent()
        task = create_scout_task(agent, "Django 4.2")
        crew = Crew(agents=[agent], tasks=[task], process=Process.sequential)

        result = crew.kickoff()
        result_str = str(result).strip()

        # 嘗試解析 JSON（可能有 markdown 包裝）
        json_str = result_str
        if "```json" in json_str:
            json_str = json_str.split("```json")[1].split("```")[0].strip()
        elif "```" in json_str:
            json_str = json_str.split("```")[1].split("```")[0].strip()

        output = json.loads(json_str)

        # Sentinel Layer 1: Schema Validation
        assert "scan_id" in output
        assert "timestamp" in output
        assert "tech_stack" in output
        assert "vulnerabilities" in output
        assert "summary" in output

        # 驗證 vulnerabilities
        for vuln in output["vulnerabilities"]:
            assert re.match(r"^CVE-\d{4}-\d{4,}$", vuln["cve_id"]), \
                f"Invalid CVE: {vuln['cve_id']}"
            assert 0.0 <= vuln["cvss_score"] <= 10.0
            assert vuln["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            assert isinstance(vuln["is_new"], bool)

        # 驗證 summary
        summary = output["summary"]
        assert summary["total"] == len(output["vulnerabilities"])
        new_count = sum(1 for v in output["vulnerabilities"] if v["is_new"])
        assert summary["new_since_last_scan"] == new_count

    def test_full_pipeline_multiple_packages(self):
        """多套件 Pipeline 測試"""
        from agents.scout import create_scout_agent, create_scout_task
        from crewai import Crew, Process

        agent = create_scout_agent()
        task = create_scout_task(agent, "Django 4.2, Redis 7.0")
        crew = Crew(agents=[agent], tasks=[task], process=Process.sequential)

        result = crew.kickoff()
        result_str = str(result).strip()

        json_str = result_str
        if "```json" in json_str:
            json_str = json_str.split("```json")[1].split("```")[0].strip()
        elif "```" in json_str:
            json_str = json_str.split("```")[1].split("```")[0].strip()

        output = json.loads(json_str)
        assert output["summary"]["total"] >= 0
        # 應該有來自兩個套件的 CVE
        packages = {v["package"] for v in output["vulnerabilities"]}
        # 至少有一個套件有結果
        assert len(packages) >= 1
