"""
test_pipeline_integration.py
=============================
端到端 Pipeline 整合測試

測試範圍：
  1. 完整 Pipeline 輸出結構驗證
  2. 每個 Stage 失敗時的降級行為
  3. Critic 開關的行為差異
  4. pipeline_meta 欄位完整性

注意：本測試不依賴外部 API 或 LLM，使用 mock 方式模擬各 Stage 輸出。
"""

import json
import os
import sys
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

import pytest

# 確保專案根目錄在 sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


# ======================================================================
# 測試用 Mock 資料（符合 data_contracts.md 契約）
# ======================================================================

MOCK_SCOUT_OUTPUT = {
    "scan_id": "scan_test_001",
    "timestamp": "2026-04-06T10:00:00Z",
    "tech_stack": ["django 4.2", "redis 7.0"],
    "vulnerabilities": [
        {
            "cve_id": "CVE-2024-42005",
            "package": "django",
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "description": "SQL injection in QuerySet.values()",
            "is_new": True,
        },
        {
            "cve_id": "CVE-2023-45678",
            "package": "redis",
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "Buffer overflow in Redis cluster",
            "is_new": False,
        },
    ],
    "summary": {
        "total": 2,
        "new_since_last_scan": 1,
        "critical": 1,
        "high": 1,
        "medium": 0,
        "low": 0,
    },
}

MOCK_ANALYST_OUTPUT = {
    "scan_id": "scan_test_001",
    "risk_score": 85,
    "risk_trend": "+10",
    "analysis": [
        {
            "cve_id": "CVE-2024-42005",
            "original_cvss": 9.8,
            "adjusted_risk": "CRITICAL",
            "in_cisa_kev": True,
            "exploit_available": True,
            "chain_risk": {
                "is_chain": True,
                "chain_with": ["CVE-2023-45678"],
                "chain_description": "SQL injection + Redis buffer overflow = RCE chain",
                "confidence": "HIGH",
            },
            "reasoning": "In CISA KEV + public exploit + chains with Redis vulnerability",
        },
        {
            "cve_id": "CVE-2023-45678",
            "original_cvss": 7.5,
            "adjusted_risk": "HIGH",
            "in_cisa_kev": False,
            "exploit_available": False,
            "chain_risk": {
                "is_chain": True,
                "chain_with": ["CVE-2024-42005"],
                "chain_description": "Part of SQLi -> Redis RCE chain",
                "confidence": "MEDIUM",
            },
            "reasoning": "Part of attack chain with Django SQL injection",
        },
    ],
}

MOCK_CRITIC_OUTPUT = {
    "debate_rounds": 2,
    "challenges": ["Challenge: Redis exposure prerequisite not fully verified."],
    "scorecard": {
        "evidence": 0.85,
        "chain_completeness": 0.80,
        "critique_quality": 0.75,
        "defense_quality": 0.70,
        "calibration": 0.90,
    },
    "weighted_score": 80.5,
    "verdict": "MAINTAIN",
    "reasoning": "Evidence is strong, chain analysis is well-supported.",
    "generated_at": "2026-04-06T10:05:00Z",
}

MOCK_ADVISOR_OUTPUT = {
    "executive_summary": "1 actively exploited chain detected. Immediate action required.",
    "actions": {
        "urgent": [
            {
                "cve_id": "CVE-2024-42005",
                "package": "django",
                "severity": "CRITICAL",
                "action": "Update Django to latest patched version immediately.",
                "command": "pip install --upgrade django",
                "reason": "In CISA KEV with public exploit, part of RCE chain.",
                "is_repeated": False,
            },
        ],
        "important": [
            {
                "cve_id": "CVE-2023-45678",
                "package": "redis",
                "severity": "HIGH",
                "action": "Update Redis and verify network exposure settings.",
                "reason": "Part of attack chain with Django SQL injection.",
            },
        ],
        "resolved": [],
    },
    "risk_score": 85,
    "risk_trend": "+10",
    "scan_count": 1,
    "generated_at": "2026-04-06T10:06:00Z",
}

MOCK_CRITIC_SKIPPED = {
    "debate_rounds": 0,
    "challenges": [],
    "scorecard": {
        "evidence": 1.0,
        "chain_completeness": 1.0,
        "critique_quality": 1.0,
        "defense_quality": 1.0,
        "calibration": 1.0,
    },
    "weighted_score": 100.0,
    "verdict": "SKIPPED",
    "reasoning": "ENABLE_CRITIC=false",
    "generated_at": "2026-04-06T10:05:00Z",
    "_harness_skipped": True,
}


# ======================================================================
# Helper: Mock 各 Stage 函式
# ======================================================================


def _mock_stage_scout(*args, **kwargs):
    return MOCK_SCOUT_OUTPUT, MagicMock(steps=[{"duration_ms": 100}])


def _mock_stage_analyst(*args, **kwargs):
    return MOCK_ANALYST_OUTPUT, MagicMock(steps=[{"duration_ms": 200}])


def _mock_stage_critic(*args, **kwargs):
    return MOCK_CRITIC_OUTPUT, MagicMock(steps=[{"duration_ms": 150}])


def _mock_stage_critic_skipped(*args, **kwargs):
    return MOCK_CRITIC_SKIPPED, MagicMock(steps=[{"duration_ms": 0}])


def _mock_stage_advisor(*args, **kwargs):
    return MOCK_ADVISOR_OUTPUT, MagicMock(steps=[{"duration_ms": 120}])


def _mock_stage_orchestrator(*args, **kwargs):
    """Mock Orchestrator Stage 回傳路徑 B（預設）"""
    from agents.orchestrator import OrchestrationContext, ScanPath
    ctx = OrchestrationContext()
    ctx.scan_path = ScanPath.FULL_CODE
    task_plan = {
        "path": "B",
        "parallel_layer1": [],  # 測試時跳過 Layer 1 並行
        "agents_to_run": ["scout", "analyst", "debate", "judge"],
    }
    from main import StepLogger
    sl = StepLogger("orchestrator")
    sl.log("COMPLETE", "SUCCESS", "path=B", 10)
    return ctx, task_plan, sl


def _mock_degraded_scout(*args, **kwargs):
    """Scout 降級的 Mock（模組層級函式）"""
    return {
        "scan_id": "scan_degraded_001",
        "vulnerabilities": [],
        "summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        "_degraded": True,
        "_error": "NVD API timeout",
    }, MagicMock(steps=[{"duration_ms": 50}])


def _mock_degraded_analyst(*args, **kwargs):
    """Analyst 降級的 Mock（模組層級函式）"""
    return {
        "scan_id": "scan_test_001",
        "risk_score": 50,
        "risk_trend": "+0",
        "analysis": [],
        "_degraded": True,
        "_error": "LLM timeout",
    }, MagicMock(steps=[{"duration_ms": 30}])


# ======================================================================
# 測試 1：完整 Pipeline 輸出結構
# ======================================================================


class TestPipelineOutputSchema:
    """測試最終輸出符合 data_contracts.md 契約"""

    @patch("main.stage_scout", _mock_stage_scout)
    @patch("main.stage_analyst", _mock_stage_analyst)
    @patch("main.stage_critic", _mock_stage_critic)
    @patch("main.stage_advisor", _mock_stage_advisor)
    def test_full_pipeline_has_pipeline_meta(self):
        """完整管線必須包含 pipeline_meta 欄位"""
        from main import run_pipeline

        result = run_pipeline("Django 4.2, Redis 7.0")
        assert "pipeline_meta" in result

    @patch("main.stage_scout", _mock_stage_scout)
    @patch("main.stage_analyst", _mock_stage_analyst)
    @patch("main.stage_critic", _mock_stage_critic)
    @patch("main.stage_advisor", _mock_stage_advisor)
    def test_pipeline_meta_has_required_fields(self):
        """pipeline_meta 必須包含所有必要欄位"""
        from main import run_pipeline

        result = run_pipeline("Django 4.2, Redis 7.0")
        meta = result["pipeline_meta"]

        required_fields = [
            "pipeline_version",
            "tech_stack",
            "stages_completed",
            "stages_detail",
            "enable_critic",
            "critic_verdict",
            "critic_score",
            "duration_seconds",
            "degradation",
            "generated_at",
        ]
        for field in required_fields:
            assert field in meta, f"pipeline_meta 缺少欄位: {field}"

    @patch("main.stage_scout", _mock_stage_scout)
    @patch("main.stage_analyst", _mock_stage_analyst)
    @patch("main.stage_critic", _mock_stage_critic)
    @patch("main.stage_advisor", _mock_stage_advisor)
    def test_pipeline_meta_stages_detail(self):
        """stages_detail 必須包含 4 個 Stage 的詳細資訊"""
        from main import run_pipeline

        result = run_pipeline("Django 4.2, Redis 7.0")
        detail = result["pipeline_meta"]["stages_detail"]

        for stage in ["scout", "analyst", "critic", "advisor"]:
            assert stage in detail, f"stages_detail 缺少: {stage}"
            assert "status" in detail[stage]

    @patch("main.stage_orchestrator", _mock_stage_orchestrator)
    @patch("main.stage_scout", _mock_stage_scout)
    @patch("main.stage_analyst", _mock_stage_analyst)
    @patch("main.stage_critic", _mock_stage_critic)
    @patch("main.stage_advisor", _mock_stage_advisor)
    def test_pipeline_meta_stages_completed_count(self):
        """stages_completed 必須 >= 5（v3.1 含 orchestrator）"""
        from main import run_pipeline

        result = run_pipeline("Django 4.2, Redis 7.0")
        # v3.1: orchestrator + scout + analyst + critic + advisor = 5
        assert result["pipeline_meta"]["stages_completed"] >= 5

    @patch("main.stage_scout", _mock_stage_scout)
    @patch("main.stage_analyst", _mock_stage_analyst)
    @patch("main.stage_critic", _mock_stage_critic)
    @patch("main.stage_advisor", _mock_stage_advisor)
    def test_advisor_output_has_required_fields(self):
        """Advisor 輸出必須包含 executive_summary, actions, risk_score"""
        from main import run_pipeline

        result = run_pipeline("Django 4.2, Redis 7.0")

        assert "executive_summary" in result
        assert "actions" in result
        assert "risk_score" in result
        assert "risk_trend" in result
        assert "generated_at" in result

    @patch("main.stage_scout", _mock_stage_scout)
    @patch("main.stage_analyst", _mock_stage_analyst)
    @patch("main.stage_critic", _mock_stage_critic)
    @patch("main.stage_advisor", _mock_stage_advisor)
    def test_actions_has_three_sections(self):
        """actions 必須包含 urgent, important, resolved 三個區段"""
        from main import run_pipeline

        result = run_pipeline("Django 4.2, Redis 7.0")
        actions = result["actions"]

        assert "urgent" in actions
        assert "important" in actions
        assert "resolved" in actions
        assert isinstance(actions["urgent"], list)
        assert isinstance(actions["important"], list)
        assert isinstance(actions["resolved"], list)

    @patch("main.stage_scout", _mock_stage_scout)
    @patch("main.stage_analyst", _mock_stage_analyst)
    @patch("main.stage_critic", _mock_stage_critic)
    @patch("main.stage_advisor", _mock_stage_advisor)
    def test_urgent_items_have_command(self):
        """每個 URGENT 項目必須附帶 command 欄位"""
        from main import run_pipeline

        result = run_pipeline("Django 4.2, Redis 7.0")

        for item in result["actions"]["urgent"]:
            assert "command" in item, f"URGENT {item.get('cve_id')} 缺少 command"
            assert "cve_id" in item
            assert "action" in item


# ======================================================================
# 測試 2：Critic 開關行為
# ======================================================================


class TestCriticToggle:
    """測試 ENABLE_CRITIC 開關的行為差異"""

    @patch("main.ENABLE_CRITIC", False)
    @patch("main.stage_scout", _mock_stage_scout)
    @patch("main.stage_analyst", _mock_stage_analyst)
    @patch("main.stage_critic", _mock_stage_critic_skipped)
    @patch("main.stage_advisor", _mock_stage_advisor)
    def test_critic_disabled_returns_skipped(self):
        """ENABLE_CRITIC=false 時，critic_verdict 應為 SKIPPED"""
        from main import run_pipeline

        result = run_pipeline("Django 4.2")
        meta = result["pipeline_meta"]

        assert meta["critic_verdict"] == "SKIPPED"
        assert meta["enable_critic"] is False

    @patch("main.ENABLE_CRITIC", True)
    @patch("main.stage_scout", _mock_stage_scout)
    @patch("main.stage_analyst", _mock_stage_analyst)
    @patch("main.stage_critic", _mock_stage_critic)
    @patch("main.stage_advisor", _mock_stage_advisor)
    def test_critic_enabled_returns_verdict(self):
        """ENABLE_CRITIC=true 時，critic_verdict 應為 MAINTAIN 或 DOWNGRADE"""
        from main import run_pipeline

        result = run_pipeline("Django 4.2")
        meta = result["pipeline_meta"]

        assert meta["critic_verdict"] in ("MAINTAIN", "DOWNGRADE")
        assert meta["enable_critic"] is True
        assert meta["critic_score"] > 0


# ======================================================================
# 測試 3：降級行為
# ======================================================================


class TestPipelineDegradation:
    """測試各 Stage 失敗時的降級行為"""

    def _mock_degraded_scout(self, *args, **kwargs):
        return {
            "scan_id": "scan_degraded_001",
            "vulnerabilities": [],
            "summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
            "_degraded": True,
            "_error": "NVD API timeout",
        }, MagicMock(steps=[{"duration_ms": 50}])

    @patch("main.stage_orchestrator", _mock_stage_orchestrator)
    @patch("main.stage_scout", _mock_degraded_scout)
    @patch("main.stage_analyst", _mock_stage_analyst)
    @patch("main.stage_critic", _mock_stage_critic_skipped)
    @patch("main.stage_advisor", _mock_stage_advisor)
    def test_pipeline_continues_after_scout_degraded(self):
        """Scout 降級時，管線仍應繼續執行"""
        from main import run_pipeline

        result = run_pipeline("Django 4.2")

        # 管線應該完成
        assert "pipeline_meta" in result
        # stages_completed v3.1 應 >= 5（orchestrator + 4 個主 stage）
        assert result["pipeline_meta"]["stages_completed"] >= 5
        # Scout 狀態應標記為 DEGRADED
        assert result["pipeline_meta"]["stages_detail"]["scout"]["status"] == "DEGRADED"

    def _mock_degraded_analyst(self, *args, **kwargs):
        return {
            "scan_id": "scan_test_001",
            "risk_score": 50,
            "risk_trend": "+0",
            "analysis": [],
            "_degraded": True,
            "_error": "LLM timeout",
        }, MagicMock(steps=[{"duration_ms": 30}])

    @patch("main.stage_orchestrator", _mock_stage_orchestrator)
    @patch("main.stage_scout", _mock_stage_scout)
    @patch("main.stage_analyst", _mock_degraded_analyst)
    @patch("main.stage_critic", _mock_stage_critic)
    @patch("main.stage_advisor", _mock_stage_advisor)
    def test_pipeline_continues_after_analyst_degraded(self):
        """Analyst 降級時，管線仍應繼續執行"""
        from main import run_pipeline

        result = run_pipeline("Django 4.2")

        assert (
            result["pipeline_meta"]["stages_detail"]["analyst"]["status"] == "DEGRADED"
        )
        # Critic 和 Advisor 仍應執行
        assert "critic" in result["pipeline_meta"]["stages_detail"]
        assert "advisor" in result["pipeline_meta"]["stages_detail"]


# ======================================================================
# 測試 4：StepLogger 整合
# ======================================================================


class TestStepLoggerIntegration:
    """測試 StepLogger 正確整合到 pipeline_meta"""

    @patch("main.stage_orchestrator", _mock_stage_orchestrator)
    @patch("main.stage_scout", _mock_stage_scout)
    @patch("main.stage_analyst", _mock_stage_analyst)
    @patch("main.stage_critic", _mock_stage_critic)
    @patch("main.stage_advisor", _mock_stage_advisor)
    def test_stages_detail_contains_all_stages(self):
        """stages_detail 必須包含 4 個主 Stage（v3.1 orchestrator 另外記錄）"""
        from main import run_pipeline

        result = run_pipeline("Django 4.2")
        detail = result["pipeline_meta"]["stages_detail"]

        # 必要的 4 個主 Stage 必須存在
        for stage in ["scout", "analyst", "critic", "advisor"]:
            assert stage in detail, f"stages_detail 缺少: {stage}"
        # v3.1 會額外包含 orchestrator
        assert "orchestrator" in detail

    @patch("main.stage_scout", _mock_stage_scout)
    @patch("main.stage_analyst", _mock_stage_analyst)
    @patch("main.stage_critic", _mock_stage_critic)
    @patch("main.stage_advisor", _mock_stage_advisor)
    def test_stages_detail_has_status(self):
        """每個 Stage 的 detail 必須有 status 欄位"""
        from main import run_pipeline

        result = run_pipeline("Django 4.2")
        detail = result["pipeline_meta"]["stages_detail"]

        for stage_name, stage_info in detail.items():
            assert "status" in stage_info, f"{stage_name} 缺少 status"
            assert stage_info["status"] in ("SUCCESS", "DEGRADED")

    @patch("main.stage_scout", _mock_stage_scout)
    @patch("main.stage_analyst", _mock_stage_analyst)
    @patch("main.stage_critic", _mock_stage_critic)
    @patch("main.stage_advisor", _mock_stage_advisor)
    def test_pipeline_version_is_3(self):
        """pipeline_version 應為 3.0（整合後版本）"""
        from main import run_pipeline

        result = run_pipeline("Django 4.2")
        assert result["pipeline_meta"]["pipeline_version"] == "3.1"


# ======================================================================
# 測試 5：模組匯入驗證
# ======================================================================


class TestModuleImports:
    """測試 agents 和 tools 模組的 __init__.py 匯出"""

    def test_agents_module_exports(self):
        """agents 模組應匙出所有 create_* 和 run_* 函式（含 v3.1 新增）"""
        import agents

        # v3.0 原有導出
        assert hasattr(agents, "create_scout_agent")
        assert hasattr(agents, "create_analyst_agent")
        assert hasattr(agents, "create_critic_agent")
        assert hasattr(agents, "create_advisor_agent")
        assert hasattr(agents, "run_scout_pipeline")
        assert hasattr(agents, "run_analyst_pipeline")
        assert hasattr(agents, "run_critic_pipeline")
        assert hasattr(agents, "run_advisor_pipeline")
        # v3.1 新增導出
        assert hasattr(agents, "build_security_guard_agent")
        assert hasattr(agents, "run_security_guard")
        assert hasattr(agents, "build_intel_fusion_agent")
        assert hasattr(agents, "run_intel_fusion")
        assert hasattr(agents, "calculate_composite_score")

    def test_tools_module_exports(self):
        """tools 模組應匯出所有 Tool 函式"""
        import tools

        assert hasattr(tools, "search_nvd")
        assert hasattr(tools, "search_otx")
        assert hasattr(tools, "check_cisa_kev")
        assert hasattr(tools, "search_exploits")
        assert hasattr(tools, "read_memory")
        assert hasattr(tools, "write_memory")
        assert hasattr(tools, "history_search")
