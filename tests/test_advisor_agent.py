"""
tests/test_advisor_agent.py
===========================
Advisor Agent 單元測試 — 不需要 LLM，只測 Harness 保障層和輸出格式

執行：
    .venv\\Scripts\\python.exe -m pytest tests/test_advisor_agent.py -v
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.advisor import (
    _build_fallback_output,
    _extract_json_from_output,
    _harness_ensure_commands,
    _harness_validate_risk_score,
    _harness_validate_schema,
    create_advisor_agent,
)

# ══════════════════════════════════════════════════════════════
# 測試資料
# ══════════════════════════════════════════════════════════════

SAMPLE_SCOUT_OUTPUT = {
    "scan_id": "scan_20260401_001",
    "vulnerabilities": [
        {
            "cve_id": "CVE-2024-42005",
            "package": "django",
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "description": "SQL injection via crafted JSON field",
            "is_new": True,
        },
        {
            "cve_id": "CVE-2024-41991",
            "package": "django",
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "DoS via urlize",
            "is_new": True,
        },
        {
            "cve_id": "CVE-2023-46136",
            "package": "redis",
            "cvss_score": 5.3,
            "severity": "MEDIUM",
            "description": "ACL bypass",
            "is_new": False,
        },
    ],
    "summary": {"total": 3, "critical": 1, "high": 1, "medium": 1, "low": 0},
}

VALID_ADVISOR_OUTPUT = {
    "executive_summary": "Critical vulnerability detected. Immediate action required.",
    "actions": {
        "urgent": [
            {
                "cve_id": "CVE-2024-42005",
                "package": "django",
                "severity": "CRITICAL",
                "action": "Upgrade Django to 4.2.15+",
                "command": "pip install django>=4.2.15",
                "reason": "CVSS 9.8 CRITICAL",
                "is_repeated": False,
            }
        ],
        "important": [
            {
                "cve_id": "CVE-2024-41991",
                "package": "django",
                "severity": "HIGH",
                "action": "Upgrade Django",
                "reason": "CVSS 7.5 HIGH",
            }
        ],
        "resolved": [],
    },
    "risk_score": 75,
    "risk_trend": "+5",
    "scan_count": 1,
    "generated_at": "2026-04-01T10:00:00Z",
}


# ══════════════════════════════════════════════════════════════
# Agent 建立測試
# ══════════════════════════════════════════════════════════════

class TestAdvisorAgentCreation:
    """Advisor Agent 建立測試"""

    def test_agent_has_correct_role(self):
        """Agent 角色必須包含 Advisor"""
        agent = create_advisor_agent()
        assert "advisor" in agent.role.lower() or "裁決" in agent.role

    def test_agent_has_memory_tools(self):
        """Agent 必須具備 read_memory 和 write_memory"""
        agent = create_advisor_agent()
        tool_names = [t.name for t in agent.tools]
        assert "read_memory" in tool_names
        assert "write_memory" in tool_names

    def test_agent_has_no_nvd_otx_tools(self):
        """Advisor 不需要直接查詢 NVD/OTX"""
        agent = create_advisor_agent()
        tool_names = [t.name for t in agent.tools]
        assert "search_nvd" not in tool_names
        assert "search_otx" not in tool_names

    def test_agent_max_iter(self):
        """max_iter 必須 <= 15（防止無限迴圈）"""
        agent = create_advisor_agent()
        assert agent.max_iter <= 15

    def test_agent_no_delegation(self):
        """Advisor 不應允許委派（防止角色擴散）"""
        agent = create_advisor_agent()
        assert agent.allow_delegation is False

    def test_constitution_in_backstory(self):
        """系統憲法必須嵌入 backstory"""
        agent = create_advisor_agent()
        assert "ThreatHunter Constitution" in agent.backstory

    def test_json_schema_in_backstory(self):
        """輸出 JSON Schema 規格必須嵌入 backstory"""
        agent = create_advisor_agent()
        assert "executive_summary" in agent.backstory
        assert "risk_score" in agent.backstory


# ══════════════════════════════════════════════════════════════
# JSON 提取測試
# ══════════════════════════════════════════════════════════════

class TestJsonExtraction:
    """LLM 輸出 JSON 提取測試"""

    def test_pure_json(self):
        """純 JSON 字串直接解析"""
        raw = json.dumps(VALID_ADVISOR_OUTPUT)
        result = _extract_json_from_output(raw)
        assert result["risk_score"] == 75

    def test_markdown_wrapped_json(self):
        """Markdown code block 包裝的 JSON"""
        raw = f"Here is the report:\n```json\n{json.dumps(VALID_ADVISOR_OUTPUT)}\n```"
        result = _extract_json_from_output(raw)
        assert result["risk_score"] == 75

    def test_markdown_no_language_tag(self):
        """無語言標記的 ``` 包裝"""
        raw = f"```\n{json.dumps(VALID_ADVISOR_OUTPUT)}\n```"
        result = _extract_json_from_output(raw)
        assert result["risk_score"] == 75

    def test_json_in_text(self):
        """JSON 嵌在文字中"""
        raw = f"The output is: {json.dumps(VALID_ADVISOR_OUTPUT)} Thank you."
        result = _extract_json_from_output(raw)
        assert result["risk_score"] == 75

    def test_invalid_returns_empty_dict(self):
        """無效輸出回傳空 dict"""
        result = _extract_json_from_output("This is not JSON at all.")
        assert result == {}

    def test_empty_string(self):
        """空字串回傳空 dict"""
        result = _extract_json_from_output("")
        assert result == {}


# ══════════════════════════════════════════════════════════════
# Fallback 輸出建立測試
# ══════════════════════════════════════════════════════════════

class TestFallbackOutput:
    """Harness Layer 1：降級輸出建立測試"""

    def test_fallback_critical_goes_urgent(self):
        """CRITICAL 漏洞必須放在 urgent"""
        output = _build_fallback_output(SAMPLE_SCOUT_OUTPUT)
        urgent_ids = [v["cve_id"] for v in output["actions"]["urgent"]]
        assert "CVE-2024-42005" in urgent_ids

    def test_fallback_high_goes_important(self):
        """HIGH 漏洞必須放在 important"""
        output = _build_fallback_output(SAMPLE_SCOUT_OUTPUT)
        important_ids = [v["cve_id"] for v in output["actions"]["important"]]
        assert "CVE-2024-41991" in important_ids

    def test_fallback_urgent_has_command(self):
        """URGENT 項目必須有 command 欄位"""
        output = _build_fallback_output(SAMPLE_SCOUT_OUTPUT)
        for item in output["actions"]["urgent"]:
            assert "command" in item
            assert len(item["command"]) > 0

    def test_fallback_risk_score_in_range(self):
        """risk_score 必須在 0-100"""
        output = _build_fallback_output(SAMPLE_SCOUT_OUTPUT)
        assert 0 <= output["risk_score"] <= 100

    def test_fallback_has_executive_summary(self):
        """必須有 executive_summary"""
        output = _build_fallback_output(SAMPLE_SCOUT_OUTPUT)
        assert "executive_summary" in output
        assert len(output["executive_summary"]) > 0

    def test_fallback_empty_vulnerabilities(self):
        """空漏洞清單不崩潰"""
        output = _build_fallback_output({"vulnerabilities": []})
        assert output["risk_score"] == 0
        assert output["actions"]["urgent"] == []

    def test_fallback_has_generated_at(self):
        """必須有 generated_at 時間戳"""
        output = _build_fallback_output(SAMPLE_SCOUT_OUTPUT)
        assert "generated_at" in output


# ══════════════════════════════════════════════════════════════
# Harness 驗證層測試
# ══════════════════════════════════════════════════════════════

class TestHarnessValidation:
    """Harness 保障層測試"""

    def test_schema_valid_output_no_errors(self):
        """合法輸出不回傳錯誤"""
        errors = _harness_validate_schema(VALID_ADVISOR_OUTPUT)
        assert errors == []

    def test_schema_missing_executive_summary(self):
        """缺少 executive_summary 回傳錯誤"""
        bad = {k: v for k, v in VALID_ADVISOR_OUTPUT.items() if k != "executive_summary"}
        errors = _harness_validate_schema(bad)
        assert any("executive_summary" in e for e in errors)

    def test_schema_missing_actions(self):
        """缺少 actions 回傳錯誤"""
        bad = {k: v for k, v in VALID_ADVISOR_OUTPUT.items() if k != "actions"}
        errors = _harness_validate_schema(bad)
        assert any("actions" in e for e in errors)

    def test_schema_missing_risk_score(self):
        """缺少 risk_score 回傳錯誤"""
        bad = {k: v for k, v in VALID_ADVISOR_OUTPUT.items() if k != "risk_score"}
        errors = _harness_validate_schema(bad)
        assert any("risk_score" in e for e in errors)

    def test_risk_score_clamp_over_100(self):
        """risk_score > 100 被修正為 100"""
        output = {"risk_score": 999}
        _harness_validate_risk_score(output)
        assert output["risk_score"] == 100

    def test_risk_score_clamp_negative(self):
        """risk_score < 0 被修正為 0"""
        output = {"risk_score": -5}
        _harness_validate_risk_score(output)
        assert output["risk_score"] == 0

    def test_risk_score_valid_unchanged(self):
        """合法 risk_score 不被修改"""
        output = {"risk_score": 75}
        _harness_validate_risk_score(output)
        assert output["risk_score"] == 75

    def test_ensure_commands_adds_missing(self):
        """URGENT 缺少 command 時自動補全"""
        output = {
            "actions": {
                "urgent": [
                    {"cve_id": "CVE-2024-42005", "package": "django"}
                ]
            }
        }
        _harness_ensure_commands(output)
        assert "command" in output["actions"]["urgent"][0]
        assert "django" in output["actions"]["urgent"][0]["command"]

    def test_ensure_commands_existing_unchanged(self):
        """URGENT 已有 command 不覆蓋"""
        output = {
            "actions": {
                "urgent": [
                    {
                        "cve_id": "CVE-2024-42005",
                        "package": "django",
                        "command": "pip install django==4.2.15",
                    }
                ]
            }
        }
        _harness_ensure_commands(output)
        assert output["actions"]["urgent"][0]["command"] == "pip install django==4.2.15"

    def test_ensure_commands_no_urgent(self):
        """無 URGENT 時不崩潰"""
        output = {"actions": {"urgent": [], "important": [], "resolved": []}}
        _harness_ensure_commands(output)  # 不拋出例外
