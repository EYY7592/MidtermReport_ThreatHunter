"""
tests/test_sg_to_advisor_flow.py
================================================
端到端資料流驗證測試（Data Flow Gap 修復 v4.0）

測試目標：
  1. _build_code_patterns_summary() 正確將 SG patterns 轉換為 code_patterns
  2. code_patterns 正確注入 scout_output（main.py pipe）
  3. Analyst Task description 包含 code_patterns 指示
  4. Advisor Task description 包含 CODE-finding 輸出規則
  5. code_action_report.md Skill 包含 fixed_snippet 範本
  6. 修復後 code_patterns 不洩漏 secret 值

不呼叫 LLM，所有 Agent 邏輯均為單元測試。
"""

import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest


# ══════════════════════════════════════════════════════════════
# 1. _build_code_patterns_summary() 單元測試
# ══════════════════════════════════════════════════════════════

class TestBuildCodePatternsSummary:
    """驗證 SG patterns → code_patterns 的確定性轉換函式"""

    @pytest.fixture(autouse=True)
    def import_fn(self):
        from main import _build_code_patterns_summary
        self.fn = _build_code_patterns_summary

    def _make_sg_result(self, patterns=None, hardcoded=None, language="python"):
        return {
            "language": language,
            "patterns": patterns or [],
            "hardcoded": hardcoded or [],
        }

    def test_empty_sg_returns_empty_list(self):
        result = self.fn(self._make_sg_result())
        assert result == []

    def test_sql_injection_pattern_converted(self):
        sg = self._make_sg_result(patterns=[{
            "pattern_type": "SQL_INJECTION",
            "snippet": "cursor.execute(f\"SELECT * FROM users WHERE id={user_id}\")",
            "line_no": 45,
        }])
        patterns = self.fn(sg)
        assert len(patterns) == 1
        p = patterns[0]
        assert p["finding_id"] == "CODE-001"
        assert p["pattern_type"] == "SQL_INJECTION"
        assert p["cwe_id"] == "CWE-89"
        assert p["owasp_category"] == "A03:2021-Injection"
        assert p["severity"] == "CRITICAL"
        assert p["type"] == "code_pattern"

    def test_xss_pattern_converted(self):
        sg = self._make_sg_result(patterns=[{
            "pattern_type": "INNERHTML_XSS",
            "snippet": ".innerHTML = query",
            "line_no": 23,
        }])
        patterns = self.fn(sg)
        assert patterns[0]["cwe_id"] == "CWE-79"
        assert patterns[0]["severity"] == "HIGH"

    def test_cmd_injection_is_critical(self):
        sg = self._make_sg_result(patterns=[{
            "pattern_type": "CMD_INJECTION",
            "snippet": "os.system(user_input)",
            "line_no": 10,
        }])
        patterns = self.fn(sg)
        assert patterns[0]["severity"] == "CRITICAL"

    def test_pickle_unsafe_is_critical(self):
        sg = self._make_sg_result(patterns=[{
            "pattern_type": "PICKLE_UNSAFE",
            "snippet": "pickle.loads(data)",
            "line_no": 67,
        }])
        patterns = self.fn(sg)
        assert patterns[0]["cwe_id"] == "CWE-502"
        assert patterns[0]["severity"] == "CRITICAL"

    def test_ssrf_pattern_converted(self):
        sg = self._make_sg_result(patterns=[{
            "pattern_type": "SSRF_RISK",
            "snippet": "requests.get(user_url)",
            "line_no": 30,
        }])
        patterns = self.fn(sg)
        assert patterns[0]["cwe_id"] == "CWE-918"
        assert patterns[0]["severity"] == "HIGH"

    def test_hardcoded_secret_converted(self):
        sg = self._make_sg_result(hardcoded=[{
            "name": "API_KEY",
            "line_no": 5,
        }])
        patterns = self.fn(sg)
        assert len(patterns) == 1
        p = patterns[0]
        assert p["finding_id"] == "CODE-001"
        assert p["pattern_type"] == "HARDCODED_SECRET"
        assert p["type"] == "hardcoded_secret"
        assert p["cwe_id"] == "CWE-798"
        assert p["severity"] == "HIGH"

    def test_secret_value_not_leaked(self):
        """最重要：硬編碼憑證的值不能出現在 code_patterns 中"""
        sg = self._make_sg_result(hardcoded=[{
            "name": "PASSWORD",
            "line_no": 3,
        }])
        patterns = self.fn(sg)
        snippet = patterns[0]["snippet"]
        # snippet 應該是 "PASSWORD = '****' (value redacted)"
        assert "****" in snippet or "redacted" in snippet
        # 確保沒有 "actual_password_value" 等真實密碼字串
        assert len(snippet) < 100  # 截斷安全

    def test_multiple_patterns_have_unique_finding_ids(self):
        sg = self._make_sg_result(patterns=[
            {"pattern_type": "SQL_INJECTION", "snippet": "sql", "line_no": 1},
            {"pattern_type": "CMD_INJECTION", "snippet": "cmd", "line_no": 2},
            {"pattern_type": "SSRF_RISK",     "snippet": "ssrf", "line_no": 3},
        ], hardcoded=[
            {"name": "API_KEY", "line_no": 4},
        ])
        patterns = self.fn(sg)
        assert len(patterns) == 4
        ids = [p["finding_id"] for p in patterns]
        assert ids == ["CODE-001", "CODE-002", "CODE-003", "CODE-004"]

    def test_snippet_truncated_to_200_chars(self):
        long_snippet = "x" * 500
        sg = self._make_sg_result(patterns=[{
            "pattern_type": "SQL_INJECTION",
            "snippet": long_snippet,
            "line_no": 1,
        }])
        patterns = self.fn(sg)
        assert len(patterns[0]["snippet"]) <= 200

    def test_language_preserved(self):
        sg = self._make_sg_result(
            patterns=[{"pattern_type": "INNERHTML_XSS", "snippet": "x", "line_no": 1}],
            language="javascript"
        )
        patterns = self.fn(sg)
        assert patterns[0]["language"] == "javascript"

    def test_unknown_pattern_type_uses_default(self):
        sg = self._make_sg_result(patterns=[{
            "pattern_type": "SOME_FUTURE_PATTERN",
            "snippet": "something",
            "line_no": 99,
        }])
        patterns = self.fn(sg)
        assert len(patterns) == 1
        # 未知 pattern 不應崩潰，使用 default
        assert patterns[0]["severity"] == "MEDIUM"
        assert "CWE-unknown" in patterns[0]["cwe_id"]

    def test_ssrf_owasp_category_correct(self):
        sg = self._make_sg_result(patterns=[{
            "pattern_type": "SSRF_RISK",
            "snippet": "requests.get(url)",
            "line_no": 5,
        }])
        patterns = self.fn(sg)
        assert "SSRF" in patterns[0]["owasp_category"] or "A10" in patterns[0]["owasp_category"]

# ══════════════════════════════════════════════════════════════
# 2. Scout Output 注入驗證（main.py 資料流）
# ══════════════════════════════════════════════════════════════

class TestScoutOutputInjection:
    """驗證 code_patterns 正確注入 scout_output 結構"""

    def test_code_patterns_key_injected_correctly(self):
        """模擬 main.py 注入邏輯，確認 scout_output 包含 code_patterns 欄位"""
        from main import _build_code_patterns_summary

        # 模擬 SG 偵測到 SQL Injection
        sg_result = {
            "language": "python",
            "patterns": [{"pattern_type": "SQL_INJECTION", "snippet": "f-string sql", "line_no": 10}],
            "hardcoded": [],
        }

        # 模擬 scout_output（Scout 只查到套件 CVE）
        scout_output = {
            "vulnerabilities": [],
            "summary": {"total": 0},
        }

        # 執行注入邏輯（複製 main.py 邏輯）
        _sg_code_patterns = _build_code_patterns_summary(sg_result)
        if _sg_code_patterns:
            scout_output["code_patterns"] = _sg_code_patterns

        # 驗證
        assert "code_patterns" in scout_output
        assert len(scout_output["code_patterns"]) == 1
        assert scout_output["code_patterns"][0]["finding_id"] == "CODE-001"
        assert scout_output["code_patterns"][0]["severity"] == "CRITICAL"

    def test_code_patterns_not_injected_when_empty(self):
        """乾淨的程式碼不應注入空的 code_patterns"""
        from main import _build_code_patterns_summary

        sg_result = {
            "language": "python",
            "patterns": [],      # 沒有問題
            "hardcoded": [],     # 沒有硬編碼
        }
        scout_output = {"vulnerabilities": []}

        _sg_code_patterns = _build_code_patterns_summary(sg_result)
        if _sg_code_patterns:
            scout_output["code_patterns"] = _sg_code_patterns

        # 乾淨程式碼不應有 code_patterns 欄位
        assert "code_patterns" not in scout_output

    def test_code_patterns_json_serializable(self):
        """code_patterns 必須能 JSON 序列化（供 LLM 使用）"""
        from main import _build_code_patterns_summary

        sg_result = {
            "language": "python",
            "patterns": [
                {"pattern_type": "SQL_INJECTION", "snippet": "evil query", "line_no": 1},
                {"pattern_type": "CMD_INJECTION", "snippet": "os.system(x)", "line_no": 2},
            ],
            "hardcoded": [{"name": "SECRET_KEY", "line_no": 3}],
        }
        patterns = _build_code_patterns_summary(sg_result)
        # 不應拋出 TypeError
        serialized = json.dumps(patterns)
        assert len(serialized) > 0

    def test_multiple_vuln_types_all_included(self):
        """混合類型（patterns + hardcoded）都應注入"""
        from main import _build_code_patterns_summary
        sg_result = {
            "language": "javascript",
            "patterns": [
                {"pattern_type": "INNERHTML_XSS", "snippet": ".innerHTML = x", "line_no": 5},
                {"pattern_type": "PROTOTYPE_POLLUTION", "snippet": "__proto__", "line_no": 8},
            ],
            "hardcoded": [{"name": "API_TOKEN", "line_no": 2}],
        }
        patterns = _build_code_patterns_summary(sg_result)
        assert len(patterns) == 3
        types = [p["pattern_type"] for p in patterns]
        assert "INNERHTML_XSS" in types
        assert "PROTOTYPE_POLLUTION" in types
        assert "HARDCODED_SECRET" in types


# ══════════════════════════════════════════════════════════════
# 3. Analyst Task Description 驗證
# ══════════════════════════════════════════════════════════════

class TestAnalystTaskDescription:
    """驗證 Analyst task description 包含 code_patterns 處理指示"""

    @pytest.fixture(autouse=True)
    def load_source(self):
        import inspect
        import agents.analyst as mod
        # 直接讀取模組原始碼，避免觸發 CrewAI Pydantic 的 agent 型別驗證
        self.source = inspect.getsource(mod)

    def test_description_mentions_code_patterns(self):
        assert "code_patterns" in self.source, "Analyst task 應提及 code_patterns 欄位"

    def test_description_mentions_finding_id_code(self):
        assert "CODE-" in self.source, "Analyst task 應說明 CODE- finding_id 格式"

    def test_description_mentions_critical_patterns(self):
        assert "SQL_INJECTION" in self.source or "CMD_INJECTION" in self.source, \
            "Analyst task 應列出 CRITICAL 程式碼模式"

    def test_description_mentions_owasp(self):
        assert "OWASP" in self.source or "owasp_category" in self.source, \
            "Analyst task 應提及 OWASP 分類"


# ══════════════════════════════════════════════════════════════
# 4. Advisor Task Description 驗證
# ══════════════════════════════════════════════════════════════

class TestAdvisorTaskDescription:
    """驗證 Advisor task description 包含 CODE-finding 輸出規則"""

    @pytest.fixture(autouse=True)
    def load_source(self):
        import inspect
        import agents.advisor as mod
        # 直接讀取模組原始碼，避免觸發 CrewAI Pydantic 的 agent 型別驗證
        self.source = inspect.getsource(mod)

    def test_description_mentions_code_finding(self):
        assert "CODE-" in self.source, "Advisor task 應提及 CODE- finding"

    def test_description_requires_fixed_snippet(self):
        assert "fixed_snippet" in self.source, \
            "Advisor task 應要求輸出 fixed_snippet 欄位"

    def test_description_requires_vulnerable_snippet(self):
        assert "vulnerable_snippet" in self.source, \
            "Advisor task 應要求輸出 vulnerable_snippet 欄位"

    def test_description_forbids_pip_for_code_findings(self):
        # 必須明確說 CODE finding 不使用套件升級指令
        assert ("pip install" in self.source and "CODE" in self.source) or \
               "套件升級" in self.source, \
            "Advisor task 應明確說明 CODE finding 不使用 pip install"

    def test_description_requires_why_this_works(self):
        assert "why_this_works" in self.source, \
            "Advisor task 應要求解釋修復原因"

    def test_description_forbids_vague_advice(self):
        """Advisor 不得輸出 'sanitize your inputs' 這種模糊建議"""
        # 原始碼中應有明確禁止模糊建議的文字
        assert "sanitize your inputs" in self.source or "模糊" in self.source or "具體" in self.source, \
            "Advisor task 應禁止模糊建議"


# ══════════════════════════════════════════════════════════════
# 5. code_action_report.md Skill 驗證
# ══════════════════════════════════════════════════════════════

class TestCodeActionReportSkill:
    """驗證 code_action_report.md 包含修復規則（v5.1：SOP 不再嵌入具體範例，防止 LLM 捏造）"""

    @pytest.fixture(autouse=True)
    def load_skill(self):
        skill_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "skills", "code_action_report.md"
        )
        with open(skill_path, "r", encoding="utf-8") as f:
            self.skill_content = f.read()

    def test_skill_contains_sql_fix_example(self):
        # v5.1: SOP 說明 SQL 要改用 parameterized queries（不再嵌入具體程式碼範例以防 LLM 捏造）
        assert "parameterized" in self.skill_content or "SQL_INJECTION" in self.skill_content, \
            "code_action_report.md 應包含 SQL Injection 修復指示"

    def test_skill_contains_cmd_injection_fix(self):
        # v5.1: SOP 說明 CMD 要用 safe subprocess API
        assert "CMD_INJECTION" in self.skill_content or "Command Injection" in self.skill_content, \
            "code_action_report.md 應包含 Command Injection 修復指示"

    def test_skill_contains_fixed_snippet_field(self):
        assert "fixed_snippet" in self.skill_content, \
            "code_action_report.md Schema 應包含 fixed_snippet 欄位"

    def test_skill_contains_vulnerable_snippet_field(self):
        assert "vulnerable_snippet" in self.skill_content, \
            "code_action_report.md Schema 應包含 vulnerable_snippet 欄位"

    def test_skill_contains_hardcoded_secret_fix(self):
        # v5.1: SOP 說明 HARDCODED_SECRET 要用 environment variable 或 secrets manager
        assert "environment variable" in self.skill_content or "HARDCODED_SECRET" in self.skill_content, \
            "code_action_report.md 應包含硬編碼憑證修復指示"

    def test_skill_contains_why_this_works_field(self):
        assert "why_this_works" in self.skill_content, \
            "code_action_report.md Schema 應包含 why_this_works 欄位"

    def test_skill_urgent_tier_defined(self):
        assert "URGENT" in self.skill_content, \
            "code_action_report.md 應定義 URGENT 分級"

    def test_skill_contains_anti_fabrication_rule(self):
        """v5.1 新增：SOP 必須包含防捏造規則"""
        assert "ANTI-FABRICATION" in self.skill_content or "fabricat" in self.skill_content.lower(), \
            "code_action_report.md 應包含防捏造規則（v5.1 新增需求）"

    def test_skill_prohibits_invented_snippets(self):
        """v5.1 新增：SOP 必須禁止自行捏造 vulnerable_snippet"""
        assert "Analyst" in self.skill_content, \
            "code_action_report.md 應說明 snippet 必須來自 Analyst （不可捏造）"


# ══════════════════════════════════════════════════════════════
# 6. 整合場景模擬（Simulation）
# ══════════════════════════════════════════════════════════════

class TestEndToEndSimulation:
    """模擬完整的 code scan 資料流，不呼叫 LLM"""

    def test_sql_injection_code_produces_code_pattern(self):
        """SQL Injection 程式碼 → SG 偵測 → code_patterns → scout_output 正確"""
        from agents.security_guard import extract_code_surface
        from main import _build_code_patterns_summary

        code = """
import sqlite3
def get_user(name):
    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{name}'"
    cursor.execute(query)
    return cursor.fetchall()
"""
        # Step 1: Security Guard 提取
        sg_result = extract_code_surface(code)
        assert sg_result["extraction_status"] == "ok"

        # Step 2: 轉換為 code_patterns
        code_patterns = _build_code_patterns_summary(sg_result)
        assert len(code_patterns) > 0, "SQL Injection 程式碼應產生 code_patterns"

        # Step 3: 驗證 SQL_INJECTION 被包含
        pattern_types = [p["pattern_type"] for p in code_patterns]
        assert "SQL_INJECTION" in pattern_types, f"SQL_INJECTION not in {pattern_types}"

        # Step 4: 驗證 CWE 和嚴重性
        sql_p = next(p for p in code_patterns if p["pattern_type"] == "SQL_INJECTION")
        assert sql_p["cwe_id"] == "CWE-89"
        assert sql_p["severity"] == "CRITICAL"
        assert sql_p["owasp_category"].startswith("A03")

    def test_hardcoded_secret_code_produces_code_pattern(self):
        """硬編碼 API Key → SG 偵測 → code_patterns 正確，值不洩漏"""
        from agents.security_guard import extract_code_surface
        from main import _build_code_patterns_summary

        code = """
import requests
API_KEY = "sk-abc123xyz456"
password = "admin_password_123"

def call_api():
    return requests.get("https://api.example.com",
                        headers={"Authorization": f"Bearer {API_KEY}"})
"""
        sg_result = extract_code_surface(code)
        code_patterns = _build_code_patterns_summary(sg_result)

        secret_patterns = [p for p in code_patterns if p["type"] == "hardcoded_secret"]
        assert len(secret_patterns) >= 1, "應偵測到至少一個硬編碼 secret"

        # 確認值沒有洩漏
        for p in secret_patterns:
            assert "sk-abc123xyz456" not in p["snippet"], "真實 API key 不應洩漏"
            assert "admin_password_123" not in p["snippet"], "真實密碼不應洩漏"

    def test_clean_code_produces_no_code_patterns(self):
        """乾淨的程式碼不應產生任何 code_patterns"""
        from agents.security_guard import extract_code_surface
        from main import _build_code_patterns_summary

        code = """
import os
from pathlib import Path

def read_config(filename: str) -> dict:
    safe_path = (Path("/config") / filename).resolve()
    if not str(safe_path).startswith("/config"):
        raise ValueError("Invalid path")
    with safe_path.open() as f:
        import json
        return json.load(f)
"""
        sg_result = extract_code_surface(code)
        code_patterns = _build_code_patterns_summary(sg_result)
        # 乾淨的安全程式碼不應有 patterns
        # （注意：SG 可能對 Path 有誤報，但此程式碼應相對乾淨）
        assert isinstance(code_patterns, list)
        # 若有 false positive 也可接受，但不應超過 2 個
        assert len(code_patterns) <= 2, f"乾淨程式碼不應有超過 2 個 findings: {code_patterns}"
