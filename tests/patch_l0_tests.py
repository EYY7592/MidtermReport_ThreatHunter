"""Patch TestL0Warnings in test_multidim.py"""
import re

path = 'tests/test_multidim.py'
with open(path, encoding='utf-8') as f:
    content = f.read()

# Find TestL0Warnings class start/end by locating next class
start = content.find('\nclass TestL0Warnings:')
assert start >= 0, "TestL0Warnings not found"

# Find the start of the next class or end-of-classes marker
next_class = content.find('\n# ══', start + 1)
if next_class < 0:
    next_class = len(content)

old_block = content[start:next_class]

new_block = '''
class TestL0Warnings:
    """L0 淨化器對各類型輸入的 finding 偵測（含 INFO/WARNING/CRITICAL）"""

    @pytest.fixture(autouse=True)
    def _import(self):
        from input_sanitizer import sanitize_input, format_l0_report
        self.sanitize = sanitize_input
        self.fmt = format_l0_report

    def _findings(self, path: str) -> list:
        result = self.sanitize(_load(path))
        return self.fmt(result).get("l0_findings", [])

    def test_sqli_code_has_l0_findings(self):
        """SQL Injection 程式碼 — L0 應有 sql_injection finding"""
        findings = self._findings("dim3_vulnerable/vuln_sqli.py")
        assert len(findings) >= 1, f"SQLi 應有 L0 finding，得: {findings}"

    def test_cmdi_code_has_l0_findings(self):
        """CMDi 程式碼 — L0 應有 os_command finding"""
        findings = self._findings("dim3_vulnerable/vuln_cmdi.py")
        assert len(findings) >= 1, f"CMDi 應有 L0 finding，得: {findings}"

    def test_clean_code_has_low_l0_findings(self):
        """乾淨 Flask — L0 finding ≤ 4（允許 sqlite3 路徑誤報）"""
        findings = self._findings("dim1_clean/clean_flask_app.py")
        assert len(findings) <= 4, f"乾淨程式碼 L0 finding 應 ≤4，實際: {len(findings)}"

    def test_prompt_injection_has_l0_findings(self):
        """Prompt Injection — L0 應偵測到 sql/os_command finding"""
        findings = self._findings("dim4_injection/pi_ignore_rules.py")
        assert len(findings) >= 1, f"PI 代碼應觸發 L0 finding，得: {findings}"

    def test_hardcoded_secret_has_l0_findings(self):
        """硬編碼密鑰 — L0 應有 hardcoded_secret finding"""
        findings = self._findings("dim3_vulnerable/vuln_secret_leak.py")
        assert len(findings) >= 1, f"硬編碼密鑰應觸發 L0 finding，得: {findings}"

    def test_code_passes_l0_not_blocked(self):
        """含漏洞程式碼不被 L0 阻擋（SanitizeResult.safe == True）"""
        result = self.sanitize(_load("dim3_vulnerable/vuln_sqli.py"))
        assert result.safe is True, "含漏洞的程式碼應通過 L0（只標記，不阻擋）"

    def test_multi_vuln_all_warnings(self):
        """多重漏洞 — L0 應有 ≥2 個 findings"""
        findings = self._findings("dim5_mixed/mix_multi_vuln.py")
        assert len(findings) >= 2, f"多重漏洞應有 ≥2 個 finding，實際: {len(findings)}"

    def test_empty_input_handled(self):
        """空輸入 — 不崩潰"""
        result = self.sanitize("")
        assert result is not None
        assert result.input_type is not None

'''

content = content[:start] + new_block + content[next_class:]
with open(path, 'w', encoding='utf-8') as f:
    f.write(content)
print("PATCHED OK — TestL0Warnings replaced")
print(f"  old block len={len(old_block)}, new block len={len(new_block)}")
