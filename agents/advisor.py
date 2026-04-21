"""
agents/advisor.py
================
Advisor Agent — ThreatHunter 最終裁決者（Judge）

職責：
    接收 Analyst Agent（或降級情況下 Scout Agent）的分析結果，
    產出可執行的資安行動報告。不需要額外查詢 NVD/OTX/KEV，
    所有資料由前序 Agent 提供。

Harness 保護層（遵循 HARNESS_ENGINEERING.md 三柱架構）：
    Layer 1 — 強制 write_memory（Agent 若未呼叫，程式碼代執行）
    Layer 2 — 輸出格式驗證（符合 docs/data_contracts.md Advisor→UI 契約）
    Layer 3 — 風險分數範圍驗證（0-100）
    Layer 4 — URGENT 項目必須附帶 command（修補指令）
    Layer 5 — 歷史比對：重複未修補項目語氣遞升

作者：ThreatHunter 組長
遵守：project_CONSTITUTION.md + docs/system_constitution.md
"""

import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Any

from crewai import Agent, Task

from config import get_llm
from tools.memory_tool import history_search, read_memory, write_memory

# LLM 延遲初始化：在 create_advisor_agent() 中才呼叫 get_llm()

logger = logging.getLogger("ThreatHunter")

# ══════════════════════════════════════════════════════════════
# 第一部份：系統憲法 + Skill SOP
# ══════════════════════════════════════════════════════════════

# 嵌入 docs/system_constitution.md 英文版
CONSTITUTION = """
=== ThreatHunter Constitution ===
1. All CVE IDs must come from Tool-returned data. Fabrication is prohibited.
2. You must use the provided Tools for queries. Skip is not allowed.
3. Output must conform to the specified JSON schema.
4. Uncertain reasoning must be tagged with confidence: HIGH / MEDIUM / NEEDS_VERIFICATION.
5. Each judgment must include a reasoning field.
6. Reports use English; technical terms are not translated.
7. Do not call the same Tool twice for the same data.
"""

# 嵌入 skills/action_report.md SOP
_SKILL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "skills", "action_report.md"
)
try:
    with open(_SKILL_PATH, "r", encoding="utf-8") as _f:
        ADVISOR_SKILL = _f.read()
except FileNotFoundError:
    ADVISOR_SKILL = "## Skill: Action Report\nPrioritize URGENT → IMPORTANT → RESOLVED."

# v3.7: Path-Aware Skill Map（對應 main.py recorder.stage_enter 使用）
SKILL_MAP: dict[str, str] = {
    "pkg":       "action_report.md",        # Path A: package scan report
    "code":      "code_action_report.md",   # Path B-code: source code report
    "injection": "ai_action_report.md",     # Path B-inject: AI security report
    "config":    "config_action_report.md", # Path C: config report
}

# ══════════════════════════════════════════════════════════════
# 第二部份：Agent 建立函式
# ══════════════════════════════════════════════════════════════

def create_advisor_agent(excluded_models: list[str] | None = None) -> Agent:
    """
    建立 Advisor Agent。

    Args:
        excluded_models: 需要跳過的模型名稱列表（429 被限速的模型）

    Returns:
        CrewAI Agent 實例，具備記憶讀寫能力。
    """
    return Agent(
        role="資安顧問暨最終裁決者（Advisor & Judge）",
        goal=(
            "審閱前序 Agent 的漏洞分析結果，結合歷史建議記錄，"
            "為非技術管理者產出清晰、可執行的資安行動報告。"
            "按 URGENT / IMPORTANT / RESOLVED 三級分類，"
            "每個行動項必須附帶具體修補指令。"
        ),
        backstory=f"""你是一位資深的資安顧問（CISO 級別），专业背景横跨攻擊手法分析與風險管理。

{CONSTITUTION}

## 行動報告 SOP（來自 skills/action_report.md）
{ADVISOR_SKILL}

## 輸出規格（Advisor → UI 資料契約）

你必須輸出以下 JSON 格式，不可有任何 JSON 以外的文字：

```json
{{
  "executive_summary": "（一句話說明整體風險狀況，英文）",
  "actions": {{
    "urgent": [
      {{
        "cve_id": "CVE-XXXX-XXXX",
        "package": "套件名稱",
        "severity": "CRITICAL 或 HIGH",
        "action": "具體修補說明",
        "command": "pip install package==version 或具體指令",
        "reason": "為何標記為 URGENT",
        "is_repeated": false
      }}
    ],
    "important": [
      {{
        "cve_id": "CVE-XXXX-XXXX",
        "package": "套件名稱",
        "severity": "HIGH 或 MEDIUM",
        "action": "具體修補說明",
        "reason": "優先處理理由"
      }}
    ],
    "resolved": []
  }},
  "risk_score": 0,
  "risk_trend": "+0",
  "scan_count": 1,
  "generated_at": "ISO 8601 timestamp"
}}
```

## 分級規則
- URGENT：CVSS >= 9.0（CRITICAL），或有已知野外利用（in_cisa_kev=true），或有公開 PoC
- IMPORTANT：CVSS >= 7.0（HIGH），或有攻擊鏈風險
- 其他（MEDIUM/LOW 且無利用跡象）：暫時不列入行動清單

## 風險分數計算
risk_score = min(100, sum of (cvss_score * weight for each vuln))
weight: CRITICAL=3, HIGH=2, MEDIUM=1, LOW=0.5
""",
        tools=[read_memory, write_memory, history_search],
        llm=get_llm(exclude_models=excluded_models),
        verbose=True,
        max_iter=4,  # v3.5: Advisor 只讀/寫記憶，不需多次迭代
        allow_delegation=False,
    )


def create_advisor_task(agent: Agent, analyst_output: str) -> Task:
    """
    建立 Advisor Task。

    Args:
        agent: create_advisor_agent() 回傳的 Agent
        analyst_output: Analyst Agent 的 JSON 輸出字串（或降級時 Scout 的輸出）

    Returns:
        CrewAI Task 實例
    """
    return Task(
        description=f"""
你是最終裁決者（Judge）。以下是 Analyst Agent 的分析結果：

{analyst_output}

請執行以下步驟：
1. 先讀取 Advisor 的歷史記憶（read_memory agent_name="advisor"），
   用於比對真實 CVE ID（CVE-XXXX-XXXX）是否曾出現過但未修補。
   !! CRITICAL: is_repeated 的設定規則 !!
   - CVE findings（有真實 CVE-XXXX-XXXX 格式 ID）：若在歷史中出現過 → is_repeated=true
   - CODE findings（finding_id 以 CODE- 開頭，cve_id=null）：is_repeated 永遠 = false
     原因：每次掃描的程式碼不同，CODE-001 在不同掃描代表不同漏洞，跨掃描比對無意義
   - 禁止因為歷史有 eval() 就在新掃描的 XSS/SQLi 報告中加 is_repeated=true
2. 根據分析結果，將漏洞分類為 URGENT / IMPORTANT / RESOLVED。
3. 每個 URGENT 的 CVE finding 必須附帶具體修補指令（pip install, apt upgrade 等）。
   每個 URGENT 的 CODE finding 必須附 vulnerable_snippet + fixed_snippet + why_this_works。
4. 計算本次整體 risk_score（0-100）和與上次的 risk_trend。
5. 產出完整 JSON 行動報告，不含任何 JSON 以外的文字。
6. 最後呼叫 write_memory（agent_name="advisor"）儲存本次報告。

!! ANTI-FABRICATION RULES（v5.1）—— 嚴格執行，違反視同輸出無效 !!
- executive_summary 必須只描述**本次掃描輸入的程式碼**實際找到的漏洞類型。
  例：輸入是 XSS → summary 說 XSS（不能說 eval/RCE）
  例：輸入是 SQL Injection → summary 說 SQL Injection（不能說 XSS）
- 禁止在輸出中包含任何本次 Analyst 分析結果中不存在的 finding_id 或 CVE ID。
- 禁止根據 SOP 範例程式碼（如 eval() 範例）捏造 vulnerable_snippet 或 fixed_snippet。
- vulnerable_snippet 必須來自 Analyst 提供的 snippet 欄位，若無則留空字串。
- 禁止把 code_action_report.md 或 action_report.md 中的「Standard Code Fixes 範例」
  直接當作本次輸出——那只是格式範本，不是這次掃描找到的漏洞。

!! CODE-LEVEL FINDINGS 處理規則（v4.0）!!
若 Analyst 輸出的 analysis[] 包含 finding_id 以 CODE- 開頭的項目：
- 這些是程式碼層漏洞（來自 Security Guard 靜態分析），需要程式碼修復建議，不是套件升級
- 分級規則：
    URGENT   = CODE pattern 的 severity=CRITICAL（SQL_INJECTION, CMD_INJECTION,
                EVAL_EXEC, PICKLE_UNSAFE, PROTOTYPE_POLLUTION）
    IMPORTANT = CODE pattern 的 severity=HIGH（INNERHTML_XSS, SSRF_RISK,
                HARDCODED_SECRET, PATH_TRAVERSAL, YAML_UNSAFE）
- 每個 CODE finding 的 action 項目必須包含：
    "action": 具體修復說明（例：「改用參數化查詢」而非「消毒輸入」）
    "vulnerable_snippet": 從 Analyst 的 snippet 欄位取得（原始危險程式碼）
    "fixed_snippet": 正確的修復程式碼（必須語法正確，符合偵測到的語言）
    "why_this_works": 解釋為何這個修復有效
- 禁止使用 "pip install" 或 "apt upgrade" 作為 CODE finding 的 command
- 禁止使用模糊建議如 "sanitize your inputs"，必須給出具體 API 或寫法
""",
        expected_output=(
            "符合 Advisor→UI 資料契約的完整 JSON 行動報告，"
            "包含 executive_summary、actions（urgent/important/resolved）、"
            "risk_score、risk_trend、scan_count、generated_at。"
        ),
        agent=agent,
    )


# ══════════════════════════════════════════════════════════════
# 第三部份：Harness 保障層（5 層）
# ══════════════════════════════════════════════════════════════

def _extract_json_from_output(raw: str) -> dict[str, Any]:
    """從 LLM 輸出中提取 JSON（容忍 Markdown 包裝）。"""
    # 嘗試 1：直接解析
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    # 嘗試 2：提取 ```json ... ``` 區塊
    match = re.search(r"```(?:json)?\s*([\s\S]+?)```", raw)
    if match:
        try:
            return json.loads(match.group(1).strip())
        except json.JSONDecodeError:
            pass

    # 嘗試 3：提取 { ... } 區塊
    match = re.search(r"\{[\s\S]+\}", raw)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    return {}


def _build_fallback_output(analyst_data: dict[str, Any]) -> dict[str, Any]:
    """
    Harness 保障：當 LLM 輸出無法解析時，
    根據 Analyst/Scout 輸出建立最小可行報告。
    """
    vulns = analyst_data.get("vulnerabilities", analyst_data.get("analysis", []))
    urgent, important = [], []

    for v in vulns:
        cve_id = v.get("cve_id", "UNKNOWN")
        package = v.get("package", "unknown")
        severity = v.get("severity", "MEDIUM")
        cvss = float(v.get("cvss_score", v.get("original_cvss", 0)))

        item = {
            "cve_id": cve_id,
            "package": package,
            "severity": severity,
            "action": f"Update {package} to the latest stable version.",
            "reason": f"CVSS {cvss:.1f} ({severity})",
            "is_repeated": False,
        }

        if cvss >= 9.0 or severity == "CRITICAL":
            item["command"] = f"pip install --upgrade {package}"
            urgent.append(item)
        elif cvss >= 7.0 or severity == "HIGH":
            important.append(item)

    # 計算風險分數
    weight_map = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0.5}
    risk_score = min(100, int(sum(
        float(v.get("cvss_score", v.get("original_cvss", 0))) *
        weight_map.get(v.get("severity", "LOW"), 1)
        for v in vulns
    )))

    total = len(vulns)
    critical_count = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
    summary = (
        f"{total} vulnerabilities found. "
        f"{critical_count} CRITICAL. "
        f"Immediate action required for {len(urgent)} item(s)."
    )

    return {
        "executive_summary": summary,
        "actions": {
            "urgent": urgent,
            "important": important,
            "resolved": [],
        },
        "risk_score": risk_score,
        "risk_trend": "+0",
        "scan_count": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "_harness_fallback": True,
    }


def _harness_validate_schema(output: dict[str, Any]) -> list[str]:
    """
    Harness Layer 2：驗證輸出格式符合 data_contracts.md。
    回傳錯誤清單，空清單表示通過。
    """
    errors = []
    required_keys = ["executive_summary", "actions", "risk_score", "risk_trend"]
    for k in required_keys:
        if k not in output:
            errors.append(f"缺少必要欄位：{k}")

    actions = output.get("actions", {})
    for section in ["urgent", "important", "resolved"]:
        if section not in actions:
            errors.append(f"actions 缺少 {section} 欄位")

    return errors


def _harness_validate_risk_score(output: dict[str, Any]) -> None:
    """Harness Layer 3：風險分數必須在 0-100 範圍。"""
    score = output.get("risk_score", 0)
    if not (0 <= score <= 100):
        logger.warning("⚠️ Harness Layer 3：risk_score=%s 超出範圍，強制修正為 clamp(0,100)", score)
        output["risk_score"] = max(0, min(100, score))


def _harness_ensure_commands(output: dict[str, Any]) -> None:
    """
    Harness Layer 4：URGENT 項目必須附帶 command 欄位。
    v5.1：CODE-pattern 不使用 pip install，改用 Manual code fix required。
    """
    urgent = output.get("actions", {}).get("urgent", [])
    for item in urgent:
        if "command" not in item or not item["command"]:
            cve_id = item.get("cve_id") or ""
            is_code = not (cve_id.startswith("CVE-") or cve_id.startswith("GHSA-"))
            if is_code:
                # CODE-pattern 不與任何套件管理工具連結
                item["command"] = "Manual code fix required (see fixed_snippet)"
            else:
                pkg = item.get("package", "package")
                item["command"] = f"pip install --upgrade {pkg}"
            logger.warning("⚠️ Harness Layer 4：%s 缺少 command，自動補全", item.get("cve_id", "?"))


_CONSTITUTION_VIOLATION_WARNED = False



def _harness_enrich_cwe_evidence(output: dict) -> None:
    """
    Harness Layer 6.5: 為 code_patterns_summary 注入 MITRE CWE 官方佐證。

    為每個 code pattern 加入：
    - CWE 官方名稱（MITRE CWE v4.14）
    - NIST 嚴重性等級
    - CVSS Base 分數（典型值）
    - OWASP 2021 對應
    - 官方 URL
    - 修復建議（中文）
    - 代表性 CVE（同類弱點真實案例）

    效果：讓 code_pattern 不再只是 LLM 的說法，而是有 MITRE 官方定義支撐。
    免責聲明：代表性 CVE 是「同類弱點的真實案例」，
              不代表用戶程式碼「就是」那個 CVE。
    """
    try:
        from tools.cwe_database import get_cwe_info, format_cwe_for_advisor
    except ImportError:
        logger.warning("[ADVISOR] tools/cwe_database not found, skipping CWE enrichment")
        return

    patterns = output.get("code_patterns_summary", [])
    if not patterns:
        return

    enriched_count = 0
    for item in patterns:
        cwe_id = item.get("cwe_id") or item.get("cve_id", "")
        if not cwe_id or not cwe_id.startswith("CWE-"):
            # 如果沒有 cwe_id，從 pattern_type 推斷
            pt = item.get("pattern_type", "")
            cwe_id_guess = _pattern_type_to_cwe(pt)
            if cwe_id_guess:
                cwe_id = cwe_id_guess

        if cwe_id and cwe_id.startswith("CWE-"):
            cwe_info = get_cwe_info(cwe_id)
            if cwe_info:
                item["cwe_reference"] = {
                    "id": cwe_id,
                    "name": cwe_info.get("name", ""),
                    "source": cwe_info.get("source", "MITRE CWE v4.14"),
                    "nist_severity": cwe_info.get("nist_severity", "UNKNOWN"),
                    "cvss_base": cwe_info.get("cvss_base", None),
                    "owasp_2021": cwe_info.get("owasp_2021", ""),
                    "cwe_url": cwe_info.get("cwe_url", ""),
                    "remediation_zh": cwe_info.get("remediation_zh", ""),
                    "representative_cves": cwe_info.get("representative_cves", [])[:3],
                    "disclaimer": (
                        "代表性 CVE 為同類弱點的真實被利用案例，"
                        "非本程式碼的直接 CVE 識別碼。"
                        "用於說明此類弱點的風險嚴重性。"
                    ),
                }
                enriched_count += 1

    if enriched_count:
        logger.info(
            "[ADVISOR] CWE enrichment: %d/%d code_patterns enriched with MITRE data",
            enriched_count, len(patterns),
        )


def _pattern_type_to_cwe(pattern_type: str) -> str | None:
    """從 pattern_type 名稱推斷 CWE ID（fallback 用）"""
    mapping = {
        "SQL_INJECTION": "CWE-89",
        "SQL_CONCAT": "CWE-89",
        "COMMAND_INJECTION": "CWE-78",
        "SHELL_EXEC": "CWE-78",
        "XSS": "CWE-79",
        "EVAL_EXEC": "CWE-95",
        "EVAL_INJECTION": "CWE-95",
        "CODE_INJECTION": "CWE-94",
        "FILE_INCLUSION": "CWE-98",
        "PATH_TRAVERSAL": "CWE-22",
        "DESERIALIZATION": "CWE-502",
        "INSECURE_DESERIALIZATION": "CWE-502",
        "HARDCODED_SECRET": "CWE-798",
        "HARDCODED_CREDENTIALS": "CWE-798",
        "SSRF": "CWE-918",
        "XXE": "CWE-611",
        "OPEN_REDIRECT": "CWE-601",
        "LDAP_INJECTION": "CWE-90",
        "PROTOTYPE_POLLUTION": "CWE-1321",
        "REDOS": "CWE-1333",
        "BUFFER_OVERFLOW": "CWE-119",
        "USE_AFTER_FREE": "CWE-416",
    }
    if pattern_type:
        return mapping.get(pattern_type.upper())
    return None

def _harness_constitution_guard(output: dict[str, Any]) -> None:
    """
    Harness Layer 6：憑法 CI-1/CI-2 守衛。

    憑法規則：
    規則 CI-1：所有 CVE 編號必須來自 Tool 回傳的真實 API 資料
    規則 CI-2：禁止 LLM 自行編造任何 CVE 編號或漏洞細節

    URGENT / IMPORTANT 區塊只允許有真實 CVE ID（CVE-XXXX-XXXX 或 GHSA-XXXX）的項目。
    CODE-pattern（finding_id = CODE-001 等，cve_id = null）為 LLM 自行生成的雜訊，
    不是可驗證的外部來源，不得呈現在 URGENT/IMPORTANT 區塊。

    移除的 CODE-pattern 會被放入 code_patterns_summary 欄位，供 UI 參考顯示。
    """
    global _CONSTITUTION_VIOLATION_WARNED
    actions = output.get("actions", {})
    code_patterns_removed = []

    for section in ["urgent", "important"]:
        original = actions.get(section, [])
        clean = []
        for item in original:
            cve_id = item.get("cve_id") or ""
            finding_id = item.get("finding_id") or ""
            # 判斷是否為 CODE-pattern：
            # 1) cve_id 為 null/空
            # 2) 或 cve_id 以 CWE- 開頭（這是 Harness 訊息類型，不是真實 CVE）
            # 3) 或 finding_id 以 CODE- 開頭
            is_code_pattern = (
                finding_id.startswith("CODE-")
                or cve_id.startswith("CWE-")
                or (
                    not cve_id
                    and not (cve_id.startswith("CVE-") if cve_id else False)
                    and not (cve_id.startswith("GHSA-") if cve_id else False)
                )
            )
            has_real_cve = bool(
                cve_id
                and (cve_id.startswith("CVE-") or cve_id.startswith("GHSA-"))
            )

            if is_code_pattern and not has_real_cve:
                code_patterns_removed.append(item)
                if not _CONSTITUTION_VIOLATION_WARNED:
                    logger.warning(
                        "🛡️ Harness Layer 6 [CONSTITUTION CI-1/CI-2]："
                        "CODE-pattern %r 從 %s 移除(非可驗證來源)",
                        finding_id or cve_id, section
                    )
                    _CONSTITUTION_VIOLATION_WARNED = True
            else:
                clean.append(item)
        actions[section] = clean

    # 如果有被移除的 CODE-pattern，記錄到獨立欄位
    if code_patterns_removed:
        existing = output.get("code_patterns_summary", [])
        output["code_patterns_summary"] = existing + code_patterns_removed
        logger.info(
            "🛡️ Harness Layer 6：將 %d 個 CODE-pattern 移除出 URGENT/IMPORTANT，"
            "移入 code_patterns_summary",
            len(code_patterns_removed)
        )


def _harness_check_repeated(output: dict[str, Any]) -> None:
    """
    Harness Layer 5：比對歷史記憶，標記重複未修補項目。
    讀取 advisor_memory.json，若 CVE 已在歷史中出現且未 resolved，
    則 is_repeated=True 並強化語氣。

    CRITICAL RULE（v5.1）：
    - CODE-level patterns (cve_id is null/empty) 絕對不能標記 REPEATED。
      原因：每次掃描的程式碼都不同，CODE-001 在不同掃描中代表不同漏洞，
      跨掃描比對沒有任何意義，且會產生嚴重誤報。
    - REPEATED 機制僅適用於有真實 CVE ID 的套件漏洞。
    """
    try:
        history_str = read_memory.run(agent_name="advisor")
        history_data = json.loads(history_str) if history_str else {}
        prev_vulns = set()

        # 收集歷史中所有曾建議的真實 CVE ID（不含 null 和空字串）
        for scan in history_data.get("history", []):
            for section in ["urgent", "important"]:
                for item in scan.get("actions", {}).get(section, []):
                    cve_id = item.get("cve_id") or ""
                    # 只收集真實 CVE ID（必須以 CVE- 或 GHSA- 開頭）
                    if cve_id and (cve_id.startswith("CVE-") or cve_id.startswith("GHSA-")):
                        prev_vulns.add(cve_id)

        if not prev_vulns:
            return

        for section in ["urgent", "important"]:
            for item in output.get("actions", {}).get(section, []):
                cve_id = item.get("cve_id") or ""
                # CODE-pattern（cve_id 為空）永遠不標 REPEATED
                if not cve_id or not (cve_id.startswith("CVE-") or cve_id.startswith("GHSA-")):
                    item["is_repeated"] = False  # 強制清除 LLM 可能設的 True
                    continue
                if cve_id in prev_vulns:
                    item["is_repeated"] = True
                    # 強化語氣（Skill SOP 規定）
                    existing = item.get("action", "")
                    if not existing.startswith("[REPEATED"):
                        item["action"] = "[REPEATED — STILL NOT PATCHED] " + existing
                    logger.info("📋 Harness Layer 5：%s 標記為重複未修補", cve_id)

    except Exception as e:
        logger.debug("Harness Layer 5 跳過（歷史記憶尚無記錄）：%s", e)


# ══════════════════════════════════════════════════════════════
# 第四部份：完整 Pipeline 執行函式
# ══════════════════════════════════════════════════════════════

def run_advisor_pipeline(analyst_output: str | dict[str, Any]) -> dict[str, Any]:
    """
    執行 Advisor Agent Pipeline（含 5 層 Harness 保障）。

    Args:
        analyst_output: Analyst Agent 的 JSON 輸出（字串或 dict）。
                        當成員 C 未就緒時，可傳入 Scout 的輸出作為降級路徑。

    Returns:
        dict：符合 Advisor→UI 資料契約的行動報告 JSON。
    """
    from crewai import Crew, Process

    # 統一轉成 dict 和 str 兩種形式
    if isinstance(analyst_output, dict):
        analyst_dict = analyst_output
        analyst_str = json.dumps(analyst_output, ensure_ascii=False, indent=2)
    else:
        analyst_str = analyst_output
        try:
            analyst_dict = json.loads(analyst_output)
        except json.JSONDecodeError:
            analyst_dict = {}

    logger.info("[START] Advisor Pipeline")

    # 429 自動輪替：最多重試 MAX_LLM_RETRIES 次（每次切換模型）
    from config import mark_model_failed, get_current_model_name
    MAX_LLM_RETRIES = 2
    excluded_models: list[str] = []

    # ── 建立 Agent + Task ──────────────────────────────────────
    raw_output = ""
    output: dict[str, Any] = {}
    crew_success = False

    for attempt in range(MAX_LLM_RETRIES + 1):
        agent = create_advisor_agent(excluded_models)
        task = create_advisor_task(agent, analyst_str)

        # ── 執行 CrewAI ────────────────────────────────────────────
        try:
            crew = Crew(
                agents=[agent],
                tasks=[task],
                process=Process.sequential,
                verbose=True,
            )
            logger.info("[START] Advisor Crew kickoff (attempt %d/%d)", attempt + 1, MAX_LLM_RETRIES + 1)
            try:
                from checkpoint import recorder as _cp
                _adv_model = get_current_model_name(agent.llm)
                _cp.llm_call("advisor", _adv_model, "openrouter", f"attempt={attempt+1}")
            except Exception:
                _adv_model = "unknown"
            _t_adv = time.time()
            result = crew.kickoff()
            raw_output = str(result.raw) if hasattr(result, "raw") else str(result)
            try:
                _cp.llm_result("advisor", _adv_model, "SUCCESS",
                               len(raw_output), int((time.time() - _t_adv) * 1000),
                               thinking=raw_output[:1000])
            except Exception:
                pass
            output = _extract_json_from_output(raw_output)
            crew_success = bool(output)
            break  # 成功則跳出重試迴圈
        except Exception as e:
            error_str = str(e)
            if "429" in error_str and attempt < MAX_LLM_RETRIES:
                current_model = get_current_model_name(agent.llm)
                mark_model_failed(current_model)
                excluded_models.append(current_model)
                import re as _re
                _m = _re.search(r'retry.{1,10}(\d+\.?\d*)s', error_str, _re.IGNORECASE)
                retry_after = float(_m.group(1)) if _m else 0.0
                logger.warning("[RETRY] Advisor 429 on %s (attempt %d/%d), api_retry_after=%.0fs",
                              current_model, attempt + 1, MAX_LLM_RETRIES, retry_after)
                try:
                    _cp.llm_retry("advisor", current_model, error_str[:200],
                                  attempt + 1, "next_in_waterfall")
                except Exception:
                    pass
                from config import rate_limiter as _rl
                _rl.on_429(retry_after=retry_after, caller="advisor")  # 最少 30s
                continue

            logger.error("[FAIL] CrewAI execution failed: %s", e)
            try:
                _cp.llm_error("advisor", _adv_model, error_str[:300])
            except Exception:
                pass

    # ── Harness Layer 1：強制建立輸出 ─────────────────────────
    need_fallback = not output or not crew_success
    if need_fallback:
        logger.warning("[WARN] Harness Layer 1: LLM output unparseable, using fallback")
        output = _build_fallback_output(analyst_dict)

    # ── Harness Layer 2：Schema 驗證 ──────────────────────────
    schema_errors = _harness_validate_schema(output)
    if schema_errors:
        logger.warning("[WARN] Harness Layer 2: Schema errors %s, merging fallback", schema_errors)
        fallback = _build_fallback_output(analyst_dict)
        for k, v in fallback.items():
            if k not in output:
                output[k] = v

    # ── Harness Layer 3：風險分數範圍驗證 ─────────────────────
    _harness_validate_risk_score(output)

    # ── Harness Layer 4：URGENT 必須有 command ────────────────
    _harness_ensure_commands(output)

    # ── Harness Layer 4.5：憲法 CI-1/CI-2 守衛 ───────────────
    # CODE-pattern（finding_id = CODE-xxx，cve_id = null）不得出現在 URGENT/IMPORTANT
    # 這是對 project_CONSTITUTION.md 第三條 3.2 的硬性執行
    _harness_constitution_guard(output)
    _harness_enrich_cwe_evidence(output)

    # ── Harness Layer 5：歷史比對，重複未修補語氣遞升 ─────────
    _harness_check_repeated(output)

    # ── Harness Layer 6：CVE 年份過濾（最終防線）─────────────────
    # 無論哪個 Agent/Tool 帶入了舊 CVE，在 Advisor 輸出前一律移除
    CVE_YEAR_MIN = 2005
    ancient_cves_removed = []
    for section in ["urgent", "important"]:
        items = output.get("actions", {}).get(section, [])
        clean_items = []
        for item in items:
            cve_id = item.get("cve_id") or ""
            if not cve_id or cve_id.startswith("GHSA-") or not cve_id.startswith("CVE-"):
                clean_items.append(item)
                continue
            try:
                yr = int(cve_id.split("-")[1])
                if yr < CVE_YEAR_MIN:
                    ancient_cves_removed.append(cve_id)
                    logger.warning(
                        "[ADVISOR HARNESS 6] Ancient CVE removed from %s (year=%d < %d): %s",
                        section, yr, CVE_YEAR_MIN, cve_id
                    )
                else:
                    clean_items.append(item)
            except (IndexError, ValueError):
                clean_items.append(item)
        output["actions"][section] = clean_items

    if ancient_cves_removed:
        logger.warning(
            "[ADVISOR HARNESS 6] Total ancient CVEs removed: %d — %s",
            len(ancient_cves_removed), ancient_cves_removed
        )
        output["ancient_cves_removed"] = ancient_cves_removed
    # ────────────────────────────────────────────────────────────

    # ── 補充 generated_at ─────────────────────────────────────
    if "generated_at" not in output:
        output["generated_at"] = datetime.now(timezone.utc).isoformat()

    # ── 強制寫入記憶（若 LLM 已呼叫，此處為冪等操作）────────
    try:
        write_result = write_memory.run(
            agent_name="advisor",
            data=json.dumps(output, ensure_ascii=False),
        )
        logger.info("[OK] Advisor memory saved: %s", write_result)
    except Exception as e:
        logger.error("[FAIL] write_memory failed: %s", e)

    logger.info(
        "[OK] Advisor Pipeline complete | risk_score=%s | urgent=%s | important=%s",
        output.get("risk_score", 0),
        len(output.get("actions", {}).get("urgent", [])),
        len(output.get("actions", {}).get("important", [])),
    )

    return output


# ══════════════════════════════════════════════════════════════
# 第五部份：本地測試入口（直接執行此檔案時）
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(message)s",
    )

    # 使用 Scout 輸出作為降級測試輸入（成員 C 尚未就緒）
    _scout_output_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "memory", "scout_memory.json"
    )

    if os.path.exists(_scout_output_path):
        with open(_scout_output_path, encoding="utf-8") as _f:
            _test_input = _f.read()
        print(f"[TEST] 使用 Scout 記憶作為輸入：{_scout_output_path}")
    else:
        _test_input = json.dumps({
            "scan_id": "scan_test_001",
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2024-42005",
                    "package": "django",
                    "cvss_score": 9.8,
                    "severity": "CRITICAL",
                    "description": "Django SQL injection vulnerability",
                    "is_new": True,
                },
                {
                    "cve_id": "CVE-2015-4335",
                    "package": "redis",
                    "cvss_score": 10.0,
                    "severity": "CRITICAL",
                    "description": "Redis RCE via Lua bytecode",
                    "is_new": True,
                },
            ],
            "summary": {"total": 2, "critical": 2, "high": 0, "medium": 0, "low": 0},
        })
        print("[TEST] 使用預設測試輸入")

    result = run_advisor_pipeline(_test_input)
    print("\n=== Advisor 輸出 ===")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print(f"\nrisk_score: {result.get('risk_score', 0)}")
    print(f"urgent: {len(result.get('actions', {}).get('urgent', []))}")
    print(f"important: {len(result.get('actions', {}).get('important', []))}")
