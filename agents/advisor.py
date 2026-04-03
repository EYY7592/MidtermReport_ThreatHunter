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
from datetime import datetime, timezone
from typing import Any

from crewai import Agent, Task

from config import get_llm
from tools.memory_tool import history_search, read_memory, write_memory

# 延遲取得 LLM 實例（config.get_llm() 支援三模式降級）
llm = get_llm()

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

# ══════════════════════════════════════════════════════════════
# 第二部份：Agent 建立函式
# ══════════════════════════════════════════════════════════════

def create_advisor_agent() -> Agent:
    """
    建立 Advisor Agent。

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
        llm=llm,
        verbose=True,
        max_iter=10,
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
   確認哪些漏洞曾被建議過但尚未修補（is_repeated=true 語氣遞升）。
2. 根據分析結果，將漏洞分類為 URGENT / IMPORTANT / RESOLVED。
3. 每個 URGENT 項目必須附帶具體修補指令（pip install, apt upgrade 等）。
4. 計算本次整體 risk_score（0-100）和與上次的 risk_trend。
5. 產出完整 JSON 行動報告，不含任何 JSON 以外的文字。
6. 最後呼叫 write_memory（agent_name="advisor"）儲存本次報告。
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
    """Harness Layer 4：URGENT 項目必須附帶 command 欄位。"""
    urgent = output.get("actions", {}).get("urgent", [])
    for item in urgent:
        if "command" not in item or not item["command"]:
            pkg = item.get("package", "package")
            item["command"] = f"pip install --upgrade {pkg}"
            logger.warning("⚠️ Harness Layer 4：%s 缺少 command，自動補全", item.get("cve_id", "?"))


def _harness_check_repeated(output: dict[str, Any]) -> None:
    """
    Harness Layer 5：比對歷史記憶，標記重複未修補項目。
    讀取 advisor_memory.json，若 CVE 已在歷史中出現且未 resolved，
    則 is_repeated=True 並強化語氣。
    """
    try:
        history_str = read_memory.run(agent_name="advisor")
        history_data = json.loads(history_str) if history_str else {}
        prev_vulns = set()

        # 收集歷史中所有曾建議的 CVE
        for scan in history_data.get("history", []):
            for section in ["urgent", "important"]:
                for item in scan.get("actions", {}).get(section, []):
                    prev_vulns.add(item.get("cve_id", ""))

        if not prev_vulns:
            return

        for section in ["urgent", "important"]:
            for item in output.get("actions", {}).get(section, []):
                if item.get("cve_id") in prev_vulns:
                    item["is_repeated"] = True
                    # 強化語氣（Skill SOP 規定）
                    item["action"] = "[REPEATED — STILL NOT PATCHED] " + item.get("action", "")
                    logger.info("📋 Harness Layer 5：%s 標記為重複未修補", item.get("cve_id"))

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

    logger.info("🚀 Advisor Pipeline 啟動")

    # ── 建立 Agent + Task ──────────────────────────────────────
    agent = create_advisor_agent()
    task = create_advisor_task(agent, analyst_str)

    # ── 執行 CrewAI ────────────────────────────────────────────
    raw_output = ""
    output: dict[str, Any] = {}
    crew_success = False

    try:
        crew = Crew(
            agents=[agent],
            tasks=[task],
            process=Process.sequential,
            verbose=True,
        )
        result = crew.kickoff()
        raw_output = str(result.raw) if hasattr(result, "raw") else str(result)
        output = _extract_json_from_output(raw_output)
        crew_success = bool(output)
    except Exception as e:
        logger.error("❌ CrewAI 執行失敗：%s", e)

    # ── Harness Layer 1：強制建立輸出 ─────────────────────────
    need_fallback = not output or not crew_success
    if need_fallback:
        logger.warning("⚠️ Harness Layer 1：LLM 輸出無法解析，程式碼使用降級輸出")
        output = _build_fallback_output(analyst_dict)

    # ── Harness Layer 2：Schema 驗證 ──────────────────────────
    schema_errors = _harness_validate_schema(output)
    if schema_errors:
        logger.warning("⚠️ Harness Layer 2：Schema 錯誤 %s，合併降級輸出修補", schema_errors)
        fallback = _build_fallback_output(analyst_dict)
        for k, v in fallback.items():
            if k not in output:
                output[k] = v

    # ── Harness Layer 3：風險分數範圍驗證 ─────────────────────
    _harness_validate_risk_score(output)

    # ── Harness Layer 4：URGENT 必須有 command ────────────────
    _harness_ensure_commands(output)

    # ── Harness Layer 5：歷史比對，重複未修補語氣遞升 ─────────
    _harness_check_repeated(output)

    # ── 補充 generated_at ─────────────────────────────────────
    if "generated_at" not in output:
        output["generated_at"] = datetime.now(timezone.utc).isoformat()

    # ── 強制寫入記憶（若 LLM 已呼叫，此處為冪等操作）────────
    try:
        write_result = write_memory.run(
            agent_name="advisor",
            data=json.dumps(output, ensure_ascii=False),
        )
        logger.info("💾 Advisor 記憶已寫入：%s", write_result)
    except Exception as e:
        logger.error("❌ write_memory 失敗：%s", e)

    logger.info(
        "✅ Advisor Pipeline 完成｜risk_score=%s｜urgent=%s｜important=%s",
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
