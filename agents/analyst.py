# agents/analyst.py
# 功能：Analyst Agent 定義 — 漏洞連鎖分析師
# Harness 支柱：Constraints（系統憲法 + Skill SOP）+ Observability（verbose=True）
# 擁有者：成員 C（Analyst Agent Pipeline）
#
# 使用方式：
#   from agents.analyst import create_analyst_agent, create_analyst_task, run_analyst_pipeline
#
# 架構定位：
#   Pipeline 的第二環 — 接收 Scout 的情報清單 → 深度分析 → 輸出風險評估 JSON → Advisor 接收
#   Agent = Tool（手）+ Skill（腦）+ Constitution（法）

import json
import os
import re
import time
import logging
from datetime import datetime, timezone
from typing import Any

from crewai import Agent, Task

from config import get_llm, LLM_RPM
from tools.kev_tool import check_cisa_kev
from tools.exploit_tool import search_exploits
from tools.memory_tool import read_memory, write_memory, history_search

# LLM 延遲初始化：在 create_*_agent() 中才呼叫 get_llm()

logger = logging.getLogger("ThreatHunter")

# 專案根目錄（agents/ 的上一層）
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ══════════════════════════════════════════════════════════════
# 第一部份：系統憲法 + Skill SOP 載入
# ══════════════════════════════════════════════════════════════

CONSTITUTION = """
=== ThreatHunter Constitution ===
1. All CVE IDs must come from Tool-returned data. Fabrication is prohibited.
2. You must use the provided Tools for queries. Skip is not allowed.
3. Output must conform to the specified JSON schema.
4. Uncertain reasoning must be tagged with confidence: HIGH / MEDIUM / NEEDS_VERIFICATION.
5. Each judgment must include a reasoning field.
6. Reports use English; technical terms are not translated.
7. Do not call the same Tool twice for the same data.
8. Risk adjustment can only ESCALATE, never DOWNGRADE.
9. Chain analysis must include chain_with, chain_description, and confidence.
""".strip()


SKILL_PATH = os.path.join(PROJECT_ROOT, "skills", "chain_analysis.md")


def _load_skill() -> str:
    """
    載入 Skill SOP 文件內容。

    安全閥：
      - 檔案不存在 → 使用內嵌的精簡版 Skill（Graceful Degradation）
      - 編碼錯誤 → 嘗試 utf-8-sig → 仍失敗 → 內嵌版
    """
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            if os.path.exists(SKILL_PATH):
                with open(SKILL_PATH, "r", encoding=encoding) as f:
                    content = f.read().strip()
                if content:
                    logger.info("[OK] Skill loaded: %s (%d chars)", SKILL_PATH, len(content))
                    return content
        except (IOError, UnicodeDecodeError):
            continue

    logger.warning("[WARN] Skill file load failed, using fallback: %s", SKILL_PATH)
    return _FALLBACK_SKILL


# 內嵌精簡版 Skill（Graceful Degradation — Skill 檔案遺失時的保底）
_FALLBACK_SKILL = """
# Skill: Vulnerability Chain Analysis (Fallback)

## SOP
1. read_memory(agent_name="analyst") — read historical data
2. Parse Scout's JSON: extract tech_stack + vulnerabilities
3. For each CVE with CVSS >= 7.0: call check_cisa_kev
4. For each CVE with in_kev=true OR CVSS >= 9.0: call search_exploits
5. Chain analysis: classify attack types, identify prerequisite→outcome chains
6. Risk scoring: weighted sum (CRITICAL=3, HIGH=2, MEDIUM=1, LOW=0.5)
7. write_memory(agent_name="analyst", data=report) — save results
8. Output pure JSON (Analyst → Advisor contract)

## Quality Gates
- CVE must come from Scout's intelligence, never fabricate
- Chain analysis must include reasoning and confidence
- Risk can only escalate, never downgrade
- Output must be pure JSON
""".strip()


# ══════════════════════════════════════════════════════════════
# 第二部份：Agent 工廠函式
# ══════════════════════════════════════════════════════════════

def _build_analyst_backstory() -> str:
    """建立共用的 Analyst backstory（系統憲法 + Skill SOP）"""
    skill_content = _load_skill()
    return f"""You are a senior vulnerability analyst specializing in attack chain analysis
and exploit intelligence. You are precise, methodical, and never fabricate data.

{CONSTITUTION}

---

## 📋 Analysis Methodology (Skill SOP)

The following is your standard operating procedure for vulnerability chain analysis:

{skill_content}
"""


def create_analyst_agent(excluded_models: list[str] | None = None) -> Agent:
    """
    建立 Analyst Agent 實例（完整工具版，供 main.py 使用）。

    Args:
        excluded_models: 需要跳過的模型名稱列表（429 被限速的模型）

    Returns:
        CrewAI Agent 實例，可直接用於 Task 和 Crew
    """
    backstory = _build_analyst_backstory()

    analyst = Agent(
        role="漏洞連鎖分析師 (Analyst)",
        goal=(
            "接收 Scout 的情報清單，驗證 KEV 和 Exploit 狀態，"
            "分析漏洞連鎖攻擊路徑，評估風險等級"
        ),
        backstory=backstory,
        tools=[check_cisa_kev, search_exploits, read_memory, write_memory, history_search],
        llm=get_llm(exclude_models=excluded_models),
        verbose=True,        # Harness: Observability — 完整 ReAct 推理可見
        max_iter=5,           # v3.5: Gemini-3-Flash ~4s/call, KEV+Exploit 各查一次就夠
        max_rpm=LLM_RPM,      # Harness: Graceful Degradation — 免費方案限速
        allow_delegation=False,  # Analyst 不委派，自己做完
    )

    logger.info(
        "[OK] Analyst Agent created | tools=%s | max_iter=%s | llm=%s",
        [t.name for t in analyst.tools],
        analyst.max_iter,
        analyst.llm.model if hasattr(analyst.llm, 'model') else 'unknown'
    )

    return analyst


# ── 子 Agent 工廠（工具限縮版，供 run_analyst_pipeline 使用）─────
# 每個子 Agent 有專屬 backstory，只包含其負責的 SOP 步驟，
# 避免弱模型看到完整 8 步 SOP 後混淆自己的職責。

def _create_collector_agent(excluded_models: list[str] | None = None) -> Agent:
    """
    建立資料收集子 Agent（只有 read_memory 工具）。
    認知負荷最低：讀記憶 + 解析 Scout JSON。

    Args:
        excluded_models: 需要跳過的模型名稱列表
    """
    backstory = f"""You are a data collection specialist. You are precise and methodical.

{CONSTITUTION}

---

## Your Responsibility: Data Collection ONLY

You handle Step 1-2 of the analysis pipeline:
- Step 1: Call `read_memory` tool to retrieve historical analysis data
- Step 2: Parse the Scout Agent's JSON to extract all CVE entries

You do NOT perform KEV validation, exploit search, risk scoring, or write memory.
Those are handled by other agents in the pipeline.
"""
    agent = Agent(
        role="漏洞分析師 — 資料收集 (Collector)",
        goal="讀取歷史記憶並解析 Scout 的情報清單",
        backstory=backstory,
        tools=[read_memory],
        llm=get_llm(exclude_models=excluded_models),
        verbose=True,
        max_iter=8,
        max_rpm=LLM_RPM,
        allow_delegation=False,
    )
    logger.info("[OK] Collector Sub-Agent created | tools=%s", [t.name for t in agent.tools])
    return agent


def _create_verifier_agent(excluded_models: list[str] | None = None) -> Agent:
    """
    建立驗證分析子 Agent（只有 check_cisa_kev + search_exploits 工具）。
    專注：KEV 驗證 + Exploit 搜尋 + Chain 分析。

    Args:
        excluded_models: 需要跳過的模型名稱列表
    """
    backstory = f"""You are a vulnerability verification specialist. You validate KEV status and search for public exploits.

{CONSTITUTION}

---

## Your Responsibility: Verification & Analysis ONLY

You handle Step 3-5 of the analysis pipeline:
- Step 3: Call `check_cisa_kev` for all CVEs with cvss_score >= 7.0 (comma-separated)
- Step 4: Call `search_exploits` for each CVE where in_kev=true OR cvss_score >= 9.0
- Step 5: Perform chain analysis (classify attack types, identify prerequisite→outcome chains)

You do NOT read memory, write memory, or calculate risk scores.
Those are handled by other agents in the pipeline.
"""
    agent = Agent(
        role="漏洞分析師 — 驗證分析 (Verifier)",
        goal="驗證 CVE 的 KEV 狀態、搜尋公開 Exploit、分析漏洞連鎖攻擊路徑",
        backstory=backstory,
        tools=[check_cisa_kev, search_exploits],
        llm=get_llm(exclude_models=excluded_models),
        verbose=True,
        max_iter=5,        # KEV+Exploit各一次
        max_rpm=LLM_RPM,
        allow_delegation=False,
    )
    logger.info("[OK] Verifier Sub-Agent created | tools=%s", [t.name for t in agent.tools])
    return agent


def _create_scorer_agent(excluded_models: list[str] | None = None) -> Agent:
    """
    建立評分輸出子 Agent（只有 write_memory 工具）。
    專注：風險計算 + 寫入記憶 + 輸出最終 JSON。

    Args:
        excluded_models: 需要跳過的模型名稱列表
    """
    backstory = f"""You are a risk scoring specialist. You calculate risk scores and produce final JSON reports.

{CONSTITUTION}

---

## Your Responsibility: Risk Scoring & Output ONLY

You handle Step 6-8 of the analysis pipeline:
- Step 6: Calculate risk_score = min(100, sum of cvss_score * weight)
  Weight: CRITICAL=3, HIGH=2, MEDIUM=1, LOW=0.5
- Step 7: Call `write_memory` tool to save your report
- Step 8: Output the final JSON report

!! ABSOLUTE PROHIBITIONS:
- You do NOT have `read_memory` tool. Do NOT try to call it.
- You do NOT have `check_cisa_kev` tool. Do NOT try to call it.
- You do NOT have `search_exploits` tool. Do NOT try to call it.
- Steps 1-5 are ALREADY DONE by other agents. Their results are in your task context.
- Your ONLY tool is `write_memory`. Use it to save, then output Final Answer.
"""
    agent = Agent(
        role="漏洞分析師 — 風險評分 (Scorer)",
        goal="計算風險分數、寫入記憶、輸出最終 JSON 報告",
        backstory=backstory,
        tools=[write_memory],
        llm=get_llm(exclude_models=excluded_models),
        verbose=True,
        max_iter=8,
        max_rpm=LLM_RPM,
        allow_delegation=False,
    )
    logger.info("[OK] Scorer Sub-Agent created | tools=%s", [t.name for t in agent.tools])
    return agent


# ══════════════════════════════════════════════════════════════
# 第三部份：Task 工廠函式
# ══════════════════════════════════════════════════════════════

# ── 原始單一 Task（向後相容，供 main.py 使用）──────────────────

def create_analyst_task(agent: Agent, context: list | None = None) -> Task:
    """
    建立 Analyst Agent 的 Task（供 main.py 的單一 Crew 使用）。

    重構為 CrewAI 標準架構：
      - 不再把 scout_output 內容嵌入 description（舊方式）
      - 改用 context=[scout_task] 讓 CrewAI 自動將前一個 Task 的輸出
        傳遞給本 Task（CrewAI 原生樓制）

    Args:
        agent: create_analyst_agent() 回傳的 Agent 實例
        context: 前一個 Task 的清單（如 [scout_task])

    Returns:
        CrewAI Task 實例
    """
    return Task(
        description="""You are the Analyst Agent. The Scout Agent's intelligence report
is available in your context (previous task output).

Execute the following steps in strict order, calling the specified tools:

Step 1: Read historical memory
   Action: read_memory
   Action Input: analyst

Step 2: Parse the Scout intelligence from context
   Extract all CVE entries from the vulnerabilities array.
   Note each CVE's cve_id, cvss_score, severity, package, description, and is_new.

Step 3: KEV validation
   Collect all CVE IDs with cvss_score >= 7.0 into a comma-separated string.
   Action: check_cisa_kev
   Action Input: CVE-XXXX-XXXX,CVE-YYYY-YYYY (all qualifying CVEs in one call)
   Record in_kev status for each CVE.

Step 4: Exploit search
   For each CVE where in_kev=true OR cvss_score >= 9.0:
   Action: search_exploits
   Action Input: CVE-XXXX-XXXX (one CVE per call)
   Record exploit_available and exploit_count.

Step 5: Chain analysis
   Classify each vulnerability's attack type.
   Identify prerequisite-outcome chains between vulnerabilities.
   Risk adjustment rules:
   - in_kev + exploit + chain -> CRITICAL
   - in_kev + exploit -> CRITICAL
   - chain alone -> at least original severity
   Risk can ONLY escalate, never downgrade.

Step 6: Risk scoring
   risk_score = min(100, sum of (cvss x weight))
   Weight: CRITICAL=3, HIGH=2, MEDIUM=1, LOW=0.5

Step 7: Write memory (MANDATORY)
   Action: write_memory
   Action Input: analyst|{your complete JSON report}

Step 8: Output Final Answer as pure JSON.

Absolute prohibitions:
- Do NOT fabricate CVE IDs.
- Do NOT skip tool calls.
- Do NOT skip write_memory.
- Do NOT downgrade risk.
""",
        expected_output=(
            "Pure JSON following the Analyst -> Advisor contract: "
            "scan_id, risk_score, risk_trend, analysis[] with "
            "cve_id, original_cvss, adjusted_risk, in_cisa_kev, "
            "exploit_available, chain_risk, reasoning for each CVE."
        ),
        agent=agent,
        context=context or [],
    )


# ── 拆分版 Task 工廠（3 個子 Task，供 run_analyst_pipeline 使用）─

def _create_collection_task(agent: Agent, scout_output: str) -> Task:
    """
    子 Task 1：資料收集。
    讀取歷史記憶 + 解析 Scout 的情報清單。
    """
    return Task(
        description=f"""You are the Analyst Agent performing Step 1 of 3: Data Collection.

Below is the Scout Agent's intelligence report:

{scout_output}

=== YOUR GOAL ===
1. Read your historical memory using the `read_memory` tool.
2. Parse the Scout JSON above to extract all CVEs.
3. Once (and ONLY once) you have the tool result, output your Final Answer in this JSON structure:
{{
  "historical_risk_score": <number or null>,
  "parsed_cves": [
    {{ "cve_id": "...", "package": "...", "cvss_score": 0.0, "severity": "...", "description": "...", "is_new": true }}
  ],
  "tech_stack": ["..."],
  "total_cves": <number>
}}

=== ⛔ CRITICAL RULE FOR FREE LLMS ⛔ ===
You MUST NOT generate the JSON response right now.
You MUST call the `read_memory` tool FIRST.
If you generate the Final Answer JSON without calling the tool, you will be penalized.
Stop thinking about the Final Answer and output your thought and action to call `read_memory` immediately!
""",
        expected_output=(
            "JSON with historical_risk_score (number or null) and "
            "parsed_cves array containing all CVEs from Scout intelligence."
        ),
        agent=agent,
    )


def _create_analysis_task(agent: Agent) -> Task:
    """
    子 Task 2：驗證與分析。
    KEV 驗證 + Exploit 搜尋 + Chain 分析。
    上一個 Task 的輸出會作為 context 自動傳入。
    """
    return Task(
        description="""You are the Analyst Agent performing Step 2 of 3: Verification & Analysis.

The previous task gave you parsed CVE data. Now you must verify and analyze each CVE.

=== YOUR GOAL ===
1. Use `check_cisa_kev` tool to check ALL CVE IDs with cvss_score >= 7.0 (comma-separated).
2. Use `search_exploits` tool for each CVE where in_kev=true OR cvss_score >= 9.0.
3. Perform chain analysis using your logic (risk can only escalate).
4. Once you have ALL tool results, output your Final Answer in this JSON structure:
{
  "analysis": [
    {
      "cve_id": "...",
      "original_cvss": 9.8,
      "adjusted_risk": "CRITICAL",
      "in_cisa_kev": true,
      "exploit_available": true,
      "chain_risk": { "is_chain": true, "chain_with": ["..."], "chain_description": "...", "confidence": "HIGH" },
      "reasoning": "..."
    }
  ]
}

=== ⛔ CRITICAL RULE FOR FREE LLMS ⛔ ===
You MUST NOT generate the JSON response right now.
You MUST call the `check_cisa_kev` tool FIRST!
DO NOT FABRICATE DATA. 
Stop thinking about the Final Answer and output your thought and action to call the tools immediately!
""",
        expected_output=(
            "JSON with analysis array. Each entry has: cve_id, original_cvss, "
            "adjusted_risk, in_cisa_kev, exploit_available, chain_risk, reasoning."
        ),
        agent=agent,
    )


def _create_scoring_task(agent: Agent) -> Task:
    """
    子 Task 3：評分與輸出。
    計算風險分數 + 寫入記憶 + 輸出最終 JSON。
    上一個 Task 的輸出會作為 context 自動傳入。
    """
    now = datetime.now(timezone.utc)
    scan_id = f"scan_{now.strftime('%Y%m%d')}_001"

    return Task(
        description=f"""You are performing the FINAL step: Scoring & Output.

⚠️ IMPORTANT CONTEXT:
- Step 1 (data collection) and Step 2 (KEV/exploit verification) are ALREADY COMPLETED by other agents.
- Their results are provided to you in the task context above.
- You do NOT need to call read_memory, check_cisa_kev, or search_exploits.
- You do NOT have those tools. Your ONLY tool is `write_memory`.

=== YOUR GOAL ===

1. Look at the analysis results from the previous task context.
2. Calculate risk_score: min(100, sum of (each CVE's cvss_score × weight))
   Weight by adjusted_risk: CRITICAL=3, HIGH=2, MEDIUM=1, LOW=0.5
3. Calculate risk_trend: compare with historical_risk_score from task 1 context.
   If no history, use "+0". Format: "+7" or "-3" or "+0".
4. Call `write_memory` tool with these EXACT arguments:
   - agent_name: analyst
   - data: your complete JSON report as a string
5. After write_memory confirms success, output your Final Answer.

=== FINAL ANSWER FORMAT (pure JSON, no other text) ===
{{
  "scan_id": "{scan_id}",
  "risk_score": <calculated number 0-100>,
  "risk_trend": "<+N or -N or +0>",
  "analysis": <copy the analysis array from previous task context>
}}

=== ⛔ RULES ⛔ ===
- Do NOT call read_memory (you don't have it).
- Do NOT call check_cisa_kev (you don't have it).
- Do NOT call search_exploits (you don't have it).
- DO call write_memory FIRST, then output Final Answer.
- Final Answer must be pure JSON only. No markdown, no explanation.
""",
        expected_output=(
            "Pure JSON: scan_id, risk_score (0-100), risk_trend, "
            "and complete analysis array from previous task."
        ),
        agent=agent,
    )


# ══════════════════════════════════════════════════════════════
# 第四部份：Harness 保障層（3 層）
# ══════════════════════════════════════════════════════════════

def _strip_react_residue(parsed: dict[str, Any]) -> dict[str, Any]:
    """
    偵測並剝離 ReAct tool-call 殘留欄位。
    弱模型常把 thought/action/action_input 混入最終 JSON，
    這些不屬於 Analyst → Advisor 契約。
    """
    react_keys = {"thought", "action", "action_input",
                  "Thought", "Action", "Action Input"}
    found_react = react_keys & set(parsed.keys())
    if not found_react:
        return parsed  # 沒有 ReAct 殘留，原樣返回

    logger.warning("[WARN] Detected ReAct residual fields %s, stripped", found_react)
    cleaned = {k: v for k, v in parsed.items() if k not in react_keys}

    # 如果剝離後仍有 schema 必要欄位，則視為有效
    schema_keys = {"scan_id", "risk_score", "risk_trend", "analysis"}
    if schema_keys & set(cleaned.keys()):
        return cleaned

    # 剝離後空空如也 → 純 ReAct 格式，視為無效輸出
    logger.warning("[WARN] After stripping ReAct, no valid schema fields remain")
    return {}


def _extract_json_from_output(raw: str) -> dict[str, Any]:
    """從 LLM 輸出中提取 JSON（容忍 Markdown 包裝 + 剝離 ReAct 殘留）"""
    parsed = None

    # 嘗試 1：直接解析
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        pass

    # 嘗試 2：提取 ```json ... ``` 區塊
    if parsed is None:
        match = re.search(r"```(?:json)?\s*([\s\S]+?)```", raw)
        if match:
            try:
                parsed = json.loads(match.group(1).strip())
            except json.JSONDecodeError:
                pass

    # 嘗試 3：提取 { ... } 區塊
    if parsed is None:
        match = re.search(r"\{[\s\S]+\}", raw)
        if match:
            try:
                parsed = json.loads(match.group(0))
            except json.JSONDecodeError:
                pass

    if parsed is None:
        return {}

    # 剝離 ReAct 殘留（防止 thought/action 被當成有效輸出）
    return _strip_react_residue(parsed)


def _harness_validate_schema(output: dict[str, Any]) -> list[str]:
    """
    Harness Layer 2：JSON Schema 驗證。
    驗證 Analyst → Advisor 契約的必要欄位。
    回傳錯誤清單，空清單表示通過。
    """
    errors = []
    required_keys = ["scan_id", "risk_score", "risk_trend", "analysis"]
    for k in required_keys:
        if k not in output:
            errors.append(f"缺少必要欄位：{k}")

    # 驗證 analysis 陣列中的每個項目
    for i, item in enumerate(output.get("analysis", [])):
        item_required = ["cve_id", "original_cvss", "adjusted_risk", "reasoning"]
        for k in item_required:
            if k not in item:
                errors.append(f"analysis[{i}] 缺少欄位：{k}")

    return errors


def _harness_validate_chain_risk(output: dict[str, Any]) -> None:
    """
    Harness Layer 3：chain_risk 邏輯驗證。
    is_chain=true 必須有 chain_with + chain_description。
    """
    for i, item in enumerate(output.get("analysis", [])):
        chain_risk = item.get("chain_risk", {})
        if chain_risk.get("is_chain", False):
            if not chain_risk.get("chain_with"):
                logger.warning(
                    "[WARN] Harness Layer 3: analysis[%d] is_chain=true but missing chain_with, "
                    "auto-set to empty array", i
                )
                chain_risk["chain_with"] = []
            if not chain_risk.get("chain_description"):
                logger.warning(
                    "[WARN] Harness Layer 3: analysis[%d] is_chain=true but missing chain_description, "
                    "auto-patched", i
                )
                chain_risk["chain_description"] = "Chain detected but description not provided by Agent"
            if not chain_risk.get("confidence"):
                chain_risk["confidence"] = "NEEDS_VERIFICATION"


def _build_fallback_output(scout_data: dict[str, Any]) -> dict[str, Any]:
    """
    Harness 保障：當 LLM 輸出無法解析時，
    根據 Scout 輸出建立最小可行的 Analyst 報告。
    """
    vulns = scout_data.get("vulnerabilities", [])
    analysis = []

    for v in vulns:
        cve_id = v.get("cve_id", "UNKNOWN")
        cvss = float(v.get("cvss_score", 0))
        severity = v.get("severity", "LOW")

        analysis.append({
            "cve_id": cve_id,
            "original_cvss": cvss,
            "adjusted_risk": severity,
            "in_cisa_kev": False,
            "exploit_available": False,
            "chain_risk": {
                "is_chain": False,
                "chain_with": [],
                "chain_description": "",
                "confidence": "NEEDS_VERIFICATION",
            },
            "reasoning": f"Fallback analysis: CVSS {cvss:.1f} ({severity}), KEV/Exploit status unknown (Harness fallback)",
        })

    # 計算風險分數
    weight_map = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0.5}
    risk_score = min(100, int(sum(
        float(v.get("cvss_score", 0)) * weight_map.get(v.get("severity", "LOW"), 1)
        for v in vulns
    )))

    now = datetime.now(timezone.utc)
    scan_id = f"scan_{now.strftime('%Y%m%d')}_001"

    return {
        "scan_id": scan_id,
        "risk_score": risk_score,
        "risk_trend": "+0",
        "analysis": analysis,
        "_harness_fallback": True,
    }


# ══════════════════════════════════════════════════════════════
# 第五部份：Pipeline 執行函式（含 Harness 保障層）
# ══════════════════════════════════════════════════════════════

def run_analyst_pipeline(scout_output: str | dict) -> dict:
    """
    執行完整的 Analyst Pipeline，包含 Agent 執行 + 程式碼層保障。

    Harness Engineering 核心理念：
      不要 100% 依賴 LLM 遵守指令。
      Agent 負責「盡力做」，程式碼負責「確保做到」。

    架構：3-Task Sequential Pipeline（降低弱模型認知負荷）
      Task 1: 資料收集（Collector）— read_memory + 解析 Scout JSON
      Task 2: 驗證分析（Verifier）— KEV + Exploit + Chain 分析
      Task 3: 評分輸出（Scorer）— 風險計算 + write_memory + 輸出 JSON

    程式碼層保障：
      Layer 1：強制 write_memory（Agent 若未呼叫，程式碼代為執行）
      Layer 2：JSON Schema 驗證（必要欄位檢查）
      Layer 3：chain_risk 邏輯驗證（is_chain=true 必須有 chain_with + chain_description）

    Args:
        scout_output: Scout Agent 的 JSON 輸出（字串或 dict）

    Returns:
        dict: 解析後的 Analyst 報告 JSON（符合 Analyst → Advisor 契約）
    """
    from crewai import Crew, Process

    # 統一轉成 dict 和 str 兩種形式
    if isinstance(scout_output, dict):
        scout_dict = scout_output
        scout_str = json.dumps(scout_output, ensure_ascii=False, indent=2)
    else:
        scout_str = scout_output
        try:
            scout_dict = json.loads(scout_output)
        except json.JSONDecodeError:
            scout_dict = {}

    logger.info("[START] Analyst Pipeline (3-Task split architecture)")

    # 記錄 pipeline 啟動前的記憶檔 mtime（用於判斷 Agent 是否呼叫了 write_memory）
    memory_path_check = os.path.join(PROJECT_ROOT, "memory", "analyst_memory.json")
    pre_mtime = os.path.getmtime(memory_path_check) if os.path.exists(memory_path_check) else 0

    # 429 自動輪替：最多重試 MAX_LLM_RETRIES 次（每次切換模型）
    from config import mark_model_failed, get_current_model_name
    MAX_LLM_RETRIES = 2
    excluded_models: list[str] = []

    raw_output = ""
    output: dict[str, Any] = {}
    crew_success = False

    for attempt in range(MAX_LLM_RETRIES + 1):
        # ── 建立 3 個專責子 Agent（每次重試都用新模型）───────
        collector = _create_collector_agent(excluded_models)
        verifier = _create_verifier_agent(excluded_models)
        scorer = _create_scorer_agent(excluded_models)

        # ── 建立 3 個子 Task ────────────────────────────────────────
        task_1 = _create_collection_task(collector, scout_str)
        task_2 = _create_analysis_task(verifier)
        task_3 = _create_scoring_task(scorer)

        # ── 執行 CrewAI Sequential Pipeline ─────────────────────────
        try:
            crew = Crew(
                agents=[collector, verifier, scorer],
                tasks=[task_1, task_2, task_3],
                process=Process.sequential,
                verbose=True,
            )
            logger.info("[START] Analyst Crew kickoff (attempt %d/%d)", attempt + 1, MAX_LLM_RETRIES + 1)
            try:
                from checkpoint import recorder as _cp
                _a_model = get_current_model_name(collector.llm)
                _cp.llm_call("analyst", _a_model, "openrouter", f"3-task-split attempt={attempt+1}")
            except Exception:
                _a_model = "unknown"
            _t_a = time.time()
            result = crew.kickoff()
            raw_output = str(result.raw) if hasattr(result, "raw") else str(result)
            try:
                _cp.llm_result("analyst", _a_model, "SUCCESS",
                               len(raw_output), int((time.time() - _t_a) * 1000),
                               thinking=raw_output[:1000])
            except Exception:
                pass
            output = _extract_json_from_output(raw_output)
            crew_success = bool(output)
            logger.info("[OK] CrewAI 3-Task Pipeline done | crew_success=%s", crew_success)
            break  # 成功則跳出重試迴圈
        except Exception as e:
            error_str = str(e)
            if "429" in error_str and attempt < MAX_LLM_RETRIES:
                # 標記當前模型為冷卻中，從任一 sub-agent 取得模型名
                current_model = get_current_model_name(collector.llm)
                mark_model_failed(current_model)
                excluded_models.append(current_model)
                wait_sec = (attempt + 1) * 12  # 遞增等待：12s, 24s
                logger.warning("[RETRY] Analyst 429 on %s, waiting %ds before retry %d/%d",
                              current_model, wait_sec, attempt + 1, MAX_LLM_RETRIES)
                try:
                    _cp.llm_retry("analyst", current_model, error_str[:200],
                                  attempt + 1, "next_in_waterfall")
                except Exception:
                    pass
                time.sleep(wait_sec)
                continue

            logger.error("[FAIL] CrewAI execution failed: %s", e)
            try:
                _cp.llm_error("analyst", _a_model, error_str[:300])
            except Exception:
                pass

    # ── Harness Layer 1：強制建立輸出 + 強制 write_memory ──────
    need_fallback = not output or not crew_success
    if need_fallback:
        logger.warning("[WARN] Harness Layer 1: LLM output unparseable, using fallback")
        output = _build_fallback_output(scout_dict)

    # 強制 write_memory（使用 mtime 比較判斷 Agent 是否已寫入）
    memory_path = os.path.join(PROJECT_ROOT, "memory", "analyst_memory.json")
    post_mtime = os.path.getmtime(memory_path) if os.path.exists(memory_path) else 0
    need_write = (post_mtime <= pre_mtime)

    if need_write:
        logger.warning("[WARN] Agent did not call write_memory -- code forcing write (Harness)")
        try:
            write_result = write_memory.run(
                agent_name="analyst",
                data=json.dumps(output, ensure_ascii=False),
            )
            logger.info("[OK] Forced memory write: %s", write_result)
        except Exception as e:
            logger.error("[FAIL] Forced write_memory failed: %s", e)
    else:
        logger.info("[OK] Agent already called write_memory (mtime updated)")

    # ── Harness Layer 2：JSON Schema 驗證 ──────────────────────
    schema_errors = _harness_validate_schema(output)
    if schema_errors:
        logger.warning("[WARN] Harness Layer 2: Schema errors %s, merging fallback", schema_errors)
        fallback = _build_fallback_output(scout_dict)
        for k, v in fallback.items():
            if k not in output:
                output[k] = v

    # ── Harness Layer 3：chain_risk 邏輯驗證 ───────────────────
    _harness_validate_chain_risk(output)

    # ── 確保 risk_score 在合理範圍 ─────────────────────────────
    risk_score = output.get("risk_score", 0)
    if not (0 <= risk_score <= 100):
        logger.warning("[WARN] risk_score=%s out of range, forcing correction", risk_score)
        output["risk_score"] = max(0, min(100, risk_score))

    # ── Harness Layer 4：Risk Escalation Rule (風險禁止降級) ────
    scout_vulns = {v.get("cve_id"): v.get("severity", "LOW") for v in scout_dict.get("vulnerabilities", [])}
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

    # ── 確保 analysis 中每個項目都有 chain_risk ────────────────
    for item in output.get("analysis", []):
        cve_id = item.get("cve_id", "")
        orig_severity = scout_vulns.get(cve_id, "LOW")
        adj_risk = item.get("adjusted_risk", orig_severity)
        
        # 檢查是否降級
        if severity_rank.get(adj_risk, 0) < severity_rank.get(orig_severity, 0):
            logger.warning(
                "[WARN] Harness Layer 4: %s tried to downgrade from %s to %s, "
                "violates SOP, forcing back to %s",
                cve_id, orig_severity, adj_risk, orig_severity
            )
            item["adjusted_risk"] = orig_severity

        if "chain_risk" not in item:
            item["chain_risk"] = {
                "is_chain": False,
                "chain_with": [],
                "chain_description": "",
                "confidence": "NEEDS_VERIFICATION",
            }
        if "in_cisa_kev" not in item:
            item["in_cisa_kev"] = False
        if "exploit_available" not in item:
            item["exploit_available"] = False

    analysis_count = len(output.get("analysis", []))
    logger.info(
        "[OK] Analyst Pipeline complete | risk_score=%s | risk_trend=%s | analysis_count=%d",
        output.get('risk_score', 0),
        output.get('risk_trend', '+0'),
        analysis_count
    )

    return output


# ══════════════════════════════════════════════════════════════
# 第六部份：本地測試入口（直接執行此檔案時）
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(message)s",
    )

    # 使用 Scout 記憶作為測試輸入
    _scout_output_path = os.path.join(PROJECT_ROOT, "memory", "scout_memory.json")

    if os.path.exists(_scout_output_path):
        with open(_scout_output_path, encoding="utf-8") as _f:
            _test_input = _f.read()
        print(f"[TEST] 使用 Scout 記憶作為輸入：{_scout_output_path}")
    else:
        _test_input = json.dumps({
            "scan_id": "scan_test_001",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tech_stack": ["Django 4.2", "Redis 7.0"],
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2024-42005",
                    "package": "django",
                    "cvss_score": 9.8,
                    "severity": "CRITICAL",
                    "description": "Django SQL injection vulnerability in QuerySet.values() and values_list()",
                    "is_new": True,
                },
                {
                    "cve_id": "CVE-2015-4335",
                    "package": "redis",
                    "cvss_score": 10.0,
                    "severity": "CRITICAL",
                    "description": "Redis Lua Sandbox Escape and Remote Code Execution",
                    "is_new": True,
                },
            ],
            "summary": {"total": 2, "critical": 2, "high": 0, "medium": 0, "low": 0},
        })
        print("[TEST] 使用預設測試輸入")

    result = run_analyst_pipeline(_test_input)
    print("\n=== Analyst 輸出 ===")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print(f"\nrisk_score: {result.get('risk_score', 0)}")
    print(f"risk_trend: {result.get('risk_trend', '+0')}")
    print(f"analysis count: {len(result.get('analysis', []))}")
