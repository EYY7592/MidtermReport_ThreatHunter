"""
ThreatHunter Orchestrator Agent
================================

職責：動態任務規劃 + Agent 分配 + 回饋迴路管理
架構依據：CrewAI Process.hierarchical + MacNet DAG 不規則拓撲
論文：arXiv:2406.07155 (MacNet) + LLM Discussion (arXiv:2405.06373)

邊界規則（AGENTS.md 合規）：
  本模組屬於 agents/ 層
  可引用 tools/ (第1層) 和 config.py
  不可引用 harness/constraints/ 或 harness/entropy/ 內容
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from crewai import Agent, Task

from core.config import (
    SKILLS_DIR,
    SYSTEM_CONSTITUTION,
    degradation_status,
    get_llm,
)
from tools.memory_tool import read_memory, write_memory

logger = logging.getLogger("threathunter.orchestrator")


# ── 掃描路徑類型（MacNet 動態路由）─────────────────────────────
class ScanPath(str, Enum):
    """動態任務路由路徑（對應 skills/orchestrator.md Step 2）"""
    PACKAGES_ONLY = "A"      # 輕量：套件掃描
    FULL_CODE = "B"          # 完整：程式碼 + 文件 + 套件
    DOCUMENTS_ONLY = "C"     # 文件弱配置掃描
    FEEDBACK_LOOP = "D"      # Judge 回饋 → 補充分析


# ── Orchestrator 執行上下文（共享記憶）──────────────────────────
@dataclass
class OrchestrationContext:
    """
    跨 Agent 的共享短期記憶。
    每次掃描建立一個實例，所有 Worker Agent 可讀寫。
    """
    scan_path: ScanPath = ScanPath.FULL_CODE
    agents_invoked: list[str] = field(default_factory=list)
    agents_skipped: list[str] = field(default_factory=list)
    shortcuts_taken: list[str] = field(default_factory=list)
    kev_hits: list[str] = field(default_factory=list)       # CISA KEV 命中的 CVE
    feedback_loops: int = 0
    max_feedback_loops: int = 2
    api_health: dict[str, str] = field(default_factory=dict)
    intermediate_results: dict[str, Any] = field(default_factory=dict)
    final_confidence: str = "NEEDS_VERIFICATION"
    start_time: float = field(default_factory=time.time)

    def record_invocation(self, agent_name: str) -> None:
        """記錄 Agent 被呼叫"""
        self.agents_invoked.append(agent_name)
        logger.info("[ORCH] Agent invoked: %s", agent_name)

    def record_skip(self, agent_name: str, reason: str) -> None:
        """記錄 Agent 被跳過（MacNet Small-World 優化）"""
        self.agents_skipped.append(agent_name)
        logger.info("[ORCH] Agent skipped: %s (reason: %s)", agent_name, reason)

    def record_shortcut(self, shortcut: str) -> None:
        """記錄走了捷徑（MacNet Small-World 邊）"""
        self.shortcuts_taken.append(shortcut)
        logger.info("[ORCH] Shortcut taken: %s", shortcut)

    def record_kev_hit(self, cve_id: str) -> None:
        """記錄 CISA KEV 命中（觸發 Small-World 捷徑）"""
        self.kev_hits.append(cve_id)
        logger.warning("[ORCH][CRITICAL] KEV Hit: %s → triggering shortcut", cve_id)

    def store_result(self, agent_name: str, result: Any) -> None:
        """儲存 Worker 輸出到共享上下文"""
        self.intermediate_results[agent_name] = result

    def get_result(self, agent_name: str) -> Any:
        """取得 Worker 輸出"""
        return self.intermediate_results.get(agent_name)

    def elapsed_seconds(self) -> float:
        """計算執行時間"""
        return time.time() - self.start_time

    def to_summary(self) -> dict:
        """輸出執行摘要（給 main.py 和 UI）"""
        return {
            "scan_path": self.scan_path.value,
            "agents_invoked": self.agents_invoked,
            "agents_skipped": self.agents_skipped,
            "shortcuts_taken": self.shortcuts_taken,
            "kev_hits": self.kev_hits,
            "feedback_loops": self.feedback_loops,
            "final_confidence": self.final_confidence,
            "elapsed_seconds": round(self.elapsed_seconds(), 1),
        }


# ── 輸入分類器（確定性程式碼，非 LLM）─────────────────────────
def classify_input(user_input: str | dict) -> ScanPath:
    """
    根據用戶輸入類型決定掃描路徑。

    這是確定性邏輯，不需要 LLM 推理。
    對應 skills/orchestrator.md Step 2。

    Args:
        user_input: 用戶提交的掃描請求

    Returns:
        ScanPath 枚舉值
    """
    # 支援 dict 格式（含 type 欄位）
    if isinstance(user_input, dict):
        input_type = user_input.get("type", "mixed")
        if input_type == "packages":
            return ScanPath.PACKAGES_ONLY
        elif input_type in ("document", "config"):
            return ScanPath.DOCUMENTS_ONLY
        elif input_type == "feedback":
            return ScanPath.FEEDBACK_LOOP
        return ScanPath.FULL_CODE

    # 純字串：啟發式分類
    text = str(user_input).lower()

    # 判斷是否是套件清單（無程式碼）
    if all(tok in text for tok in ["==", "\n"]) and "def " not in text and "class " not in text:
        return ScanPath.PACKAGES_ONLY

    # 判斷是否是文件類型
    doc_extensions = [".env", ".yaml", ".yml", ".json", ".ini", ".toml", "dockerfile"]
    if any(ext in text for ext in doc_extensions) and "def " not in text:
        return ScanPath.DOCUMENTS_ONLY

    return ScanPath.FULL_CODE


# ── MacNet Small-World 捷徑決策器 ───────────────────────────────
def check_shortcuts(ctx: OrchestrationContext, scan_result: dict) -> list[str]:
    """
    檢查是否有 MacNet Small-World 捷徑可以走。
    （不規則拓撲的核心：有條件的長程邊）

    Args:
        ctx: 當前執行上下文
        scan_result: 最近的掃描結果

    Returns:
        可走的捷徑列表
    """
    shortcuts = []

    # 捷徑 1：CISA KEV 命中 → Intel Fusion 直接通知 Analyst（跳過 Scout 重新評分）
    kev_hits = scan_result.get("kev_hits", [])
    if kev_hits:
        for cve_id in kev_hits:
            ctx.record_kev_hit(cve_id)
        shortcuts.append("kev_to_analyst_direct")
        logger.warning("[SHORTCUT] KEV hits detected, bypassing Scout re-scoring")

    # 捷徑 2：L0 正則無可疑點 → 跳過 L2 LLM（省 Token）
    l0_findings = scan_result.get("l0_findings", [])
    if len(l0_findings) == 0:
        shortcuts.append("skip_l2_llm")
        ctx.record_shortcut("skip_l2_llm")
        logger.info("[SHORTCUT] L0 found 0 suspicious patterns, skipping L2 LLM")

    # 捷徑 3：Debate 三方第一輪一致 → 跳過 Phase 2（省 6 次 LLM 呼叫）
    debate_consensus = scan_result.get("debate_consensus", False)
    if debate_consensus:
        shortcuts.append("debate_phase2_skipped")
        ctx.record_shortcut("debate_phase2_skipped")
        logger.info("[SHORTCUT] Debate consensus reached in Phase 1, skipping Phase 2")

    # 捷徑 4：所有 CVE 均為低危（CVSS < 4.0）→ 跳過 Debate Cluster
    vulnerabilities = scan_result.get("vulnerabilities", [])
    high_risk_vulns = [v for v in vulnerabilities if float(v.get("cvss_score", 0)) >= 4.0]
    if vulnerabilities and not high_risk_vulns:
        shortcuts.append("skip_debate_all_low")
        ctx.record_shortcut("skip_debate_all_low")
        logger.info("[SHORTCUT] All vulnerabilities low risk, skipping Debate Cluster")

    return shortcuts


# ── Orchestrator Agent 建構器 ────────────────────────────────────
def build_orchestrator_agent() -> Agent:
    """
    建立 Orchestrator Agent（CrewAI Manager）。

    使用高推理 LLM，負責動態任務規劃和 Agent 分配。
    對應 CrewAI Process.hierarchical 的 manager_agent。

    Returns:
        CrewAI Agent 實例
    """
    skill_path = SKILLS_DIR / "orchestrator.md"
    skill_content = skill_path.read_text(encoding="utf-8") if skill_path.exists() else ""

    backstory = f"""你是 ThreatHunter 的指揮官（CISO-level Manager）。
你負責動態規劃任務圖、分配 Worker Agents、審閱輸出品質、管理回饋迴路。
你不做具體漏洞分析，但你確保整個系統高效且準確地運作。

{SYSTEM_CONSTITUTION}

--- Orchestrator SOP ---
{skill_content}
"""

    llm = get_llm()

    return Agent(
        role="Security Operations Manager (Orchestrator)",
        goal=(
            "動態規劃掃描任務圖，根據輸入類型分配最適合的 Worker Agents，"
            "審閱每個 Agent 的輸出品質，並在信心度不足時觸發 Feedback Loop 進行補充分析。"
        ),
        backstory=backstory,
        llm=llm,
        verbose=True,
        allow_delegation=True,   # CrewAI Hierarchical 核心：允許委派任務
        max_iter=8,              # Manager 最多 8 次迭代（防止無限循環）
    )


# ── Orchestration 主函式 ─────────────────────────────────────────
def run_orchestration(
    user_input: str | dict,
    worker_results: dict[str, Any] | None = None,
    feedback_from_judge: dict | None = None,
) -> tuple[OrchestrationContext, dict]:
    """
    執行 Orchestrator 的任務規劃邏輯。

    這個函式實作 skills/orchestrator.md 的完整 SOP。
    不直接使用 LLM（規劃邏輯是確定性的），只在必要時呼叫 Agent。

    Args:
        user_input: 用戶的掃描請求
        worker_results: 已完成的 Worker 輸出（可選，用於捷徑檢查）
        feedback_from_judge: Judge 的回饋訊息（Feedback Loop 觸發時）

    Returns:
        (OrchestrationContext, task_plan_dict)
    """
    logger.info("[ORCH] Starting orchestration...")

    # Step 1：建立執行上下文
    ctx = OrchestrationContext()

    # Step 1a：讀取全局歷史狀態
    try:
        history = json.loads(read_memory.invoke({"agent_name": "orchestrator"}))
        ctx.api_health = history.get("api_health", {})
        logger.info("[ORCH] Historical API health loaded: %s", ctx.api_health)
    except Exception as e:
        logger.warning("[ORCH] Could not load orchestrator memory: %s", e)

    # Step 1b：若有 Feedback Loop 請求
    if feedback_from_judge:
        ctx.scan_path = ScanPath.FEEDBACK_LOOP
        ctx.feedback_loops += 1
        logger.info(
            "[ORCH] Feedback loop triggered (%d/%d): %s",
            ctx.feedback_loops,
            ctx.max_feedback_loops,
            feedback_from_judge.get("specific_question", "")
        )

        # 超過上限 → 強制輸出
        if ctx.feedback_loops > ctx.max_feedback_loops:
            logger.warning("[ORCH] Max feedback loops reached, forcing output with NEEDS_VERIFICATION")
            return ctx, {
                "action": "force_output",
                "confidence": "NEEDS_VERIFICATION",
                "reason": f"Max feedback loops ({ctx.max_feedback_loops}) reached",
                "target_cves": feedback_from_judge.get("target_cves", []),
            }

    # Step 2：輸入分類 → 決定掃描路徑
    if not feedback_from_judge:
        ctx.scan_path = classify_input(user_input)
    logger.info("[ORCH] Scan path determined: %s", ctx.scan_path.value)

    # Step 3：SmallWorld 捷徑檢查（若有中間結果）
    shortcuts = []
    if worker_results:
        shortcuts = check_shortcuts(ctx, worker_results)

    # Step 4：根據路徑建立任務規劃
    task_plan = _build_task_plan(ctx, shortcuts, feedback_from_judge)

    logger.info(
        "[ORCH] Task plan ready | path=%s | agents=%s | shortcuts=%s",
        ctx.scan_path.value,
        task_plan.get("agents_to_run", []),
        shortcuts,
    )

    return ctx, task_plan


def _build_task_plan(
    ctx: OrchestrationContext,
    shortcuts: list[str],
    feedback: dict | None,
) -> dict:
    """
    根據掃描路徑和捷徑建立任務規劃字典。

    對應 skills/orchestrator.md 的三條路徑設計。

    Args:
        ctx: 執行上下文
        shortcuts: 已確定的捷徑列表
        feedback: Judge 回饋（Feedback Loop 時）

    Returns:
        task_plan dict，包含要啟動的 Agent 順序和並行組
    """
    skip_debate = "skip_debate_all_low" in shortcuts
    skip_l2_llm = "skip_l2_llm" in shortcuts
    kev_shortcut = "kev_to_analyst_direct" in shortcuts

    if ctx.scan_path == ScanPath.PACKAGES_ONLY:
        # 路徑 A：輕量套件掃描
        ctx.record_skip("security_guard", "no code input")
        ctx.record_skip("doc_scanner", "no documents")
        return {
            "path": "A",
            "parallel_layer1": ["intel_fusion"],          # 只有情報融合
            "layer2": ["scout"],
            "layer3": ["analyst"] if not skip_debate else [],
            "debate_cluster": not skip_debate,
            "judge": True,
            "skip_l2_llm": True,                          # 套件掃描不需要 L2 LLM
            "kev_shortcut": kev_shortcut,
            "agents_to_run": ["intel_fusion", "scout", "analyst", "debate", "judge"],
        }

    elif ctx.scan_path == ScanPath.DOCUMENTS_ONLY:
        # 路徑 C：文件弱配置掃描
        ctx.record_skip("security_guard", "documents don't need LLM isolation")
        ctx.record_skip("analyst", "doc scanning doesn't need chain analysis")
        ctx.record_skip("debate_cluster", "doc findings don't need debate")
        return {
            "path": "C",
            "parallel_layer1": ["doc_scanner", "intel_fusion"],
            "layer2": ["scout"],
            "layer3": [],
            "debate_cluster": False,
            "judge": True,
            "skip_l2_llm": True,
            "kev_shortcut": False,
            "agents_to_run": ["doc_scanner", "intel_fusion", "scout", "judge"],
        }

    elif ctx.scan_path == ScanPath.FEEDBACK_LOOP:
        # 路徑 D：精準補充分析（不重跑整個 Pipeline）
        target_cves = feedback.get("target_cves", []) if feedback else []
        missing_data = feedback.get("missing_data", []) if feedback else []
        return {
            "path": "D",
            "parallel_layer1": ["intel_fusion"],          # 只補充情報
            "layer2": [],                                  # 跳過 Scout（已有結果）
            "layer3": ["analyst"],                         # 只分析目標 CVE
            "debate_cluster": True,
            "judge": True,
            "targeted_cves": target_cves,
            "missing_data": missing_data,
            "skip_l2_llm": skip_l2_llm,
            "kev_shortcut": kev_shortcut,
            "agents_to_run": ["intel_fusion", "analyst", "debate", "judge"],
        }

    else:
        # 路徑 B：完整程式碼掃描（預設）
        return {
            "path": "B",
            "parallel_layer1": [                          # MacNet Layer 1：並行
                "security_guard",
                "intel_fusion",
                "l0_l1_scanner",
            ],
            "layer2": ["scout"],                          # MacNet Layer 2：合成
            "layer3": ["analyst"] if not skip_debate else [],  # MacNet Layer 3：連鎖
            "debate_cluster": not skip_debate,            # MacNet Layer 4：ColMAD
            "judge": True,                                # MacNet Layer 5：裁決
            "skip_l2_llm": skip_l2_llm,
            "kev_shortcut": kev_shortcut,
            "agents_to_run": [
                "security_guard", "intel_fusion", "l0_l1_scanner",
                "scout", "analyst", "debate", "judge",
            ],
        }


# ── 結果品質審閱（CrewAI Hierarchical 的 Manager 審閱機制）───────
def review_worker_output(agent_name: str, output: Any, ctx: OrchestrationContext) -> tuple[bool, str]:
    """
    Manager 審閱 Worker 輸出品質。
    對應 CrewAI Hierarchical 中 Manager 的審閱機制。

    Args:
        agent_name: 輸出的 Agent 名稱
        output: Worker 的輸出（str 或 dict）
        ctx: 當前執行上下文

    Returns:
        (is_acceptable: bool, issue_description: str)
    """
    # 嘗試解析 JSON
    if isinstance(output, str):
        try:
            output_dict = json.loads(output)
        except json.JSONDecodeError:
            return False, f"{agent_name}: output is not valid JSON"
    else:
        output_dict = output

    # 各 Agent 的品質檢查標準
    quality_checks = {
        "security_guard": lambda o: (
            "functions" in o and "patterns" in o,
            "missing functions or patterns in extraction"
        ),
        "intel_fusion": lambda o: (
            "fusion_results" in o and len(o["fusion_results"]) > 0,
            "empty fusion_results"
        ),
        "scout": lambda o: (
            "vulnerabilities" in o,
            "missing vulnerabilities array"
        ),
        "analyst": lambda o: (
            "analysis" in o and "risk_score" in o,
            "missing analysis or risk_score"
        ),
        "debate": lambda o: (
            "debate_record" in o and "weighted_score" in o,
            "missing debate_record or weighted_score"
        ),
        "judge": lambda o: (
            "confidence" in o,
            "missing confidence field"
        ),
    }

    check = quality_checks.get(agent_name)
    if check is None:
        return True, ""  # 未知 Agent，放行

    is_ok, issue = check(output_dict)
    if not is_ok:
        logger.warning("[ORCH][REVIEW] %s output rejected: %s", agent_name, issue)
        return False, issue

    # 儲存通過審閱的結果到共享上下文
    ctx.store_result(agent_name, output_dict)
    logger.info("[ORCH][REVIEW] %s output accepted", agent_name)
    return True, ""


# ── 執行結束：寫入 Orchestration 摘要 ───────────────────────────
def finalize_orchestration(ctx: OrchestrationContext) -> dict:
    """
    掃描結束時，寫入執行摘要到記憶，輸出給 main.py。

    Args:
        ctx: 最終執行上下文

    Returns:
        orchestration_summary dict
    """
    summary = ctx.to_summary()

    # 寫入長期記憶（包含 API 健康狀態，供下次 Intel Fusion 讀取）
    try:
        intel_result = ctx.get_result("intel_fusion") or {}
        api_health = intel_result.get("api_health_summary", {})

        memory_payload = json.dumps({
            "api_health": api_health,
            "last_scan_path": summary["scan_path"],
            "last_shortcuts": summary["shortcuts_taken"],
            "last_elapsed_s": summary["elapsed_seconds"],
        })
        write_memory.invoke({"agent_name": "orchestrator", "content": memory_payload})
        logger.info("[ORCH] Orchestration summary written to memory")
    except Exception as e:
        logger.warning("[ORCH] Could not write orchestration memory: %s", e)

    logger.info(
        "[ORCH] Done | path=%s | agents=%d | shortcuts=%d | loops=%d | confidence=%s | time=%.1fs",
        summary["scan_path"],
        len(summary["agents_invoked"]),
        len(summary["shortcuts_taken"]),
        summary["feedback_loops"],
        summary["final_confidence"],
        summary["elapsed_seconds"],
    )

    return summary
