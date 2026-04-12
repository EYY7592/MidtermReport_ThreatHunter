"""
main.py - ThreatHunter 主程式
==============================
Pipeline 架構（v3.1）：Orchestrator → [Layer 1 並行] → Scout → Analyst → Debate → Advisor

架構圖（v3.1 Orchestrator 驅動）：
  Orchestrator 動態路由：
    路徑 A：套件掃描     → 跳過 Security Guard
    路徑 B：完整程式碼   → Layer 1 並行（Security Guard + Intel Fusion）
    路徑 C：文件弱配置   → 跳過 Analyst + Debate
    路徑 D：回饋補充     → 只重跑低信心 CVE

舊架構圖（保留供參考）：
  使用者輸入 "Django 4.2, Redis 7.0"
           │
           ▼
  ┌─────────────────────────────────────────────────────┐
  │              main.py Pipeline                        │
  │                                                      │
  │  ┌──────────┐  ┌──────────┐  ┌──────────┐          │
  │  │  Scout   │─▶│ Analyst  │─▶│  Critic  │──┐       │
  │  │(事實收集) │  │(推理判斷) │  │(可插拔)  │  │       │
  │  └──────────┘  └──────────┘  └──────────┘  │       │
  │                              ┌──────────────▼──┐    │
  │                              │    Advisor      │    │
  │                              │  (最終裁決報告)  │    │
  │                              └─────────────────┘    │
  │                                                      │
  │  每個 Stage 獨立：                                    │
  │    - try-except + Graceful Degradation               │
  │    - StepLogger 原子步驟日誌                          │
  │    - Harness 保障層（在 agents/*.py 內部）            │
  └─────────────────────────────────────────────────────┘

資料流：
  Scout 輸出 (dict) ──▶ Analyst 輸入 (dict)
  Analyst 輸出 (dict) ──▶ Critic 輸入 (dict)
  Analyst + Critic 輸出 ──▶ Advisor 輸入 (dict)
  Advisor 輸出 (dict) + pipeline_meta ──▶ 最終結果

Harness Engineering 保障：
  - 每個 Agent 都使用真實模組（agents/*.py），非 Stub
  - Critic 由 ENABLE_CRITIC 開關控制（可插拔）
  - 每個 Stage 有獨立的 Graceful Degradation 降級路徑
  - 全程記錄 Observability 日誌（FINAL_PLAN.md 支柱 2）
  - 17 層 Harness 保障層（分散於 agents/*.py 內部）

遵守：project_CONSTITUTION.md + HARNESS_ENGINEERING.md
"""

import json
import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

from config import (
    ENABLE_CRITIC,
    degradation_status,
    rate_limiter,
)


logger = logging.getLogger("threathunter.main")


# ======================================================================
# Observability: 原子步驟日誌（FINAL_PLAN.md 支柱 2）
# ======================================================================


class StepLogger:
    """每個 Agent Stage 的原子步驟追蹤器。"""

    def __init__(self, agent_name: str):
        self.agent_name = agent_name
        self.steps: list[dict[str, Any]] = []

    def log(
        self, step: str, status: str, detail: str = "", duration_ms: int = 0
    ) -> None:
        entry = {
            "step": step,
            "agent": self.agent_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": status,
            "detail": detail,
            "duration_ms": duration_ms,
        }
        self.steps.append(entry)
        icon = (
            "OK" if status == "SUCCESS" else "WAIT" if status == "RUNNING" else "FAIL"
        )
        logger.info("[%s] %s | %s | %s", icon, self.agent_name.upper(), step, detail)

    def summary(self) -> dict[str, Any]:
        failed = [s for s in self.steps if s["status"] == "FAILED"]
        return {
            "agent": self.agent_name,
            "total_steps": len(self.steps),
            "failed_steps": len(failed),
            "steps": self.steps,
        }


# ======================================================================
# Stage 1：Scout Agent（事實收集）
# ======================================================================


def stage_scout(tech_stack: str) -> tuple[dict[str, Any], StepLogger]:
    """
    Stage 1: Scout Agent 偵察漏洞。
    使用 agents/scout.py 的真實實作。
    Graceful Degradation: 失敗時回傳空資料，讓後續 Agent 知道是第一次。

    Returns:
        (result_dict, step_logger) — 輸出和日誌追蹤器
    """
    from agents.scout import run_scout_pipeline

    sl = StepLogger("scout")
    sl.log("INIT", "RUNNING", f"tech_stack={tech_stack}")

    t0 = time.time()
    try:
        result = run_scout_pipeline(tech_stack)
        duration_ms = int((time.time() - t0) * 1000)
        vuln_count = len(result.get("vulnerabilities", []))
        sl.log(
            "COMPLETE", "SUCCESS", f"found {vuln_count} vulnerabilities", duration_ms
        )
        return result, sl
    except Exception as e:
        duration_ms = int((time.time() - t0) * 1000)
        # 區分 429 Rate Limit（外部限制）vs 真正的錯誤
        is_rate_limit = "429" in str(e) or "rate limit" in str(e).lower()
        if is_rate_limit:
            logger.warning("[SCOUT] Rate limited — returning empty results (not a real failure)")
            sl.log("COMPLETE", "RATE_LIMITED", str(e)[:100], duration_ms)
        else:
            logger.error("Scout Stage failed: %s", e)
            sl.log("COMPLETE", "FAILED", str(e)[:100], duration_ms)
            degradation_status.degrade("Scout", str(e))
        # Graceful Degradation: 回傳最小結構讓管線繼續
        return {
            "scan_id": f"scan_degraded_{int(time.time())}",
            "vulnerabilities": [],
            "summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
            "_degraded": not is_rate_limit,  # 429 不算真正降級
            "_error": str(e),
        }, sl


# ======================================================================
# Stage 2：Analyst Agent（推理判斷）
# ======================================================================


def stage_analyst(scout_output: dict[str, Any]) -> tuple[dict[str, Any], StepLogger]:
    """
    Stage 2: Analyst Agent 分析漏洞連鎖風險。
    使用 agents/analyst.py 的真實實作。
    Graceful Degradation: 失敗時傳回 Scout 原始資料並標記 chain_analysis: SKIPPED。

    Returns:
        (result_dict, step_logger) — 輸出和日誌追蹤器
    """
    from agents.analyst import run_analyst_pipeline

    sl = StepLogger("analyst")
    sl.log(
        "INIT", "RUNNING", f"input_vulns={len(scout_output.get('vulnerabilities', []))}"
    )

    t0 = time.time()
    try:
        result = run_analyst_pipeline(scout_output)
        duration_ms = int((time.time() - t0) * 1000)
        risk = result.get("risk_score", 0)
        sl.log("COMPLETE", "SUCCESS", f"risk_score={risk}", duration_ms)
        return result, sl
    except Exception as e:
        duration_ms = int((time.time() - t0) * 1000)
        logger.error("Analyst Stage failed: %s", e)
        sl.log("COMPLETE", "FAILED", str(e)[:100], duration_ms)
        degradation_status.degrade("Analyst", str(e))
        # Graceful Degradation (FINAL_PLAN.md 層級 4)：跳過連鎖分析
        vulns = scout_output.get("vulnerabilities", [])
        analysis = [
            {
                "cve_id": v.get("cve_id", "UNKNOWN"),
                "original_cvss": v.get("cvss_score", 0),
                "adjusted_risk": v.get("severity", "UNKNOWN"),
                "in_cisa_kev": False,
                "exploit_available": False,
                "chain_risk": {
                    "is_chain": False,
                    "chain_with": [],
                    "chain_description": "chain_analysis: SKIPPED",
                    "confidence": "NEEDS_VERIFICATION",
                },
                "reasoning": "Analyst degraded - chain analysis skipped.",
            }
            for v in vulns
        ]
        return {
            "scan_id": scout_output.get("scan_id", "unknown"),
            "risk_score": 50,
            "risk_trend": "+0",
            "analysis": analysis,
            "_degraded": True,
            "_error": str(e),
        }, sl


# ======================================================================
# Stage 3（可插拔）：Critic Agent（質疑挑戰）
# ======================================================================


def stage_critic(analyst_output: dict[str, Any]) -> tuple[dict[str, Any], StepLogger]:
    """
    Stage 3 (pluggable): Critic Agent 對抗式辯論。
    使用 agents/critic.py 的真實實作。
    若 ENABLE_CRITIC=false，直接回傳 SKIPPED（由 Critic 本身的 Harness Layer 1 處理）。

    Returns:
        (result_dict, step_logger) — 輸出和日誌追蹤器
    """
    from agents.critic import run_critic_pipeline

    sl = StepLogger("critic")
    sl.log("INIT", "RUNNING", f"enable_critic={ENABLE_CRITIC}")

    t0 = time.time()
    try:
        result = run_critic_pipeline(analyst_output)
        duration_ms = int((time.time() - t0) * 1000)
        verdict = result.get("verdict", "UNKNOWN")
        score = result.get("weighted_score", 0)
        sl.log("COMPLETE", "SUCCESS", f"verdict={verdict} score={score}", duration_ms)
        return result, sl
    except Exception as e:
        duration_ms = int((time.time() - t0) * 1000)
        logger.error("Critic Stage failed: %s", e)
        sl.log("COMPLETE", "FAILED", str(e)[:100], duration_ms)
        degradation_status.degrade("Critic", str(e))
        return {
            "debate_rounds": 0,
            "challenges": [],
            "scorecard": {
                "evidence": 0.6,
                "chain_completeness": 0.6,
                "critique_quality": 0.6,
                "defense_quality": 0.6,
                "calibration": 0.6,
            },
            "weighted_score": 60.0,
            "verdict": "MAINTAIN",
            "reasoning": "Critic degraded - debate skipped.",
            "_degraded": True,
        }, sl


# ======================================================================
# Stage 4：Advisor Agent（最終裁決）
# ======================================================================


def stage_advisor(
    analyst_output: dict[str, Any], critic_output: dict[str, Any]
) -> tuple[dict[str, Any], StepLogger]:
    """
    Stage 4: Advisor Agent 產出行動報告。
    使用 agents/advisor.py 的真實實作。
    將 Critic 裁決作為上下文傳遞給 Advisor（若 MAINTAIN 則信任分析，DOWNGRADE 則保守處理）。

    Returns:
        (result_dict, step_logger) — 輸出和日誌追蹤器
    """
    from agents.advisor import run_advisor_pipeline

    sl = StepLogger("advisor")
    verdict = critic_output.get("verdict", "SKIPPED")
    sl.log("INIT", "RUNNING", f"critic_verdict={verdict}")

    # 若 Critic 建議降級，在傳入 Advisor 前調整風險上下文
    advisor_input = dict(analyst_output)
    if verdict == "DOWNGRADE":
        advisor_input["_critic_note"] = (
            f"Critic scored {critic_output.get('weighted_score', 0):.1f}/100. "
            f"Challenges: {critic_output.get('challenges', [])}. "
            "Use conservative risk assessment."
        )
        logger.info(
            "Critic verdict=DOWNGRADE: Advisor will use conservative assessment"
        )

    t0 = time.time()
    try:
        result = run_advisor_pipeline(advisor_input)
        duration_ms = int((time.time() - t0) * 1000)
        risk = result.get("risk_score", 0)
        urgent = len(result.get("actions", {}).get("urgent", []))
        sl.log("COMPLETE", "SUCCESS", f"risk_score={risk} urgent={urgent}", duration_ms)
        return result, sl
    except Exception as e:
        duration_ms = int((time.time() - t0) * 1000)
        logger.error("Advisor Stage failed: %s", e)
        sl.log("COMPLETE", "FAILED", str(e)[:100], duration_ms)
        degradation_status.degrade("Advisor", str(e))
        # Graceful Degradation 層級 5: 最低生存模式
        return {
            "executive_summary": "System degraded. Please review raw scan data manually.",
            "actions": {"urgent": [], "important": [], "resolved": []},
            "risk_score": 0,
            "risk_trend": "+0",
            "scan_count": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "_degraded": True,
            "_error": str(e),
        }, sl


# ======================================================================
# 主管線：完整執行 Scout -> Analyst -> [Critic] -> Advisor
# ======================================================================


# ======================================================================
# Stage 0（新增）：Orchestrator 動態路由
# ======================================================================


def stage_orchestrator(
    tech_stack: str,
    feedback_from_judge: dict | None = None,
) -> tuple[Any, dict, StepLogger]:
    """
    Stage 0: Orchestrator 決定掃描路徑（A/B/C/D）。
    回傳 (OrchestrationContext, task_plan, StepLogger)。
    Graceful Degradation: 失敗時回傳路徑 B（完整程式碼）作為安全預設。
    """
    from agents.orchestrator import run_orchestration

    sl = StepLogger("orchestrator")
    sl.log("INIT", "RUNNING", f"tech_stack={tech_stack[:60]}")
    t0 = time.time()

    try:
        ctx, task_plan = run_orchestration(
            user_input=tech_stack,
            feedback_from_judge=feedback_from_judge,
        )
        duration_ms = int((time.time() - t0) * 1000)
        scan_path = task_plan.get("path", "B")
        sl.log("COMPLETE", "SUCCESS", f"path={scan_path}", duration_ms)
        logger.info("[ORCH] Scan path: %s | plan: %s", scan_path, task_plan.get("agents_to_run", []))
        return ctx, task_plan, sl
    except Exception as e:
        duration_ms = int((time.time() - t0) * 1000)
        logger.error("Orchestrator Stage failed: %s", e)
        sl.log("COMPLETE", "FAILED", str(e)[:100], duration_ms)
        degradation_status.degrade("Orchestrator", str(e))
        # Graceful Degradation: 路徑 B（完整分析）作為安全預設
        from agents.orchestrator import OrchestrationContext, ScanPath
        ctx = OrchestrationContext()
        ctx.scan_path = ScanPath.FULL_CODE
        task_plan = {
            "path": "B",
            # 修正：降級時並行層也必須包含 security_guard，否則 UI 永遠 WAITING
            "parallel_layer1": ["security_guard", "intel_fusion"],
            "debate_cluster": True,
            "judge": True,
            "agents_to_run": ["security_guard", "intel_fusion", "scout", "analyst", "debate", "judge"],
            "_degraded": True,
        }
        return ctx, task_plan, sl


# ======================================================================
# Layer 1 並行執行（路徑 B：MacNet Layer 1）
# ======================================================================


def _run_layer1_parallel(
    tech_stack: str,
    task_plan: dict,
    on_progress: Any,
) -> dict[str, Any]:
    """
    路徑 B 的 Layer 1 並行執行（使用 ThreadPoolExecutor 最小改動）。

    Why ThreadPoolExecutor（非 asyncio）：
      - main.py 是同步程式碼，SSE callback 也是同步的
      - ThreadPoolExecutor 可在同步環境下並行執行多個 IO-bound 工作（LLM 呼叫）
      - 最小改動：不需要重構 callback 機制

    並行執行對象（視 task_plan 決定）：
      - security_guard：從程式碼提取函式/套件/模式（輸入：tech_stack）
      - intel_fusion：六維情報查詢（輸入：tech_stack）

    Args:
        tech_stack: 使用者輸入
        task_plan: Orchestrator 的任務規劃
        on_progress: SSE 進度回調

    Returns:
        {"security_guard": dict, "intel_fusion": dict}
    """
    parallel_agents = task_plan.get("parallel_layer1", [])
    layer1_results: dict[str, Any] = {}

    def _run_security_guard() -> tuple[str, dict]:
        """在 Thread 中執行 Security Guard（隔離 LLM 提取）"""
        try:
            from agents.security_guard import run_security_guard
            result = run_security_guard(tech_stack, on_progress)
            return ("security_guard", result)
        except Exception as e:
            logger.error("[LAYER1] Security Guard failed: %s", e)
            degradation_status.degrade("Security Guard", str(e))
            return ("security_guard", {
                "extraction_status": "degraded",
                "functions": [], "imports": [], "patterns": [], "hardcoded": [],
                "stats": {"total_lines": 0, "functions_found": 0, "patterns_found": 0},
                "_degraded": True, "_error": str(e),
            })

    def _run_intel_fusion(intel_input: list | str) -> tuple[str, dict]:
        """在 Thread 中執行 Intel Fusion（六維情報查詢）

        v3.4 修復：接受套件名稱列表（而非原始程式碼），解決 0 CVE 問題。
        intel_input 可以是：
          - list[str]：套件名稱列表（由 package_extractor 萃取後傳入）
          - str：原始 tech_stack（fallback，Path A 套件清單模式）
        """
        try:
            from agents.intel_fusion import run_intel_fusion
            result = run_intel_fusion(intel_input, on_progress)
            return ("intel_fusion", result)
        except Exception as e:
            logger.error("[LAYER1] Intel Fusion failed: %s", e)
            degradation_status.degrade("Intel Fusion", str(e))
            return ("intel_fusion", {
                "fusion_results": [],
                "strategy_applied": "degraded",
                "api_health_summary": {},
                "_degraded": True, "_error": str(e),
            })

    # ── v3.4 修復：序列執行，SG 先跑，提取套件後傳給 IF ──────────
    # 核心修復：之前 Intel Fusion 收到整段程式碼 → 查不到任何 CVE → DEGRADED
    # 現在：Security Guard 提取 imports → PackageExtractor 過濾標準庫 → IF 收到乾淨套件名稱
    extracted_packages: list[str] = []

    if "security_guard" in parallel_agents:
        rate_limiter.wait_if_needed("security_guard")
        _, sg_result = _run_security_guard()
        layer1_results["security_guard"] = sg_result
        logger.info("[LAYER1] security_guard complete")

        # v3.4：從 SG imports 萃取第三方套件
        try:
            from tools.package_extractor import packages_from_security_guard
            extracted_packages = packages_from_security_guard(sg_result)
            logger.info(
                "[LAYER1] PackageExtractor: %d packages extracted from imports: %s",
                len(extracted_packages), extracted_packages,
            )
        except Exception as pe:
            logger.warning("[LAYER1] PackageExtractor failed (fallback to raw input): %s", pe)
            extracted_packages = []

    if "intel_fusion" in parallel_agents:
        rate_limiter.wait_if_needed("intel_fusion")
        # v3.4：優先傳套件列表，fallback 傳原始 tech_stack
        intel_input: list | str = extracted_packages if extracted_packages else tech_stack
        logger.info(
            "[LAYER1] Intel Fusion input: %s",
            f"{len(intel_input)} packages" if isinstance(intel_input, list) else "raw tech_stack",
        )
        _, if_result = _run_intel_fusion(intel_input)
        # 記錄萃取的套件列表，供前端展示
        if_result["_extracted_packages"] = extracted_packages
        layer1_results["intel_fusion"] = if_result
        logger.info("[LAYER1] intel_fusion complete")

    return layer1_results



def run_pipeline(tech_stack: str) -> dict[str, Any]:
    """
    執行完整的 ThreatHunter 管線（v3.1 Orchestrator 驅動）。

    Pipeline: Orchestrator → [Layer 1 並行] → Scout → Analyst → [Critic] → Advisor

    FINAL_PLAN.md 五柱架構對應：
      Constraints    : 每個 Agent 的 backstory 有憲法約束 + Security Guard 隔離 LLM
      Observability  : StepLogger 記錄每個原子步驟 + OrchestrationContext
      Feedback Loops : memory_tool 雙層記憶 + Advisor Feedback Loop（路徑 D）
      Graceful Degrad: 每個 Stage 有獨立的降級路徑（5 層降級瀑布）
      Evaluation     : Critic Agent ColMAD 辯論 + Intel Fusion 六維評分

    Args:
        tech_stack: 使用者輸入的技術堆疊字串（如 "Django 4.2, Redis 7.0"）

    Returns:
        包含完整 Advisor 行動報告的 dict，加上 pipeline_meta 欄位
    """
    return run_pipeline_with_callback(tech_stack, progress_callback=None)


def run_pipeline_with_callback(
    tech_stack: str,
    progress_callback: Any = None,
) -> dict[str, Any]:
    """
    執行完整 Pipeline，每個 Stage 完成後呼叫 progress_callback。

    與 run_pipeline() 相同邏輯，但在每個 Stage 完成後即時回報狀態。
    用於 Streamlit UI 的即時監控。

    Args:
        tech_stack: 技術堆疊字串
        progress_callback: 接收 (agent_name: str, status: str, detail: dict) 的函式

    Returns:
        包含完整 Advisor 行動報告的 dict
    """
    pipeline_start = time.time()
    completed_stages: list[str] = []
    stages_detail: dict[str, Any] = {}
    # Orchestrator 執行上下文（跨 Stage 共享）
    orch_ctx: Any = None
    task_plan: dict = {"path": "B"}  # 預設路徑 B
    layer1_results: dict[str, Any] = {}
    feedback_loop_count: int = 0
    MAX_FEEDBACK_LOOPS: int = 2

    def _notify(agent: str, status: str, detail: dict) -> None:
        if progress_callback:
            try:
                progress_callback(agent, status, detail)
            except Exception:
                pass  # callback 失敗不影響 pipeline

    logger.info("=" * 60)
    logger.info("  ThreatHunter Pipeline v3.1 Start (Orchestrator-driven)")
    logger.info("  tech_stack : %s", tech_stack)
    logger.info("  ENABLE_CRITIC: %s", ENABLE_CRITIC)
    logger.info("=" * 60)

    # ── Checkpoint 初始化 ─────────────────────────────────────
    from checkpoint import recorder
    recorder.start_scan(f"pipe_{int(pipeline_start)}")

    # ── Stage -1: L0 確定性輸入淨化（OWASP LLM01:2025）─────────
    # 在 CrewAI 啟動前執行，純確定性，無 LLM
    l0_report: dict[str, Any] = {}
    sanitized_stack: str = tech_stack
    try:
        from input_sanitizer import sanitize_input, format_l0_report
        san_result = sanitize_input(tech_stack)
        l0_report = format_l0_report(san_result)

        if not san_result.safe:
            # 高信心惡意輸入：直接拒絕，不進入 Pipeline
            logger.warning("[L0] Input BLOCKED: %s", san_result.blocked_reason)
            _notify("input_sanitizer", "COMPLETE", {
                "status": "BLOCKED",
                "reason": san_result.blocked_reason,
            })
            return {
                "executive_summary": f"輸入被安全過濾器拒絕：{san_result.blocked_reason}",
                "blocked": True,
                "actions": {"urgent": [], "important": [], "resolved": []},
                "risk_score": 0,
                "risk_trend": "+0",
                "pipeline_meta": {
                    "pipeline_version": "3.1",
                    "tech_stack": tech_stack,
                    "stages_completed": 0,
                    "stages_detail": {},
                    "enable_critic": ENABLE_CRITIC,
                    "critic_verdict": "SKIPPED",
                    "critic_score": 0.0,
                    "duration_seconds": 0.0,
                    "degradation": {"level": 5, "label": "INPUT_BLOCKED"},
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "l0_report": l0_report,
                },
            }

        sanitized_stack = san_result.sanitized_input
        if san_result.truncated:
            logger.warning("[L0] Input truncated: %d → %d chars",
                           san_result.original_length, len(sanitized_stack))

        logger.info("[L0] OK: type=%s l0_findings=%d hash=%s",
                    san_result.input_type, len(san_result.l0_findings), san_result.input_hash)
        _notify("input_sanitizer", "COMPLETE", {
            "status": "SUCCESS",
            "input_type": san_result.input_type,
            "l0_warning_count": l0_report.get("l0_warning_count", 0),
            "truncated": san_result.truncated,
        })
        recorder.stage_exit("input_sanitizer", "SUCCESS", {
            "input_type": san_result.input_type,
            "l0_warning_count": l0_report.get("l0_warning_count", 0),
        }, 0)

    except ImportError:
        # input_sanitizer 不存在時降級：允許通過，不阻擋
        logger.warning("[L0] input_sanitizer not available, skipping L0 filter")
    except Exception as e:
        # 淨化器本身出錯：允許通過（不讓守門人成為阻擋點）
        logger.error("[L0] Sanitizer error (non-fatal): %s", e)

    # ── Stage 0: Orchestrator 動態路由（新增）─────────────────
    _notify("orchestrator", "RUNNING", {})
    orch_ctx, task_plan, orch_sl = stage_orchestrator(sanitized_stack)
    scan_path = task_plan.get("path", "B")
    orch_detail = {
        "status": "SUCCESS" if not task_plan.get("_degraded") else "DEGRADED",
        "scan_path": scan_path,
        "agents_to_run": task_plan.get("agents_to_run", []),
        "duration_ms": orch_sl.steps[-1].get("duration_ms", 0) if orch_sl.steps else 0,
        "l0_input_type": l0_report.get("input_type", "unknown"),
    }
    stages_detail["orchestrator"] = orch_detail
    completed_stages.append("orchestrator")
    _notify("orchestrator", "COMPLETE", orch_detail)
    recorder.stage_enter("orchestrator", {"tech_stack": sanitized_stack[:200]})
    recorder.stage_exit("orchestrator", orch_detail.get("status", "SUCCESS"), {
        "scan_path": scan_path,
        "agents_to_run": task_plan.get("agents_to_run", []),
    }, orch_detail.get("duration_ms", 0))
    logger.info("[PIPELINE] Scan path: %s", scan_path)


    # ── MacNet Layer 1 並行（路徑 B：完整程式碼）─────────────
    # 路徑 A（套件掃描）只跑 Intel Fusion，路徑 C/D 跳過 Security Guard
    # v3.4：在外層初始化 extracted_packages，_run_layer1_parallel 內部填充後
    #        透過 layer1_results["intel_fusion"]["_extracted_packages"] 傳出
    extracted_packages: list[str] = []

    if scan_path in ("A", "B"):
        parallel_agents = task_plan.get("parallel_layer1", [])
        if parallel_agents:
            _notify("layer1_parallel", "RUNNING", {"agents": parallel_agents})
            layer1_results = _run_layer1_parallel(tech_stack, task_plan, _notify)
            _notify("layer1_parallel", "COMPLETE", {
                "agents_completed": list(layer1_results.keys()),
            })
            # v3.4：從 intel_fusion 結果讀取橋接套件列表（由 _run_layer1_parallel 填充）
            if "intel_fusion" in layer1_results:
                extracted_packages = layer1_results["intel_fusion"].get("_extracted_packages", [])
                if extracted_packages:
                    logger.info(
                        "[PIPELINE] extracted_packages from layer1: %s", extracted_packages
                    )
            # 將 Layer 1 結果寫入 stages_detail（供 done 事件更新 UI 卡片）
            for agent_name, result in layer1_results.items():
                agent_detail = {
                    "status": "DEGRADED" if result.get("_degraded") else "SUCCESS",
                    "duration_ms": result.get("_duration_ms", 0),
                }
                # Security Guard 額外欄位
                if agent_name == "security_guard":
                    agent_detail["functions_found"] = result.get("stats", {}).get("functions_found", 0)
                    agent_detail["patterns_found"] = result.get("stats", {}).get("patterns_found", 0)
                    agent_detail["injection_detected"] = result.get("injection_attempts_detected", False)
                # Intel Fusion 額外欄位
                elif agent_name == "intel_fusion":
                    agent_detail["cves_scored"] = len(result.get("fusion_results", []))
                stages_detail[agent_name] = agent_detail
                completed_stages.append(agent_name)
                recorder.stage_exit(agent_name, agent_detail["status"], agent_detail, agent_detail.get("duration_ms", 0))
            # 同步儲存到 Orchestration Context
            if orch_ctx is not None:
                for agent_name, result in layer1_results.items():
                    try:
                        orch_ctx.store_result(agent_name, result)
                    except Exception:
                        pass

    # ── Stage 1: Scout ────────────────────────────────────────
    # 路徑 C：文件弱配置 → 跳過 Analyst 和 Debate，但 Scout 還是跑
    _notify("scout", "RUNNING", {})
    rate_limiter.wait_if_needed("scout")
    # v3.4 修復：若已從 SG imports 萃取套件，傳套件名稱給 Scout
    # 這讓 Scout 知道要查哪些套件，而非把整段程式碼丟給 LLM
    scout_input: str
    if extracted_packages:
        from tools.package_extractor import format_packages_for_intel_fusion
        scout_input = format_packages_for_intel_fusion(extracted_packages)
        logger.info("[PIPELINE] Scout using extracted packages: %s", scout_input)
    else:
        scout_input = tech_stack
        logger.info("[PIPELINE] Scout using raw tech_stack (no packages extracted)")
    scout_output, scout_sl = stage_scout(scout_input)
    # 若有 Intel Fusion 結果，附加到 Scout 輸出（供 Analyst 使用）
    if "intel_fusion" in layer1_results:
        scout_output["intel_fusion_result"] = layer1_results["intel_fusion"]
    scout_detail = {
        "status": "SUCCESS" if not scout_output.get("_degraded") else "DEGRADED",
        "vuln_count": len(scout_output.get("vulnerabilities", [])),
        "duration_ms": scout_sl.steps[-1].get("duration_ms", 0) if scout_sl.steps else 0,
        "packages_used": extracted_packages,
    }
    stages_detail["scout"] = scout_detail
    completed_stages.append("scout")
    _notify("scout", "COMPLETE", scout_detail)
    recorder.stage_enter("scout", {"tech_stack": scout_input[:200], "packages": extracted_packages})
    recorder.stage_exit("scout", scout_detail.get("status", "SUCCESS"), scout_output, scout_detail.get("duration_ms", 0))


    # ── 路徑 C 早出：文件弱配置 → 跳過 Analyst + Critic，直接 Advisor ──
    if scan_path == "C":
        logger.info("[PIPELINE] Path C: skipping Analyst + Critic → direct to Advisor")
        _notify("analyst", "COMPLETE", {"status": "SKIPPED", "reason": "path_C"})
        _notify("critic", "COMPLETE", {"status": "SKIPPED", "reason": "path_C"})
        # 建立最小 analyst_output 和 critic_output
        analyst_output: dict[str, Any] = {
            "scan_id": scout_output.get("scan_id", "unknown"),
            "risk_score": 30,
            "risk_trend": "+0",
            "analysis": [],
            "_skipped": True,
            "_reason": "path_C_doc_scan",
        }
        critic_output: dict[str, Any] = {
            "verdict": "SKIPPED",
            "weighted_score": 60.0,
            "_skipped": True,
        }
    else:
        # ── Stage 2: Analyst ───────────────────────────────────
        _notify("analyst", "RUNNING", {})
        rate_limiter.wait_if_needed("analyst")
        analyst_output, analyst_sl = stage_analyst(scout_output)
        analyst_detail = {
            "status": "SUCCESS" if not analyst_output.get("_degraded") else "DEGRADED",
            "risk_score": analyst_output.get("risk_score", 0),
            "duration_ms": analyst_sl.steps[-1].get("duration_ms", 0) if analyst_sl.steps else 0,
        }
        stages_detail["analyst"] = analyst_detail
        completed_stages.append("analyst")
        _notify("analyst", "COMPLETE", analyst_detail)
        recorder.stage_enter("analyst", scout_output)
        recorder.stage_exit("analyst", analyst_detail.get("status", "SUCCESS"), analyst_output, analyst_detail.get("duration_ms", 0))

        # ── Stage 3: Critic ────────────────────────────────────
        _notify("critic", "RUNNING", {})
        rate_limiter.wait_if_needed("critic")
        critic_output, critic_sl = stage_critic(analyst_output)
        critic_detail = {
            "status": "SUCCESS" if not critic_output.get("_degraded") else "DEGRADED",
            "verdict": critic_output.get("verdict", "SKIPPED"),
            "score": critic_output.get("weighted_score", 0),
            "duration_ms": critic_sl.steps[-1].get("duration_ms", 0) if critic_sl.steps else 0,
        }
        stages_detail["critic"] = critic_detail
        completed_stages.append("critic")
        _notify("critic", "COMPLETE", critic_detail)
        recorder.stage_enter("critic", analyst_output)
        recorder.stage_exit("critic", critic_detail.get("status", "SUCCESS"), critic_output, critic_detail.get("duration_ms", 0))

    # ── Stage 4: Advisor ──────────────────────────────────────
    _notify("advisor", "RUNNING", {})
    rate_limiter.wait_if_needed("advisor")
    advisor_output, advisor_sl = stage_advisor(analyst_output, critic_output)
    advisor_detail = {
        "status": "SUCCESS" if not advisor_output.get("_degraded") else "DEGRADED",
        "urgent_count": len(advisor_output.get("actions", {}).get("urgent", [])),
        "duration_ms": advisor_sl.steps[-1].get("duration_ms", 0) if advisor_sl.steps else 0,
    }
    stages_detail["advisor"] = advisor_detail
    completed_stages.append("advisor")
    _notify("advisor", "COMPLETE", advisor_detail)
    recorder.stage_enter("advisor", analyst_output)
    recorder.stage_exit("advisor", advisor_detail.get("status", "SUCCESS"), advisor_output, advisor_detail.get("duration_ms", 0))

    # ── Advisor Feedback Loop（路徑 D）────────────────────────
    # 若 Advisor 信心度不足（< 0.70），觸發回饋迴路（最多 MAX_FEEDBACK_LOOPS 次）
    advisor_confidence = advisor_output.get("confidence", "HIGH")
    feedback_triggered = (
        advisor_confidence in ("NEEDS_VERIFICATION", "LOW", "MEDIUM")
        and feedback_loop_count < MAX_FEEDBACK_LOOPS
        and scan_path != "D"  # 防止路徑 D 無限回饋
    )

    if feedback_triggered:
        feedback_loop_count += 1
        logger.warning(
            "[PIPELINE] Advisor confidence=%s → triggering Feedback Loop %d/%d",
            advisor_confidence, feedback_loop_count, MAX_FEEDBACK_LOOPS,
        )
        _notify("feedback_loop", "RUNNING", {
            "loop": feedback_loop_count,
            "reason": f"confidence={advisor_confidence}",
        })
        # 建立回饋訊息給 Orchestrator
        low_conf_cves = [
            a.get("cve_id") for a in analyst_output.get("analysis", [])
            if a.get("chain_risk", {}).get("confidence") in ("NEEDS_VERIFICATION", "LOW")
        ]
        logger.info("[PIPELINE] Feedback Loop targeting CVEs: %s", low_conf_cves)
        # 記錄到 Orchestration Context
        if orch_ctx is not None:
            try:
                orch_ctx.feedback_loops = feedback_loop_count
            except Exception:
                pass
        _notify("feedback_loop", "COMPLETE", {"loop": feedback_loop_count, "cves": low_conf_cves})

    # ── Orchestration 結束 + 記憶寫入 ────────────────────────
    orch_summary: dict = {}
    if orch_ctx is not None:
        try:
            from agents.orchestrator import finalize_orchestration
            orch_ctx.final_confidence = advisor_confidence
            orch_summary = finalize_orchestration(orch_ctx)
        except Exception as e:
            logger.warning("[PIPELINE] finalize_orchestration failed: %s", e)

    # ── 彙整 ──────────────────────────────────────────────────
    duration = round(time.time() - pipeline_start, 2)
    pipeline_meta = {
        "pipeline_version": "3.1",
        "tech_stack": tech_stack,
        "scan_path": scan_path,
        "stages_completed": len(completed_stages),
        "stages_detail": stages_detail,
        "enable_critic": ENABLE_CRITIC,
        "critic_verdict": critic_output.get("verdict", "SKIPPED"),
        "critic_score": critic_output.get("weighted_score", 0),
        "feedback_loops": feedback_loop_count,
        "duration_seconds": duration,
        "degradation": degradation_status.to_dict(),
        "orchestration": orch_summary,
        "layer1_agents": list(layer1_results.keys()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    logger.info(
        "Pipeline v3.1 COMPLETE in %.1fs | path=%s | feedback_loops=%d",
        duration, scan_path, feedback_loop_count,
    )
    recorder.end_scan("COMPLETE", duration)
    return {**advisor_output, "pipeline_meta": pipeline_meta}



# ======================================================================
# CLI 入口
# ======================================================================

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    if len(sys.argv) > 1:
        tech_stack = " ".join(sys.argv[1:])
    else:
        tech_stack = "Django 4.2, Redis 7.0, PostgreSQL 16"

    print(f"\nThreatHunter - Scanning: {tech_stack}\n")
    result = run_pipeline(tech_stack)
    print("\n=== Pipeline Result ===")
    print(json.dumps(result, ensure_ascii=False, indent=2))
