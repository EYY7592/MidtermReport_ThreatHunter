"""
main.py - ThreatHunter 銝餌撘
==============================
Pipeline 嗆嚗v3.1嚗嚗Orchestrator  [Layer 1 銝西]  Scout  Analyst  Debate  Advisor

嗆嚗v3.1 Orchestrator 撽嚗嚗
  Orchestrator 頝舐梧
    頝臬 A嚗憟隞嗆      頝喲 Security Guard
    頝臬 B嚗摰渡撘蝣    Layer 1 銝西嚗Security Guard + Intel Fusion嚗
    頝臬 C嚗隞嗅摹蝵    頝喲 Analyst + Debate
    頝臬 D嚗擖鋆      芷頝雿靽∪ CVE

嗆嚗靽靘嚗嚗
  雿輻刻頛詨 "Django 4.2, Redis 7.0"
                main.py Pipeline                        
      Scout   嗯 Analyst  嗯  Critic         
    (鈭撖行園)   (函斗)   (舀)           
                                潑    
                                    Advisor          
                                  (蝯鋆瘙箏勗)      
    瘥 Stage 函嚗                                    
      - try-except + Graceful Degradation               
      - StepLogger 摮甇仿亥                          
      - Harness 靽撅歹 agents/*.py 折剁            

鞈瘚嚗
  Scout 頛詨 (dict)  Analyst 頛詨 (dict)
  Analyst 頛詨 (dict)  Critic 頛詨 (dict)
  Analyst + Critic 頛詨  Advisor 頛詨 (dict)
  Advisor 頛詨 (dict) + pipeline_meta  蝯蝯

Harness Engineering 靽嚗
  - 瘥 Agent 賭蝙函撖行芋蝯嚗agents/*.py嚗嚗 Stub
  - Critic  ENABLE_CRITIC 批塚舀嚗
  - 瘥 Stage 函 Graceful Degradation 蝝頝臬
  - 函閮 Observability 亥嚗FINAL_PLAN.md 舀 2嚗
  - 17 撅 Harness 靽撅歹 agents/*.py 折剁

萄嚗project_CONSTITUTION.md + HARNESS_ENGINEERING.md
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

import os  # noqa: E402 (import after logger for ordering clarity)

# (comment encoding corrupted)
# (comment encoding corrupted)
# (comment encoding corrupted)
SANDBOX_ENABLED = os.getenv("SANDBOX_ENABLED", "false").lower() == "true"

try:
    from sandbox.docker_sandbox import run_in_sandbox, is_docker_available
    _DOCKER_SANDBOX_OK = True
except ImportError:
    _DOCKER_SANDBOX_OK = False
    def run_in_sandbox(*args, **kwargs):  # type: ignore[misc]
        return {"error": "SANDBOX_NOT_AVAILABLE", "fallback": True}
    def is_docker_available() -> bool:  # type: ignore[misc]
        return False

if SANDBOX_ENABLED:
    logger.info(
        "[SANDBOX] Docker isolation ENABLED | docker_available=%s",
        is_docker_available(),
    )
else:
    logger.debug("[SANDBOX] Docker isolation DISABLED (in-process mode)")
# (comment encoding corrupted)



# ======================================================================
# (comment encoding corrupted)
# ======================================================================


class StepLogger:
    """瘥 Agent Stage 摮甇仿餈質馱具"""

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
# (comment encoding corrupted)
# ======================================================================


def stage_scout(tech_stack: str, input_type: str = "pkg") -> tuple[dict[str, Any], StepLogger]:
    """
    Stage 1: Scout Agent 萄瞍瘣
    雿輻 agents/scout.py 撖血祕雿
    Graceful Degradation: 憭望喟征鞈嚗霈敺蝥 Agent 仿舐洵銝甈～

    v3.7: input_type 瘙箏頛芸 Skill SOP (Path-Aware Skills)

    Returns:
        (result_dict, step_logger)  頛詨箏亥餈質馱
    """
    from agents.scout import run_scout_pipeline

    sl = StepLogger("scout")
    sl.log("INIT", "RUNNING", f"tech_stack={tech_stack} | input_type={input_type}")

    t0 = time.time()
    try:
        result = run_scout_pipeline(tech_stack, input_type=input_type)

        duration_ms = int((time.time() - t0) * 1000)
        vuln_count = len(result.get("vulnerabilities", []))
        sl.log(
            "COMPLETE", "SUCCESS", f"found {vuln_count} vulnerabilities", duration_ms
        )
        return result, sl
    except Exception as e:
        duration_ms = int((time.time() - t0) * 1000)
        # (comment encoding corrupted)
        is_rate_limit = "429" in str(e) or "rate limit" in str(e).lower()
        if is_rate_limit:
            logger.warning("[SCOUT] Rate limited  returning empty results (not a real failure)")
            sl.log("COMPLETE", "RATE_LIMITED", str(e)[:100], duration_ms)
        else:
            logger.error("Scout Stage failed: %s", e)
            sl.log("COMPLETE", "FAILED", str(e)[:100], duration_ms)
            degradation_status.degrade("Scout", str(e))
        # (comment encoding corrupted)
        return {
            "scan_id": f"scan_degraded_{int(time.time())}",
            "vulnerabilities": [],
            "summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
            "_degraded": not is_rate_limit,  # 429 銝蝞甇蝝
            "_error": str(e),
        }, sl


# ======================================================================
# (comment encoding corrupted)
# ======================================================================


def stage_analyst(
    scout_output: dict[str, Any],
    input_type: str = "pkg",
) -> tuple[dict[str, Any], StepLogger]:
    """
    Stage 2: Analyst Agent vulnerability chain analysis.
    v3.7: input_type selects path-aware chain analysis skill.

    Returns:
        (result_dict, step_logger)
    """
    from agents.analyst import run_analyst_pipeline

    sl = StepLogger("analyst")
    sl.log(
        "INIT", "RUNNING",
        f"input_vulns={len(scout_output.get('vulnerabilities', []))} | input_type={input_type}"
    )

    t0 = time.time()
    try:
        result = run_analyst_pipeline(scout_output, input_type=input_type)
        duration_ms = int((time.time() - t0) * 1000)
        risk = result.get("risk_score", 0)
        sl.log("COMPLETE", "SUCCESS", f"risk_score={risk}", duration_ms)
        return result, sl
    except Exception as e:
        duration_ms = int((time.time() - t0) * 1000)
        logger.error("Analyst Stage failed: %s", e)
        sl.log("COMPLETE", "FAILED", str(e)[:100], duration_ms)
        degradation_status.degrade("Analyst", str(e))
        # (comment encoding corrupted)
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

        # (comment encoding corrupted)
        code_patterns = scout_output.get("code_patterns", [])
        for cp in code_patterns:
            sev = cp.get("severity", "MEDIUM")
            cvss_equiv = 9.0 if sev == "CRITICAL" else (7.5 if sev == "HIGH" else 5.0)
            analysis.append({
                "finding_id": cp.get("finding_id", "CODE-000"),
                "cve_id": None,
                "pattern_type": cp.get("pattern_type", "UNKNOWN"),
                "cwe_id": cp.get("cwe_id", "CWE-unknown"),
                "owasp_category": cp.get("owasp_category", ""),
                "severity": sev,
                "snippet": cp.get("snippet", ""),
                "line_no": cp.get("line_no", 0),
                "original_cvss": cvss_equiv,
                "adjusted_risk": sev,
                "in_cisa_kev": False,
                "exploit_available": False,
                "chain_risk": {
                    "is_chain": False,
                    "chain_with": [],
                    "chain_description": "Analyst degraded - deterministic pattern only.",
                    "confidence": "HIGH",  # 蝣箏批菜葫嚗靽∪擃
                },
                "reasoning": f"Deterministic detection: {cp.get('pattern_type')} ({cp.get('cwe_id')}). Analyst degraded but code pattern is confirmed by Security Guard.",
            })
        if code_patterns:
            logger.info("[DEGRADED] Analyst fallback preserved %d code_patterns", len(code_patterns))

        return {
            "scan_id": scout_output.get("scan_id", "unknown"),
            "risk_score": 50,
            "risk_trend": "+0",
            "analysis": analysis,
            "_degraded": True,
            "_error": str(e),
        }, sl


# ======================================================================
# (comment encoding corrupted)
# ======================================================================


def stage_critic(
    analyst_output: dict[str, Any],
    input_type: str = "pkg",
) -> tuple[dict[str, Any], StepLogger]:
    """
    Stage 3: Adversarial Debate Engine.
    v5.3: 升級為 3 輪辯論引擎（Du et al. 2023 ICML, arXiv:2305.14325）。
    無共識時由 Judge sub-agent 仲裁。偏保守原則：高估風險比低估安全。

    Returns:
        (result_dict, step_logger)
    """
    from agents.debate_engine import run_debate_pipeline

    sl = StepLogger("critic")
    sl.log("INIT", "RUNNING", f"enable_critic={ENABLE_CRITIC} | input_type={input_type} | mode=3-round-debate")

    t0 = time.time()
    try:
        result = run_debate_pipeline(
            analyst_output,
            input_type=input_type,
            on_progress=None,
        )
        duration_ms = int((time.time() - t0) * 1000)
        verdict = result.get("verdict", "UNKNOWN")
        score = result.get("weighted_score", 0)
        meta = result.get("_debate_meta", {})
        consensus = meta.get("consensus", None)
        rounds = meta.get("total_rounds", "?")
        judge_invoked = meta.get("judge_invoked", False)
        sl.log(
            "COMPLETE", "SUCCESS",
            f"verdict={verdict} score={score} consensus={consensus} rounds={rounds} judge={judge_invoked}",
            duration_ms,
        )
        return result, sl
    except Exception as e:
        duration_ms = int((time.time() - t0) * 1000)
        logger.error("Debate Stage failed: %s", e)
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
            "reasoning": "Debate engine degraded - all rounds skipped.",
            "_degraded": True,
            "_error": str(e),
        }, sl


def stage_advisor(
    analyst_output: dict[str, Any],
    critic_output: dict[str, Any],
    input_type: str = "pkg",
) -> tuple[dict[str, Any], StepLogger]:
    """
    Stage 4: Advisor Agent action report generation.
    v3.7: input_type selects path-aware action report skill.

    Returns:
        (result_dict, step_logger)
    """
    from agents.advisor import run_advisor_pipeline

    sl = StepLogger("advisor")
    verdict = critic_output.get("verdict", "SKIPPED")
    sl.log("INIT", "RUNNING", f"critic_verdict={verdict} | input_type={input_type}")

    # (comment encoding corrupted)
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

        # (comment encoding corrupted)
        # (comment encoding corrupted)
        # (comment encoding corrupted)
        urgent_actions = []
        important_actions = []
        code_patterns_fallback = []  # 脣 CODE-pattern 靘 UI 
        _SEVERITY_MAP = {"CRITICAL": "urgent", "HIGH": "important"}

        for entry in advisor_input.get("analysis", []):
            finding_id = entry.get("finding_id", "")
            cve_id = entry.get("cve_id")
            sev = entry.get("severity") or entry.get("adjusted_risk", "MEDIUM")
            bucket = _SEVERITY_MAP.get(sev, "important")

            # (comment encoding corrupted)
            # (comment encoding corrupted)
            if finding_id.startswith("CODE-") or entry.get("pattern_type"):
                pt = entry.get("pattern_type", "UNKNOWN")
                cwe = entry.get("cwe_id", "CWE-unknown")
                snippet = entry.get("snippet", "")
                code_patterns_fallback.append({
                    "finding_id": finding_id,
                    "cve_id": None,
                    "cwe_id": cwe,
                    "pattern_type": pt,
                    "package": f"Custom Code Pattern",
                    "severity": sev,
                    "action": f"Fix {pt} vulnerability ({cwe}). {entry.get('reasoning', '')}",
                    "vulnerable_snippet": snippet[:200],
                    "reason": entry.get("reasoning", f"Security Guard deterministic detection: {pt}"),
                    "is_repeated": False,
                    "_constitution_note": "CODE-pattern: not in URGENT per CI-1/CI-2. See code_patterns_summary.",
                })
            # (comment encoding corrupted)
            elif cve_id and (str(cve_id).startswith("CVE-") or str(cve_id).startswith("GHSA-")):
                action_entry = {
                    "cve_id": cve_id,
                    "package": entry.get("package", "unknown"),
                    "severity": sev,
                    "action": f"Review and patch {cve_id}.",
                    "command": f"# Investigate {cve_id}",
                    "reason": entry.get("reasoning", "Advisor degraded - manual review required."),
                    "is_repeated": False,
                }
                if bucket == "urgent":
                    urgent_actions.append(action_entry)
                else:
                    important_actions.append(action_entry)

        risk_score = max(
            50,
            min(100, len(urgent_actions) * 25 + len(important_actions) * 10),
        )
        summary_parts = []
        if urgent_actions:
            summary_parts.append(f"{len(urgent_actions)} package CVE(s) require immediate patching")
        if code_patterns_fallback:
            summary_parts.append(f"{len(code_patterns_fallback)} code-level pattern(s) detected (see Code Analysis tab)")
        if important_actions:
            summary_parts.append(f"{len(important_actions)} high-severity CVE(s) need review within 72h")
        if not summary_parts:
            summary_parts.append("System degraded. Please review raw scan data manually.")

        logger.info(
            "[DEGRADED] Advisor fallback: %d urgent CVEs + %d important CVEs + %d code-patterns (not in URGENT per CI-1/CI-2)",
            len(urgent_actions), len(important_actions), len(code_patterns_fallback),
        )

        return {
            "executive_summary": ". ".join(summary_parts),
            "actions": {
                "urgent": urgent_actions,
                "important": important_actions,
                "resolved": [],
            },
            "code_patterns_summary": code_patterns_fallback,
            "risk_score": risk_score,
            "risk_trend": "+0",
            "scan_count": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "_degraded": True,
            "_error": str(e),
        }, sl


# ======================================================================
# (comment encoding corrupted)
# ======================================================================


# ======================================================================
# (comment encoding corrupted)
# ======================================================================


def stage_orchestrator(
    tech_stack: str,
    feedback_from_judge: dict | None = None,
) -> tuple[Any, dict, StepLogger]:
    """
    Stage 0: Orchestrator 瘙箏頝臬嚗A/B/C/D嚗
     (OrchestrationContext, task_plan, StepLogger)
    Graceful Degradation: 憭望唾楝敺 B嚗摰渡撘蝣潘雿箏券閮准
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
        # (comment encoding corrupted)
        from agents.orchestrator import OrchestrationContext, ScanPath
        ctx = OrchestrationContext()
        ctx.scan_path = ScanPath.FULL_CODE
        task_plan = {
            "path": "B",
            # (comment encoding corrupted)
            "parallel_layer1": ["security_guard", "intel_fusion"],
            "debate_cluster": True,
            "judge": True,
            "agents_to_run": ["security_guard", "intel_fusion", "scout", "analyst", "debate", "judge"],
            "_degraded": True,
        }
        return ctx, task_plan, sl


# ======================================================================
# (comment encoding corrupted)
# ======================================================================


def _build_code_patterns_summary(sg_result: dict) -> list[dict]:
    """
    Security Guard patterns + hardcoded secrets を
    CWE-enriched code_patterns_summary に変換する。

    確定性抽出 + MITRE CWE v4.14 佐証注入。
    LLM に依存しない。
    """
    _DEFAULT_META = ("CWE-UNKNOWN", "A03:2021-Injection", "MEDIUM")
    _SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

    _PATTERN_META: dict[str, tuple[str, str, str]] = {
        "SQL_INJECTION":      ("CWE-89",   "A03:2021-Injection",                       "CRITICAL"),
        "CMD_INJECTION":      ("CWE-78",   "A03:2021-Injection",                       "CRITICAL"),
        "EVAL_EXEC":          ("CWE-95",   "A03:2021-Injection",                       "CRITICAL"),
        "EVAL_USAGE":         ("CWE-95",   "A03:2021-Injection",                       "CRITICAL"),
        "INNERHTML_XSS":      ("CWE-79",   "A03:2021-Injection",                       "HIGH"),
        "SSRF_RISK":          ("CWE-918",  "A10:2021-Server-Side Request Forgery",    "HIGH"),
        "PICKLE_UNSAFE":      ("CWE-502",  "A08:2021-Software and Data Integrity",    "CRITICAL"),
        "YAML_UNSAFE":        ("CWE-502",  "A08:2021-Software and Data Integrity",    "HIGH"),
        "HARDCODED_SECRET":   ("CWE-798",  "A07:2021-Identification and Auth Failures","HIGH"),
        "PATH_TRAVERSAL":     ("CWE-22",   "A01:2021-Broken Access Control",           "HIGH"),
        "XXE_ENTITY":         ("CWE-611",  "A05:2021-Security Misconfiguration",       "HIGH"),
        "PROTOTYPE_POLLUTION":("CWE-1321", "A03:2021-Injection",                       "CRITICAL"),
        "DESERIALIZE_UNSAFE": ("CWE-502",  "A08:2021-Software and Data Integrity",    "CRITICAL"),
        "SQL_CONCAT":         ("CWE-89",   "A03:2021-Injection",                       "CRITICAL"),
        "SQL_CONCAT_PHP":     ("CWE-89",   "A03:2021-Injection",                       "CRITICAL"),
        "SQL_STATEMENT":      ("CWE-89",   "A03:2021-Injection",                       "CRITICAL"),
        "OPEN_PIPE":          ("CWE-78",   "A03:2021-Injection",                       "CRITICAL"),
        "SHELL_EXEC":         ("CWE-78",   "A03:2021-Injection",                       "CRITICAL"),
        "FILE_INCLUDE":       ("CWE-98",   "A03:2021-Injection",                       "HIGH"),
        "BUFFER_OVERFLOW":    ("CWE-120",  "A06:2021-Vulnerable Components",           "CRITICAL"),
        "FORMAT_STRING":      ("CWE-134",  "A03:2021-Injection",                       "HIGH"),
        "UNSAFE_BLOCK":       ("CWE-119",  "A06:2021-Vulnerable Components",           "HIGH"),
        "LDAP_INJECTION":     ("CWE-90",   "A03:2021-Injection",                       "HIGH"),
        "XXE_FAULT":          ("CWE-611",  "A05:2021-Security Misconfiguration",       "HIGH"),
        "CMD_UNSAFE":         ("CWE-78",   "A03:2021-Injection",                       "CRITICAL"),
        "CMD_PATTERN":        ("CWE-78",   "A03:2021-Injection",                       "HIGH"),
        "TAINT_SUPERGLOBAL":  ("CWE-89",   "A03:2021-Injection",                       "HIGH"),
        "REDOS":              ("CWE-1333", "A06:2021-Vulnerable Components",           "MEDIUM"),
    }

    # 嘗試載入 MITRE CWE 資料庫
    try:
        from tools.cwe_database import get_cwe_info
        _cwe_db_available = True
    except ImportError:
        _cwe_db_available = False
        logger.warning("[CODE_PATTERNS] cwe_database not available, no CWE enrichment")

    def _attach_cwe_reference(entry: dict, cwe_id: str) -> dict:
        """將 MITRE CWE 官方定義注入 entry 的 cwe_reference 欄位"""
        if not _cwe_db_available or not cwe_id or not cwe_id.startswith("CWE-"):
            return entry
        info = get_cwe_info(cwe_id)
        if not info:
            return entry
        entry["cwe_reference"] = {
            "id": cwe_id,
            "name": info.get("name", cwe_id),
            "source": info.get("source", "MITRE CWE v4.14"),
            "nist_severity": info.get("nist_severity", "UNKNOWN"),
            "cvss_base": info.get("cvss_base", None),
            "owasp_2021": info.get("owasp_2021", ""),
            "cwe_url": info.get("cwe_url",
                f"https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-','')}.html"),
            "description": info.get("description", "")[:300],
            "remediation_zh": info.get("remediation_zh", info.get("remediation_en", "")),
            "representative_cves": info.get("representative_cves", [])[:3],
            "disclaimer": (
                "代表性 CVE 為同類弱點的真實被利用案例，"
                "非本程式碼的直接 CVE 識別碼。"
                "用於說明此類弱點的風險嚴重性。"
            ),
        }
        return entry

    # ── Step 1: 對 patterns 去重（同行 + 前 30 字元相同視為重複，保留嚴重性最高者）
    _dedup: dict[tuple, dict] = {}
    for p in sg_result.get("patterns", []):
        pt = p.get("pattern_type", "UNKNOWN")
        _, _, sev = _PATTERN_META.get(pt, _DEFAULT_META)
        key = (p.get("line_no", 0), str(p.get("snippet", ""))[:30])
        existing = _dedup.get(key)
        if existing is None:
            _dedup[key] = p
        else:
            ex_pt = existing.get("pattern_type", "UNKNOWN")
            _, _, ex_sev = _PATTERN_META.get(ex_pt, _DEFAULT_META)
            if _SEVERITY_RANK.get(sev, 0) > _SEVERITY_RANK.get(ex_sev, 0):
                _dedup[key] = p

    code_patterns: list[dict] = []
    counter = 1

    # ── Step 2: 為每個 pattern 建立 finding entry + 注入 CWE reference
    for p in _dedup.values():
        pt = p.get("pattern_type", "UNKNOWN")
        cwe, owasp, severity = _PATTERN_META.get(pt, _DEFAULT_META)
        entry = {
            "finding_id":    f"CODE-{counter:03d}",
            "type":          "code_pattern",
            "pattern_type":  pt,
            "cwe_id":        cwe,
            "owasp_category": owasp,
            "severity":      severity,
            "snippet":       str(p.get("snippet", ""))[:200],
            "line_no":       p.get("line_no", 0),
            "language":      sg_result.get("language", "unknown"),
        }
        entry = _attach_cwe_reference(entry, cwe)
        code_patterns.append(entry)
        counter += 1

    # ── Step 3: 硬編碼密鑰
    for h in sg_result.get("hardcoded", []):
        entry = {
            "finding_id":    f"CODE-{counter:03d}",
            "type":          "hardcoded_secret",
            "pattern_type":  "HARDCODED_SECRET",
            "cwe_id":        "CWE-798",
            "owasp_category": "A07:2021-Identification and Authentication Failures",
            "severity":      "HIGH",
            "snippet":       f"{h.get('name', 'secret')} = '****' (value redacted)",
            "line_no":       h.get("line_no", 0),
            "language":      sg_result.get("language", "unknown"),
        }
        entry = _attach_cwe_reference(entry, "CWE-798")
        code_patterns.append(entry)
        counter += 1

    logger.info(
        "[CODE_PATTERNS] Built %d CWE-enriched patterns (from %d raw patterns, %d hardcoded)",
        len(code_patterns),
        len(sg_result.get("patterns", [])),
        len(sg_result.get("hardcoded", [])),
    )
    return code_patterns

def _run_layer1_parallel(
    tech_stack: str,
    task_plan: dict,
    on_progress: Any,
) -> dict[str, Any]:
    """
    頝臬 B  Layer 1 銝西瑁嚗雿輻 ThreadPoolExecutor 撠孵嚗

    Why ThreadPoolExecutor嚗 asyncio嚗嚗
      - main.py 臬甇亦撘蝣潘SSE callback 銋臬甇亦
      - ThreadPoolExecutor 臬典甇亦啣銝銝西瑁憭 IO-bound 撌乩嚗LLM 澆恬
      - 撠孵嚗銝閬瑽 callback 璈

    銝西瑁撠鞊∴閬 task_plan 瘙箏嚗嚗
      - security_guard嚗敺蝔撘蝣潭賢/憟隞/璅∪嚗頛詨伐tech_stack嚗
      - intel_fusion嚗剔雁望亥岷嚗頛詨伐tech_stack嚗

    Args:
        tech_stack: 雿輻刻頛詨
        task_plan: Orchestrator 隞餃閬
        on_progress: SSE 脣漲隤

    Returns:
        {"security_guard": dict, "intel_fusion": dict}
    """
    parallel_agents = task_plan.get("parallel_layer1", [])
    layer1_results: dict[str, Any] = {}

    def _run_security_guard() -> tuple[str, dict]:
        """ Thread 銝剖瑁 Security Guard嚗 LLM 嚗"""
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
        """ Thread 銝剖瑁 Intel Fusion嚗剔雁望亥岷嚗

        v3.4 靽桀儔嚗亙憟隞嗅蝔勗銵剁憪蝔撘蝣潘嚗閫瘙 0 CVE 憿
        intel_input 臭誑荔
          - list[str]嚗憟隞嗅蝔勗銵剁 package_extractor 敺喳伐
          - str嚗憪 tech_stack嚗fallback嚗Path A 憟隞嗆格芋撘嚗
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

    # (comment encoding corrupted)
    # (comment encoding corrupted)
    # (comment encoding corrupted)
    extracted_packages: list[str] = []

    if "security_guard" in parallel_agents:
        rate_limiter.wait_if_needed("security_guard")
        _, sg_result = _run_security_guard()
        layer1_results["security_guard"] = sg_result
        logger.info("[LAYER1] security_guard complete")

        # (comment encoding corrupted)
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

        # (comment encoding corrupted)
        # (comment encoding corrupted)
        # (comment encoding corrupted)
        # (comment encoding corrupted)
        # (comment encoding corrupted)
        cwe_targets: list[str] = []
        if not extracted_packages and "security_guard" in layer1_results:
            sg_patterns = layer1_results["security_guard"].get("patterns", [])  # SG output key is "patterns"
            seen_cwe: set[str] = set()
            for pattern in sg_patterns:
                cwe = pattern.get("cwe_id", "")
                # (comment encoding corrupted)
                if cwe and cwe.startswith("CWE-") and cwe not in seen_cwe:
                    seen_cwe.add(cwe)
                    cwe_targets.append(cwe)
            if cwe_targets:
                logger.info(
                    "[LAYER1] Intel Fusion: extracted_packages empty, "
                    "using %d CWE targets from Security Guard: %s",
                    len(cwe_targets), cwe_targets,
                )

        # (comment encoding corrupted)
        if extracted_packages:
            intel_input: list | str = extracted_packages
            logger.info("[LAYER1] Intel Fusion input: %d packages", len(intel_input))
        elif cwe_targets:
            intel_input = cwe_targets  #  CWE ID 亥岷 NVD
            logger.info("[LAYER1] Intel Fusion input: %d CWE targets (no packages detected)", len(intel_input))
        else:
            intel_input = tech_stack
            logger.info("[LAYER1] Intel Fusion input: raw tech_stack (fallback)")

        _, if_result = _run_intel_fusion(intel_input)
        # (comment encoding corrupted)
        if_result["_extracted_packages"] = extracted_packages
        if cwe_targets:
            if_result["_cwe_targets"] = cwe_targets
        layer1_results["intel_fusion"] = if_result
        logger.info("[LAYER1] intel_fusion complete")

    return layer1_results



def run_pipeline(tech_stack: str, input_type: str = "pkg") -> dict[str, Any]:
    """
    瑁摰渡 ThreatHunter 蝞∠嚗v3.1 Orchestrator 撽嚗

    Pipeline: Orchestrator  [Layer 1 銝西]  Scout  Analyst  [Critic]  Advisor

    v3.7: input_type 瘙箏 Path-Aware Skills 頝舐晞
    pkg=憟隞嗆 / code=皞蝣澆祟閮 / injection=AI摰 / config=閮剖瑼

    v3.9 Sandbox:  SANDBOX_ENABLED=true 銝 Docker 舐剁典捆典批瑁

    Args:
        tech_stack: 雿輻刻頛詨亦銵摮銝莎憒 "Django 4.2, Redis 7.0"嚗
        input_type: 蝡臬菜葫頛詨仿 (pkg/code/config/injection)

    Returns:
        怠 Advisor 銵勗 dict嚗銝 pipeline_meta 甈雿
    """
    # (comment encoding corrupted)
    if SANDBOX_ENABLED and _DOCKER_SANDBOX_OK and is_docker_available():
        logger.info("[SANDBOX] Docker isolation ACTIVE  delegating to container")
        result = run_in_sandbox(tech_stack=tech_stack, input_type=input_type)
        if not result.get("fallback"):
            return result          # 摰孵典瑁
        # (comment encoding corrupted)
        logger.warning(
            "[SANDBOX] Container fallback: %s  using in-process mode",
            result.get("error", "unknown"),
        )
    # (comment encoding corrupted)
    return run_pipeline_with_callback(tech_stack, progress_callback=None, input_type=input_type)


def run_pipeline_sync(tech_stack: str, input_type: str = "pkg") -> dict[str, Any]:
    """
    run_pipeline 甇亙亙嚗靘 sandbox/sandbox_runner.py 典捆典批澆恬
    瘜冽嚗摰孵典批澆急迨賢 SANDBOX_ENABLED=false嚗踹餈湧脣 Docker
    """
    # (comment encoding corrupted)
    return run_pipeline_with_callback(tech_stack, progress_callback=None, input_type=input_type)


def run_pipeline_with_callback(
    tech_stack: str,
    progress_callback: Any = None,
    input_type: str = "pkg",
) -> dict[str, Any]:
    """
    瑁摰 Pipeline嚗瘥 Stage 摰敺澆 progress_callback

    v3.7: input_type 瘙箏 Agent 頛芸 Skill SOP嚗Path-Aware Skills嚗

    Args:
        tech_stack: 銵摮銝
        progress_callback: 交 (agent_name: str, status: str, detail: dict) 賢
        input_type: 頛詨仿 (pkg / code / config / injection)

    Returns:
        怠 Advisor 銵勗 dict
    """
    pipeline_start = time.time()
    completed_stages: list[str] = []
    stages_detail: dict[str, Any] = {}
    # (comment encoding corrupted)
    orch_ctx: Any = None
    task_plan: dict = {"path": "B"}  # 閮剛楝敺 B
    layer1_results: dict[str, Any] = {}
    feedback_loop_count: int = 0
    MAX_FEEDBACK_LOOPS: int = 2

    def _notify(agent: str, status: str, detail: dict) -> None:
        if progress_callback:
            try:
                progress_callback(agent, status, detail)
            except Exception:
                pass  # callback 憭望銝敶梢 pipeline

    logger.info("=" * 60)
    logger.info("  ThreatHunter Pipeline v3.1 Start (Orchestrator-driven)")
    logger.info("  tech_stack : %s", tech_stack)
    logger.info("  input_type : %s", input_type)
    logger.info("  ENABLE_CRITIC: %s", ENABLE_CRITIC)
    logger.info("=" * 60)

    # (comment encoding corrupted)
    from checkpoint import recorder
    recorder.start_scan(f"pipe_{int(pipeline_start)}")

    # (comment encoding corrupted)
    # (comment encoding corrupted)
    l0_report: dict[str, Any] = {}
    sanitized_stack: str = tech_stack
    try:
        from input_sanitizer import sanitize_input, format_l0_report
        san_result = sanitize_input(tech_stack)
        l0_report = format_l0_report(san_result)

        if not san_result.safe:
            # (comment encoding corrupted)
            logger.warning("[L0] Input BLOCKED: %s", san_result.blocked_reason)
            _notify("input_sanitizer", "COMPLETE", {
                "status": "BLOCKED",
                "reason": san_result.blocked_reason,
            })
            return {
                "executive_summary": f"頛詨亥◤摰券瞈曉冽蝯嚗{san_result.blocked_reason}",
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
            logger.warning("[L0] Input truncated: %d  %d chars",
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
        # (comment encoding corrupted)
        logger.warning("[L0] input_sanitizer not available, skipping L0 filter")
    except Exception as e:
        # (comment encoding corrupted)
        logger.error("[L0] Sanitizer error (non-fatal): %s", e)

    # (comment encoding corrupted)
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


    # (comment encoding corrupted)
    # (comment encoding corrupted)
    # (comment encoding corrupted)
    # (comment encoding corrupted)
    extracted_packages: list[str] = []

    if scan_path in ("A", "B"):
        parallel_agents = task_plan.get("parallel_layer1", [])
        if parallel_agents:
            _notify("layer1_parallel", "RUNNING", {"agents": parallel_agents})
            layer1_results = _run_layer1_parallel(tech_stack, task_plan, _notify)
            _notify("layer1_parallel", "COMPLETE", {
                "agents_completed": list(layer1_results.keys()),
            })
            # (comment encoding corrupted)
            if "intel_fusion" in layer1_results:
                extracted_packages = layer1_results["intel_fusion"].get("_extracted_packages", [])
                if extracted_packages:
                    logger.info(
                        "[PIPELINE] extracted_packages from layer1: %s", extracted_packages
                    )
            # (comment encoding corrupted)
            for agent_name, result in layer1_results.items():
                is_degraded = result.get("_degraded", False)
                agent_detail = {
                    "status": "DEGRADED" if is_degraded else "SUCCESS",
                    "duration_ms": result.get("_duration_ms", 0),
                    # (comment encoding corrupted)
                    "_degraded": is_degraded,
                    "_error": result.get("_error", "") if is_degraded else "",
                }
                # (comment encoding corrupted)
                if agent_name == "security_guard":
                    agent_detail["functions_found"] = result.get("stats", {}).get("functions_found", 0)
                    agent_detail["patterns_found"] = result.get("stats", {}).get("patterns_found", 0)
                    agent_detail["injection_detected"] = result.get("injection_attempts_detected", False)
                # (comment encoding corrupted)
                elif agent_name == "intel_fusion":
                    agent_detail["cves_scored"] = len(result.get("fusion_results", []))
                stages_detail[agent_name] = agent_detail
                completed_stages.append(agent_name)
                recorder.stage_exit(agent_name, agent_detail["status"], agent_detail, agent_detail.get("duration_ms", 0))
            # (comment encoding corrupted)
            if orch_ctx is not None:
                for agent_name, result in layer1_results.items():
                    try:
                        orch_ctx.store_result(agent_name, result)
                    except Exception:
                        pass

    # (comment encoding corrupted)
    # (comment encoding corrupted)
    _notify("scout", "RUNNING", {})
    rate_limiter.wait_if_needed("scout")
    # (comment encoding corrupted)
    # (comment encoding corrupted)
    scout_input: str
    if extracted_packages:
        from tools.package_extractor import format_packages_for_intel_fusion
        scout_input = format_packages_for_intel_fusion(extracted_packages)
        logger.info("[PIPELINE] Scout using extracted packages: %s", scout_input)
    else:
        scout_input = tech_stack
        logger.info("[PIPELINE] Scout using raw tech_stack (no packages extracted)")
    scout_output, scout_sl = stage_scout(scout_input, input_type=input_type)
    # (comment encoding corrupted)
    if "intel_fusion" in layer1_results:
        scout_output["intel_fusion_result"] = layer1_results["intel_fusion"]

    # (comment encoding corrupted)
    # (comment encoding corrupted)
    # (comment encoding corrupted)
    # (comment encoding corrupted)
    # (comment encoding corrupted)
    _sg_code_patterns: list[dict] = []  # 函式級別變數，確保 final return 可存取
    if "security_guard" in layer1_results:
        _sg_code_patterns = _build_code_patterns_summary(
            layer1_results["security_guard"]
        )
        if _sg_code_patterns:
            scout_output["code_patterns"] = _sg_code_patterns
            logger.info(
                "[PIPELINE] v4.0: SG code_patterns injected into scout_output "
                "(%d patterns, Path=%s) — will be merged into final result",
                len(_sg_code_patterns),
                input_type,
            )
        else:
            logger.debug("[PIPELINE] v4.0: SG returned no code_patterns (clean code path)")

    scout_detail = {
        "status": "SUCCESS" if not scout_output.get("_degraded") else "DEGRADED",
        "vuln_count": len(scout_output.get("vulnerabilities", [])),
        "duration_ms": scout_sl.steps[-1].get("duration_ms", 0) if scout_sl.steps else 0,
        "packages_used": extracted_packages,
    }
    stages_detail["scout"] = scout_detail
    completed_stages.append("scout")
    _notify("scout", "COMPLETE", scout_detail)
    # (comment encoding corrupted)
    from agents.scout import SKILL_MAP as SCOUT_SKILL_MAP
    recorder.stage_enter("scout", {"tech_stack": scout_input[:200], "packages": extracted_packages},
                         skill_file=SCOUT_SKILL_MAP.get(input_type, "threat_intel.md"),
                         input_type=input_type)
    recorder.stage_exit("scout", scout_detail.get("status", "SUCCESS"), scout_output, scout_detail.get("duration_ms", 0))


    # (comment encoding corrupted)
    if scan_path == "C":
        logger.info("[PIPELINE] Path C: skipping Analyst + Critic  direct to Advisor")
        _notify("analyst", "COMPLETE", {"status": "SKIPPED", "reason": "path_C"})
        _notify("critic", "COMPLETE", {"status": "SKIPPED", "reason": "path_C"})
        # (comment encoding corrupted)
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
        # (comment encoding corrupted)
        _notify("analyst", "RUNNING", {})
        rate_limiter.wait_if_needed("analyst")
        analyst_output, analyst_sl = stage_analyst(scout_output, input_type=input_type)
        analyst_detail = {
            "status": "SUCCESS" if not analyst_output.get("_degraded") else "DEGRADED",
            "risk_score": analyst_output.get("risk_score", 0),
            "duration_ms": analyst_sl.steps[-1].get("duration_ms", 0) if analyst_sl.steps else 0,
        }
        stages_detail["analyst"] = analyst_detail
        completed_stages.append("analyst")
        _notify("analyst", "COMPLETE", analyst_detail)
        # v3.7: stage_enter with skill_file + input_type
        from agents.analyst import SKILL_MAP as ANALYST_SKILL_MAP
        recorder.stage_enter("analyst", scout_output,
                             skill_file=ANALYST_SKILL_MAP.get(input_type, "chain_analysis.md"),
                             input_type=input_type)
        recorder.stage_exit("analyst", analyst_detail.get("status", "SUCCESS"), analyst_output, analyst_detail.get("duration_ms", 0))

        # (comment encoding corrupted)
        _notify("critic", "RUNNING", {})
        rate_limiter.wait_if_needed("critic")
        critic_output, critic_sl = stage_critic(analyst_output, input_type=input_type)
        critic_detail = {
            "status": "SUCCESS" if not critic_output.get("_degraded") else "DEGRADED",
            "verdict": critic_output.get("verdict", "SKIPPED"),
            "score": critic_output.get("weighted_score", 0),
            "duration_ms": critic_sl.steps[-1].get("duration_ms", 0) if critic_sl.steps else 0,
        }
        stages_detail["critic"] = critic_detail
        completed_stages.append("critic")
        _notify("critic", "COMPLETE", critic_detail)
        # v3.7: stage_enter with skill_file + input_type
        from agents.critic import SKILL_MAP as CRITIC_SKILL_MAP
        recorder.stage_enter("critic", analyst_output,
                             skill_file=CRITIC_SKILL_MAP.get(input_type, "debate_sop.md"),
                             input_type=input_type)
        recorder.stage_exit("critic", critic_detail.get("status", "SUCCESS"), critic_output, critic_detail.get("duration_ms", 0))

    # (comment encoding corrupted)
    _notify("advisor", "RUNNING", {})
    rate_limiter.wait_if_needed("advisor")
    advisor_output, advisor_sl = stage_advisor(analyst_output, critic_output, input_type=input_type)
    advisor_detail = {
        "status": "SUCCESS" if not advisor_output.get("_degraded") else "DEGRADED",
        "urgent_count": len(advisor_output.get("actions", {}).get("urgent", [])),
        "duration_ms": advisor_sl.steps[-1].get("duration_ms", 0) if advisor_sl.steps else 0,
    }
    stages_detail["advisor"] = advisor_detail
    completed_stages.append("advisor")
    _notify("advisor", "COMPLETE", advisor_detail)
    # v3.7: stage_enter with skill_file + input_type
    from agents.advisor import SKILL_MAP as ADVISOR_SKILL_MAP
    recorder.stage_enter("advisor", analyst_output,
                         skill_file=ADVISOR_SKILL_MAP.get(input_type, "action_report.md"),
                         input_type=input_type)
    recorder.stage_exit("advisor", advisor_detail.get("status", "SUCCESS"), advisor_output, advisor_detail.get("duration_ms", 0))

    # (comment encoding corrupted)
    # (comment encoding corrupted)
    advisor_confidence = advisor_output.get("confidence", "HIGH")
    feedback_triggered = (
        advisor_confidence in ("NEEDS_VERIFICATION", "LOW", "MEDIUM")
        and feedback_loop_count < MAX_FEEDBACK_LOOPS
        and scan_path != "D"  # 脫迫頝臬 D ⊿擖
    )

    if feedback_triggered:
        feedback_loop_count += 1
        logger.warning(
            "[PIPELINE] Advisor confidence=%s  triggering Feedback Loop %d/%d",
            advisor_confidence, feedback_loop_count, MAX_FEEDBACK_LOOPS,
        )
        _notify("feedback_loop", "RUNNING", {
            "loop": feedback_loop_count,
            "reason": f"confidence={advisor_confidence}",
        })
        # (comment encoding corrupted)
        low_conf_cves = [
            a.get("cve_id") for a in analyst_output.get("analysis", [])
            if a.get("chain_risk", {}).get("confidence") in ("NEEDS_VERIFICATION", "LOW")
        ]
        logger.info("[PIPELINE] Feedback Loop targeting CVEs: %s", low_conf_cves)
        # (comment encoding corrupted)
        if orch_ctx is not None:
            try:
                orch_ctx.feedback_loops = feedback_loop_count
            except Exception:
                pass
        _notify("feedback_loop", "COMPLETE", {"loop": feedback_loop_count, "cves": low_conf_cves})

    # (comment encoding corrupted)
    orch_summary: dict = {}
    if orch_ctx is not None:
        try:
            from agents.orchestrator import finalize_orchestration
            orch_ctx.final_confidence = advisor_confidence
            orch_summary = finalize_orchestration(orch_ctx)
        except Exception as e:
            logger.warning("[PIPELINE] finalize_orchestration failed: %s", e)

    # (comment encoding corrupted)
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

    # ── Harness Layer 7: 強制注入 Security Guard CWE 佐證 ──────────────────
    # _sg_code_patterns 由 _build_code_patterns_summary() 生成，含 MITRE CWE 定義。
    # Advisor LLM 從不接收 code_patterns，因此必須在 return 前直接合併。
    # 確保無論掃描路徑（A/B/C）都能在 API response 中看到 CWE 佐證。
    final_output: dict[str, Any] = {**advisor_output, "pipeline_meta": pipeline_meta}
    if _sg_code_patterns:
        existing_cps = final_output.get("code_patterns_summary", [])
        final_output["code_patterns_summary"] = existing_cps + _sg_code_patterns
        logger.info(
            "[PIPELINE] Harness L7: %d CWE-enriched code patterns merged into final result",
            len(_sg_code_patterns),
        )
    return final_output



# ======================================================================
# (comment encoding corrupted)
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
