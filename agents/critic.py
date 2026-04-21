"""
agents/critic.py - Critic Agent (Devil's Advocate)
Harness Layers:
  Layer 1  - ENABLE_CRITIC=false -> SKIPPED
  Layer 1b - Fallback when LLM unparseable
  Layer 2  - Schema validation
  Layer 2' - Deep scorecard repair (fixes shallow-merge defect)
  Layer 3  - weighted_score type safety + verdict enum (fixes TypeError defect)
"""
import json, logging, os, re, time
from datetime import datetime, timezone
from typing import Any
from crewai import Agent, Task
from core.config import ENABLE_CRITIC, MAX_DEBATE_ROUNDS, get_llm
from tools.kev_tool import check_cisa_kev
from tools.exploit_tool import search_exploits
from tools.memory_tool import read_memory

logger = logging.getLogger("ThreatHunter.Critic")

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

_SKILL_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "skills", "debate_sop.md")
try:
    with open(_SKILL_PATH, "r", encoding="utf-8") as _f:
        CRITIC_SKILL = _f.read()
except FileNotFoundError:
    CRITIC_SKILL = "## Skill: Debate SOP\nChallenge Analyst assumptions. Use tools to verify."

# v3.7: Path-Aware Skill Map（對應 main.py recorder.stage_enter 使用）
SKILL_MAP: dict[str, str] = {
    "pkg":       "debate_sop.md",       # Path A: package debate
    "code":      "code_debate_sop.md",  # Path B-code: source code debate
    "injection": "ai_debate_sop.md",   # Path B-inject: AI security debate
    "config":    "config_debate_sop.md", # Path C: config debate
}

VALID_VERDICTS = {"MAINTAIN", "DOWNGRADE", "SKIPPED"}
SCORECARD_FIELDS = ["evidence", "chain_completeness", "critique_quality", "defense_quality", "calibration"]
WEIGHTS = {"evidence": 0.30, "chain_completeness": 0.25, "critique_quality": 0.20, "defense_quality": 0.15, "calibration": 0.10}


def create_critic_agent(excluded_models: list[str] | None = None) -> Agent:
    """Build the Critic Agent (Devil's Advocate).

    Args:
        excluded_models: Models to skip (429 rate-limited models)
    """
    return Agent(
        role="Security Debate Advisor (Critic / Devil's Advocate)",
        goal=(
            "Challenge Analyst Agent results via adversarial debate. "
            "Validate every prerequisite with tools, detect overconfidence, "
            "output a 5-dimensional scorecard and verdict (MAINTAIN / DOWNGRADE / SKIPPED)."
        ),
        backstory=f"""You are a rigorous Red Team Analyst.

{CONSTITUTION}

## Debate SOP (from skills/debate_sop.md)
{CRITIC_SKILL}

## Output Specification (Critic Data Contract)
Output ONLY the following JSON, no text outside it:
```json
{{
  "debate_rounds": 1,
  "challenges": ["Challenge 1: description (English)"],
  "scorecard": {{
    "evidence": 0.85, "chain_completeness": 0.80,
    "critique_quality": 0.75, "defense_quality": 0.70, "calibration": 0.90
  }},
  "weighted_score": 80.5,
  "verdict": "MAINTAIN",
  "reasoning": "One sentence verdict rationale (English)",
  "generated_at": "ISO 8601 timestamp"
}}
```

## Verdict Rules
- weighted_score >= 70 -> verdict: "MAINTAIN"
- 50 <= score < 70    -> verdict: "MAINTAIN" (with challenge notes)
- score < 50          -> verdict: "DOWNGRADE"

## Prohibited Actions
- Do NOT downgrade a CVE with in_cisa_kev=true
- Do NOT conclude without calling at least one tool
""",
        tools=[check_cisa_kev, search_exploits, read_memory],
        llm=get_llm(exclude_models=excluded_models),  # lazy init: 只在建立 Agent 時才呼叫
        verbose=True,
        max_iter=8,
        allow_delegation=False,
    )


def create_critic_task(agent: Agent, analyst_output: str) -> Task:
    """Build Critic Task."""
    return Task(
        description=f"""
You are the Devil's Advocate. Analyst Agent result:
{analyst_output}

Steps (max {MAX_DEBATE_ROUNDS} rounds):
1. For chain_risk.is_chain=true: call check_cisa_kev + search_exploits
2. For confidence=HIGH with low tool coverage: detect overconfidence
3. Calculate 5D scorecard (evidence/chain_completeness/critique_quality/defense_quality/calibration)
4. Determine verdict: MAINTAIN or DOWNGRADE
5. Output complete JSON debate report

Note: if any CVE has in_cisa_kev=true, DOWNGRADE is prohibited.
""",
        expected_output="Complete JSON debate report with debate_rounds, challenges, scorecard, weighted_score, verdict, reasoning.",
        agent=agent,
    )


def _extract_json_from_output(raw: str) -> dict[str, Any]:
    """Extract JSON from LLM output (tolerates Markdown wrapping)."""
    if not raw or not isinstance(raw, str):
        return {}
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        pass
    match = re.search(r"```(?:json)?\s*([\s\S]+?)```", raw)
    if match:
        try:
            return json.loads(match.group(1).strip())
        except (json.JSONDecodeError, ValueError):
            pass
    match = re.search(r"\{[\s\S]+\}", raw)
    if match:
        try:
            return json.loads(match.group(0))
        except (json.JSONDecodeError, ValueError):
            pass
    return {}


def _build_skipped_output(reason: str = "ENABLE_CRITIC=false") -> dict[str, Any]:
    """Harness Layer 1: Build SKIPPED output."""
    return {
        "debate_rounds": 0, "challenges": [],
        "scorecard": {field: 1.0 for field in SCORECARD_FIELDS},
        "weighted_score": 100.0, "verdict": "SKIPPED",
        "reasoning": reason,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "_harness_skipped": True,
    }


def _compute_weighted_score(scorecard: dict[str, Any]) -> float:
    """
    Calculate 5D weighted score (0-100). Type-safe: float() conversion per field.
    FIX: Invalid types fall back to 0.5 instead of raising TypeError.
    """
    total = 0.0
    for field, weight in WEIGHTS.items():
        raw = scorecard.get(field, 0.5)
        try:
            val = float(raw)
        except (TypeError, ValueError):
            logger.warning("Critic scorecard.%s = %r invalid type, using 0.5", field, raw)
            val = 0.5
        total += max(0.0, min(1.0, val)) * weight
    return round(min(100.0, max(0.0, total * 100)), 2)


def _build_fallback_output(analyst_data: dict[str, Any]) -> dict[str, Any]:
    """Harness guarantee: minimum viable debate report when LLM output unparseable."""
    analysis = analyst_data.get("analysis", analyst_data.get("vulnerabilities", []))
    challenges = [
        f"Challenge: {item.get('cve_id', 'UNKNOWN')} chain prerequisites not fully verified."
        for item in analysis
        if item.get("chain_risk", {}).get("is_chain") and item.get("chain_risk", {}).get("confidence") == "HIGH"
    ] or ["No specific challenges raised (fallback mode)."]
    scorecard = {"evidence": 0.6, "chain_completeness": 0.5, "critique_quality": 0.6, "defense_quality": 0.7, "calibration": 0.7}
    weighted_score = _compute_weighted_score(scorecard)
    return {
        "debate_rounds": 1, "challenges": challenges, "scorecard": scorecard,
        "weighted_score": weighted_score,
        "verdict": "MAINTAIN" if weighted_score >= 50 else "DOWNGRADE",
        "reasoning": "Fallback evaluation: LLM output unavailable. Conservative scoring applied.",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "_harness_fallback": True,
    }


def _harness_validate_schema(output: dict[str, Any]) -> list[str]:
    """Harness Layer 2: Validate output format (data_contracts.md Critic section)."""
    errors = []
    for k in ["debate_rounds", "challenges", "scorecard", "weighted_score", "verdict"]:
        if k not in output:
            errors.append(f"Missing required field: {k}")
    scorecard = output.get("scorecard", {})
    if not isinstance(scorecard, dict):
        errors.append("scorecard must be an object")
        return errors
    for field in SCORECARD_FIELDS:
        if field not in scorecard:
            errors.append(f"scorecard missing field: {field}")
        else:
            try:
                val = float(scorecard[field])
                if not (0.0 <= val <= 1.0):
                    errors.append(f"scorecard.{field} out of range ({val})")
            except (TypeError, ValueError):
                errors.append(f"scorecard.{field} invalid type: {scorecard[field]!r}")
    return errors


def _harness_repair_scorecard(output: dict[str, Any]) -> None:
    """
    Harness Layer 2': Deep scorecard repair.
    FIX for stress test defect: 'Shallow merge defect - 2,500 cases with missing
    calibration field escaped because Layer 2 only does top-level key comparison.'
    """
    scorecard = output.get("scorecard")
    if not isinstance(scorecard, dict):
        output["scorecard"] = {field: 0.6 for field in SCORECARD_FIELDS}
        logger.warning("Harness Layer 2': scorecard entirely missing, building safe defaults")
        return
    for field in SCORECARD_FIELDS:
        if field not in scorecard:
            scorecard[field] = 0.6
            logger.warning("Harness Layer 2': scorecard missing sub-field %s, auto-patched to 0.6", field)
        else:
            try:
                scorecard[field] = max(0.0, min(1.0, float(scorecard[field])))
            except (TypeError, ValueError):
                logger.warning("Harness Layer 2': scorecard.%s invalid type (%r), reset to 0.5", field, scorecard[field])
                scorecard[field] = 0.5


def _harness_validate_verdict(output: dict[str, Any]) -> None:
    """
    Harness Layer 3: verdict enum + weighted_score type safety.
    FIX for stress test defect: '392 TypeError cases - str >= int comparison failure
    when LLM returns string as weighted_score. Root fix: force float FIRST.'
    """
    # ROOT FIX: force weighted_score to float before any comparison
    raw_ws = output.get("weighted_score", 50.0)
    try:
        output["weighted_score"] = float(raw_ws)
    except (TypeError, ValueError):
        logger.warning("Harness Layer 3: weighted_score invalid (%r), forcing to 50.0", raw_ws)
        output["weighted_score"] = 50.0

    # Correct verdict enum
    if output.get("verdict", "") not in VALID_VERDICTS:
        logger.warning("Harness Layer 3: illegal verdict=%s, forcing MAINTAIN", output.get("verdict"))
        output["verdict"] = "MAINTAIN"

    # Recompute from scorecard (prevent LLM arithmetic errors)
    scorecard = output.get("scorecard", {})
    if scorecard:
        recalculated = _compute_weighted_score(scorecard)
        original = output["weighted_score"]  # guaranteed float
        if abs(recalculated - original) > 5.0:
            logger.warning("Harness Layer 3: weighted_score drift (%.2f vs %.2f), using recalculated", original, recalculated)
            output["weighted_score"] = recalculated
        if output["verdict"] != "SKIPPED":
            output["verdict"] = "MAINTAIN" if output["weighted_score"] >= 50 else "DOWNGRADE"


def run_critic_pipeline(analyst_output: str | dict[str, Any], input_type: str = "pkg") -> dict[str, Any]:
    """Execute Critic Agent Pipeline (Harness Layers 1/1b/2/2'/3).

    Args:
        analyst_output: Analyst 輸出 JSON
        input_type:     Path-Aware Skill 路由（pkg/code/injection/config）
    """
    from crewai import Crew, Process

    if not ENABLE_CRITIC:
        logger.info("Harness Layer 1: ENABLE_CRITIC=false, skipping")
        return _build_skipped_output()

    if isinstance(analyst_output, dict):
        analyst_dict = analyst_output
        analyst_str = json.dumps(analyst_output, ensure_ascii=False, indent=2)
    else:
        analyst_str = str(analyst_output) if analyst_output else ""
        try:
            analyst_dict = json.loads(analyst_str)
        except (json.JSONDecodeError, ValueError):
            analyst_dict = {}

    logger.info("Critic Pipeline started (max rounds: %d)", MAX_DEBATE_ROUNDS)

    # 429 自動輪替：最多重試 MAX_LLM_RETRIES 次（每次切換模型）
    from core.config import mark_model_failed, get_current_model_name
    MAX_LLM_RETRIES = 2
    excluded_models: list[str] = []

    output: dict[str, Any] = {}
    crew_success = False

    for attempt in range(MAX_LLM_RETRIES + 1):
        agent = create_critic_agent(excluded_models)
        task = create_critic_task(agent, analyst_str)

        try:
            crew = Crew(agents=[agent], tasks=[task], process=Process.sequential, verbose=True)
            logger.info("Critic Crew kickoff (attempt %d/%d)", attempt + 1, MAX_LLM_RETRIES + 1)
            try:
                from core.checkpoint import recorder as _cp
                _c_model = get_current_model_name(agent.llm)
                _cp.llm_call("critic", _c_model, "openrouter", f"attempt={attempt+1}")
            except Exception:
                _c_model = "unknown"
            _t_c = time.time()
            result = crew.kickoff()
            raw_output = str(result.raw) if hasattr(result, "raw") else str(result)
            try:
                _cp.llm_result("critic", _c_model, "SUCCESS",
                               len(raw_output), int((time.time() - _t_c) * 1000),
                               thinking=raw_output[:1000])
            except Exception:
                pass
            output = _extract_json_from_output(raw_output)
            crew_success = bool(output)
            break  # 成功則跳出
        except Exception as e:
            error_str = str(e)
            if "429" in error_str and attempt < MAX_LLM_RETRIES:
                current_model = get_current_model_name(agent.llm)
                mark_model_failed(current_model)
                excluded_models.append(current_model)
                import re as _re
                _m = _re.search(r'retry.{1,10}(\d+\.?\d*)s', error_str, _re.IGNORECASE)
                retry_after = float(_m.group(1)) if _m else 0.0
                logger.warning("[RETRY] Critic 429 on %s (attempt %d/%d), api_retry_after=%.0fs",
                              current_model, attempt + 1, MAX_LLM_RETRIES, retry_after)
                try:
                    _cp.llm_retry("critic", current_model, error_str[:200],
                                  attempt + 1, "next_in_waterfall")
                except Exception:
                    pass
                from core.config import rate_limiter as _rl
                _rl.on_429(retry_after=retry_after, caller="critic")  # 最少 30s
                continue
            logger.error("Critic CrewAI failed: %s", e)
            try:
                _cp.llm_error("critic", _c_model, error_str[:300])
            except Exception:
                pass

    if not crew_success or not output:
        logger.warning("Harness Layer 1b: LLM output invalid, using fallback")
        output = _build_fallback_output(analyst_dict)

    schema_errors = _harness_validate_schema(output)
    if schema_errors:
        logger.warning("Harness Layer 2: Schema errors %s, merging fallback", schema_errors)
        fallback = _build_fallback_output(analyst_dict)
        for k, v in fallback.items():
            if k not in output:
                output[k] = v

    _harness_repair_scorecard(output)     # Layer 2'
    _harness_validate_verdict(output)     # Layer 3

    if "generated_at" not in output:
        output["generated_at"] = datetime.now(timezone.utc).isoformat()

    logger.info("Critic Pipeline done | verdict=%s | score=%.1f | challenges=%d",
                output.get("verdict"), output.get("weighted_score", 0), len(output.get("challenges", [])))
    return output


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
    _test = json.dumps({"analysis": [{"cve_id": "CVE-2024-42005", "original_cvss": 9.8, "chain_risk": {"is_chain": True, "confidence": "HIGH"}}]})
    result = run_critic_pipeline(_test)
    print(json.dumps(result, ensure_ascii=False, indent=2))
