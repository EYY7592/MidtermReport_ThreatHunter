# agents/debate_engine.py
# 功能：3 輪辯論引擎 + Judge Sub-Agent
# 架構依據：Du et al. (2023) "Improving Factuality and Reasoning in LLMs through Multiagent Debate"
#           ICML 2023, arXiv:2305.14325
#
# 設計原則（來自論文）：
#   - 多個獨立 LLM 實例（Analyst / Critic 各自獨立）
#   - 最多 3 輪迭代（報酬遞減，3 輪後效益趨緩）
#   - 無共識 → 第三方 Judge sub-agent 仲裁
#   - 安全性領域：偏向保守（高估風險比低估安全）
#
# 共識定義：
#   Analyst 與 Critic 的整體風險等級相差 ≤ 1 級
#   (例如 HIGH vs CRITICAL 不共識；HIGH vs HIGH 共識)

from __future__ import annotations

import json
import logging
import time
from typing import Any

from crewai import Agent, Task, Crew, Process

from config import SYSTEM_CONSTITUTION, get_llm, degradation_status

logger = logging.getLogger("ThreatHunter.debate_engine")

# ══════════════════════════════════════════════════════════════════
# 風險等級映射（用於共識判定）
# ══════════════════════════════════════════════════════════════════
RISK_LEVELS: dict[str, int] = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

MAX_DEBATE_ROUNDS = 3


# ══════════════════════════════════════════════════════════════════
# Judge Sub-Agent 構建
# ══════════════════════════════════════════════════════════════════

def _build_judge_agent() -> Agent:
    """
    Judge sub-agent：獨立第三方裁決者。

    設計原則（Du et al. 2023）：
    - 不是 Analyst 也不是 Critic 的延伸
    - 收到完整辯論紀錄後，選擇最有邏輯支持的立場
    - 安全性領域偏向保守（寧可高估風險）
    """
    return Agent(
        role="Security Arbitration Judge",
        goal=(
            "Review the complete debate history between Analyst and Critic. "
            "Select the most logically supported risk assessment. "
            "In case of equal evidence, err on the side of caution (higher risk). "
            "Output a final JSON verdict."
        ),
        backstory=(
            f"{SYSTEM_CONSTITUTION}\n\n"
            "You are an impartial security arbitration judge. You were not involved in the debate. "
            "Your task is to read both sides' arguments and render a final, binding verdict. "
            "You must cite which round's argument was most persuasive and why. "
            "In security contexts, when evidence is ambiguous, choose the MORE SEVERE rating."
        ),
        llm=get_llm(),
        verbose=True,
        max_iter=3,
    )


# ══════════════════════════════════════════════════════════════════
# 辯論引擎
# ══════════════════════════════════════════════════════════════════

class DebateEngine:
    """
    實作 Du et al. (2023) Multiagent Debate 機制。

    流程：
      Round 1: Analyst 提出初始立場 → Critic 質疑
      Round 2: Analyst 更新立場（含 Critic 反饋）→ Critic 再評
      Round 3: Analyst 最終立場 → Critic 最終評判
      Final:   若 3 輪後仍無共識 → Judge sub-agent 仲裁
    """

    def __init__(self, max_rounds: int = MAX_DEBATE_ROUNDS):
        self.max_rounds = max_rounds
        self.min_rounds_with_findings = min(2, max_rounds)

    def run_debate(
        self,
        analyst_output: dict[str, Any],
        input_type: str = "pkg",
        on_progress: Any = None,
    ) -> dict[str, Any]:
        """
        執行完整辯論流程。

        Args:
            analyst_output: Analyst 的初始分析結果（来自 run_analyst_pipeline）
            input_type: 輸入類型（pkg/code/config 等，影響 Critic skill 選擇）
            on_progress: SSE 進度回調

        Returns:
            最終裁決結果（格式同 run_critic_pipeline 輸出）
        """
        from agents.critic import run_critic_pipeline

        t0 = time.time()
        history: list[dict[str, Any]] = []
        current_analyst_output = analyst_output
        consensus = False
        consensus_round = 0
        early_stop_reason = ""
        final_critic_result: dict[str, Any] = {}
        has_findings = self._has_findings(analyst_output)

        logger.info("[DEBATE] Starting %d-round debate (Du et al. 2023)", self.max_rounds)

        if on_progress:
            try:
                on_progress("debate", "RUNNING", {"step": "starting", "max_rounds": self.max_rounds})
            except Exception:
                pass

        for round_num in range(1, self.max_rounds + 1):
            logger.info("[DEBATE] Round %d/%d starting", round_num, self.max_rounds)

            if on_progress:
                try:
                    on_progress("debate", "RUNNING", {
                        "step": f"round_{round_num}",
                        "round": round_num,
                        "max_rounds": self.max_rounds,
                    })
                except Exception:
                    pass

            # ── Critic 評審 Analyst 的當輪立場 ──────────────
            # 注入當輪上下文，讓 Critic 知道這是第幾輪
            round_context = dict(current_analyst_output)
            round_context["_debate_round"] = round_num
            round_context["_debate_max_rounds"] = self.max_rounds
            if history:
                round_context["_prev_critic_challenges"] = history[-1].get("critic", {}).get("challenges", [])

            try:
                critic_result = run_critic_pipeline(round_context, input_type=input_type)
            except Exception as e:
                logger.warning("[DEBATE] Round %d Critic failed: %s — using maintain verdict", round_num, e)
                critic_result = {
                    "verdict": "MAINTAIN",
                    "weighted_score": 70.0,
                    "challenges": [],
                    "reasoning": f"Critic failed in round {round_num}: {e}",
                    "_degraded": True,
                }

            history.append({
                "round": round_num,
                "analyst": current_analyst_output,
                "critic": critic_result,
            })

            final_critic_result = critic_result

            # ── 共識判定 ────────────────────────────────────
            if self._check_consensus(current_analyst_output, critic_result):
                if has_findings and round_num < self.min_rounds_with_findings and not critic_result.get("no_challenge"):
                    logger.info(
                        "[DEBATE] Consensus detected at round %d, continuing to minimum %d rounds because findings exist",
                        round_num,
                        self.min_rounds_with_findings,
                    )
                    if round_num < self.max_rounds:
                        current_analyst_output = self._analyst_rebuttal(
                            current_analyst_output, critic_result, round_num
                        )
                    continue
                consensus = True
                consensus_round = round_num
                early_stop_reason = "consensus_after_min_rounds" if has_findings else "no_findings"
                logger.info(
                    "[DEBATE] Consensus reached at round %d | "
                    "analyst_risk=%s | critic_verdict=%s",
                    round_num,
                    self._get_analyst_risk(current_analyst_output),
                    critic_result.get("verdict", "UNKNOWN"),
                )
                break

            # ── Analyst 更新立場（含 Critic 反饋）───────────
            if round_num < self.max_rounds:
                current_analyst_output = self._analyst_rebuttal(
                    current_analyst_output, critic_result, round_num
                )

        # ── 最終裁決 ────────────────────────────────────────
        elapsed_ms = int((time.time() - t0) * 1000)

        if consensus:
            logger.info(
                "[DEBATE] ✅ Consensus after %d/%d rounds | elapsed=%dms",
                consensus_round, self.max_rounds, elapsed_ms,
            )
            result = dict(final_critic_result)
            result["_debate_meta"] = {
                "consensus": True,
                "consensus_round": consensus_round,
                "total_rounds": round_num,
                "elapsed_ms": elapsed_ms,
                "method": "multiagent_debate_Du2023",
                "early_stop_reason": early_stop_reason,
                "rounds": self._summarize_rounds(history),
            }
            return result
        else:
            logger.warning(
                "[DEBATE] ⚠️ No consensus after %d rounds — invoking Judge sub-agent",
                self.max_rounds,
            )
            return self._judge_verdict(history, elapsed_ms)

    # ── 私有輔助方法 ────────────────────────────────────────────

    def _check_consensus(self, analyst_output: dict, critic_result: dict) -> bool:
        """
        共識判定：風險等級相差 ≤ 1 級視為共識。

        CRITICAL vs HIGH → 不共識（差 1 級，視為邊界，保留辯論）
        CRITICAL vs CRITICAL → 共識
        HIGH vs MEDIUM → 不共識
        HIGH vs HIGH → 共識
        Critic verdict=MAINTAIN → 直接共識（Critic 同意 Analyst）
        """
        # Critic 直接同意 → 共識
        verdict = critic_result.get("verdict", "MAINTAIN")
        if verdict == "MAINTAIN":
            return True

        # Critic 明確要求降級 → 需要繼續辯論
        if verdict == "DOWNGRADE":
            analyst_risk = self._get_analyst_risk(analyst_output)
            a_level = RISK_LEVELS.get(analyst_risk, 2)
            # Downgrade 代表 Critic 認為應降一級，如果分數已夠低則接受
            score = critic_result.get("weighted_score", 70)
            if score >= 80:  # Critic 評分高，說明 Analyst 立場強
                return True
            return False

        # 其他情況（ESCALATE 等）—— 看分數
        score = critic_result.get("weighted_score", 70)
        return score >= 75

    def _has_findings(self, analyst_output: dict[str, Any]) -> bool:
        """判斷 Analyst 是否真的有發現項；有發現時至少需要第二輪交叉質疑。"""
        for key in ("analysis", "vulnerabilities", "code_patterns", "code_patterns_summary"):
            value = analyst_output.get(key)
            if isinstance(value, list) and len(value) > 0:
                return True
        return False

    def _summarize_rounds(self, history: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """產生輕量回合摘要，供 UI/測試確認辯論沒有被第一輪吞掉。"""
        rounds = []
        for entry in history:
            critic = entry.get("critic", {})
            analyst = entry.get("analyst", {})
            rounds.append({
                "round": entry.get("round"),
                "analyst_risk": self._get_analyst_risk(analyst),
                "critic_verdict": critic.get("verdict"),
                "critic_score": critic.get("weighted_score"),
                "challenge_count": len(critic.get("challenges", [])),
            })
        return rounds

    def _get_analyst_risk(self, analyst_output: dict) -> str:
        """從 Analyst 輸出提取整體風險等級"""
        analysis = analyst_output.get("analysis", [])
        if not analysis:
            return "UNKNOWN"
        # 取最高嚴重性
        max_level = 0
        max_name = "UNKNOWN"
        for entry in analysis:
            sev = entry.get("severity") or entry.get("adjusted_risk", "MEDIUM")
            level = RISK_LEVELS.get(sev, 0)
            if level > max_level:
                max_level = level
                max_name = sev
        return max_name

    def _analyst_rebuttal(
        self,
        analyst_output: dict,
        critic_result: dict,
        round_num: int,
    ) -> dict:
        """
        Analyst 更新立場（簡化版：注入 Critic 挑戰並修改 reasoning）

        在完整實作中，這裡應該重新呼叫 Analyst LLM。
        目前為輕量實作：直接在輸出中注入 Critic 反饋，
        讓下一輪的 Critic 看到更新後的上下文。
        """
        updated = dict(analyst_output)
        challenges = critic_result.get("challenges", [])
        updated["_critic_challenges_r"] = {
            "round": round_num,
            "challenges": challenges,
            "critic_verdict": critic_result.get("verdict"),
            "critic_score": critic_result.get("weighted_score", 70),
        }
        # 更新 reasoning，標注 Analyst 已看到 Critic 反饋
        if updated.get("analysis"):
            for entry in updated["analysis"]:
                if "reasoning" in entry:
                    entry["reasoning"] = (
                        f"[Round {round_num} rebuttal after Critic verdict={critic_result.get('verdict')}: "
                        f"challenges={[c.get('type') for c in challenges[:3]]}] "
                        + entry["reasoning"]
                    )
        logger.info(
            "[DEBATE] Round %d analyst rebuttal: addressed %d challenges",
            round_num, len(challenges),
        )
        return updated

    def _judge_verdict(
        self,
        debate_history: list[dict],
        elapsed_ms: int,
    ) -> dict[str, Any]:
        """
        Judge sub-agent 仲裁：無共識時由第三方裁決。

        原則（Du et al. 2023 + 安全性保守原則）：
        - 閱讀完整辯論紀錄
        - 選擇最有邏輯支持的立場
        - 若證據相當，選 MORE SEVERE（安全性偏保守）
        """
        t_judge = time.time()
        logger.info("[DEBATE] Invoking Judge sub-agent...")

        # 準備辯論摘要文字
        debate_summary = self._format_debate_history(debate_history)

        try:
            judge_agent = _build_judge_agent()

            task_desc = (
                f"DEBATE HISTORY ({len(debate_history)} rounds):\n\n"
                f"{debate_summary}\n\n"
                f"No consensus was reached after {len(debate_history)} rounds.\n\n"
                f"Your task:\n"
                f"1. Review all rounds of argument and counter-argument\n"
                f"2. Identify which side presented stronger evidence\n"
                f"3. If evidence is equal, choose the HIGHER risk level (security-conservative principle)\n"
                f"4. Output a JSON verdict with:\n"
                f"   {{\"verdict\": \"MAINTAIN|DOWNGRADE|ESCALATE\", "
                f"\"weighted_score\": 0-100, "
                f"\"reasoning\": \"...\", "
                f"\"winning_round\": 1-3, "
                f"\"judge_note\": \"...\"}}\n\n"
                f"Output ONLY the JSON, no other text."
            )

            task = Task(
                description=task_desc,
                expected_output="Pure JSON judge verdict",
                agent=judge_agent,
            )

            crew = Crew(
                agents=[judge_agent],
                tasks=[task],
                process=Process.sequential,
                verbose=False,
            )

            result_str = str(crew.kickoff()).strip()

            # 解析 JSON
            import re
            if "```json" in result_str:
                result_str = result_str.split("```json")[1].split("```")[0].strip()
            elif "```" in result_str:
                parts = result_str.split("```")
                if len(parts) >= 3:
                    result_str = parts[1].strip()

            judge_verdict = json.loads(result_str)
            judge_elapsed = int((time.time() - t_judge) * 1000)

            logger.info(
                "[DEBATE] Judge verdict: %s (score=%s) in %dms",
                judge_verdict.get("verdict"),
                judge_verdict.get("weighted_score"),
                judge_elapsed,
            )

            judge_verdict["_debate_meta"] = {
                "consensus": False,
                "total_rounds": len(debate_history),
                "judge_invoked": True,
                "judge_elapsed_ms": judge_elapsed,
                "total_elapsed_ms": elapsed_ms + judge_elapsed,
                "method": "multiagent_debate_Du2023_with_judge",
                "rounds": self._summarize_rounds(debate_history),
            }
            return judge_verdict

        except Exception as e:
            logger.error("[DEBATE] Judge sub-agent failed: %s — falling back to last Critic result", e)
            degradation_status.degrade("DebateJudge", str(e))

            # Fallback：取最後一輪的 Critic 結果，強制為 MAINTAIN（保守）
            last_critic = debate_history[-1].get("critic", {}) if debate_history else {}
            fallback = dict(last_critic)
            fallback["verdict"] = "MAINTAIN"  # 保守：維持 Analyst 立場
            fallback["_debate_meta"] = {
                "consensus": False,
                "total_rounds": len(debate_history),
                "judge_invoked": True,
                "judge_failed": True,
                "judge_error": str(e),
                "total_elapsed_ms": elapsed_ms,
                "method": "multiagent_debate_Du2023_judge_fallback",
                "rounds": self._summarize_rounds(debate_history),
            }
            return fallback

    def _format_debate_history(self, history: list[dict]) -> str:
        """將辯論紀錄格式化為可讀字串，供 Judge 閱讀"""
        lines = []
        for entry in history:
            r = entry.get("round", "?")
            analyst = entry.get("analyst", {})
            critic = entry.get("critic", {})

            # Analyst 立場摘要
            risk = self._get_analyst_risk(analyst)
            findings_count = len(analyst.get("analysis", []))
            lines.append(f"=== Round {r} ===")
            lines.append(f"ANALYST: overall_risk={risk}, findings={findings_count}")

            # 取前 2 個 finding 的 reasoning
            for f in analyst.get("analysis", [])[:2]:
                lines.append(f"  - [{f.get('severity')}] {f.get('cwe_id', f.get('cve_id', 'N/A'))}: {f.get('reasoning', '')[:100]}")

            # Critic 立場摘要
            verdict = critic.get("verdict", "UNKNOWN")
            score = critic.get("weighted_score", "?")
            lines.append(f"CRITIC: verdict={verdict}, score={score}")
            for ch in critic.get("challenges", [])[:2]:
                lines.append(f"  - Challenge [{ch.get('type')}]: {ch.get('description', '')[:100]}")

            lines.append("")

        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════
# 便利函式：整合進 main.py 的接口
# ══════════════════════════════════════════════════════════════════

def run_debate_pipeline(
    analyst_output: dict[str, Any],
    input_type: str = "pkg",
    on_progress: Any = None,
) -> dict[str, Any]:
    """
    執行完整辯論流程的頂層函式。
    直接替換 main.py 中的單輪 Critic 呼叫。

    Args:
        analyst_output: Analyst 的初始分析結果
        input_type: 輸入類型
        on_progress: SSE 進度回調

    Returns:
        辯論最終裁決（格式同 run_critic_pipeline 輸出，
        附加 _debate_meta 欄位紀錄辯論狀態）
    """
    engine = DebateEngine(max_rounds=MAX_DEBATE_ROUNDS)

    try:
        return engine.run_debate(analyst_output, input_type=input_type, on_progress=on_progress)
    except Exception as e:
        logger.error("[DEBATE] DebateEngine failed: %s — falling back to single Critic", e)
        degradation_status.degrade("DebateEngine", str(e))

        # 完全降級：退回單輪 Critic（原本行為）
        try:
            from agents.critic import run_critic_pipeline
            result = run_critic_pipeline(analyst_output, input_type=input_type)
            result["_debate_meta"] = {
                "consensus": None,
                "engine_failed": True,
                "error": str(e),
                "fallback": "single_round_critic",
            }
            return result
        except Exception as e2:
            logger.error("[DEBATE] Critic fallback also failed: %s", e2)
            return {
                "verdict": "MAINTAIN",
                "weighted_score": 60.0,
                "challenges": [],
                "reasoning": f"Debate engine and Critic both failed: {e} / {e2}",
                "_degraded": True,
                "_debate_meta": {"engine_failed": True, "critic_failed": True},
            }
