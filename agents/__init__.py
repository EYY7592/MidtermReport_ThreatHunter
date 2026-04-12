# ThreatHunter Agents 模組
# CrewAI Agent 定義
#
# 重要：使用 lazy import 避免 import agents 時觸發所有模組的 LLM 初始化
# 每次 eager import 都會呼叫 get_llm()，浪費 API 配額並觸發 cp950 編碼問題

__all__ = [
    # Orchestrator（CrewAI Hierarchical Manager + MacNet 動態路由）
    "build_orchestrator_agent",
    "run_orchestration",
    "classify_input",
    "review_worker_output",
    "finalize_orchestration",
    "OrchestrationContext",
    "ScanPath",
    # Security Guard（隔離 LLM — Dual LLM Pattern）
    "build_security_guard_agent",
    "run_security_guard",
    "extract_code_surface",
    # Intel Fusion（六維情報融合師）
    "build_intel_fusion_agent",
    "run_intel_fusion",
    "calculate_composite_score",
    # Scout
    "create_scout_agent",
    "create_scout_task",
    "run_scout_pipeline",
    # Analyst
    "create_analyst_agent",
    "create_analyst_task",
    "run_analyst_pipeline",
    # Critic（主要辯論 Pipeline）
    "create_critic_agent",
    "create_critic_task",
    "run_critic_pipeline",
    # Advisor
    "create_advisor_agent",
    "create_advisor_task",
    "run_advisor_pipeline",
]


def __getattr__(name: str):
    """Lazy import：按需載入 Agent 模組，避免 import 時觸發 LLM 初始化"""
    # Orchestrator（新增：CrewAI Hierarchical Manager）
    if name in (
        "build_orchestrator_agent", "run_orchestration", "classify_input",
        "review_worker_output", "finalize_orchestration",
        "OrchestrationContext", "ScanPath",
    ):
        from agents.orchestrator import (
            build_orchestrator_agent, run_orchestration, classify_input,
            review_worker_output, finalize_orchestration,
            OrchestrationContext, ScanPath,
        )
        return locals()[name]
    elif name in ("build_security_guard_agent", "run_security_guard", "extract_code_surface"):
        from agents.security_guard import (
            build_security_guard_agent, run_security_guard, extract_code_surface,
        )
        return locals()[name]
    elif name in ("build_intel_fusion_agent", "run_intel_fusion", "calculate_composite_score"):
        from agents.intel_fusion import (
            build_intel_fusion_agent, run_intel_fusion, calculate_composite_score,
        )
        return locals()[name]
    elif name in ("create_scout_agent", "create_scout_task", "run_scout_pipeline"):
        from agents.scout import create_scout_agent, create_scout_task, run_scout_pipeline
        return locals()[name]
    elif name in ("create_analyst_agent", "create_analyst_task", "run_analyst_pipeline"):
        from agents.analyst import create_analyst_agent, create_analyst_task, run_analyst_pipeline
        return locals()[name]
    elif name in (
        "create_critic_agent", "create_critic_task",
        "run_critic_pipeline",
    ):
        from agents.critic import (
            create_critic_agent, create_critic_task,
            run_critic_pipeline,
        )
        return locals()[name]
    elif name in ("create_advisor_agent", "create_advisor_task", "run_advisor_pipeline"):
        from agents.advisor import create_advisor_agent, create_advisor_task, run_advisor_pipeline
        return locals()[name]
    raise AttributeError(f"module 'agents' has no attribute {name!r}")
