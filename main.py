"""
ThreatHunter 主程式
==================

CrewAI Sequential Pipeline：Scout → Analyst → [Critic] → Advisor

目前狀態：Day 1 骨架（Stub Agent）
  - Scout：Stub（成員 B 替換）
  - Analyst：Stub（成員 C 替換）
  - Advisor：組長負責（Day 2 真實化）
  - Critic：可插拔（Day 4 啟用）

遵循文件：
  - FINAL_PLAN.md §三（架構圖）§九（時間線）
  - leader_plan.md §Day 1
"""

import json
import logging
import sys
from datetime import datetime, timezone

from crewai import Agent, Task, Crew, Process

from config import (
    get_llm,
    ENABLE_CRITIC,
    SYSTEM_CONSTITUTION,
    degradation_status,
)
from tools.memory_tool import read_memory, write_memory, history_search

logger = logging.getLogger("threathunter.main")


# ═══════════════════════════════════════════════════════════════
# Stub Agent 工廠（Day 1 佔位，Day 2 由成員替換）
# ═══════════════════════════════════════════════════════════════

def create_stub_scout(llm) -> Agent:
    """Stub Scout Agent — 成員 B 替換為 agents/scout.py"""
    return Agent(
        role="Scout Agent（偵察員）",
        goal="收集指定技術堆疊的已知漏洞情報",
        backstory=(
            f"{SYSTEM_CONSTITUTION}\n\n"
            "你是 ThreatHunter 的偵察員。\n"
            "你的職責是針對使用者提供的技術堆疊，\n"
            "使用 NVD 和 OTX 等工具查詢已知漏洞。\n\n"
            "【Stub 模式】回傳模擬情報。"
        ),
        tools=[read_memory, write_memory],
        llm=llm,
        verbose=True,
        max_iter=10,
    )


def create_stub_analyst(llm) -> Agent:
    """Stub Analyst Agent — 成員 C 替換為 agents/analyst.py"""
    return Agent(
        role="Analyst Agent（分析師）",
        goal="分析漏洞之間的連鎖風險，評估整體威脅等級",
        backstory=(
            f"{SYSTEM_CONSTITUTION}\n\n"
            "你是 ThreatHunter 的分析師。\n"
            "你的職責是驗證 Scout 回報的漏洞，\n"
            "分析漏洞之間是否存在連鎖攻擊路徑。\n\n"
            "【Stub 模式】回傳模擬分析。"
        ),
        tools=[read_memory, write_memory],
        llm=llm,
        verbose=True,
        max_iter=10,
    )


def create_stub_advisor(llm) -> Agent:
    """Stub Advisor Agent — 組長 Day 2 替換為真實版本"""
    return Agent(
        role="Advisor Agent（顧問 / Judge）",
        goal="根據分析結果產出分級行動方案",
        backstory=(
            f"{SYSTEM_CONSTITUTION}\n\n"
            "你是 ThreatHunter 的顧問兼裁決者（Judge）。\n"
            "產出 🔴URGENT / 🟡IMPORTANT / 🟢RESOLVED 行動方案。\n\n"
            "【Stub 模式】回傳模擬報告。"
        ),
        tools=[read_memory, write_memory, history_search],
        llm=llm,
        verbose=True,
        max_iter=10,
    )


def create_stub_critic(llm) -> Agent:
    """Stub Critic Agent — Day 4 可插拔"""
    return Agent(
        role="Critic Agent（批評者）",
        goal="質疑 Analyst 的分析結論，確保推理嚴謹",
        backstory=(
            f"{SYSTEM_CONSTITUTION}\n\n"
            "你是 Devil's Advocate。\n"
            "質疑每個連鎖推理，檢驗證據充分性。\n\n"
            "【Stub 模式】回傳模擬辯論。"
        ),
        tools=[],
        llm=llm,
        verbose=True,
        max_iter=5,
    )


# ═══════════════════════════════════════════════════════════════
# Task 定義（JSON 契約嚴格對應 FINAL_PLAN.md §八）
# ═══════════════════════════════════════════════════════════════

def create_scout_task(agent: Agent, tech_stack: str) -> Task:
    """Scout 偵察任務"""
    return Task(
        description=(
            f"針對以下技術堆疊進行漏洞情報收集：\n"
            f"技術堆疊：{tech_stack}\n\n"
            "步驟：\n"
            "1. 讀取歷史記憶（read_memory）\n"
            "2. 查詢 NVD / OTX\n"
            "3. 比對新舊差異（is_new 標記）\n"
            "4. 寫入新記憶（write_memory）\n"
            "5. 輸出結構化情報清單"
        ),
        expected_output=(
            '嚴格 JSON 格式：{"scan_id":"...","timestamp":"...","tech_stack":[...],'
            '"vulnerabilities":[{"cve_id":"...","package":"...","cvss_score":0.0,'
            '"severity":"...","description":"...","is_new":true}],'
            '"summary":{"total":0,"new":0,"critical":0,"high":0}}'
        ),
        agent=agent,
    )


def create_analyst_task(agent: Agent) -> Task:
    """Analyst 分析任務"""
    return Task(
        description=(
            "基於 Scout 的情報清單進行深度風險分析：\n"
            "1. 驗證最高危 CVE（CISA KEV）\n"
            "2. 搜尋公開 Exploit\n"
            "3. 分析漏洞連鎖路徑\n"
            "4. 計算風險分數與趨勢"
        ),
        expected_output=(
            '嚴格 JSON 格式：{"scan_id":"...","risk_score":0,"risk_trend":"...",'
            '"analysis":[{"cve_id":"...","original_cvss":0.0,"adjusted_risk":"...",'
            '"in_cisa_kev":false,"exploit_available":false,'
            '"chain_risk":{"is_chain":false,"chain_with":[],'
            '"chain_description":"...","confidence":"..."},'
            '"reasoning":"..."}]}'
        ),
        agent=agent,
    )


def create_critic_task(agent: Agent) -> Task:
    """Critic 辯論任務（可插拔）"""
    return Task(
        description=(
            "審閱 Analyst 報告，對抗式質疑：\n"
            "1. 檢查 CRITICAL/HIGH 判定的證據\n"
            "2. 質疑連鎖攻擊前提\n"
            "3. 五維評分卡評估\n"
            "4. 最多 2 輪辯論"
        ),
        expected_output=(
            '嚴格 JSON 格式：{"debate_rounds":0,"challenges":[...],'
            '"scorecard":{"evidence":0.0,"chain_completeness":0.0,'
            '"critique_quality":0.0,"defense_quality":0.0,"calibration":0.0},'
            '"weighted_score":0.0,"verdict":"MAINTAIN"}'
        ),
        agent=agent,
    )


def create_advisor_task(agent: Agent) -> Task:
    """Advisor 報告任務"""
    return Task(
        description=(
            "綜合所有分析結果產出行動報告：\n"
            "1. 讀取歷史建議（read_memory）\n"
            "2. 比對使用者回饋\n"
            "3. 搜尋語義相關歷史（history_search）\n"
            "4. 產出 🔴🟡🟢 分級方案\n"
            "5. 寫入記憶（write_memory）"
        ),
        expected_output=(
            '嚴格 JSON 格式：{"executive_summary":"...",'
            '"actions":{"urgent":[{"cve_id":"...","action":"...","command":"..."}],'
            '"important":[{"cve_id":"...","action":"..."}],'
            '"resolved":[{"cve_id":"...","resolved_date":"..."}]},'
            '"risk_score":0,"risk_trend":"...","scan_count":0}'
        ),
        agent=agent,
    )


# ═══════════════════════════════════════════════════════════════
# Crew 建構與執行
# ═══════════════════════════════════════════════════════════════

def build_crew(tech_stack: str) -> Crew:
    """
    建立完整管線：Scout → Analyst → [Critic] → Advisor

    Critic 由 ENABLE_CRITIC 環境變數控制。
    """
    logger.info("═" * 55)
    logger.info("  ThreatHunter 管線啟動")
    logger.info(f"  技術堆疊：{tech_stack}")
    logger.info(f"  Critic 辯論：{'✅ 啟用' if ENABLE_CRITIC else '❌ 停用'}")
    logger.info(f"  降級狀態：{degradation_status.get_display()}")
    logger.info("═" * 55)

    llm = get_llm()

    # 建立 Agents
    scout = create_stub_scout(llm)
    analyst = create_stub_analyst(llm)
    advisor = create_stub_advisor(llm)

    # 建立 Tasks
    scout_task = create_scout_task(scout, tech_stack)
    analyst_task = create_analyst_task(analyst)
    advisor_task = create_advisor_task(advisor)

    agents = [scout, analyst, advisor]
    tasks = [scout_task, analyst_task, advisor_task]

    # 可插拔 Critic
    if ENABLE_CRITIC:
        critic = create_stub_critic(llm)
        critic_task = create_critic_task(critic)
        agents.insert(2, critic)
        tasks.insert(2, critic_task)
        logger.info("⚖️ Critic Agent 已加入管線")

    crew = Crew(
        agents=agents,
        tasks=tasks,
        process=Process.sequential,
        verbose=True,
    )
    return crew


def run_pipeline(tech_stack: str) -> dict:
    """
    執行完整管線並回傳結果

    Args:
        tech_stack: 使用者輸入的技術堆疊

    Returns:
        管線執行結果 dict
    """
    start_time = datetime.now(timezone.utc)

    try:
        crew = build_crew(tech_stack)
        result = crew.kickoff(inputs={"tech_stack": tech_stack})

        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        logger.info(f"✅ 管線完成（耗時 {duration:.1f}s）")

        # 嘗試解析 JSON 結果
        try:
            if hasattr(result, "raw"):
                return json.loads(result.raw)
            return json.loads(str(result))
        except (json.JSONDecodeError, TypeError):
            return {
                "raw_output": str(result),
                "duration_seconds": duration,
                "degradation": degradation_status.to_dict(),
            }

    except Exception as e:
        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        logger.error(f"❌ 管線失敗（耗時 {duration:.1f}s）：{e}")
        degradation_status.degrade("Agent:Pipeline", str(e))
        return {
            "error": str(e),
            "duration_seconds": duration,
            "degradation": degradation_status.to_dict(),
        }


# ═══════════════════════════════════════════════════════════════
# CLI 入口
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) > 1:
        tech_stack = " ".join(sys.argv[1:])
    else:
        tech_stack = "Django 4.2, Redis 7.0, PostgreSQL 16"

    print(f"\n🔍 ThreatHunter — 掃描技術堆疊：{tech_stack}\n")
    result = run_pipeline(tech_stack)
    print("\n📋 結果：")
    print(json.dumps(result, ensure_ascii=False, indent=2))
