# agents/intel_fusion.py
# 功能：Intel Fusion Agent — 六維情報融合師
# 架構依據：MacNet DAG 並行節點 + 六維複合評分公式
# Harness 支柱：Constraints（憲法注入）+ Observability（維度追蹤）+ Graceful Degradation
#
# 使用方式：
#   from agents.intel_fusion import build_intel_fusion_agent, run_intel_fusion
#
# 六維情報來源（來自 skills/intel_fusion.md）：
#   NVD(CVSS)=0.20, EPSS=0.30, KEV=0.25, GHSA=0.10, ATT&CK=0.10, OTX=0.05
#
# 自主決策（Agent 根據漏洞特徵動態調整）：
#   cve_year < 2020 → EPSS 降至 0.10
#   in_kev == True  → EPSS 降至 0（KEV 已是最高事實）
#   otx_fail_rate > 0.5 → OTX 降至 0.01

import json
import logging
import time
from typing import Any, Callable

from crewai import Agent, Task

from config import SKILLS_DIR, SYSTEM_CONSTITUTION, degradation_status, get_llm
from tools.kev_tool import check_cisa_kev
from tools.memory_tool import read_memory, write_memory
from tools.nvd_tool import search_nvd
from tools.otx_tool import search_otx

logger = logging.getLogger("ThreatHunter.intel_fusion")

# ══════════════════════════════════════════════════════════════
# 六維預設權重（skills/intel_fusion.md Step 2）
# ══════════════════════════════════════════════════════════════

DEFAULT_WEIGHTS = {
    "cvss": 0.20,   # NVD CVSS — 理論嚴重性
    "epss": 0.30,   # FIRST.org EPSS — 實際利用概率（最重要）
    "kev":  0.25,   # CISA KEV — 確認在野利用（二元）
    "ghsa": 0.10,   # GitHub Advisory — 生態系專屬
    "attck": 0.10,  # MITRE ATT&CK — 攻擊戰術類型
    "otx":  0.05,   # AlienVault OTX — IoC 情報（可信度較低）
}

SKILL_PATH = SKILLS_DIR / "intel_fusion.md"

# KEV 確認後的最低複合分數（品質紅線：KEV 確認不可低估）
KEV_MIN_COMPOSITE_SCORE = 8.0

# 信心度計算閾值
CONFIDENCE_HIGH_DIMS = 4    # >= 4 個維度有資料 → HIGH
CONFIDENCE_MEDIUM_DIMS = 2  # >= 2 個維度有資料 → MEDIUM


# ══════════════════════════════════════════════════════════════
# 動態加權計算引擎（確定性程式碼）
# ══════════════════════════════════════════════════════════════

def calculate_composite_score(
    cvss: float,
    epss: float,
    in_kev: bool,
    ghsa_hits: int,
    attack_techniques: int,
    otx_count: int,
    cve_year: int,
    otx_fail_rate: float = 0.0,
) -> tuple[float, dict, str]:
    """
    六維動態加權複合分數計算（skills/intel_fusion.md Step 4）。

    這是確定性函式，不依賴 LLM。即使 LLM 推理出錯，這個計算不受影響。

    權重動態調整規則（SOP Step 2）：
      cve_year < 2020 → epss_weight = 0.10（老漏洞 EPSS 數據少，重新分配至 cvss）
      in_kev == True  → epss_weight = 0（KEV 已是最高事實，重新分配至 kev）
      otx_fail_rate > 0.5 → otx_weight = 0.01（OTX 降為可選，重新分配至 cvss）

    Args:
        cvss: CVSS 分數（0.0-10.0）
        epss: EPSS 分數（0.0-1.0）
        in_kev: 是否在 CISA KEV 清單
        ghsa_hits: GHSA 告警命中數
        attack_techniques: ATT&CK 技術匹配數（暫時用 0-3 估算）
        otx_count: OTX 威脅情報命中數
        cve_year: CVE 發布年份（如 2024）
        otx_fail_rate: OTX API 失敗率（模組級追蹤）

    Returns:
        (composite_score, weights_used, confidence)
    """
    # ── Step 1：動態調整權重 ─────────────────────────────────
    weights = dict(DEFAULT_WEIGHTS)

    if in_kev:
        # KEV 確認 → EPSS 的「機率預測」已無意義（已確認在野）
        surplus = weights["epss"]
        weights["epss"] = 0.0
        weights["kev"] += surplus  # 重新分配給 KEV
        logger.info("[INTEL] Weight adjusted: in_kev=True → epss=0.0, kev+=%.2f", surplus)

    elif cve_year < 2020:
        # 老漏洞 → EPSS 數據稀疏，降低 EPSS 權重
        surplus = weights["epss"] - 0.10
        weights["epss"] = 0.10
        weights["cvss"] += surplus  # 重新分配給 CVSS（更可靠）
        logger.info("[INTEL] Weight adjusted: cve_year=%d < 2020 → epss=0.10, cvss+=%.2f", cve_year, surplus)

    if otx_fail_rate > 0.5:
        # OTX 不穩定 → 降低 OTX 權重
        surplus = weights["otx"] - 0.01
        weights["otx"] = 0.01
        weights["cvss"] += surplus
        logger.info("[INTEL] Weight adjusted: otx_fail_rate=%.2f → otx=0.01", otx_fail_rate)

    # 確保權重總和為 1.0（浮點數精度修正）
    total = sum(weights.values())
    if abs(total - 1.0) > 0.001:
        weights["cvss"] += 1.0 - total

    # ── Step 2：各維度分數正規化（統一到 0.0-1.0）────────────
    cvss_norm = min(cvss / 10.0, 1.0)               # CVSS 0-10 → 0-1
    epss_norm = min(max(float(epss), 0.0), 1.0)     # 已是 0-1
    kev_norm = 1.0 if in_kev else 0.0               # 二元
    ghsa_norm = min(ghsa_hits / 5.0, 1.0)           # 5+ 個 advisory → 滿分
    attck_norm = min(attack_techniques / 3.0, 1.0)  # 3+ 種技術 → 滿分
    otx_norm = min(otx_count / 10.0, 1.0)           # 10+ IoC → 滿分

    # ── Step 3：加權計算 + 正規化到 0-10 ──────────────────────
    composite_raw = (
        cvss_norm  * weights["cvss"] +
        epss_norm  * weights["epss"] +
        kev_norm   * weights["kev"]  +
        ghsa_norm  * weights["ghsa"] +
        attck_norm * weights["attck"] +
        otx_norm   * weights["otx"]
    )
    composite_score = round(composite_raw * 10.0, 4)

    # ── Step 4：品質紅線（KEV 確認不可低估）───────────────────
    if in_kev and composite_score < KEV_MIN_COMPOSITE_SCORE:
        logger.warning(
            "[INTEL] KEV hit but composite_score=%.2f < %.2f, applying floor",
            composite_score, KEV_MIN_COMPOSITE_SCORE,
        )
        composite_score = KEV_MIN_COMPOSITE_SCORE

    # ── Step 5：信心度計算（有多少維度有資料）───────────────────
    dims_with_data = sum([
        bool(cvss > 0),
        bool(epss > 0),
        True,  # KEV：已查詢（即使 in_kev=False 也算查過）
        bool(ghsa_hits > 0),
        bool(attack_techniques > 0),
        bool(otx_count > 0),
    ])
    if dims_with_data >= CONFIDENCE_HIGH_DIMS:
        confidence = "HIGH"
    elif dims_with_data >= CONFIDENCE_MEDIUM_DIMS:
        confidence = "MEDIUM"
    else:
        confidence = "NEEDS_VERIFICATION"

    return composite_score, weights, confidence


# ══════════════════════════════════════════════════════════════
# Skill SOP 載入
# ══════════════════════════════════════════════════════════════

# Phase 4D: 使用 SkillLoader 熱載入系統
try:
    from skills.skill_loader import skill_loader as _skill_loader
    _SKILL_LOADER_AVAILABLE = True
    logger.info("[IntelFusion] Phase 4D: SkillLoader 啟用 ✓")
except ImportError:
    _skill_loader = None
    _SKILL_LOADER_AVAILABLE = False


def _load_skill() -> str:
    """載入 Intel Fusion SOP（Phase 4D: SkillLoader 熱載入 + Graceful Degradation）"""
    # Phase 4D: SkillLoader 熱載入路徑
    if _SKILL_LOADER_AVAILABLE and _skill_loader is not None:
        try:
            return _skill_loader.load_skill("intel_fusion.md")
        except Exception as e:
            logger.warning("[IntelFusion] SkillLoader 失敗，回退磁碟讀取: %s", e)

    # Fallback: 直接從磁碟讀取
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            if SKILL_PATH.exists():
                content = SKILL_PATH.read_text(encoding=encoding).strip()
                if content:
                    logger.info("[OK] Intel Fusion Skill loaded: %d chars", len(content))
                    return content
        except (IOError, UnicodeDecodeError):
            continue

    logger.warning("[WARN] Intel Fusion Skill file not found, using fallback")
    return _FALLBACK_SKILL


_FALLBACK_SKILL = """
# Intel Fusion Agent — 六維情報融合 SOP

## 核心工作
1. 讀取 read_memory(intel_fusion) 取得 API 健康狀態
2. 對每個 CVE 自主選擇查詢哪些維度
3. 呼叫：search_nvd / check_cisa_kev / search_otx（已有 Tools）
4. EPSS 和 GHSA 需要另外的 Tool（若有）
5. KEV 命中 → 輸出 shortcut_kev: true 通知 Orchestrator
6. 輸出純 JSON 格式的六維評分結果
""".strip()


# ══════════════════════════════════════════════════════════════
# Agent 工廠
# ══════════════════════════════════════════════════════════════

def build_intel_fusion_agent(excluded_models: list[str] | None = None) -> Agent:
    """
    建立 Intel Fusion Agent（六維情報融合師）。

    可用 Tools：
      - search_nvd（NVD CVSS）
      - check_cisa_kev（KEV 清單）
      - search_otx（OTX 威脅情報）
      - fetch_epss_score（EPSS）
      - query_ghsa（GHSA）
      - read_memory / write_memory（API 健康狀態）

    Args:
        excluded_models: 要排除的模型名稱列表（429 重試時傳入）

    Returns:
        CrewAI Agent 實例
    """
    skill_content = _load_skill()

    # 嘗試載入 EPSS 和 GHSA Tool（可選，失敗時降級）
    optional_tools: list = []
    try:
        from tools.epss_tool import fetch_epss_score
        optional_tools.append(fetch_epss_score)
        logger.info("[OK] EPSS Tool loaded for Intel Fusion")
    except Exception as e:
        logger.warning("[WARN] EPSS Tool not available: %s", e)

    try:
        from tools.ghsa_tool import query_ghsa
        optional_tools.append(query_ghsa)
        logger.info("[OK] GHSA Tool loaded for Intel Fusion")
    except Exception as e:
        logger.warning("[WARN] GHSA Tool not available: %s", e)

    core_tools = [search_nvd, check_cisa_kev, search_otx, read_memory, write_memory]
    all_tools = core_tools + optional_tools

    backstory = f"""你是 ThreatHunter 的情報融合專家（Intel Fusion Agent）。
你的任務：自主決定查詢哪些情報維度，融合六維資料，輸出複合風險評分。

=== 系統憲法 ===
{SYSTEM_CONSTITUTION}

=== 六維融合 SOP ===
{skill_content}

=== 可用 Tools ===
- search_nvd：查 NVD CVSS 分數（幾乎永遠查）
- check_cisa_kev：查 CISA KEV 清單（幾乎永遠查，批次輸入逗號分隔）
- search_otx：查 OTX 威脅情報（CVSS >= 7.0 時查）
{('- fetch_epss_score: 查 EPSS 惡意利用機率（NOT in_kev 時查）' + chr(10)) if any(t.name == 'search_epss' for t in optional_tools) else ''}
{('- query_ghsa: 查 GitHub Advisory Database（Python/npm 套件查）' + chr(10)) if any(t.name == 'search_ghsa' for t in optional_tools) else ''}
- read_memory / write_memory：讀寫 API 健康狀態

=== 自主決策規則（必須遵守）===
- in_kev == True → 跳過 EPSS 查詢（KEV 已是最高事實），輸出 shortcut_kev: true
- cve_year < 2020 → EPSS 數據可能缺乏，可跳過 EPSS
- otx 連續失敗 → 記錄到 api_health 並降低 OTX 優先度
- 至少查詢 2 個維度（否則 confidence = NEEDS_VERIFICATION）

=== 輸出格式（必須是純 JSON）===
{{
  "fusion_results": [
    {{
      "cve_id": "CVE-2024-XXXX",
      "composite_score": 8.7,
      "dimension_scores": {{
        "cvss": 9.8, "epss": 0.97, "kev": true, "ghsa_severity": "CRITICAL",
        "attck_technique": "T1190", "otx_threat": "active"
      }},
      "weights_used": {{"cvss": 0.20, "epss": 0.30, "kev": 0.25, "ghsa": 0.10, "attck": 0.10, "otx": 0.05}},
      "confidence": "HIGH",
      "dimensions_used": ["nvd", "epss", "kev"],
      "shortcut_kev": false
    }}
  ],
  "strategy_applied": "standard_2024",
  "api_health_summary": {{"nvd": "ok", "epss": "ok", "kev": "ok"}}
}}
"""

    llm = get_llm(exclude_models=excluded_models or [])
    agent = Agent(
        role="Intelligence Fusion Specialist",
        goal=(
            "自主選擇六個情報維度的查詢組合，融合 NVD/EPSS/KEV/GHSA/ATT&CK/OTX 數據，"
            "輸出帶有維度貢獻率的複合風險評分，並在 KEV 命中時觸發 Small-World 捷徑。"
        ),
        backstory=backstory,
        tools=all_tools,
        llm=llm,
        verbose=True,       # Harness: Observability
        max_iter=5,         # v3.5: Gemini-3-Flash ~4s/call, 5次NVD/KEV查詢足夠
        allow_delegation=False,  # Intel Fusion 自己做完，不委派
    )

    logger.info(
        "[OK] Intel Fusion Agent created | tools=%s | max_iter=%d",
        [t.name for t in agent.tools], agent.max_iter,
    )
    return agent


# ══════════════════════════════════════════════════════════════
# Pipeline 執行器
# ══════════════════════════════════════════════════════════════

def run_intel_fusion(
    tech_stack_or_cves: str | list,
    on_progress: Callable | None = None,
    orchestration_ctx: Any = None,
) -> dict:
    """
    執行完整的 Intel Fusion Pipeline。

    Harness Engineering 多層保障：
      Layer 1（Agent）：LLM 自主選擇查詢維度 + 執行工具呼叫
      Layer 2（程式碼）：確定性 calculate_composite_score() 重新計算（防止 LLM 算錯）
      Layer 3（Schema）：驗證輸出格式 + KEV 命中通知 Orchestrator

    Args:
        tech_stack_or_cves: 技術堆疊字串 或 CVE ID 列表（Feedback Loop 用）
        on_progress: 進度回調（SSE 使用）
        orchestration_ctx: OrchestrationContext（用於記錄 KEV 捷徑）

    Returns:
        fusion_results dict（格式符合 FINAL_PLAN.md §六 的 Scout → Analyst 輸入）
    """
    t0 = time.time()
    logger.info("[INTEL] Starting Intel Fusion Pipeline...")

    if on_progress:
        try:
            on_progress("intel_fusion", "RUNNING", {"step": "initializing"})
        except Exception:
            pass

    # ── v3.4 準備輸入（輸入類型感知）────────────────────────────
    # list[str]：來自 PackageExtractor 的乾淨套件名稱（Path B 程式碼模式，正確路徑）
    # str：原始 tech_stack 或 CVE 列表（Path A 套件清單模式）
    if isinstance(tech_stack_or_cves, list):
        if not tech_stack_or_cves:
            # Harness Layer 0：空套件列表 → 結構性降級，不浪費 LLM 呼叫
            logger.warning(
                "[INTEL] Empty package list received — no 3rd-party packages identified. "
                "Returning structured empty result (not a LLM failure)."
            )
            if on_progress:
                try:
                    on_progress("intel_fusion", "COMPLETE", {
                        "status": "NO_PACKAGES",
                        "cves_scored": 0,
                        "message": "No third-party packages identified in source code",
                        "duration_ms": 0,
                    })
                except Exception:
                    pass
            return {
                "fusion_results": [],
                "strategy_applied": "no_packages",
                "api_health_summary": {},
                "_no_packages": True,
                "_message": "No third-party packages identified — only stdlib imports detected",
                "_duration_ms": 0,
            }

        input_str = ", ".join(tech_stack_or_cves)
        input_type = "package_list"
        package_list_for_task = tech_stack_or_cves
        logger.info("[INTEL] Input: package_list mode with %d packages: %s", len(tech_stack_or_cves), tech_stack_or_cves)
    else:
        input_str = str(tech_stack_or_cves)
        input_type = "tech_stack"
        package_list_for_task = []
        if len(input_str) > 500:
            logger.warning(
                "[INTEL] WARNING: input_str length=%d (may be raw source code). "
                "Expected package names. Use PackageExtractor in main.py.",
                len(input_str)
            )

    # ── 執行 Agent（含 429 重試）──────────────────────────────
    MAX_RETRIES = 2
    excluded_models: list[str] = []
    result: dict = {}

    for attempt in range(MAX_RETRIES + 1):
        try:
            from config import get_current_model_name, mark_model_failed
            from crewai import Crew, Process

            agent = build_intel_fusion_agent(excluded_models=excluded_models)

            # v3.4：根據輸入類型使用不同的 task description
            if package_list_for_task:
                pkg_lines = "\n".join(f"  - {pkg}" for pkg in package_list_for_task)
                task_desc = (
                    f"分析以下第三方套件的安全漏洞情報（由靜態分析從原始碼提取）：\n\n"
                    f"待查套件清單：\n{pkg_lines}\n\n"
                    f"輸入類型：{input_type}（套件名稱列表）\n\n"
                    f"你必須對每個套件逐一查詢，不可跳過任何一個：\n"
                    f"1. 先呼叫 read_memory(intel_fusion) 取得 API 健康狀態\n"
                    f"2. 對每個套件分別呼叫 search_nvd（例如：search_nvd('requests')）\n"
                    f"3. 批次呼叫 check_cisa_kev 查詢 KEV 狀態\n"
                    f"4. 若 NOT in_kev，呼叫 search_otx\n"
                    f"5. 呼叫 write_memory 儲存 API 健康狀態\n"
                    f"6. 輸出純 JSON fusion_results（格式如 SOP Step 7）\n\n"
                    f"重要提示：\n"
                    f"- 上方列出的是套件名稱（如 requests、flask），不是程式碼\n"
                    f"- 對每個套件名稱呼叫 search_nvd，例如 search_nvd('requests')\n"
                    f"- 每個套件可能有 0 到多個 CVE，如實回報\n"
                    f"絕對禁止：\n"
                    f"- 不可編造任何 CVE 編號或 EPSS 分數\n"
                    f"- 不可跳過工具呼叫\n"
                    f"- 輸出必須是純 JSON"
                )
            else:
                task_desc = (
                    f"分析以下技術堆疊或 CVE 列表的情報：\n{input_str[:2000]}\n\n"
                    f"輸入類型：{input_type}\n\n"
                    f"你需要：\n"
                    f"1. 先呼叫 read_memory(intel_fusion) 取得 API 健康狀態\n"
                    f"2. 對每個套件呼叫 search_nvd 取得 CVE 和 CVSS\n"
                    f"3. 批次呼叫 check_cisa_kev 查詢 KEV 狀態\n"
                    f"4. 若 NOT in_kev，呼叫 search_epss 或 search_otx\n"
                    f"5. Python 套件 → 呼叫 search_ghsa\n"
                    f"6. 呼叫 write_memory 儲存 API 健康狀態\n"
                    f"7. 輸出純 JSON fusion_results（格式如 SOP Step 7）\n\n"
                    f"絕對禁止：\n"
                    f"- 不可編造任何 CVE 編號或 EPSS 分數\n"
                    f"- 不可跳過工具呼叫\n"
                    f"- 輸出必須是純 JSON"
                )

            task = Task(
                description=task_desc,
                expected_output=(
                    "純 JSON 格式的六維情報融合結果，"
                    "含 fusion_results 陣列和 api_health_summary"
                ),
                agent=agent,
            )

            crew = Crew(
                agents=[agent],
                tasks=[task],
                process=Process.sequential,
                verbose=True,
            )
            try:
                from checkpoint import recorder as _cp
                from config import get_current_model_name as _gcmn
                _if_model = _gcmn(agent.llm)
                _cp.llm_call("intel_fusion", _if_model, "openrouter", f"attempt={attempt+1}")
            except Exception:
                _if_model = "unknown"
            _t_if = time.time()

            crew_result = crew.kickoff()
            result_str = str(crew_result).strip()

            try:
                _cp.llm_result("intel_fusion", _if_model, "SUCCESS",
                               len(result_str), int((time.time() - _t_if) * 1000),
                               thinking=result_str[:1000])
            except Exception:
                pass

            # ── 解析 JSON 輸出 ──────────────────────────
            if "```json" in result_str:
                result_str = result_str.split("```json")[1].split("```")[0].strip()
            elif "```" in result_str:
                parts = result_str.split("```")
                if len(parts) >= 3:
                    result_str = parts[1].strip()

            result = None
            try:
                result = json.loads(result_str)
            except json.JSONDecodeError:
                # 層 2：從大段文字中提取 {} block（LLM 加了解釋文字的情況）
                _jm = re.search(r'\{[\s\S]*\}', result_str)
                if _jm:
                    try:
                        result = json.loads(_jm.group(0))
                    except json.JSONDecodeError:
                        pass
                if result is None:
                    # 層 3：無法解析，讓外層 except 捕獲並 graceful degrade
                    raise ValueError(
                        f"LLM output is not JSON (len={len(result_str)}): {result_str[:120]}"
                    )
            break  # 成功

        except Exception as e:
            error_str = str(e)
            if "429" in error_str and attempt < MAX_RETRIES:
                from config import get_current_model_name, mark_model_failed
                try:
                    current_model = get_current_model_name(agent.llm)
                    mark_model_failed(current_model)
                    excluded_models.append(current_model)
                    import re as _re
                    _m = _re.search(r'retry.{1,10}(\d+\.?\d*)s', error_str, _re.IGNORECASE)
                    retry_after = float(_m.group(1)) if _m else 0.0
                    logger.warning("[INTEL] 429 on %s (attempt %d/%d), api_retry_after=%.0fs",
                                  current_model, attempt + 1, MAX_RETRIES, retry_after)
                    try:
                        from checkpoint import recorder as _cp2
                        _cp2.llm_retry("intel_fusion", current_model, error_str[:200],
                                       attempt + 1, "next_in_waterfall")
                    except Exception:
                        pass
                    from config import rate_limiter as _rl
                    _rl.on_429(retry_after=retry_after, caller="intel_fusion")  # 最少 30s
                    continue
                except Exception:
                    pass

            # 非 429 或重試超限 → Graceful Degradation
            logger.error("[INTEL] Agent failed: %s", e)
            degradation_status.degrade("Intel Fusion Agent", str(e))
            result = _build_degraded_result(input_str, str(e))
            break

    # ── Harness Layer 2：程式碼層重新計算複合分數 ────────────
    # 即使 LLM 計算錯誤，這一層確保數學正確性
    result = _verify_and_recalculate(result)
    try:
        _recalc_count = sum(1 for f in result.get("fusion_results", []) if f.get("_score_recalculated"))
        _cp.harness_check("intel_fusion", "L2", "score_recalculation",
                          "CORRECTED" if _recalc_count > 0 else "PASS",
                          details={"recalculated_count": _recalc_count,
                                   "total_fusions": len(result.get("fusion_results", []))})
    except Exception:
        pass

    # ── Harness Layer 3：KEV 捷徑通知 ────────────────────────
    if orchestration_ctx is not None:
        for fusion in result.get("fusion_results", []):
            if fusion.get("shortcut_kev") or fusion.get("dimension_scores", {}).get("kev"):
                cve_id = fusion.get("cve_id", "")
                if cve_id:
                    try:
                        orchestration_ctx.record_kev_hit(cve_id)
                        logger.warning("[INTEL] KEV shortcut registered for %s", cve_id)
                    except Exception:
                        pass

    duration_ms = int((time.time() - t0) * 1000)
    result["_duration_ms"] = duration_ms

    if on_progress:
        try:
            fusion_count = len(result.get("fusion_results", []))
            kev_hits = sum(1 for f in result.get("fusion_results", []) if f.get("shortcut_kev"))
            is_degraded = result.get("_degraded", False)
            on_progress("intel_fusion", "COMPLETE", {
                "status": "DEGRADED" if is_degraded else "SUCCESS",
                "fusion_count": fusion_count,
                "kev_hits": kev_hits,
                "duration_ms": duration_ms,
                # DEGRADED 時帶入錯誤訊息，供 server.py on_progress 提取
                "_degraded": is_degraded,
                "_error": result.get("_error", "") if is_degraded else "",
            })
        except Exception:
            pass

    logger.info(
        "[INTEL] Pipeline complete in %dms | fusions=%d",
        duration_ms, len(result.get("fusion_results", [])),
    )
    return result


def _verify_and_recalculate(result: dict) -> dict:
    """
    Harness Layer 2：用確定性程式碼重新計算複合分數。
    防止 LLM 計算錯誤或編造數字。
    """
    fusion_results = result.get("fusion_results", [])
    if not fusion_results:
        return result

    recalculated = []
    for fusion in fusion_results:
        try:
            dims = fusion.get("dimension_scores", {})
            cvss = float(dims.get("cvss", 0.0))
            epss = float(dims.get("epss", 0.0)) if dims.get("epss") is not None else 0.0
            in_kev = bool(dims.get("kev", False))
            ghsa_sev = dims.get("ghsa_severity", "UNKNOWN")
            ghsa_hits = {"CRITICAL": 3, "HIGH": 2, "MODERATE": 1, "LOW": 1}.get(ghsa_sev, 0)
            attck_tech = 1 if dims.get("attck_technique") else 0
            otx_threat = 1 if dims.get("otx_threat") == "active" else 0

            # 從 CVE ID 取出年份
            cve_id = fusion.get("cve_id", "CVE-2024-0000")
            try:
                cve_year = int(cve_id.split("-")[1])
            except (IndexError, ValueError):
                cve_year = 2024

            recalculated_score, weights, confidence = calculate_composite_score(
                cvss=cvss,
                epss=epss,
                in_kev=in_kev,
                ghsa_hits=ghsa_hits,
                attack_techniques=attck_tech,
                otx_count=otx_threat,
                cve_year=cve_year,
            )

            # 若 LLM 的分數與程式碼計算差異超過 1.5 → 使用程式碼計算的（更可信）
            original_score = float(fusion.get("composite_score", recalculated_score))
            if abs(original_score - recalculated_score) > 1.5:
                logger.warning(
                    "[INTEL][VERIFY] Score discrepancy for %s: LLM=%.2f, Code=%.2f → using Code",
                    cve_id, original_score, recalculated_score,
                )
                fusion["composite_score"] = recalculated_score
                fusion["confidence"] = confidence
                fusion["weights_used"] = weights
                fusion["_score_recalculated"] = True
            else:
                # 分數合理，但信心度統一用程式碼計算
                fusion["confidence"] = confidence

            recalculated.append(fusion)

        except Exception as e:
            logger.warning("[INTEL][VERIFY] Failed to recalculate for %s: %s", fusion.get("cve_id"), e)
            recalculated.append(fusion)  # 保留原始值

    result["fusion_results"] = recalculated
    return result


def _build_degraded_result(input_str: str, error: str) -> dict:
    """
    Graceful Degradation：Agent 失敗時的最小生存輸出。
    讓 Scout 知道 Intel Fusion 已降級，但不中斷管線。
    """
    return {
        "fusion_results": [],
        "strategy_applied": "degraded",
        "api_health_summary": {"nvd": "unknown", "epss": "unknown", "kev": "unknown"},
        "_degraded": True,
        "_error": error[:200],
        "_input": input_str[:100],
    }


