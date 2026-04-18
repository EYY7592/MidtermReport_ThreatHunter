# agents/scout.py
# 功能：Scout Agent 定義 — 威脅情報偵察員
# Harness 支柱：Constraints（系統憲法 + Skill SOP）+ Observability（verbose=True）
# 擁有者：成員 B（Scout Agent Pipeline）
#
# 使用方式：
#   from agents.scout import create_scout_agent
#
# 架構定位：
#   Pipeline 的第一環 — 收集情報 → 輸出 JSON → Analyst 接收
#   Agent = Tool（手）+ Skill（腦）+ Constitution（法）

import os
import logging
import time

import requests

from crewai import Agent

from config import get_llm

# LLM 延遲初始化：在 create_scout_agent() 中才呼叫 get_llm()
from tools.nvd_tool import search_nvd
from tools.otx_tool import search_otx
from tools.memory_tool import read_memory, write_memory, history_search

logger = logging.getLogger("ThreatHunter")

# ══════════════════════════════════════════════════════════════
# Skill 載入（Phase 4D：使用 SkillLoader 熱載入系統）
# ══════════════════════════════════════════════════════════════

# ======================================================================
# v3.7: Path-Aware Skill Map
# 每種 input_type 對應一份 Skill SOP
# ======================================================================

SKILL_MAP: dict[str, str] = {
    "pkg":       "threat_intel.md",        # Path A: package CVE scan
    "code":      "source_code_audit.md",   # Path B-code: source code review
    "injection": "ai_security_audit.md",   # Path B-inject: AI security
    "config":    "config_audit.md",        # Path C: config file audit
}

# 專案根目錄（agents/ 的上一層）
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILL_PATH = os.path.join(PROJECT_ROOT, "skills", "threat_intel.md")  # default fallback

# Phase 4D: 使用 SkillLoader 熱載入系統
try:
    from skills.skill_loader import skill_loader as _skill_loader
    _SKILL_LOADER_AVAILABLE = True
    logger.info("[Scout] Phase 4D: SkillLoader 啟用 ✓")
except ImportError:
    _skill_loader = None
    _SKILL_LOADER_AVAILABLE = False
    logger.warning("[Scout] Phase 4D: SkillLoader 不可用，使用內建 _load_skill")


def _load_skill(skill_filename: str = "threat_intel.md") -> str:
    """
    Load Skill SOP file by filename (v3.7 path-aware + Phase 4D 熱載入).

    Phase 4D: 優先使用 SkillLoader 單例（支援熱載入、mtime 驗證）。
    Fallback: 直接從磁碟讀取（原有實作，確保向後相容）。
    """
    # Phase 4D: SkillLoader 熱載入路徑
    if _SKILL_LOADER_AVAILABLE and _skill_loader is not None:
        try:
            return _skill_loader.load_skill(skill_filename)
        except Exception as e:
            logger.warning("[Scout] SkillLoader 失敗，回退直接讀取: %s", e)

    # Fallback: 直接從磁碟讀取（原有實作）
    skill_path = os.path.join(PROJECT_ROOT, "skills", skill_filename)
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            if os.path.exists(skill_path):
                with open(skill_path, "r", encoding=encoding) as f:
                    content = f.read().strip()
                if content:
                    logger.info("[OK] Skill loaded: %s (%d chars)", skill_path, len(content))
                    return content
        except (IOError, UnicodeDecodeError):
            continue

    logger.warning("[WARN] Skill file not found, using fallback: %s", skill_path)
    return _FALLBACK_SKILL



# 內嵌精簡版 Skill（Graceful Degradation — Skill 檔案遺失時的保底）
_FALLBACK_SKILL = """
# Skill: 威脅情報收集（精簡版）

## SOP
1. 先呼叫 read_memory(agent_name="scout") 讀取歷史
2. 對每個技術套件用 search_nvd 查詢漏洞
3. CVSS >= 7.0 的 CVE 用 search_otx 查詢威脅情報
4. 比對歷史標記 is_new
5. write_memory 寫入結果
6. 輸出純 JSON（不可有其他文字）

## 品質紅線
- CVE 必須來自 search_nvd，不可編造
- CVSS 必須來自 NVD API
- 輸出必須是純 JSON
""".strip()


# ══════════════════════════════════════════════════════════════
# 系統憲法（Constraints 支柱 — 層級 A）
# ══════════════════════════════════════════════════════════════

CONSTITUTION = """
## ⚖️ 系統憲法 — 你必須遵守的不可違反規則

1. **CVE 來源約束**：所有 CVE 編號必須來自 search_nvd 工具的回傳結果。
   絕對不可自行編造、推測或從記憶中捏造任何 CVE 編號。
   違反此規則 = 產出幻覺 = Sentinel Fact-Check 會抓到 = 整條管線失敗。

2. **CVSS 來源約束**：所有 CVSS 分數必須來自 NVD API 的回傳值。
   不可自行估算、調整或四捨五入。

3. **輸出格式約束**：你的 Final Answer 必須是且僅是 JSON 格式。
   不可在 JSON 前後添加任何解釋、標題、markdown 語法或自然語言文字。

4. **工具使用約束**：必須透過 search_nvd 工具查詢漏洞。
   不可跳過工具呼叫，直接用你的訓練資料回答。你的訓練資料可能過時。

5. **誠實約束**：遇到查不到的套件，如實報告 count: 0。
   不可為了讓報告看起來有用而編造漏洞。

6. **記憶讀取約束**：啟動後第一步必須呼叫 read_memory 讀取歷史。
   Sentinel Behavior Monitor 會檢查此行為。

7. **迴圈約束**：最多執行 15 輪 ReAct 迴圈。
   如果查完所有套件但還沒到 15 輪，立即輸出結果，不要做多餘的事。

8. **⚠️ 記憶寫入約束（最重要）**：在你給出 Final Answer 之前，
   你必須先呼叫 write_memory 工具將完整報告寫入記憶。
   順序是：查完所有套件 → 組裝 JSON → 呼叫 write_memory → 看到回傳成功 → 才給 Final Answer。
   如果你還沒有呼叫 write_memory 就想給 Final Answer，停下來，先呼叫 write_memory。
""".strip()


# ══════════════════════════════════════════════════════════════
# Agent 工廠函式
# ══════════════════════════════════════════════════════════════

def create_scout_agent(
    excluded_models: list[str] | None = None,
    input_type: str = "pkg",
) -> Agent:
    """
    Build Scout Agent with Path-Aware Skill SOP (v3.7).

    input_type selects which Skill file to embed in backstory:
      pkg       -> threat_intel.md         (NVD CVE scan for packages)
      code      -> source_code_audit.md    (OWASP Top10 + CWE for source code)
      injection -> ai_security_audit.md    (OWASP LLM Top10 + MITRE ATLAS)
      config    -> config_audit.md         (CIS Benchmark for config files)

    Args:
        excluded_models: Models to skip (429-rate-limited)
        input_type: Path type from frontend detector

    Returns:
        CrewAI Agent instance ready for Task and Crew
    """
    skill_filename = SKILL_MAP.get(input_type, "threat_intel.md")
    skill_content = _load_skill(skill_filename)
    logger.info("[Scout] Path=%s -> Skill=%s", input_type, skill_filename)

    # Goal adapts to the input path
    _GOAL_MAP = {
        "pkg":       "Collect known CVEs for the given package list from NVD/OTX, compare with history, output structured JSON.",
        "code":      "Audit source code for OWASP Top10 / CWE vulnerabilities; extract package imports and scan NVD; output structured JSON.",
        "injection": "Classify and assess AI security threats (OWASP LLM Top10 / MITRE ATLAS) in the given input; output structured JSON with no CVE hallucination.",
        "config":    "Audit the given configuration file against CIS Benchmarks for misconfigurations and hardcoded secrets; output structured JSON.",
    }
    agent_goal = _GOAL_MAP.get(input_type, _GOAL_MAP["pkg"])

    backstory = f"""You are an expert security analyst specialized in identifying software and AI system vulnerabilities.
You are rigorous, precise, and never fabricate data.

{CONSTITUTION}

---

## Analysis Methodology (Skill SOP)

You MUST follow this Standard Operating Procedure for the current scan path ({input_type}):

{skill_content}
"""

    llm = get_llm(exclude_models=excluded_models)
    scout = Agent(
        role="Threat Intelligence Scout",
        goal=agent_goal,
        backstory=backstory,
        tools=[search_nvd, search_otx, read_memory, write_memory, history_search],
        llm=llm,
        verbose=True,
        max_iter=15,   # SOP: 最多 15 輪 ReAct（包含 6 步驟程：read_memory+search_nvd+OTX+write_memory）
        allow_delegation=False,
    )

    logger.info(
        "[OK] Scout Agent ready | input_type=%s | skill=%s | llm=%s",
        input_type,
        skill_filename,
        llm.model if hasattr(llm, 'model') else 'unknown',
    )
    return scout


# ══════════════════════════════════════════════════════════════
# CrewAI Task 工廠函式（便利函式，供 main.py 使用）
# ══════════════════════════════════════════════════════════════

def create_scout_task(agent, tech_stack: str):
    """
    v3.4: Scout Task - package-aware mode.
    When tech_stack is a short comma-separated package list (from PackageExtractor),
    explicitly enumerate each package for the LLM to query via search_nvd.
    """
    from crewai import Task

    # Detect if input is a clean package list or raw code/long text
    is_package_list = (
        len(tech_stack) < 300
        and "\n" not in tech_stack
        and "def " not in tech_stack
        and "import " not in tech_stack
    )

    if is_package_list:
        packages = [p.strip() for p in tech_stack.split(",") if p.strip()]
        packages_display = "\n".join(f"   {i+1}. {pkg}" for i, pkg in enumerate(packages))
        nvd_calls = "\n".join(f"   - search_nvd(\'{pkg}\')" for pkg in packages[:8])
        task_desc = (
            f"You are analyzing security vulnerabilities for packages extracted from source code.\n\n"
            f"Package list to scan:\n{packages_display}\n\n"
            f"Steps to follow (MUST call tools in order):\n\n"
            f"Step 1: Call read_memory\n"
            f"   Action: read_memory\n"
            f"   Action Input: scout\n\n"
            f"Step 2: For EACH package, call search_nvd separately:\n"
            f"{nvd_calls}\n\n"
            f"Step 3: For CVEs with CVSS >= 7.0, call search_otx for that package\n\n"
            f"Step 4: Assemble JSON report from REAL tool results only\n"
            f"   - CVE IDs, CVSS scores must come from search_nvd output\n"
            f"   - Compare with read_memory history, mark is_new\n\n"
            f"Step 5: Call write_memory to save results\n"
            f"   Action: write_memory\n"
            f"   Action Input: scout|{{JSON report}}\n\n"
            f"Step 6: Output JSON report as Final Answer\n\n"
            f"FORBIDDEN:\n"
            f"- Do NOT skip tool calls\n"
            f"- Do NOT fabricate CVE IDs\n"
            f"- Do NOT use backstory examples (they are fake)\n"
            f"- write_memory MUST be called before Final Answer"
        )
    else:
        task_desc = (
            f"You are analyzing security vulnerabilities in: {tech_stack[:800]}\n\n"
            f"Steps to follow (MUST call tools in order):\n\n"
            f"Step 1: Call read_memory\n"
            f"   Action: read_memory\n"
            f"   Action Input: scout\n\n"
            f"Step 2: Extract PACKAGE NAMES from the code, then call search_nvd for each package.\n"
            f"   RULE: Package names come from require() or import statements ONLY.\n"
            f"   Example: require('express') -> search_nvd('express')\n"
            f"   Example: require('lodash')  -> search_nvd('lodash')\n"
            f"   FORBIDDEN search terms (these are syntax, NOT packages):\n"
            f"   - eval, exec, Function, innerHTML, script, html, document\n"
            f"   - const, let, var, function, class, async, await\n"
            f"   - req, res, app, user, input (these are variable names)\n"
            f"   If no require()/import found, output empty vulnerabilities list.\n\n"
            f"Step 3: For CVEs with CVSS >= 7.0, call search_otx\n\n"
            f"Step 4: Assemble JSON report from REAL tool results only\n\n"
            f"Step 5: Call write_memory\n"
            f"   Action: write_memory\n"
            f"   Action Input: scout|{{JSON report}}\n\n"
            f"Step 6: Output JSON report as Final Answer\n\n"
            f"FORBIDDEN:\n"
            f"- Do NOT search NVD with: eval, html, innerHTML, script, const, function\n"
            f"- Do NOT skip tool calls\n"
            f"- Do NOT fabricate CVE IDs\n"
            f"- write_memory MUST be called before Final Answer"
        )

    return Task(
        description=task_desc,
        expected_output="Structured JSON threat intel report with CVEs from search_nvd tool.",
        agent=agent,
    )



def run_scout_pipeline(tech_stack: str, input_type: str = "pkg") -> dict:
    """
    Execute full Scout Pipeline with Harness code-level guarantees.

    v3.7: input_type selects the correct Skill SOP for path-aware analysis.

    Args:
        tech_stack: User input (e.g. "Django 4.2, Redis 7.0" or source code)
        input_type: Path type (pkg/code/injection/config)

    Returns:
        dict: Parsed Scout JSON report
    """
    import json
    from crewai import Crew, Process
    from config import mark_model_failed, get_current_model_name, rate_limiter
    # 新版 memory_tool 無 _write_memory_impl，使用公開 Tool 介面

    # 429 自動輪替：最多重試 MAX_LLM_RETRIES 次（每次切換模型）
    MAX_LLM_RETRIES = 2
    excluded_models: list[str] = []

    for attempt in range(MAX_LLM_RETRIES + 1):
        # v3.7: pass input_type so agent loads the correct Skill SOP
        agent = create_scout_agent(excluded_models, input_type=input_type)
        task = create_scout_task(agent, tech_stack)
        crew = Crew(agents=[agent], tasks=[task], process=Process.sequential, verbose=True)

        # 執行 Agent
        logger.info("[START] Scout Pipeline: %s (attempt %d/%d)", tech_stack, attempt + 1, MAX_LLM_RETRIES + 1)
        try:
            from checkpoint import recorder as _cp
            _current_model = get_current_model_name(agent.llm)
            _cp.llm_call("scout", _current_model, "openrouter", f"attempt={attempt+1}")
        except Exception:
            _current_model = "unknown"
        _t_llm = time.time()
        try:
            result = crew.kickoff()
            try:
                _cp.llm_result("scout", _current_model, "SUCCESS",
                               len(str(result)), int((time.time() - _t_llm) * 1000),
                               thinking=str(result)[:1000])
            except Exception:
                pass
            break  # 成功則跳出重試迴圈
        except Exception as e:
            error_str = str(e)
            if "429" in error_str and attempt < MAX_LLM_RETRIES:
                # 標記當前模型為冷卻中，下次迴圈會選擇其他模型
                current_model = get_current_model_name(agent.llm)
                mark_model_failed(current_model)
                excluded_models.append(current_model)
                # 解析 API 回傳的 retry_after 秒數
                import re as _re
                _m = _re.search(r'retry.{1,10}(\d+\.?\d*)s', error_str, _re.IGNORECASE)
                retry_after = float(_m.group(1)) if _m else 0.0
                logger.warning("[RETRY] Scout 429 on %s (attempt %d/%d), api_retry_after=%.0fs",
                              current_model, attempt + 1, MAX_LLM_RETRIES, retry_after)
                try:
                    _cp.llm_retry("scout", current_model, error_str[:200],
                                  attempt + 1, "next_in_waterfall")
                except Exception:
                    pass
                rate_limiter.on_429(retry_after=retry_after, caller="scout")  # 最少 30s
                continue

            try:
                _cp.llm_error("scout", _current_model, error_str[:300])
            except Exception:
                pass
            raise  # 非 429 或已超過重試次數，直接拋出

    result_str = str(result).strip()

    # 解析 JSON（處理可能的 markdown 包裝）
    json_str = result_str
    if "```json" in json_str:
        json_str = json_str.split("```json")[1].split("```")[0].strip()
    elif "```" in json_str:
        parts = json_str.split("```")
        if len(parts) >= 3:
            json_str = parts[1].strip()

    try:
        output = json.loads(json_str)
    except json.JSONDecodeError:
        logger.error("[FAIL] Agent output is not valid JSON: %s", result_str[:200])
        raise ValueError(f"Scout Agent output is not valid JSON: {result_str[:200]}")

    # ── Harness 保障 1：強制 write_memory ──────────────────────
    memory_path = os.path.join(PROJECT_ROOT, "memory", "scout_memory.json")
    need_write = False
    if not os.path.exists(memory_path):
        need_write = True
    else:
        try:
            with open(memory_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if not content or content == "{}":
                need_write = True
        except (IOError, json.JSONDecodeError):
            need_write = True

    if need_write:
        logger.warning("[WARN] Agent did not call write_memory -- code forcing write (Harness)")
        write_result = write_memory.run(agent_name="scout", data=json.dumps(output, ensure_ascii=False))
        logger.info("[OK] Forced memory write: %s", write_result)

    # ── Harness 保障 2：基礎 Schema 驗證 ──────────────────────
    required = ["scan_id", "timestamp", "tech_stack", "vulnerabilities", "summary"]
    for field in required:
        if field not in output:
            logger.warning("[WARN] Output missing required field: %s", field)
            if field == "vulnerabilities":
                output["vulnerabilities"] = []
            elif field == "summary":
                output["summary"] = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}

    # ── Harness 保障 2.5：Cache 注入（Anti-LLM-Omission）──────
    # 當 LLM 輸出 0 vulnerabilities，但 NVD cache 中有資料時，
    # 直接從 cache 注入——防止 LLM 忽略工具輸出的問題
    if not output.get("vulnerabilities"):
        from tools.nvd_tool import _search_nvd_impl
        injected = []
        for item in (tech_stack or "").split(","):
            pkg = item.strip().split()[0].lower()
            if not pkg:
                continue
            try:
                cached_result = json.loads(_search_nvd_impl(pkg))
                for v in cached_result.get("vulnerabilities", []):
                    cve_id = v.get("cve_id") or v.get("id", "")
                    if not cve_id.startswith("CVE-"):
                        continue
                    injected.append({
                        "cve_id":      cve_id,
                        "package":     v.get("package", pkg),
                        "cvss_score":  v.get("cvss_score", 0.0),
                        "severity":    v.get("severity", "MEDIUM"),
                        "description": v.get("description", "")[:300],
                        "published":   v.get("published_date", ""),
                        "is_new":      True,
                        "in_cisa_kev": v.get("in_cisa_kev", False),
                        "has_public_exploit": v.get("has_public_exploit", False),
                    })
            except Exception as e:
                logger.warning("[WARN] Cache inject failed for %s: %s", pkg, e)

        if injected:
            output["vulnerabilities"] = injected
            logger.warning(
                "[HARNESS 2.5] LLM output 0 CVEs, injected %d CVEs from NVD cache for tech_stack=%s",
                len(injected), tech_stack[:60]
            )

    # 重新查 NVD 建立真實 CVE 清單 + CVE→package 對應表
    from tools.nvd_tool import _search_nvd_impl
    real_cves = set()
    cve_to_package = {}  # CVE-XXXX-YYYY → package name

    # 收集所有需要查的 package：Agent 輸出的 + tech_stack 裡的
    packages_to_check = set()
    for vuln in output.get("vulnerabilities", []):
        pkg = vuln.get("package", "").lower().strip()
        if pkg:
            packages_to_check.add(pkg)
    # 從 tech_stack 提取（去版本號）
    for item in tech_stack.split(","):
        pkg_name = item.strip().split()[0].lower()
        if pkg_name:
            packages_to_check.add(pkg_name)

    for pkg in packages_to_check:
        try:
            # 驗證時用更大的頁數（比 Agent 看到的多），減少誤殺真實 CVE
            import tools.nvd_tool as nvd_mod
            original_page_size = nvd_mod.RESULTS_PER_PAGE
            nvd_mod.RESULTS_PER_PAGE = 100  # 驗證用 100 筆
            try:
                nvd_result = json.loads(_search_nvd_impl(pkg))
            finally:
                nvd_mod.RESULTS_PER_PAGE = original_page_size  # 恢復原值
            for v in nvd_result.get("vulnerabilities", []):
                cve_id = v["cve_id"]
                real_cves.add(cve_id)
                cve_to_package[cve_id] = pkg
        except Exception as e:
            logger.warning("[WARN] CVE verification NVD query failed (%s): %s", pkg, e)

    if real_cves:
        original_count = len(output.get("vulnerabilities", []))
        verified_vulns = []
        suspect_vulns = []  # 可能是真的但 keywordSearch 沒找到
        for vuln in output.get("vulnerabilities", []):
            if vuln.get("cve_id") in real_cves:
                verified_vulns.append(vuln)
            else:
                suspect_vulns.append(vuln)

        # 對可疑的 CVE 做精確查詢（cveId lookup）
        hallucinated = []
        if suspect_vulns:
            import re
            for vuln in suspect_vulns:
                cve_id = vuln.get("cve_id", "")
                if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
                    hallucinated.append(cve_id)
                    continue
                try:
                    resp = requests.get(
                        "https://services.nvd.nist.gov/rest/json/cves/2.0",
                        params={"cveId": cve_id},
                        headers={"apiKey": os.getenv("NVD_API_KEY", "")},
                        timeout=10,
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        if data.get("totalResults", 0) > 0:
                            logger.info("[OK] CVE exact verification passed: %s", cve_id)
                            verified_vulns.append(vuln)
                            # 補 package：從 description 推斷
                            if not vuln.get("package"):
                                desc = data["vulnerabilities"][0]["cve"]["descriptions"][0]["value"].lower()
                                for pkg in packages_to_check:
                                    if pkg in desc:
                                        vuln["package"] = pkg
                                        cve_to_package[cve_id] = pkg
                                        break
                            continue
                    # NVD 明確回應但找不到 → 才算幻覺
                    hallucinated.append(cve_id)
                except Exception:
                    # NVD API 不可達（timeout/connection）→ 保守保留，不當幻覺處理
                    logger.warning("[WARN] NVD verify unreachable for %s, keeping conservatively", cve_id)
                    verified_vulns.append(vuln)


        if hallucinated:
            logger.warning(
                "[ALERT] Detected %d hallucinated CVEs, removed: %s",
                len(hallucinated), hallucinated
            )
            output["vulnerabilities"] = verified_vulns
            # 重新計算 summary
            output["summary"] = {
                "total": len(verified_vulns),
                "new_since_last_scan": sum(1 for v in verified_vulns if v.get("is_new")),
                "critical": sum(1 for v in verified_vulns if v.get("severity") == "CRITICAL"),
                "high": sum(1 for v in verified_vulns if v.get("severity") == "HIGH"),
                "medium": sum(1 for v in verified_vulns if v.get("severity") == "MEDIUM"),
                "low": sum(1 for v in verified_vulns if v.get("severity") == "LOW"),
            }
            logger.info(
                "[OK] CVE verification result: %d -> %d (removed %d hallucinated)",
                original_count, len(verified_vulns), len(hallucinated)
            )
        else:
            logger.info("[OK] All %d CVEs passed verification", original_count)
    else:
        logger.warning("[WARN] Cannot build real CVE list, skipping verification")

    # ── Harness 保障 4：補全 package 欄位 ──────────────────────
    # Agent 常忘記加 package，用 Layer 3 建好的 cve_to_package 補
    patched_count = 0
    for vuln in output.get("vulnerabilities", []):
        if not vuln.get("package"):
            cve_id = vuln.get("cve_id", "")
            if cve_id in cve_to_package:
                vuln["package"] = cve_to_package[cve_id]
                patched_count += 1
            else:
                # 最後手段：從 description 猜 package
                desc = vuln.get("description", "").lower()
                for pkg in packages_to_check:
                    if pkg in desc:
                        vuln["package"] = pkg
                        patched_count += 1
                        break
                else:
                    vuln["package"] = "unknown"
                    patched_count += 1
    if patched_count:
        logger.info("[OK] Patched %d CVE package fields", patched_count)

    # ── Harness 保障 5：校正 is_new 標記 ──────────────────────
    # Agent 常常不正確比對歷史，程式碼代為校正
    try:
        mem_data = {}
        if os.path.exists(memory_path):
            with open(memory_path, "r", encoding="utf-8") as f:
                mem_data = json.load(f)

        # 從 memory 的所有歷史掃描中提取已知 CVE 集合
        historical_cves = set()
        # 新版 memory_tool 直接存 scan 結構
        if "vulnerabilities" in mem_data:
            for v in mem_data.get("vulnerabilities", []):
                historical_cves.add(v.get("cve_id", ""))
        # 舊版 memory 有 latest/history 結構
        elif "latest" in mem_data:
            for v in mem_data.get("latest", {}).get("vulnerabilities", []):
                historical_cves.add(v.get("cve_id", ""))

        corrected = 0
        for vuln in output.get("vulnerabilities", []):
            cve_id = vuln.get("cve_id", "")
            expected_is_new = cve_id not in historical_cves
            if vuln.get("is_new") != expected_is_new:
                vuln["is_new"] = expected_is_new
                corrected += 1

        if corrected:
            # 重算 summary
            vulns = output.get("vulnerabilities", [])
            output["summary"]["new_since_last_scan"] = sum(1 for v in vulns if v.get("is_new"))
            logger.info("[OK] Corrected %d CVE is_new flags", corrected)
    except Exception as e:
        logger.warning("[WARN] is_new correction failed: %s", e)

    # ── 最終 Summary 校正（確保一致性）──────────────────────────
    vulns = output.get("vulnerabilities", [])
    output["summary"] = {
        "total": len(vulns),
        "new_since_last_scan": sum(1 for v in vulns if v.get("is_new")),
        "critical": sum(1 for v in vulns if v.get("severity") == "CRITICAL"),
        "high": sum(1 for v in vulns if v.get("severity") == "HIGH"),
        "medium": sum(1 for v in vulns if v.get("severity") == "MEDIUM"),
        "low": sum(1 for v in vulns if v.get("severity") == "LOW"),
    }

    vuln_count = output["summary"]["total"]
    new_count = output["summary"]["new_since_last_scan"]
    logger.info(
        "[OK] Scout Pipeline complete: %d CVEs, %d new", vuln_count, new_count
    )

    return output
