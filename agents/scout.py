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

import requests

from crewai import Agent

from config import get_llm

# 使用新版 config.get_llm()（支援 openrouter/vllm/openai 三模式降級）
llm = get_llm()
from tools.nvd_tool import search_nvd
from tools.otx_tool import search_otx
from tools.memory_tool import read_memory, write_memory, history_search

logger = logging.getLogger("ThreatHunter")

# ══════════════════════════════════════════════════════════════
# Skill 載入（從 .md 讀取，嵌入 backstory）
# ══════════════════════════════════════════════════════════════

# 專案根目錄（agents/ 的上一層）
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILL_PATH = os.path.join(PROJECT_ROOT, "skills", "threat_intel.md")


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
                    logger.info(f"✅ Skill 載入成功：{SKILL_PATH}（{len(content)} 字元）")
                    return content
        except (IOError, UnicodeDecodeError):
            continue

    logger.warning(f"⚠️ Skill 檔案載入失敗，使用內嵌精簡版：{SKILL_PATH}")
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

def create_scout_agent() -> Agent:
    """
    建立 Scout Agent 實例。

    組成：
      - role: 威脅情報偵察員
      - goal: 收集漏洞 + 比對歷史 + 輸出 JSON
      - backstory: 系統憲法 + Skill SOP（完整嵌入）
      - tools: search_nvd, search_otx, read_memory, write_memory, history_search
      - llm: 從 config.py 取得（支援三模式切換）
      - verbose=True: Observability 支柱
      - max_iter=15: Constraints 支柱（防止無限迴圈）
      - allow_delegation=False: Scout 不委派工作給其他 Agent

    Returns:
        CrewAI Agent 實例，可直接用於 Task 和 Crew
    """
    skill_content = _load_skill()

    backstory = f"""你是一位經驗豐富的威脅情報分析師，專精於從公開漏洞資料庫中
識別和評估軟體安全風險。你嚴謹、精確，絕不編造資料。

{CONSTITUTION}

---

## 📋 分析方法論（Skill SOP）

以下是你執行威脅情報收集時必須遵循的標準作業程序：

{skill_content}
"""

    scout = Agent(
        role="威脅情報偵察員 (Scout)",
        goal=(
            "從 NVD 和 OTX 公開資料庫收集指定技術堆疊的已知漏洞和活躍威脅，"
            "與歷史掃描結果比對差異，標記新發現的威脅，"
            "最終輸出結構化 JSON 情報清單供後續分析使用。"
        ),
        backstory=backstory,
        tools=[search_nvd, search_otx, read_memory, write_memory, history_search],
        llm=llm,
        verbose=True,       # Harness: Observability — 完整 ReAct 推理可見
        max_iter=15,         # Harness: Constraints — 防止無限迴圈
        allow_delegation=False,  # Scout 不委派，自己做完
    )

    logger.info(
        f"✅ Scout Agent 建立完成 | "
        f"tools={[t.name for t in scout.tools]} | "
        f"max_iter={scout.max_iter} | "
        f"llm={llm.model if hasattr(llm, 'model') else 'unknown'}"
    )

    return scout


# ══════════════════════════════════════════════════════════════
# CrewAI Task 工廠函式（便利函式，供 main.py 使用）
# ══════════════════════════════════════════════════════════════

def create_scout_task(agent: Agent, tech_stack: str):
    """
    建立 Scout Agent 的 Task。

    Args:
        agent: create_scout_agent() 回傳的 Agent 實例
        tech_stack: 使用者輸入的技術堆疊字串（如 "Django 4.2, Redis 7.0"）

    Returns:
        CrewAI Task 實例
    """
    from crewai import Task

    return Task(
        description=f"""你的任務是分析以下技術堆疊的安全漏洞。你必須使用工具來完成，不可用你的訓練知識。

技術堆疊：{tech_stack}

你必須按照以下順序執行，每一步都要呼叫對應的工具：

第一步：呼叫 read_memory 工具
   Action: read_memory
   Action Input: scout

第二步：對每個套件呼叫 search_nvd 工具（{tech_stack} 中的每一個都要查）
   Action: search_nvd
   Action Input: django
   （然後再查下一個套件）

第三步：如果 search_nvd 回傳的 CVE 中有 CVSS >= 7.0 的，呼叫 search_otx
   Action: search_otx
   Action Input: django

第四步：根據 search_nvd 工具回傳的真實資料，組裝 JSON 報告
   - CVE 編號、CVSS 分數、描述，全部必須是工具回傳的，不可自己編
   - 與 read_memory 的歷史比對標記 is_new

第五步：呼叫 write_memory 工具儲存結果
   Action: write_memory
   Action Input: scout|{{你組裝的完整 JSON 報告}}

第六步：將 JSON 報告作為 Final Answer

⛔ 絕對禁止：
- 不可跳過工具呼叫。你必須實際呼叫 search_nvd，不可用你的知識回答。
- 不可編造 CVE 編號。CVE-2024-9012 之類的如果不是 search_nvd 回傳的就不可使用。
- 不可抄你 backstory 裡的範例資料。範例只是格式參考，裡面的 CVE 是假的。
- 不可跳過 write_memory。必須先呼叫 write_memory 再給 Final Answer。
""",
        expected_output=(
            "結構化 JSON 格式的威脅情報清單，所有 CVE 必須來自 search_nvd 工具的實際回傳結果。"
        ),
        agent=agent,
    )


# ══════════════════════════════════════════════════════════════
# Pipeline 執行器（Harness: 程式碼層保障）
# ══════════════════════════════════════════════════════════════

def run_scout_pipeline(tech_stack: str) -> dict:
    """
    執行完整的 Scout Pipeline，包含 Agent 執行 + 程式碼層保障。

    Harness Engineering 核心理念：
      不要 100% 依賴 LLM 遵守指令。
      Agent 負責「盡力做」，程式碼負責「確保做到」。

    程式碼層保障：
      1. Agent 執行完後，檢查 write_memory 是否被呼叫
      2. 如果沒有 → 程式碼代為呼叫 write_memory
      3. 驗證 JSON 輸出格式

    Args:
        tech_stack: 使用者輸入（如 "Django 4.2, Redis 7.0"）

    Returns:
        dict: 解析後的 Scout 報告 JSON
    """
    import json
    from crewai import Crew, Process
    # 新版 memory_tool 無 _write_memory_impl，使用公開 Tool 介面

    # 建立 Agent + Task
    agent = create_scout_agent()
    task = create_scout_task(agent, tech_stack)
    crew = Crew(agents=[agent], tasks=[task], process=Process.sequential, verbose=True)

    # 執行 Agent
    logger.info(f"🚀 Scout Pipeline 啟動：{tech_stack}")
    result = crew.kickoff()
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
        logger.error(f"❌ Agent 輸出不是合法 JSON：{result_str[:200]}")
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
        logger.warning("⚠️ Agent 未呼叫 write_memory — 程式碼代為執行（Harness 保障）")
        write_result = write_memory.run(agent_name="scout", data=json.dumps(output, ensure_ascii=False))
        logger.info(f"📝 程式碼強制寫入記憶：{write_result}")

    # ── Harness 保障 2：基礎 Schema 驗證 ──────────────────────
    required = ["scan_id", "timestamp", "tech_stack", "vulnerabilities", "summary"]
    for field in required:
        if field not in output:
            logger.warning(f"⚠️ 輸出缺少必要欄位：{field}")

    # ── Harness 保障 3：CVE 真實性驗證（Anti-Hallucination）──
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
            logger.warning(f"⚠️ CVE 驗證時 NVD 查詢失敗 ({pkg}): {e}")

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
                            logger.info(f"✅ CVE 精確驗證通過：{cve_id}")
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
                    hallucinated.append(cve_id)
                except Exception:
                    # 查詢失敗 → 保守移除
                    hallucinated.append(cve_id)

        if hallucinated:
            logger.warning(
                f"🚨 偵測到 {len(hallucinated)} 筆幻覺 CVE，已移除：{hallucinated}"
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
                f"📊 CVE 驗證結果：{original_count} → {len(verified_vulns)} 筆（移除 {len(hallucinated)} 筆幻覺）"
            )
        else:
            logger.info(f"✅ 所有 {original_count} 筆 CVE 通過真實性驗證")
    else:
        logger.warning("⚠️ 無法建立真實 CVE 清單，跳過驗證")

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
        logger.info(f"🔧 已補全 {patched_count} 筆 CVE 的 package 欄位")

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
            logger.info(f"🔧 已校正 {corrected} 筆 CVE 的 is_new 標記")
    except Exception as e:
        logger.warning(f"⚠️ is_new 校正失敗：{e}")

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
        f"✅ Scout Pipeline 完成：{vuln_count} 筆 CVE，新增 {new_count} 筆"
    )

    return output
