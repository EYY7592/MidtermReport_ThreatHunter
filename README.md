# 🛡️ ThreatHunter — AI-Powered Cybersecurity Threat Intelligence Platform

<div align="center">

**An autonomous multi-agent system that scouts vulnerabilities, reasons about chained risks, and delivers actionable security reports — with memory.**

[![AMD Developer Hackathon](https://img.shields.io/badge/AMD-Developer%20Hackathon%202026-ED1C24?style=for-the-badge&logo=amd&logoColor=white)](https://www.amd.com)
[![CrewAI](https://img.shields.io/badge/CrewAI-Multi--Agent-4A90D9?style=for-the-badge)](https://crewai.com)
[![vLLM](https://img.shields.io/badge/vLLM-AMD%20Cloud-00C853?style=for-the-badge)](https://vllm.ai)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)

[English](#english) | [中文](#中文)

</div>

---

<a id="english"></a>

## 🌐 English

### What is ThreatHunter?

**ThreatHunter is an AI cybersecurity advisor with memory.**

Traditional vulnerability scanners give you a list of CVEs sorted by CVSS score. ThreatHunter goes further — it **reasons** about how vulnerabilities combine into attack chains, and it **remembers** your infrastructure across scans to track risk evolution over time.

### Key Features

| Feature | Description |
|---|---|
| 🔍 **Autonomous Threat Scouting** | AI agent queries NVD + OTX APIs, compares with historical scans, and flags new threats |
| 🧠 **Chain Vulnerability Analysis** | LLM-powered reasoning discovers that SSRF + Redis = RCE, even when individual CVSS scores say "Medium" |
| 📋 **Actionable Reports** | Prioritized action plans with specific fix commands, not just CVE lists |
| 🧬 **Evolving Memory** | Every scan remembers the last. Risk trends, resolved issues, and user feedback improve future analysis |
| 🎯 **Confidence Scoring** | Every finding is tagged HIGH / MEDIUM / NEEDS_VERIFICATION — no silent hallucinations |

### Architecture

```
User Input: "Django 4.2, Redis 7.0, PostgreSQL 16"
                    │
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    ┃         CrewAI Sequential Process       ┃
    ┃                                         ┃
    ┃  ┌───────────────────────────────────┐  ┃
    ┃  │  🔍 Scout Agent                    │  ┃
    ┃  │  NVD API → OTX API → Memory       │──── → Threat Intel
    ┃  │  ReAct: Thought→Action→Observe    │  ┃
    ┃  └────────────────┬──────────────────┘  ┃
    ┃                   │                      ┃
    ┃  ┌────────────────▼──────────────────┐  ┃
    ┃  │  🧠 Analyst Agent                  │  ┃
    ┃  │  CISA KEV → Exploit DB → Memory   │──── → Risk Assessment
    ┃  │  Chain Analysis + Confidence       │  ┃
    ┃  └────────────────┬──────────────────┘  ┃
    ┃                   │                      ┃
    ┃  ┌────────────────▼──────────────────┐  ┃
    ┃  │  📋 Advisor Agent                  │  ┃
    ┃  │  Action Plan + Priority Ranking   │──── → Final Report
    ┃  │  🔴 URGENT / 🟡 IMPORTANT / 🟢 OK │  ┃
    ┃  └───────────────────────────────────┘  ┃
    ┃                                         ┃
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                        │
                        ▼
              ┌─────────────────┐
              │  Streamlit UI    │
              │  Report + Feedback│
              └─────────────────┘
```

### What Makes It Different?

```
Traditional Scanner:
  CVE-A (SSRF, CVSS 6.5) → Medium ⚠️
  CVE-B (Redis unauth, CVSS 5.3) → Medium ⚠️
  Result: Two medium vulnerabilities.

ThreatHunter:
  CVE-A (SSRF) + CVE-B (Redis unauth)
  → SSRF reaches internal network
  → Redis has no password
  → Attacker writes crontab = shell access
  → Result: Two mediums = ONE CRITICAL 🔴

  ⬆️ Only an LLM can reason about this.
  Traditional tools can't.
```

### Tech Stack

| Component | Technology |
|---|---|
| Agent Framework | CrewAI (ReAct mode) |
| LLM | Llama 3.3 70B via vLLM on AMD Cloud |
| Threat Data | NVD API, AlienVault OTX |
| Risk Validation | CISA KEV, GitHub Exploit DB |
| Memory | JSON-based persistent storage |
| UI | Streamlit |
| Methodology | Harness Engineering (OpenAI) |

### Project Structure

```
ThreatHunter/
├── main.py                    # CrewAI Crew orchestration
├── config.py                  # LLM + API configuration
├── requirements.txt
│
├── tools/                     # @tool decorated functions
│   ├── nvd_tool.py            # NVD vulnerability lookup
│   ├── otx_tool.py            # OTX threat intelligence
│   ├── kev_tool.py            # CISA KEV verification
│   ├── exploit_tool.py        # GitHub exploit search
│   └── memory_tool.py         # Persistent memory R/W
│
├── agents/
│   ├── scout.py               # Scout Agent definition
│   ├── analyst.py             # Analyst Agent definition
│   └── advisor.py             # Advisor Agent definition
│
├── skills/                    # Agent SOP documents
│   ├── threat_intel.md        # Scout reasoning guide
│   ├── chain_analysis.md      # Chain vulnerability SOP
│   └── action_report.md       # Report generation SOP
│
├── memory/                    # Persistent scan history
├── data/                      # Offline caches
└── ui/
    └── app.py                 # Streamlit interface
```

### Quick Start

```bash
# 1. Clone
git clone https://github.com/EYY7592/ThreatHunter.git
cd ThreatHunter

# 2. Install dependencies
pip install -r requirements.txt

# 3. Set environment variables
export OPENROUTER_API_KEY="your-key"
export NVD_API_KEY="your-key"
export LLM_PROVIDER="openrouter"

# 4. Run
streamlit run ui/app.py
```

### Development Methodology: Harness Engineering

We build agents using **Harness Engineering** — a methodology focused on making AI agents **reliable**, not just powerful.

| Pillar | Implementation |
|---|---|
| **Constraints** | System Constitution in every agent's prompt |
| **Observability** | `verbose=True` — full ReAct reasoning visible |
| **Feedback Loops** | Memory system — agents learn from past scans |
| **Graceful Degradation** | Offline caches + fallback LLM providers |
| **Evaluation** | Confidence scoring (HIGH/MEDIUM/NEEDS_VERIFICATION) |

---

<a id="中文"></a>

## 🇹🇼 中文

### ThreatHunter 是什麼？

**ThreatHunter 是一個有記憶的 AI 資安顧問。**

傳統漏洞掃描器只會給你一份按 CVSS 分數排序的 CVE 清單。ThreatHunter 更進一步 — 它會**推理**漏洞之間的連鎖攻擊關係，而且**記得**你的基礎設施，追蹤風險隨時間的變化。

### 核心功能

| 功能 | 說明 |
|---|---|
| 🔍 **自主威脅偵察** | AI Agent 自動查詢 NVD + OTX API，比對歷史掃描，標記新威脅 |
| 🧠 **連鎖漏洞分析** | LLM 推理發現 SSRF + Redis = RCE，即使個別 CVSS 分數顯示「中危」 |
| 📋 **可執行報告** | 附帶具體修復指令的優先行動方案，不只是 CVE 清單 |
| 🧬 **進化記憶** | 每次掃描都記住上次的結果。風險趨勢、已修復問題、使用者回饋持續改善分析 |
| 🎯 **信心度標記** | 每個發現都標注 HIGH / MEDIUM / NEEDS_VERIFICATION — 不會偷偷幻覺 |

### 為什麼跟傳統工具不一樣？

```
傳統掃描器：
  CVE-A (SSRF, CVSS 6.5) → 中危 ⚠️
  CVE-B (Redis 未授權, CVSS 5.3) → 中危 ⚠️
  結論：兩個中危漏洞。

ThreatHunter：
  CVE-A (SSRF) + CVE-B (Redis 未授權)
  → SSRF 可以讓攻擊者打到內網
  → 內網的 Redis 沒密碼
  → 攻擊者可以直接寫入 crontab = 拿到 shell
  → 結論：兩個中危 = 一個致命 🔴

  ⬆️ 這個推理只有 LLM 能做。
  傳統工具做不到。
```

### 技術棧

| 元件 | 技術 |
|---|---|
| Agent 框架 | CrewAI（ReAct 模式） |
| LLM | Llama 3.3 70B，透過 vLLM 部署於 AMD Cloud |
| 威脅資料 | NVD API、AlienVault OTX |
| 風險驗證 | CISA KEV、GitHub Exploit DB |
| 記憶系統 | JSON 持久化儲存 |
| 介面 | Streamlit |
| 開發方法論 | Harness Engineering（OpenAI） |

### 開發方法：Harness Engineering

我們使用 **Harness Engineering** 來開發 Agent — 專注於讓 AI Agent **可靠穩定**，而不只是強大。

| 支柱 | 實作方式 |
|---|---|
| **Constraints（約束）** | 系統憲法寫進每個 Agent 的 Prompt |
| **Observability（可觀測性）** | `verbose=True` — 完整 ReAct 推理可見 |
| **Feedback Loops（回饋迴圈）** | Memory 系統 — Agent 從過去的掃描學習 |
| **Graceful Degradation（優雅降級）** | 離線快取 + 備用 LLM 供應商 |
| **Evaluation（驗證）** | 信心度標記（HIGH/MEDIUM/NEEDS_VERIFICATION） |

### 團隊

| 角色 | 職責 |
|---|---|
| 👑 組長 | 架構設計、CrewAI 串接、Streamlit UI、Memory Tool |
| 🔍 成員 B | Scout Agent Pipeline（NVD Tool + OTX Tool + Skill） |
| 🧠 成員 C | Analyst Agent Pipeline（KEV Tool + Exploit Tool + Chain Analysis Skill） |

---

## 📄 License

This project is developed for the AMD Developer Hackathon 2026.

## 🙏 Acknowledgments

- [AMD](https://www.amd.com) — Cloud GPU infrastructure
- [CrewAI](https://crewai.com) — Multi-agent orchestration framework
- [NVD](https://nvd.nist.gov) — National Vulnerability Database
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — Known Exploited Vulnerabilities
- [AlienVault OTX](https://otx.alienvault.com) — Open Threat Exchange
