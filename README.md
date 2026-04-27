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

```text
User Input: "Package List / Source Code / AI Prompt / Config File"
                         │
                         ▼
╔════════════════════════════════════════════════╗
║  🦀 L0.5 WASM Runtime Sandbox (Phase 4C)       ║
║  ┌─────────────────────────────────────────┐   ║
║  │ prompt_guard.wasm (Guest)               │   ║
║  │ Defenses: Length · UTF-8 · Prompt DB    │   ║
║  └─────────────────────────────────────────┘   ║
╚════════════════════════════════════════════════╝
                         │ ALLOW
                         ▼
╔════════════════════════════════════════════════╗
║  🦀 L0 Rust Security Layer (Phase 2)           ║
║  ┌─────────────────────────────────────────┐   ║
║  │ threathunter_sanitizer                  │   ║
║  │ scan_blocklist() · infer_input_type()   │   ║
║  │ sha256_hex() · O(n) regex · ReDoS Prev. │   ║
║  └─────────────────────────────────────────┘   ║
╚════════════════════════════════════════════════╝
                         │
                         ▼
╔════════════════════════════════════════════════╗
║  🐍 L1 AST Guard (Phase 1 · sandbox/)          ║
║  safe_ast_parse() · Max Nodes 50k              ║
║  3s timeout · AST Bomb DoS Protection          ║
╚════════════════════════════════════════════════╝
                         │
                         ▼
┌────────────────────────────────────────────────┐
│  🎯 Orchestrator Agent                         │
│  Dynamic Routing → Paths A/B/C/D               │
│  A: PKG Scan  B: Code Audit                    │
│  C: CFG Audit D: Refinement                    │
└──────────────┬─────────────────────────────────┘
               │
       ┌───────┴───────┐
       ▼               ▼
┌─────────────┐ ┌──────────────────┐
│ Security    │ │ Intel Fusion     │
│ Guard Agent │ │ 6D Intelligence  │
│ (Parallel)  │ │ NVD/OTX/EPSS...  │
└──────┬──────┘ └────────┬─────────┘
       └────────┬─────────┘
                ▼
        ┌───────────────┐
        │  Scout Agent  │
        │  CVE Indexing │
        └───────┬───────┘
                ▼
        ┌───────────────┐
        │ Analyst Agent │
        │ Chain Analysis│
        └───────┬───────┘
                ▼
        ┌───────────────┐
        │ Critic Agent  │
        │ Debate & Auth │
        └───────┬───────┘
                ▼
        ┌───────────────┐
        │ Advisor Agent │
        │ Action Report │
        └───────┬───────┘
                │
                ▼
╔════════════════════════════════════════════════╗
║  🦀 L0 JSON Validator (Phase 2 · Rust)         ║
║  safe_parse_json() · depth≤32 · Verify Years   ║
╚════════════════════════════════════════════════╝
                │
                ▼
╔════════════════════════════════════════════════╗
║  🐍 L3 Memory Sanitizer (Phase 1)              ║
║  + 🦀 Memory Validator (Phase 2 · Rust)        ║
║  Toxic Scan · Hallucination Filter             ║
╚════════════════════════════════════════════════╝
                │
                ▼
        ┌───────────────┐
        │ Checkpoints   │
        │ JSONL Events  │
        └───────┬───────┘
                │
                ▼
╔════════════════════════════════════════════════╗
║  FastAPI + SSE Real-Time Streaming → Frontend  ║
╚════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🐳 L2 Docker Sandbox (Phase 3 · Optional)
   Full Pipeline execution in isolated container
   --network none · --read-only · seccomp
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
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
| UI | FastAPI (SSE) + HTML/JS/CSS |
| Methodology | Harness Engineering (OpenAI) |

### Project Structure

```text
ThreatHunter/
├── main.py                    # Pipeline Entrypoint (Orchestrator driven)
├── config.py                  # LLM configs + API Keys + Degradation Waterfall
├── checkpoint.py              # JSONL event persistence + Checkpoint recorder API
├── input_sanitizer.py         # L0 input sanitation (Python core + Rust bindings)
├── build_nvd_cache.py         # Offline NVD cache builder utility
│
├── agents/                    # Multi-Agent Definitions (7 Agents)
│   ├── orchestrator.py        # Dynamic Path Routing (A: PKG / B: Code / C: Config / D: Refine)
│   ├── security_guard.py      # Deterministic Code Static Analysis (AST + Regex, 20+ patterns)
│   ├── intel_fusion.py        # 6D Intelligence Aggregation (NVD/OTX/KEV/EPSS/GHSA/Exploit)
│   ├── scout.py               # CVE Threat Scouting (ReAct + memory-aware)
│   ├── analyst.py             # Chain Vulnerability Reasoning
│   ├── critic.py              # Adversarial Debate & Authenticity Review
│   └── advisor.py             # Final Action Report
│                              #   Harness Layer 4.5: Constitution CI-1/CI-2 Guard
│                              #   (CODE-pattern blocked from URGENT, moved to code_patterns_summary)
│
├── tools/                     # CrewAI @tool functions (10 Tools)
│   ├── nvd_tool.py            # NVD API (Primary CVE DB / CPE-aware search)
│   ├── otx_tool.py            # AlienVault OTX (Threat Intelligence)
│   ├── kev_tool.py            # CISA KEV (Known Exploited Vulnerabilities)
│   ├── epss_tool.py           # EPSS (Exploit Prediction Scoring System)
│   ├── exploit_tool.py        # GitHub Exploit DB / PoC Finder
│   ├── ghsa_tool.py           # GitHub Security Advisory
│   ├── osv_tool.py            # OSV (Open Source Vulnerabilities, ecosystem-aware)
│   ├── attck_tool.py          # MITRE ATT&CK TTP Mapping
│   ├── memory_tool.py         # Hybrid Memory Persistence (JSON + LlamaIndex)
│   └── package_extractor.py   # Extract 3rd-party packages from source AST imports
│
├── sandbox/                   # Multi-Layer Sandbox Security (Phase 1, 3)
│   ├── ast_guard.py           # L1 AST Bomb DoS Protection (50k node limit, 3s timeout)
│   ├── memory_sanitizer.py    # L3 Memory Poison & Hallucination Scan
│   ├── docker_sandbox.py      # L2 Docker Runner API for full pipeline isolation
│   ├── sandbox_runner.py      # Sandbox execution entrypoint (inside container)
│   ├── Dockerfile             # Minimal pipeline container (non-root, read-only)
│   └── seccomp-profile.json   # Linux syscall allowlist
│
├── rust/                      # Rust High-Performance Security Layer (Phase 2)
│   ├── sanitizer/             # L0 Input Sanitizer (regex DFA, SHA-256, ReDoS O(n))
│   ├── json_validator/        # JSON Bomb Protection (depth ≤ 32)
│   ├── memory_validator/      # Memory Hallucination Screening (Rust speed)
│   ├── url_builder/           # Safe URL Builder (SSRF prevention, allowlist)
│   └── prompt_sandbox/        # PyO3 host wrapper for WASM guest isolation
│
├── skills/                    # Agent SOP Directives (path-aware .md files)
│   ├── threat_intel.md        # Scout: Threat intelligence SOP
│   ├── source_code_audit.md   # Security Guard: Code audit SOP
│   ├── chain_analysis.md      # Analyst: Chain vulnerability reasoning SOP
│   ├── debate_sop.md          # Critic: Adversarial debate SOP
│   ├── code_action_report.md  # Advisor: Code findings action report (v5.1 Anti-Fabrication)
│   ├── intel_fusion.md        # Intel Fusion: 6D weighting SOP
│   ├── orchestrator.md        # Orchestrator: Path routing SOP
│   ├── security_guard.md      # Security Guard: Pattern match SOP
│   └── skill_loader.py        # Hot-reload skill caching system
│
├── harness/                   # Harness Engineering 3-Pillar Architecture
│   ├── context/               # Layer 1: System Context Rules
│   ├── constraints/           # Layer 2: Boundary definitions + arch_linter.py
│   └── entropy/               # Layer 3: Entropy scanner + UNTIL CLEAN loop
│
├── scripts/
│   └── clean_memory_contamination.py  # Startup memory cleanup (removes ancient CVEs)
│
├── docs/                      # Architecture and design documentation
├── memory/                    # Persistent agent memory (JSON + vector index)
├── data/                      # Offline API caches (NVD / CISA KEV)
├── tests/                     # pytest test suite (180+ tests)
├── ui/
│   ├── server.py              # FastAPI + SSE real-time streaming backend
│   └── static/
│       ├── index.html         # Main scan UI
│       ├── app.js             # SSE client, report rendering (CWE badge + snippet diff)
│       ├── style.css          # UI theme + action card styles
│       ├── checkpoint.html    # Pipeline checkpoint viewer
│       ├── checkpoint.js      # Checkpoint data handler
│       └── checkpoint.css     # Checkpoint viewer styles
│
├── project_CONSTITUTION.md    # Project development constitution (rules & guardrails)
├── HARNESS_ENGINEERING.md     # Harness methodology spec
├── AGENTS.md                  # AI assistant task routing guide
└── walkthrough.md             # Full architecture walkthrough (v5.3)
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
uv run python ui/server.py
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

### 整體架構圖

```text
┌─────────────────── 用戶輸入 ───────────────────┐
│  套件清單 / 原始碼 / AI 提示 / 配置檔           │
└────────────────────────┬───────────────────────┘
                         │
                         ▼
╔════════════════════════════════════════════════╗
║  🦀 L0.5 WASM 執行環境隔離 (Phase 4C)          ║
║  ┌─────────────────────────────────────────┐   ║
║  │ prompt_guard.wasm (Guest)               │   ║
║  │ 防護: 長度檢查 · UTF-8 驗證 · 提示詞注入       │   ║
║  └─────────────────────────────────────────┘   ║
╚════════════════════════════════════════════════╝
                         │ ALLOW
                         ▼
╔════════════════════════════════════════════════╗
║  🦀 L0 Rust 安全層（Phase 2）                  ║
║  ┌─────────────────────────────────────────┐   ║
║  │ threathunter_sanitizer                  │   ║
║  │ scan_blocklist() · infer_input_type()   │   ║
║  │ sha256_hex() · O(n) 正則防 ReDoS        │   ║
║  └─────────────────────────────────────────┘   ║
╚════════════════════════════════════════════════╝
                         │
                         ▼
╔════════════════════════════════════════════════╗
║  🐍 L1 AST Guard（Phase 1 · sandbox/）         ║
║  safe_ast_parse() · 節點上限 50,000            ║
║  3s 超時保護 · AST Bomb DoS 防護              ║
╚════════════════════════════════════════════════╝
                         │
                         ▼
┌────────────────────────────────────────────────┐
│  🎯 Orchestrator Agent                         │
│  動態路由 → Path A/B/C/D                       │
│  A: 套件掃描  B: 源碼審計                       │
│  C: 配置審計  D: 回饋補充                       │
└──────────────┬─────────────────────────────────┘
               │
       ┌───────┴───────┐
       ▼               ▼
┌─────────────┐ ┌──────────────────┐
│ Security    │ │ Intel Fusion     │
│ Guard Agent │ │ 六維情報查詢     │
│ (Layer 1    │ │ NVD/OTX/KEV      │
│  並行)      │ │ EPSS/GHSA/Exploit│
└──────┬──────┘ └────────┬─────────┘
       └────────┬─────────┘
                ▼
        ┌───────────────┐
        │  Scout Agent  │
        │  CVE 情報偵察 │
        └───────┬───────┘
                ▼
        ┌───────────────┐
        │ Analyst Agent │
        │ 漏洞鏈推理    │
        └───────┬───────┘
                ▼
        ┌───────────────┐
        │ Critic Agent  │
        │ 對抗式辯論    │
        └───────┬───────┘
                ▼
        ┌───────────────┐
        │ Advisor Agent │
        │ 最終行動報告  │
        └───────┬───────┘
                │
                ▼
╔════════════════════════════════════════════════╗
║  🦀 L0 JSON Validator（Phase 2 · Rust）        ║
║  safe_parse_json() · 深度≤32 · CVE 年份驗證   ║
╚════════════════════════════════════════════════╝
                │
                ▼
╔════════════════════════════════════════════════╗
║  🐍 L3 Memory Sanitizer（Phase 1 · sandbox/）  ║
║  ＋ 🦀 Memory Validator（Phase 2 · Rust）      ║
║  毒素掃描 · 幻覺 CVE 過濾 · 寫入前攔截         ║
╚════════════════════════════════════════════════╝
                │
                ▼
        ┌───────────────┐
        │ Checkpoint    │
        │  JSONL 事件記錄│
        │ （Rust 高效寫入）│
        └───────┬───────┘
                │
                ▼
╔════════════════════════════════════════════════╗
║  FastAPI + SSE 即時串流 → 前端介面             ║
╚════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🐳 L2 Docker Sandbox（Phase 3 · 可選）
   整個 Pipeline 在隔離容器內執行
   --network none · --read-only · seccomp · non-root
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### 技術棧

| 元件 | 技術 |
|---|---|
| Agent 框架 | CrewAI（ReAct 模式） |
| LLM | Llama 3.3 70B，透過 vLLM 部署於 AMD Cloud |
| 威脅資料 | NVD API、AlienVault OTX |
| 風險驗證 | CISA KEV、GitHub Exploit DB |
| 記憶系統 | JSON 持久化儲存 + 快取 |
| 介面 | FastAPI (SSE) + HTML/JS/CSS |
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

### 目錄結構

```text
ThreatHunter/
├── main.py                    # Pipeline 主程式（Orchestrator 驅動）
├── config.py                  # LLM 設定 + API Key + 降級瀑布
├── checkpoint.py              # JSONL 事件持久化 + Checkpoint 記錄 API
├── input_sanitizer.py         # L0 輸入淨化（Python 和 Rust 橋接）
├── build_nvd_cache.py         # NVD 離線快取建置工具
│
├── agents/                    # Agent 定義（7 個）
│   ├── orchestrator.py        # 動態路由（Path A: 套件 / B: 原始碼 / C: 配置 / D: 補充）
│   ├── security_guard.py      # 確定性程式碼靜態分析（AST + 正則，20+ 格式）
│   ├── intel_fusion.py        # 六維情報整合（NVD/OTX/KEV/EPSS/GHSA/Exploit）
│   ├── scout.py               # CVE 情報偵察（ReAct + 記憶感知）
│   ├── analyst.py             # 漏洞鏈推理
│   ├── critic.py              # 對抗式辯論 + 真實性審查
│   └── advisor.py             # 最終行動報告
│                              #   Harness Layer 4.5：憲法 CI-1/CI-2 守衛
│                              #   （CODE-pattern 不進 URGENT，移入 code_patterns_summary）
│
├── tools/                     # CrewAI @tool 函式（10 個）
│   ├── nvd_tool.py            # NVD API（主要 CVE 資料庫 / CPE 搜尋）
│   ├── otx_tool.py            # AlienVault OTX（威脅情報）
│   ├── kev_tool.py            # CISA KEV（已知被利用漏洞）
│   ├── epss_tool.py           # EPSS（漏洞利用預測）
│   ├── exploit_tool.py        # Exploit-DB / PoC 查詢
│   ├── ghsa_tool.py           # GitHub Security Advisory
│   ├── osv_tool.py            # OSV（開源漏洞資料庫，ecosystem-aware）
│   ├── attck_tool.py          # MITRE ATT&CK TTP 映射
│   ├── memory_tool.py         # 雙層記憶持久化（JSON + LlamaIndex）
│   └── package_extractor.py   # 從 import 提取第三方套件名稱
│
├── sandbox/                   # 多層安全防護（Phase 1、3）
│   ├── ast_guard.py           # L1 AST Bomb DoS 防護（50k 節點上限、3s 還時）
│   ├── memory_sanitizer.py    # L3 記憶毒素掃描 + 幻覺 CVE 過濾
│   ├── docker_sandbox.py      # L2 Docker 隔離容器 Python API
│   ├── sandbox_runner.py      # 容器內執行入口
│   ├── Dockerfile             # 最小化隔離容器（non-root、read-only）
│   └── seccomp-profile.json   # Linux syscall 白名單
│
├── rust/                      # Rust 高效能安全層（Phase 2）
│   ├── sanitizer/             # L0 輸入淨化（regex O(n)、SHA-256、防 ReDoS）
│   ├── json_validator/        # JSON Bomb 防護（depth≤32）
│   ├── memory_validator/      # 記憶幻覺掃描（Rust 速度）
│   ├── url_builder/           # 安全 URL 建構（防 SSRF、白名單）
│   └── prompt_sandbox/        # PyO3 Host 供 Python 呼叫 WASM
│
├── skills/                    # Agent SOP 指令文件（路徑感知 .md）
│   ├── threat_intel.md        # Scout：威脅情報收集 SOP
│   ├── source_code_audit.md   # Security Guard：程式碼審計 SOP
│   ├── chain_analysis.md      # Analyst：漏洞鏈分析 SOP
│   ├── debate_sop.md          # Critic：對抗辯論 SOP
│   ├── code_action_report.md  # Advisor：程式碼發現行動報告（v5.1 防捏造）
│   ├── intel_fusion.md        # Intel Fusion：六維加權 SOP
│   ├── orchestrator.md        # Orchestrator：路由決策 SOP
│   ├── security_guard.md      # Security Guard：格式匹配 SOP
│   └── skill_loader.py        # 動態載入 SOP 系統
│
├── harness/                   # Harness Engineering 三柱架構
│   ├── context/               # 第 1 層：系統 Context 規則
│   ├── constraints/           # 第 2 層：架構邊界規則 + arch_linter.py
│   └── entropy/               # 第 3 層：熵掃描 + UNTIL CLEAN 迭代
│
├── scripts/
│   └── clean_memory_contamination.py  # 啟動時記憶清理（移除古老 CVE）
│
├── docs/                      # 架構與設計文件
├── memory/                    # 雙層記憶持久化與向量快取
├── data/                      # NVD/KEV 等離線快取
├── ui/
│   ├── server.py              # FastAPI + SSE 即時串流後端
│   └── static/
│       ├── index.html         # 主掃描 UI
│       ├── app.js             # SSE 用戶端、報告渲染（CWE badge + snippet diff）
│       ├── style.css          # UI 主題 + 行動卡樣式
│       ├── checkpoint.html    # Pipeline Checkpoint 檢視器
│       ├── checkpoint.js      # Checkpoint 資料處理
│       └── checkpoint.css     # Checkpoint 檢視器樣式
│
├── project_CONSTITUTION.md    # 憲法指引（開發規範與保護標準）
├── HARNESS_ENGINEERING.md     # Harness 方法論規範
├── AGENTS.md                  # AI 工程夥伴任務路由指南
└── walkthrough.md             # 完整架構走查記錄（v5.3）
```

### 快速開始

```bash
# 1. 複製專案
git clone https://github.com/EYY7592/ThreatHunter.git
cd ThreatHunter

# 2. 啟動環境與安裝套件
uv sync
# 如果需要編譯 rust (可選)，請執行： python build_rust_crates.py

# 3. 設定環境變數
export OPENROUTER_API_KEY="your-key"

# 4. 執行
uv run python ui/server.py
# 接著打開瀏覽器訪問 http://localhost:1000
```

### 團隊

| 角色 | 職責 |
|---|---|
| 👑 組長 | 架構設計、CrewAI 串接、FastAPI + SSE UI、Memory Tool |
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
