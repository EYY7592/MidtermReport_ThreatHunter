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
├── checkpoint.py              # JSONL event persistence layer
├── input_sanitizer.py         # L0 input sanitation (Python core + Rust bindings)
│
├── agents/                    # Multi-Agent Definitions (7 Agents)
│   ├── orchestrator.py        # Dynamic Routing (Path A/B/C/D)
│   ├── security_guard.py      # Code Static Analysis (AST + Regex)
│   ├── intel_fusion.py        # 6D Intelligence Aggregation
│   ├── scout.py               # CVE Threat Scouting
│   ├── analyst.py             # Chain Vulnerability Reasoning
│   ├── critic.py              # Adversarial Debate & Review
│   └── advisor.py             # Final Action Plan Generation
│
├── tools/                     # CrewAI @tool functions (8 Tools)
│   ├── nvd_tool.py            # NVD API (Primary CVE DB / CPE Search)
│   ├── otx_tool.py            # AlienVault OTX (Threat Intelligence)
│   ├── kev_tool.py            # CISA KEV (Known Exploited Vulnerabilities)
│   ├── epss_tool.py           # EPSS (Exploit Prediction Scoring)
│   ├── exploit_tool.py        # GitHub Exploit DB / PoCs
│   ├── ghsa_tool.py           # GitHub Security Advisory
│   ├── memory_tool.py         # Hybrid Memory Persistence (JSON + LlamaIndex)
│   └── package_extractor.py   # Extract package names from source ast imports
│
├── sandbox/                   # Multi-Layer Sandbox Security (Phase 1, 3)
│   ├── ast_guard.py           # AST Bomb DoS Protection
│   ├── memory_sanitizer.py    # Memory Poison & Hallucination Defense
│   ├── docker_sandbox.py      # Docker Runner API for total isolation
│   ├── Dockerfile             # Minimal Pipeline Container Definition
│   └── seccomp-profile.json   # Syscall allowlist
│
├── rust/                      # Rust High-Performance Security Layer (Phase 2, 4)
│   ├── sanitizer/             # Regex DFA engine & hashes
│   ├── json_validator/        # JSON payload verification
│   ├── memory_validator/      # Swift memory screening
│   ├── url_builder/           # SSRF protection and API routing constraints
│   ├── prompt_sandbox/        # Host PyO3 wrapper for WASM guest
│   └── prompt_sandbox_guest/  # WASM Guest runtime for malicious payload filter
│
├── skills/                    # Agent SOP System (20+ markdown directives)
│   ├── threat_intel.md...     # Path-aware instructions (Pkg/Code/AI/Config)
│   └── skill_loader.py        # Hot-reload skill caching system
│
├── harness/                   # Harness Engineering Architecture
│   ├── context/               # Layer 1: Core system Context rules
│   ├── constraints/           # Layer 2: Architectural boundary definitions
│   └── entropy/               # Layer 3: Entropy management & repair loop
│
├── memory/                    # Persistent Agent Memory and Indexes
├── data/                      # Offline API caches (NVD/CISA)
├── ui/                        # Web Interface and Server
│   ├── server.py              # FastAPI + SSE active streaming backend
│   └── static/                # HTML/JS/CSS frontend UI
│
├── project_CONSTITUTION.md    # Development Standards and Guardrails
└── HARNESS_ENGINEERING.md     # Methodologies and constraint guidelines
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
├── checkpoint.py              # JSONL 事件持久化 + Checkpoint API
├── input_sanitizer.py         # L0 輸入淨化（Python 版 + Rust 橋接）
│
├── agents/                    # Agent 定義（7 個）
│   ├── orchestrator.py        # 動態路由（Path A/B/C/D）
│   ├── security_guard.py      # 程式碼靜態分析（AST + 正則）
│   ├── intel_fusion.py        # 六維情報整合（並行 API 查詢）
│   ├── scout.py               # CVE 情報偵察
│   ├── analyst.py             # 漏洞鏈推理
│   ├── critic.py              # 對抗式質疑辯論
│   └── advisor.py             # 最終行動報告
│
├── tools/                     # CrewAI @tool 函式（8 個）
│   ├── nvd_tool.py            # NVD API（主要 CVE 資料庫 / CPE 搜尋）
│   ├── otx_tool.py            # AlienVault OTX（威脅情報）
│   ├── kev_tool.py            # CISA KEV（已知被利用漏洞）
│   ├── epss_tool.py           # EPSS（漏洞利用預測）
│   ├── exploit_tool.py        # Exploit-DB / PoC 查詢
│   ├── ghsa_tool.py           # GitHub Security Advisory
│   ├── memory_tool.py         # 雙層記憶持久化（JSON + LlamaIndex）
│   └── package_extractor.py   # 從 import 提取第三方套件名稱
│
├── sandbox/                   # 多層安全防護（ Phase 1, Phase 3 ）
│   ├── ast_guard.py           # L1 AST Bomb 防護
│   ├── memory_sanitizer.py    # L3 記憶毒素掃描
│   ├── docker_sandbox.py      # L2 Docker Python API
│   ├── Dockerfile             # 最小化隔離容器 Dockerfile
│   └── seccomp-profile.json   # Linux syscall 白名單
│
├── rust/                      # Rust 高效能安全層（ Phase 2, Phase 4 ）
│   ├── sanitizer/             # L0 輸入淨化（regex O(n)·SHA256）
│   ├── json_validator/        # JSON Bomb 防護（depth≤32）
│   ├── memory_validator/      # 記憶毒素掃描（高效能版）
│   ├── url_builder/           # URL 安全建構（SSRF·白名單）
│   ├── prompt_sandbox/        # Host PyO3 供 Python 呼叫 WASM
│   └── prompt_sandbox_guest/  # WASM Guest 用於隔離惡意負載
│
├── skills/                    # Agent SOP 文件（20 餘個 .md 各路徑配置）
│   ├── threat_intel.md...     # Path-aware instructions (Pkg/Code/AI/Config)
│   └── skill_loader.py        # 動態載入 SOP 系統
│
├── harness/                   # Harness Engineering 三柱架構
│   ├── context/               # 第 1 層：專案上下文 Context
│   ├── constraints/           # 第 2 層：架構邊界規則 + linter
│   └── entropy/               # 第 3 層：熵掃描 + UNTIL CLEAN 迴圈
│
├── memory/                    # 雙層記憶持久化與向量快取
├── data/                      # NVD/KEV 等離線快取
├── ui/                        # 前端介面與 API Server
│   ├── server.py              # FastAPI + SSE 即時串流後端
│   └── static/                # HTML/CSS/JS 前端檔案
│
├── project_CONSTITUTION.md    # 開發規範與憲法指引
└── HARNESS_ENGINEERING.md     # 方法論規範
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
