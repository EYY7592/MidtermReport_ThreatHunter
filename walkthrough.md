# ThreatHunter — 完整架構與程式碼總結 Walkthrough
# 版本：v5.3（2026-04-20）Phase 7.17 Constitution Guard + Intel Fusion Hardening
# 維護作者：Antigravity AI 工程夥伴

> ⚠️ **三條強制守則（閱讀前必看）**
> 1. 永遠使用 `uv run python`，禁止裸 `python` 指令
> 2. 任何程式碼修改前先跑 `uv run python -m harness.constraints.arch_linter`
> 3. 任何修改後必跑 `uv run python -m pytest tests/ -v`

---

## 一、專案定位

ThreatHunter 是一個 **多 Agent AI 安全掃描平台**，設計目標為：

- 掃描 Python/JS/Go 套件、原始碼、AI 系統提示、配置檔，找出 CVE / OWASP / CIS 漏洞
- 以 **四層安全防護** 保護 AI Pipeline 本身不被操控
- 符合 AMD Developer Hackathon 提交規格（FastAPI + SSE 即時串流）
- 採用 **Harness Engineering** 方法論保證架構邊界不退化

---

## 二、整體架構圖

```
┌─────────────────── 用戶輸入 ───────────────────┐
│  套件清單 / 原始碼 / AI 提示 / 配置檔           │
└────────────────────────┬───────────────────────┘
                         │
                         ▼
╔════════════════════════════════════════════════╗
║  🦀 L0 Rust 安全層（Phase 2）                  ║
║  ┌─────────────────────────────────────────┐   ║
║  │ threathunter_sanitizer                  │   ║
║  │   scan_blocklist() · infer_input_type() │   ║
║  │   sha256_hex()  · O(n) regex · 防 ReDoS│   ║
║  └─────────────────────────────────────────┘   ║
╚════════════════════════════════════════════════╝
                         │
                         ▼
╔════════════════════════════════════════════════╗
║  🐍 L1 AST Guard（Phase 1 · sandbox/）         ║
║  safe_ast_parse()  · 節點上限 50,000           ║
║  3s timeout · AST Bomb DoS 防護               ║
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
│ (Layer 1   │ │ NVD/OTX/KEV      │
│  並行)      │ │ EPSS/GHSA/Exploit│
└──────┬──────┘ └────────┬─────────┘
       └────────┬─────────┘
                ▼
        ┌───────────────┐
        │  Scout Agent  │
        │  15條CVE 索引 │
        └───────┬───────┘
                ▼
        ┌───────────────┐
        │ Analyst Agent │
        │ 漏洞鏈 分析   │
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
║  safe_parse_json() · depth≤32 · CVE 年份驗證  ║
╚════════════════════════════════════════════════╝
                │
                ▼
╔════════════════════════════════════════════════╗
║  🐍 L3 Memory Sanitizer（Phase 1 · sandbox/） ║
║  ＋ 🦀 Memory Validator（Phase 2 · Rust）     ║
║  毒素掃描 · 幻覺 CVE 過濾 · 寫入前攔截        ║
╚════════════════════════════════════════════════╝
                │
                ▼
        ┌───────────────┐
        │ Checkpoint    │
        │  JSONL 事件   │
        │  持久化記錄   │
        └───────┬───────┘
                │
                ▼
╔════════════════════════════════════════════════╗
║  FastAPI + SSE 即時串流 → 前端                 ║
╚════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🐳 L2 Docker Sandbox（Phase 3 · 可選）
   整個 Pipeline 在隔離容器內執行
   --network none · --read-only · seccomp · non-root
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## 三、目錄結構與檔案對應

```
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
├── tools/                     # CrewAI @tool 函式（9 個）
│   ├── nvd_tool.py            # NVD API（主要 CVE 資料庫）
│   ├── otx_tool.py            # AlienVault OTX（威脅情報）
│   ├── kev_tool.py            # CISA KEV（已知被利用漏洞）
│   ├── epss_tool.py           # EPSS（漏洞利用預測）
│   ├── exploit_tool.py        # Exploit-DB / PoC 查詢
│   ├── ghsa_tool.py           # GitHub Security Advisory
│   ├── memory_tool.py         # 雙層記憶持久化（JSON + LlamaIndex）
│   └── package_extractor.py   # 從 import 提取第三方套件名稱
│
├── sandbox/                   # 多層安全防護（三個 Phase 的核心）
│   ├── ast_guard.py           # [Phase 1] L1 AST Bomb 防護
│   ├── memory_sanitizer.py    # [Phase 1] L3 記憶毒素掃描
│   ├── docker_sandbox.py      # [Phase 3] L2 Docker Python API
│   ├── sandbox_runner.py      # [Phase 3] 容器內 Pipeline 進入點
│   ├── Dockerfile             # [Phase 3] 最小化隔離容器
│   └── seccomp-profile.json   # [Phase 3] Linux syscall 白名單
│
├── rust/                      # Rust 高效能安全層（4 個 crate）
│   ├── .cargo/config.toml     # MinGW toolchain 設定
│   ├── Cargo.toml             # Workspace 根設定
│   ├── sanitizer/             # L0 輸入淨化（regex O(n)·SHA256）
│   ├── json_validator/        # JSON Bomb 防護（depth≤32）
│   ├── memory_validator/      # 記憶毒素掃描（高效能版）
│   └── url_builder/           # URL 安全建構（SSRF·白名單）
│
├── skills/                    # Agent SOP 文件（20 個 .md）
│   ├── threat_intel.md        # Scout / pkg 路徑
│   ├── source_code_audit.md   # Scout / code 路徑
│   ├── ai_security_audit.md   # Scout / injection 路徑
│   ├── config_audit.md        # Scout / config 路徑
│   ├── chain_analysis.md      # Analyst / pkg
│   ├── code_chain_analysis.md # Analyst / code
│   ├── ai_chain_analysis.md   # Analyst / injection
│   ├── config_chain_analysis.md # Analyst / config
│   ├── debate_sop.md          # Critic / pkg
│   ├── code_debate_sop.md     # Critic / code
│   ├── ai_debate_sop.md       # Critic / injection
│   ├── config_debate_sop.md   # Critic / config
│   ├── action_report.md       # Advisor / pkg
│   ├── code_action_report.md  # Advisor / code
│   ├── ai_action_report.md    # Advisor / injection
│   ├── config_action_report.md # Advisor / config
│   ├── orchestrator.md        # Orchestrator SOP
│   ├── intel_fusion.md        # Intel Fusion SOP
│   └── security_guard.md      # Security Guard SOP
│
├── harness/                   # Harness Engineering 三柱架構
│   ├── context/               # 第1層：專案上下文
│   ├── constraints/           # 第2層：架構邊界規則 + linter
│   └── entropy/               # 第3層：熵掃描 + UNTIL CLEAN 迴圈
│
├── ui/
│   ├── server.py              # FastAPI + SSE 即時串流後端
│   └── static/                # HTML/CSS/JS 前端
│
├── memory/                    # 雙層記憶持久化
│   ├── *.json                 # 短期 JSON 快取
│   └── (LlamaIndex 向量索引)  # 長期語意搜尋
│
├── data/                      # NVD/KEV 離線快取（避免 API 限速）
│
├── tests/                     # pytest 測試（32 個測試檔）
│
├── build_rust_crates.py       # 一鍵建置 4 個 Rust crate
├── requirements.txt           # Python 依賴
├── project_CONSTITUTION.md    # 專案憲法（開發規範）
├── HARNESS_ENGINEERING.md     # Harness Engineering 方法論
└── AGENTS.md                  # AI 工程助理任務地圖
```

---

## 四、三個 Phase 的安全強化架構

### Phase 1：Sandbox 純 Python 層 ✅

#### B-1：AST Guard（`sandbox/ast_guard.py`）
防護目標：AST Bomb —— 惡意構造超深巢狀代碼拖垮 CPython stack

```python
MAX_AST_NODES    = 50_000   # 超過此節點數 → 拒絕
MAX_PARSE_SECONDS = 3.0     # 超過 3 秒 → timeout → regex fallback

def safe_ast_parse(code: str) -> ast.AST | None:
    """thread 封裝：防 AST Bomb + 超時保護"""
    # 在 daemon thread 內 parse，join(timeout=3.0)
    # 若超時 → 返回 None，呼叫方使用正則 fallback
    # 若節點數 > 50_000 → 拋 ValueError
```

**整合點**：`agents/security_guard.py` 中所有 `ast.parse(code)` 替換為 `safe_ast_parse(code)`

#### B-2：Memory Sanitizer（`sandbox/memory_sanitizer.py`）
防護目標：LLM 被操控輸出含毒素 JSON → 汙染記憶快取 → 下次掃描中招

```python
_POISON_PATTERNS = [
    re.compile(r"ignore\s+(?:previous|all|above)", re.I),   # 提示注入
    re.compile(r"you\s+are\s+now\s+(?:a|an)", re.I),        # 角色扮演劫持
    re.compile(r"developer\s+mode", re.I),                    # 越獄嘗試
    re.compile(r"jailbreak", re.I),
    re.compile(r"<script[^>]*>", re.I),                       # XSS 殘留
    re.compile(r"DROP\s+TABLE", re.I),                        # SQL injection
    re.compile(r"system\s+prompt", re.I),
]
_CVE_YEAR_PATTERN = re.compile(r"CVE-(\d{4})-")  # 幻覺 CVE 年份 1999≤y≤2027

def sanitize_memory_write(data) -> tuple[bool, dict, str]:
    """返回 (is_safe, cleaned_data, reason)"""
```

**整合點**：`tools/memory_tool.py` 的 `write_memory()` 前置毒素過濾

---

### Phase 2：Rust 高效能安全層 ✅

#### 工具鏈（Windows 環境）

| 工具 | 版本 | 角色 |
|------|------|------|
| rustc | 1.94.1 | Rust 編譯器 |
| maturin | 1.13.1 | PyO3 wheel 建置 |
| gcc (MinGW-w64) | 15.2.0 | GNU 連結器（繞開 MSVC）|
| Python | 3.12.12 | .venv 目標環境 |

**關鍵突破**：Windows 無 MSVC `link.exe` → 改用 MSYS2 MinGW-w64，設定 `rust/.cargo/config.toml` 強制 target=`x86_64-pc-windows-gnu`

#### 四個 Crate

**A. `rust/sanitizer/` → `threathunter_sanitizer`**
```python
from threathunter_sanitizer import scan_blocklist, infer_input_type, sha256_hex
```
- `scan_blocklist(text)` — O(n) regex DFA，免疫 ReDoS
- `infer_input_type(text)` — 確定性分類（pkg/code/config/injection）
- `sha256_hex(text)` — SHA-256 雜湊（用於快取 key / 防竄改）

**B. `rust/json_validator/` → `threathunter_json_validator`**
```python
from threathunter_json_validator import safe_parse_json, validate_cve_id, validate_cve_list
```
- `safe_parse_json(s)` — serde_json 解析，depth≤32，單欄位≤8000 chars
- `validate_cve_id(id)` — 年份 1999~2027，序號 4~7 位
- 防護 5 個 `ui/server.py` 的 `json.loads()` 熱點

**C. `rust/memory_validator/` → `threathunter_memory_validator`**
```python
from threathunter_memory_validator import validate_memory_write, validate_cve_id
```
- `validate_memory_write(json_str)` — 毒素 pattern + CVE 年份雙驗證
- 返回 `(bool, str)` = `(is_safe, reason)`

**D. `rust/url_builder/` → `threathunter_url_builder`**
```python
from threathunter_url_builder import build_api_url, validate_url, encode_query_value
```
- `build_api_url(base, params)` — 強制 HTTPS + Host 白名單（nvd/otx/cisa 等）
- 防護 `tools/nvd_tool.py` 的 SSRF + HTTP Header 注入

#### 編譯與安裝結果

```
✅ cargo check (x86_64-pc-windows-gnu)   Finished
✅ maturin develop × 4                   全部 Installed

Python 驗證：
  [OK] threathunter_memory_validator (validate_memory_write, validate_cve_id)
  [OK] threathunter_json_validator   (safe_parse_json, validate_cve_id, validate_cve_list)
  [OK] threathunter_sanitizer        (scan_blocklist, infer_input_type, sha256_hex)
  [OK] threathunter_url_builder      (build_api_url, validate_url, encode_query_value)
```

---

### Phase 3：Docker Container Sandbox ✅

#### 架構設計
```
SANDBOX_ENABLED=true + docker available
    │
    ▼
docker run --rm \
  --network none                          # 完全斷網
  --read-only                             # Filesystem 唯讀
  --tmpfs /tmp:noexec,nosuid,size=64m    # 唯一可寫、不可執行
  --memory 512m --memory-swap 512m        # 記憶體硬上限
  --cpus 1.0                             # CPU 配額
  --no-new-privileges                    # 禁止 setuid/capabilities
  --pids-limit 256                       # 防 fork bomb
  --user sandbox                         # 非 root 執行
  --security-opt seccomp=sandbox/seccomp-profile.json
  -v ./data:/app/data:ro                 # NVD cache 唯讀
  -v ./skills:/app/skills:ro
  --env-file .env                        # API keys 傳遞
  threathunter-sandbox:latest

容器進入點: sandbox/sandbox_runner.py
  stdin  → JSON 任務 (tech_stack, input_type)
  stdout → JSON 結果 (vulnerabilities, summary, ...)
  stderr → 結構化 log（不汙染 JSON）
```

#### seccomp 設定
- 預設動作：`SCMP_ACT_ERRNO`（拒絕所有未列出 syscall）
- 白名單分類：基本 I/O、記憶體管理、進程控制、時間計時、同步原語、tmpfs 寫入
- 網路：`--network none`（network namespace 層隔離）

#### Graceful Degradation 六層
```
SANDBOX_ENABLED=false          → in-process（預設，正常模式）
docker 不可用                   → in-process + warning
映像不存在                      → SANDBOX_IMAGE_NOT_FOUND + hint
容器超時（>300s）               → SANDBOX_TIMEOUT + fallback
容器 exit ≠ 0/1               → SANDBOX_CONTAINER_ERROR + fallback
stdout 空 / 非 JSON            → SANDBOX_EMPTY_OUTPUT / PARSE_ERROR + fallback
所有 fallback 自動降級回 in-process，服務不中斷
```

#### 核心 API（`sandbox/docker_sandbox.py`）
```python
run_in_sandbox(tech_stack, input_type, scan_id) -> dict
is_docker_available() -> bool
is_sandbox_image_ready() -> bool
build_sandbox_image(no_cache=False) -> bool
run_sandbox_selftest() -> dict  # 驗證隔離設定
_build_docker_cmd(selftest=False) -> list[str]
```

#### 使用方式
```bash
# 建置映像（一次性）
docker build -t threathunter-sandbox:latest -f sandbox/Dockerfile .

# 驗證隔離（selftest）
docker run --rm --network none threathunter-sandbox:latest --selftest

# 啟用（.env 設定）
SANDBOX_ENABLED=true

# 測試（不需要 Docker daemon）
uv run python -m pytest tests/test_docker_sandbox.py -v
```

---

## 五、Agents 詳細說明

### Orchestrator（`agents/orchestrator.py`）
任務：分析用戶輸入，決定 Pipeline 路徑

| Path | 條件 | 執行 Agents |
|------|------|------------|
| A | 純套件清單 | Intel Fusion → Scout → Analyst → [Critic] → Advisor |
| B | 含程式碼 | Security Guard + Intel Fusion (並行) → Scout → Analyst → Debate → Advisor |
| C | 配置檔 | Security Guard → Scout → Advisor（跳過 Analyst + Debate）|
| D | 回饋補充 | 只重跑低信心 CVE |

### Security Guard（`agents/security_guard.py`）
任務：靜態程式碼分析，提取安全相關元素
- AST 解析：uses `sandbox/ast_guard.py`（Phase 1 整合）
- 提取：函式/類別/import/硬編碼密鑰/安全模式
- 輸出：`{functions, imports, patterns, hardcoded, stats}`

### Intel Fusion（`agents/intel_fusion.py`）
任務：六維情報並行查詢
1. **NVD** — CVE 資料庫（主要）
2. **OTX** — AlienVault 威脅情報
3. **KEV** — CISA 已知被利用漏洞
4. **EPSS** — 漏洞利用概率預測
5. **GHSA** — GitHub Security Advisory
6. **ExploitDB** — PoC / EXP 可用性

### Scout（`agents/scout.py`）
任務：彙整 Intel Fusion 資料，輸出結構化 CVE 清單
- 每個 CVE 標準欄位：`cve_id, cvss_score, severity, description, affected_versions, fix_version`
- Path-Aware：依 `input_type` 載入不同 Skill SOP（16 個 SOP）

### Analyst（`agents/analyst.py`）
任務：漏洞鏈推理，計算攻擊路徑複雜度
- 判斷 CVE 是否可鏈式利用（`is_chain: bool`）
- 調整後風險評分（`adjusted_risk`）
- KEV 在庫確認（`in_cisa_kev`）

### Critic（`agents/critic.py`）
任務：對抗式辯論，質疑 Analyst 的結論
- 評分維度：evidence / chain_completeness / critique_quality / defense_quality / calibration
- 最終裁決：`MAINTAIN / DOWNGRADE / ESCALATE`
- `ENABLE_CRITIC=false`（`config.py` 控制）→ 可插拔跳過

### Advisor（`agents/advisor.py`）
任務：生成最終行動報告
- 三層行動清單：`urgent / important / resolved`
- 執行摘要（`executive_summary`）
- 風險分數 + 趨勢（`risk_score, risk_trend`）

---

## 六、Tools 詳細說明

| Tool | 主要函式 | 資料來源 | 快取 |
|------|---------|---------|------|
| `nvd_tool.py` | `search_nvd_for_package()` | NVD REST APIv2 | `data/nvd_cache/` JSON |
| `otx_tool.py` | `search_otx_for_ioc()` | AlienVault OTX | 記憶體 TTL |
| `kev_tool.py` | `check_cisa_kev()` | CISA KEV JSON | `data/kev_cache.json` |
| `epss_tool.py` | `get_epss_score()` | EPSS API v3 | 記憶體 |
| `exploit_tool.py` | `search_exploits()` | ExploitDB / PoC-in-GitHub | 記憶體 |
| `ghsa_tool.py` | `search_ghsa()` | GitHub GraphQL API | 記憶體 |
| `memory_tool.py` | `read_memory()` / `write_memory()` | 本機 JSON + LlamaIndex | `memory/*.json` |
| `package_extractor.py` | `packages_from_security_guard()` | 本機解析 | 無 |

---

## 七、Path-Aware Skills 系統（v3.7）

16 個 Skill SOP 文件，依 `input_type` × `agent` 路由：

| input_type | Scout | Analyst | Critic | Advisor |
|-----------|-------|---------|--------|---------|
| **pkg** | `threat_intel.md` | `chain_analysis.md` | `debate_sop.md` | `action_report.md` |
| **code** | `source_code_audit.md` | `code_chain_analysis.md` | `code_debate_sop.md` | `code_action_report.md` |
| **injection** | `ai_security_audit.md` | `ai_chain_analysis.md` | `ai_debate_sop.md` | `ai_action_report.md` |
| **config** | `config_audit.md` | `config_chain_analysis.md` | `config_debate_sop.md` | `config_action_report.md` |

**特殊規則**：
- `injection` 路徑：Critic 禁止呼叫 CISA KEV（AI 威脅不在 KEV 索引）
- `config` 路徑：跳過 Analyst + Critic（加速路徑 C）
- 任何 Skill 檔案遺失 → `_load_skill()` 返回內嵌 fallback SOP

---

## 八、Harness Engineering 架構

```
harness/
├── context/     第1層：專案上下文（不可引用其他層）
├── constraints/ 第2層：邊界規則 + arch_linter（只可引用 context）
└── entropy/     第3層：熵掃描 + UNTIL CLEAN（可引用所有層）
```

**驗證指令**：
```bash
uv run python -m harness.constraints.arch_linter   # 架構邊界
uv run python -m harness.entropy.entropy_scanner   # 熵防掃描
uv run python -m harness.entropy.until_clean_loop  # UNTIL CLEAN
```

---

## 九、測試覆蓋

| 測試檔 | 測試數 | 覆蓋範圍 |
|--------|--------|---------|
| `test_docker_sandbox.py` | **41** | Phase 3 全覆蓋（mock，不需 Docker）|
| `test_sandbox.py` | ~30 | Phase 1 AST Guard + Memory Sanitizer |
| `test_path_aware_skills.py` | **63** | 16 路由正確性 + Skill 存在 + Agent 簽名 |
| `test_pipeline_integration.py` | ~25 | 端到端 Pipeline 整合 |
| `test_memory_tool.py` | **16** | 記憶讀寫 + 毒素過濾 |
| `test_checkpoint.py` | **14** | JSONL 事件記錄 |
| `test_input_sanitizer.py` | ~20 | L0 輸入淨化 |
| `test_nvd_tool.py` | ~20 | NVD API + 快取 |
| `test_security_guard.py` | ~15 | 靜態分析 |
| `test_harness.py` | ~10 | 架構邊界 |
| `test_redteam.py` | ~15 | 對抗測試（Prompt Injection / JSON Bomb）|
| *(其他 21 個)* | ... | tool / agent / stress 測試 |

---

## 十、環境設定

### 必要環境變數（`.env`）

```bash
# LLM
GEMINI_API_KEY=...

# 情報來源 API（可選，降級路徑自動啟用）
NVD_API_KEY=...       # NVD APIv2（無 key 仍可用，但限速）
OTX_API_KEY=...       # AlienVault OTX

# Sandbox（Phase 3）
SANDBOX_ENABLED=false  # true = Docker 隔離模式
SANDBOX_IMAGE=threathunter-sandbox:latest
SANDBOX_TIMEOUT=300
SANDBOX_MEMORY=512m
SANDBOX_CPUS=1.0
```

### Rust 建置（一次性）

```powershell
# 設定 MinGW toolchain（MSYS2 需已安裝）
$env:PATH = "C:\msys64\mingw64\bin;" + $env:PATH
$env:PYO3_PYTHON = ".\.venv\Scripts\python.exe"

# 一鍵建置 4 個 crate
uv run python build_rust_crates.py
```

### 啟動服務

```bash
# Streamlit UI（開發用）
uv run streamlit run ui/app.py        # 若 app.py 存在

# FastAPI + SSE 後端
uv run python ui/server.py

# 只跑 Pipeline（CLI 測試）
uv run python main.py
```

---

## 十一、已知限制與後續路徑

### 目前限制

| 項目 | 說明 |
|------|------|
| seccomp | Linux only；Docker Desktop on Windows 透過 WSL2 支援 |
| Rust wheel | `.pyd` for Windows，`.so` for Linux（CI 應用 Linux 建置）|
| NVD 速率限制 | 無 key 時 5 req/30s；有 key 時 50 req/30s |
| LlamaIndex 向量索引 | 需要 `memory/` 目錄預熱，冷啟動略慢 |

### Phase 4（Hackathon 後）

- `rust/checkpoint_writer/` — Rust `tokio::BufWriter` 替換 Python `threading.Lock`，解決高頻 SSE 事件競爭
- GitHub Actions CI/CD — 自動 `docker build` + 全套測試
- GPU Sandbox — 本地 LLM 推理的安全 GPU 掛載方案
- 動態 Skill 熱載入 — 無需重啟更新 SOP

---

## 十二、快速驗證指令

```bash
# 1. 架構邊界（必須無 violation）
uv run python -m harness.constraints.arch_linter

# 2. 全套測試
uv run python -m pytest tests/ -v

# 3. Phase 3 Docker Sandbox 測試（41 案例）
uv run python -m pytest tests/test_docker_sandbox.py -v

# 4. Rust import 驗證
uv run python -c "import threathunter_sanitizer; import threathunter_json_validator; import threathunter_memory_validator; import threathunter_url_builder; print('Rust crates OK')"

# 5. Sandbox selftest（需先 docker build）
docker build -t threathunter-sandbox:latest -f sandbox/Dockerfile .
docker run --rm --network none threathunter-sandbox:latest --selftest
```


---

*本文件由 Antigravity AI 工程夥伴生成，舊版本：2026-04-14*

---

# Phase 4 完整實作紀錄（v4.0 新增）

> Phase 4 目標：強化 ThreatHunter 的**基礎設施層**，使其達到生產部署等級。
> 四個子階段全部完成（2026-04-17）。

---

## Phase 4A：Rust Checkpoint Writer（高效持久化）

### 問題
舊版 `checkpoint.py` 使用 Python `open()` 逐行寫入，在高頻 checkpoint 場景下存在 I/O 競爭。

### 解決方案
建立 `rust/checkpoint_writer/` PyO3 crate，使用 `parking_lot::Mutex<BufWriter<File>>`：

| 函式 | 說明 |
|------|------|
| `open_writer(path, append)` | 開啟 BufWriter，建立/追加檔案 |
| `write_line(text)` | 原子性寫入一行 |
| `write_batch(lines)` | 批次寫入（一次 flush） |
| `flush_writer()` | 強制刷新緩衝區到磁碟 |
| `close_writer()` | 關閉並釋放資源 |
| `get_lines_written()` | 取得累計寫入行數 |

**Graceful Degradation**：若 `maturin develop` 尚未執行，`checkpoint.py` 自動回退到 Python `open()` 實作，完全透明。

### 測試
`tests/test_checkpoint_writer.py` — 27 個測試（含 Rust 不可用時的 fallback 驗證）。

---

## Phase 4D：Skill SOP 熱載入系統

### 問題
所有 Agent 的 `_load_skill()` 是靜態讀檔，每次修改 SOP `.md` 都需要重啟服務。

### 解決方案
`skills/skill_loader.py` — `SkillLoader` 單例，實作基於 `mtime` 的 LRU 快取：

```
load_skill(name) → str
  ├── 快取未命中  → 直接讀檔 + 更新快取
  ├── TTL 未超時 → 直接回傳快取內容（無 I/O）
  ├── mtime 未變 → 更新 last_check，跳過讀取
  ├── mtime 已變 → 重新讀檔（熱載入！）
  └── 檔案消失  → 回退至嵌入式 Fallback SOP（Graceful Degradation）
```

**執行緒安全**：所有快取操作在 `threading.Lock` 保護下執行。

**已整合的 Agent**：Scout、Analyst、Advisor、Critic、Intel Fusion、Security Guard（6 個全部遷移）。

### `/api/skills` 端點群（`ui/server.py`）

| 方法 | 路徑 | 說明 |
|------|------|------|
| GET | `/api/skills` | 列出所有 Skill 及快取狀態 |
| GET | `/api/skills/{name}` | 讀取指定 Skill `.md` 內容 |
| POST | `/api/skills/reload` | 強制重載（`{"name": "..."}` 或省略重載全部） |

### 測試
`tests/test_skill_loader.py` — **32/32 全通過** ✅

```
TestInitialization       (4)  ← 路徑配置、LRU 大小
TestBasicLoading         (7)  ← 讀檔、快取、Fallback SOP
TestCacheAndHotReload    (4)  ← TTL、mtime 變化偵測
TestReloadAPI            (6)  ← reload()、invalidate()
TestRegistryAndStats     (5)  ← registry 結構、統計欄位
TestThreadSafety         (2)  ← 並發讀取、並發重載
TestGlobalSingleton      (4)  ← OnceLock 單例模式
```

---

## Phase 4C：WASM Runtime Sandbox（L0.5 輸入邊界守衛）

### 架構設計

```
用戶輸入
   │
   ▼
╔═══════════════════════════════════════════╗
║  L0.5 WASM Runtime Sandbox (Phase 4C)    ║
║  ┌─────────────────────────────────────┐ ║
║  │  wasmtime::Engine (Host)            │ ║
║  │    ↕ Linear Memory I/O              │ ║
║  │  prompt_guard.wasm (Guest)          │ ║
║  │    防護 1: 輸入長度上限 (512KB)      │ ║
║  │    防護 2: 緩衝區邊界檢查            │ ║
║  │    防護 3: UTF-8 合法性驗證          │ ║
║  │    防護 4: 危險 Unicode 偵測         │ ║
║  │    防護 5: Prompt Injection (18模式) │ ║
║  │    防護 6: AST Bomb 前驅檢測        │ ║
║  │    防護 7: SQL/OS Code Injection     │ ║
║  └─────────────────────────────────────┘ ║
║  Graceful Degradation: Rust pure filter  ║
╚═══════════════════════════════════════════╝
   │ ALLOW  → 繼續 L0 Python 正則掃描
   │ BLOCK  → 直接拒絕，回傳錯誤訊息
   │ SANITIZE → 標記，繼續處理
   └ TRUNCATE → 截斷，繼續處理
   ▼
╔═══════════════════════════════════════════╗
║  L0 Python input_sanitizer（原有）        ║
║  Blocklist + L0 正則掃描 + 輸入類型推斷  ║
╚═══════════════════════════════════════════╝
```

### WASM 安全保證（規格層級）
- **無 OS syscall**：WASM guest 無法呼叫任何系統呼叫
- **無網路存取**：完全隔離於主機網路之外
- **記憶體隔離**：WASM linear memory 與主機進程記憶體空間完全分離
- **確定性執行**：相同輸入永遠產生相同輸出

### 介面設計

**Host（Rust `rust/prompt_sandbox/src/lib.rs`）**

| Python API | 說明 |
|-----------|------|
| `sandbox_eval(input, max_bytes)` | 評估輸入，回傳 JSON |
| `sandbox_version()` | 版本字串 |
| `sandbox_reload_wasm(path)` | 熱換 .wasm 模組 |
| `sandbox_stats()` | call_count / block_count / fallback_mode |

**Guest（Rust `rust/prompt_sandbox_guest/src/lib.rs`）**

| WASM Export | 說明 |
|-------------|------|
| `get_buffer_ptr()` | IO 緩衝區位址 |
| `eval_input(offset, len)` | 核心評估（回傳 0-3） |
| `get_result_ptr()` | JSON 結果位址 |
| `get_result_len()` | JSON 結果長度 |

### 編譯流程

```bash
# Step 1: WASM Guest（wasm32-unknown-unknown target）
cargo build --target wasm32-unknown-unknown --release \
    --manifest-path rust/prompt_sandbox_guest/Cargo.toml
cp rust/target/wasm32-unknown-unknown/release/prompt_guard.wasm \
    rust/prompt_sandbox/assets/

# Step 2: Host PyO3 crate
maturin develop --manifest-path rust/prompt_sandbox/Cargo.toml

# 一鍵執行
python build_rust_crates.py
```

### 環境變數

| 變數 | 預設 | 說明 |
|------|------|------|
| `WASM_SANDBOX_ENABLED` | `true` | `false` 跳過 L0.5，僅 Python L0 過濾 |
| `SKILL_CACHE_TTL` | `5.0` | Skill 熱載入快取 TTL（秒） |

### 測試
`tests/test_prompt_sandbox.py` — **28 個測試，四層結構** ✅

```
A. TestGracefulDegradation   (6)  ← WASM 不可用時降級行為
B. TestWasmMockFunctionality (4)  ← Mock 整合邏輯驗證
C. TestRealWasmSandbox      (15)  ← 真實 WASM 執行（@wasm_only）
D. TestEnvironmentControl    (2)  ← 環境變數控制
```

---

## Phase 4B：GitHub Actions CI/CD

### `ci.yml` — 主 CI Pipeline

```mermaid
graph TD
    A[push/PR] --> B[unit-tests<br/>Py 3.11 + 3.12]
    A --> C[lint<br/>Ruff + Bandit]
    A --> D[arch-linter<br/>架構邊界驗證]
    A --> E[rust-check<br/>cargo check + clippy]
    B --> F[ci-summary<br/>Gate]
    C --> F
    D --> F
    E --> F
```

| 作業 | 說明 | 強制通過 |
|------|------|---------|
| `unit-tests` | pytest（排除 LLM/WASM 整合測試） | ✅ |
| `lint` | Ruff lint + Bandit SAST | ⚠️ 非致命 |
| `arch-linter` | harness 邊界驗證，0 violations 才通過 | ✅ |
| `rust-check` | cargo check + clippy + fmt | ⚠️ 非致命 |
| `ci-summary` | Gate：unit-tests + arch-linter 必須 pass | ✅ |

### `docker-build.yml` — Docker CI/CD

| 作業 | 觸發條件 |
|------|---------|
| `docker-build` | push main / tag v*.*.* |
| `docker-build-rocm` | workflow_dispatch (build_rocm=true) / tag |
| `docker-security-scan` | 每次 docker-build 後（Trivy SARIF → GitHub Security） |

### `Dockerfile` — 多階段建置

```
Stage 1 (builder):
  rustup stable + wasm32-unknown-unknown target
  → cargo build prompt_guard.wasm
  → maturin build 全部 PyO3 crates
  → pip install -r requirements.txt

Stage 2 (runtime):
  python:3.12-slim
  → COPY site-packages from builder
  → 非 root 使用者（uid 1001）
  → HEALTHCHECK /api/health
  → CMD uvicorn ui.server:app
```

### `Dockerfile.rocm` — AMD ROCm 版本

```
Base: rocm/dev-ubuntu-22.04:6.3
  HSA_OVERRIDE_GFX_VERSION=9.4.0
  ROCR_VISIBLE_DEVICES=all
  usermod -a -G video,render
  可選：PyTorch ROCm 6.2 (for local LLM inference)
```

---

## Phase 4 整體驗證

### 測試覆蓋率

| 測試模組 | 測試數 | 狀態 |
|---------|--------|------|
| `test_skill_loader.py` | 32 | ✅ 32/32 全通過 |
| `test_prompt_sandbox.py` | 28 | ✅ 13 passed, 15 skipped (Real WASM 等待 cargo) |
| `test_input_sanitizer.py` | 36 | ✅ 全通過（含 wasm_verdict） |
| `test_checkpoint_writer.py` | 27 | ✅ 11 passed（Rust 部分等待 maturin） |
| 其他既有測試 | 450+ | ✅ 全通過 |

### 架構驗證
- Arch Linter：**0 violations**（CLEAN）
- 所有新增模組均符合 `harness/constraints/boundary_rules.toml` 規範
- WASM Guest 完全不引用 harness 任何模組（隔離邊界）

### 快速驗證指令

```bash
# Phase 4D 測試
uv run python -m pytest tests/test_skill_loader.py -v

# Phase 4C 測試
uv run python -m pytest tests/test_prompt_sandbox.py -v

# 架構 linter
uv run python -m harness.constraints.arch_linter

# 編譯 WASM + 全部 Rust crates（需 Rust 工具鏈）
python build_rust_crates.py

# WASM 真實測試（編譯後執行）
uv run python -m pytest tests/test_prompt_sandbox.py -v -k "TestRealWasm"

# Skill 熱載入示範
curl -X POST http://localhost:1000/api/skills/reload
curl http://localhost:1000/api/skills
```

---

*本文件由 Antigravity AI 工程夥伴生成，2026-04-17*
*版本 v4.0 — Phase 4 Final*
*遵守：project_CONSTITUTION.md + HARNESS_ENGINEERING.md + AGENTS.md*

---

## Phase 5 — CVE 精確度修復（2026-04-18）

### 問題診斷：五個破點

| # | 破點 | 根本原因 |
|---|------|---------|
| 1 | Scout NVD 搜尋策略錯誤 | 用語法關鍵字（`eval`、`html`、`script`）呼叫 NVD keywordSearch，回傳 1999 年 ColdFusion/Windows 漏洞 |
| 2 | NVD keywordSearch 全文污染 | NVD 全文搜尋忠實回傳任何包含該字的舊 CVE，不限平台 |
| 3 | Analyst 缺 CPE 相關性驗證 | `CVE-1999-0967`（Windows HTML Library）格式合法，直接通過 |
| 4 | Advisor 無平台核查 | 看到 Windows CVE 就生成 PowerShell 修補指令，目標卻是 Node.js |
| 5 | Memory REPEATED 放大錯誤 | 錯誤 CVE 被 `REPEATED — STILL NOT PATCHED` 標記後反覆強調，語氣越來越強 |

### 修復內容

#### 破點 1 & 2：`tools/nvd_tool.py` — CPE 優先搜尋
- 新增 `_query_nvd_api_cpe(cpe_name)` 函式，使用 NVD API `cpeName` 參數精確搜尋
- 新增 `PACKAGE_CPE_MAP`（35+ 常見套件 → CPE URI 對應表）
- `_search_nvd_impl` 搜尋策略改為：**Cache → CPE 精確查 → Keyword fallback**
- 新增 `_extract_cpe_vendors()` — 從 NVD configurations 提取 `vendor:product`，輸出到每個 CVE 的 `cpe_vendors` 欄位
- 每個 CVE 結果現在帶 `search_mode: "cpe" | "keyword" | "cache"` 可審計

#### 破點 3：`skills/chain_analysis.md` — Analyst CPE 相關性驗證（v3.8）
- 新增 Step 2：**CPE Relevance Filter**（在 KEV 確認之前）
- 驗證規則：`cpe_vendors` 必須與技術棧的 ecosystem vendor 吻合
- 被過濾的 CVE 記錄在 `filtered_cves[]` 供審計
- `cpe_vendors` 為空 → 保留但設 `confidence = "NEEDS_VERIFICATION"`

#### 破點 4：`skills/action_report.md` — Advisor 平台核查（v3.8）
- 新增 Step 2：**Platform Sanity Check**
- 規則：修復指令的 OS/平台必須與掃描目標一致
- Node.js 目標 → PowerShell 指令 = 不通過 → 改為 `N/A — CVE platform does not match scan target`
- 不符合的 CVE 記錄在 `platform_mismatches[]` 供審計

#### 破點 5（間接修復）
- 透過破點 3 & 4 過濾後，進入 Memory 的 CVE 都是已驗證正確的，`REPEATED` 機制只會強調真正相關的問題

#### `skills/threat_intel.md` — Scout SOP v3.8
- 新增 **Step 0：識別套件名稱**（原始碼 → import/require → 套件名）
- Quality Redline 6 & 7：明確禁止用語法關鍵字搜 NVD
- 說明 `search_nvd` Tool 已自動 CPE 優先

### 驗證結果

```bash
python -c "import py_compile; py_compile.compile('tools/nvd_tool.py', doraise=True); print('OK')"
# → nvd_tool.py OK
```

### 修改檔案清單

| 檔案 | 版本 | 變更類型 |
|------|------|---------|
| `tools/nvd_tool.py` | v3.8 | 加 CPE 搜尋 + `PACKAGE_CPE_MAP` + `_extract_cpe_vendors` |
| `skills/threat_intel.md` | v3.8 | 加 Step 0 套件識別 + Quality Redline 6-7 |
| `skills/chain_analysis.md` | v3.8 | 加 Step 2 CPE 相關性驗證 + `filtered_cves` |
| `skills/action_report.md` | v3.8 | 加 Step 2 Platform Sanity Check + `platform_mismatches` |

---

*版本 v4.1 — Phase 5 CVE 精確度修復 — 2026-04-18*
*遵守：project_CONSTITUTION.md + HARNESS_ENGINEERING.md + AGENTS.md*

---

## Phase 5.1 — 程式碼層修復（2026-04-18）

### 診斷來源
`cve_root_cause_analysis.md` — 輸入 Node.js Express XSS 程式碼，輸出 CVE-1999-0967 Windows HTML Library

### 根本原因確認
`main.py` L764-770 已有 `extracted_packages → scout_input` 路由，**但當 PackageExtractor 失敗或套件為零時**，Scout 收到原始程式碼並走 `else` 分支。該分支的 "Identify package names" 指令讓 LLM 把語法關鍵字當套件名查 NVD。

### 修復內容

#### Fix 1：`agents/scout.py` `create_scout_task()` raw code path
- `else` 分支 Step 2 由「Identify package names and call search_nvd for each one」改為明確規則
- 明確列出禁止搜尋的語法關鍵字：`eval, exec, Function, innerHTML, script, html, document, const, let, var, req, res, app`
- 提供具體例子：`require('express') → search_nvd('express')`
- 若找不到 require()/import，輸出空 vulnerabilities list

#### Fix 2：`tools/package_extractor.py` — 加 Node.js 內建模組黑名單
- 新增 `NODEJS_BUILTIN_BLACKLIST`（27 個 Node.js 20 LTS 內建模組）
- `fs`, `path`, `http`, `https`, `url`, `events`, `stream`, `util`, `crypto`, `os`, `child_process` 等
- 過濾邏輯：先 Python stdlib，再 Node.js builtin，再無效名稱
- 來源：https://nodejs.org/api/ (Node.js 20 LTS)

### 修改檔案清單（Phase 5.1）

| 檔案 | 變更類型 | 說明 |
|------|---------|------|
| `agents/scout.py` | 程式碼修改 | raw code path task_desc 加禁止關鍵字列表 |
| `tools/package_extractor.py` | 程式碼修改 | 加 `NODEJS_BUILTIN_BLACKLIST` + 過濾邏輯 |

---

*版本 v4.2 — Phase 5.1 程式碼層修復 — 2026-04-18*
*遵守：project_CONSTITUTION.md + HARNESS_ENGINEERING.md + AGENTS.md*

---

## Phase 6 — Security Guard DEGRADED 誤標 + Intel Fusion JSON + Memory 清除（2026-04-18）

### 根本原因

**P0（Security Guard 誤標 DEGRADED）**  
`checkpoint.py` L347：`if "_degraded" in output_data` — 只要 key 存在就設 degraded，**不管值是 True 還是 False**。  
`main.py` L735 明確把 `"_degraded": False` 寫入 `agent_detail`，導致 key 永遠存在，checkpoint 永遠觸發 DEGRADED 注入。  
Security Guard 的 `final_result` 本身沒有 `_degraded` 欄位，LLM 確認成功，但 stage_exit 被 agent_detail 的 key 誤判。

**P1（Intel Fusion JSON 解析錯誤）**  
`intel_fusion.py` L500：`json.loads(result_str)` 無容錯，LLM 輸出非 JSON（如 "I understand..."）直接 crash。

**P2/P3（Memory 汙染）**  
`scout_memory.json` 含 130+ 筆 CVE-1999 汙染條目，REPEATED 機制反覆放大。

### 修復內容

#### Fix 1：`checkpoint.py` L347
```diff
- if "_degraded" in output_data:
+ if output_data.get("_degraded"):
```
從「key 存在」改為「值為 True」，一行修復根本 bug。

#### Fix 2：`agents/intel_fusion.py` L500
加三層 JSON 解析容錯：
- 層 1：直接 `json.loads`
- 層 2：regex 提取 `{}` block 再 parse
- 層 3：raise `ValueError` 帶明確訊息，讓外層 except graceful degrade

#### Fix 3：Memory 清除
```bash
uv run python scripts/clean_memory_contamination.py
# → 移除 24 個汙染條目，保留 26 個正確條目
# → 備份：memory/scout_memory.json.bak
```
新增 `scripts/clean_memory_contamination.py`：備份 + 移除 CVE-1999 條目。

### 修改檔案清單（Phase 6）

| 檔案 | 變更類型 | 說明 |
|------|---------|------|
| `checkpoint.py` | 1 行修正 | `_degraded` key 存在 → 值為 True |
| `agents/intel_fusion.py` | +14 行 | JSON 三層解析容錯 |
| `scripts/clean_memory_contamination.py` | 新增 | Memory 汙染清除腳本 |
| `memory/scout_memory.json` | 資料清除 | 移除 24 筆 CVE-1999 汙染條目 |

---

*版本 v4.3 — Phase 6 修復 — 2026-04-18*
*遵守：project_CONSTITUTION.md + HARNESS_ENGINEERING.md + AGENTS.md*

---

## Phase 6.1 — CVE 年份過濾 + Memory 啟動清潔（2026-04-18）

### 學術佐證

| 主張 | 來源 | 可驗性 |
|------|------|-------|
| pre-2005 CVE 的 EPSS < 0.01 | Jacobs et al. (2023) WEIS, arxiv.org/abs/2302.14172 | ✅ |
| CVSS 需加入 Temporal Metrics | NIST CVSS v3.1 §7.3, first.org/cvss/v3.1/user-guide | ✅ |
| 2005 前目標軟體基本已退場 | NVD CPE 歷史分析（Node.js 2009, npm 2010，PHP5 2004） | ✅ 可驗 |

### 開源佐證

| 項目 | 機制 | Stars |
|------|------|-------|
| Trivy (aquasecurity) | `--ignore-unfixed` 預設過濾 15 年無修復 CVE | 23k+ |
| Grype (anchore) | `grype.yaml` suppress `CVE-1999-*` | 8k+ |
| OWASP Dependency-Check | `suppressionFile` 移除已知誤報 CVE | 6k+ |

### 修復內容

#### Fix 1：`agents/analyst.py` — Harness Layer 3.5
- 新增 `_harness_filter_ancient_cves(output)` 函式
- 對 `year < 2005` 的 CVE 設 `confidence = "NEEDS_VERIFICATION"` + `_ancient_cve_warning`
- 不刪除（保留審計軌跡）
- 呼叫點：`_harness_validate_chain_risk` 之後，`risk_score` 驗證之前

**測試驗證**：
```
CVE-1999-0967: NEEDS_VERIFICATION [FLAGGED]   ← 正確
CVE-2024-1234: HIGH               [OK]        ← 不應被動
CVE-2003-0442: NEEDS_VERIFICATION [FLAGGED]   ← 正確
CVE-2005-0001: MEDIUM             [OK]        ← 邊界值正確
```

#### Fix 2：`ui/server.py` — FastAPI Lifespan 啟動清潔
- 加 `_lifespan()` asynccontextmanager
- Server 每次啟動自動執行 `clean_memory_contamination.py`
- 移除 `memory/scout_memory.json` / `memory/advisor_memory.json` 中的遠古 CVE
- 失敗時 warning 但不影響 server 正常啟動（graceful degradation）

### 防禦深度（至此共五層）

```
層 1  PackageExtractor  Node.js builtin 黑名單過濾（確定性）
層 2  NVD Tool          CPE 優先搜尋（減少源頭誤報）
層 3  Scout task_desc   LLM 禁止詞約束（機率性）
層 4  Analyst L3.5      CVE 年份過濾（確定性 + 有審計軌跡）
層 5  Memory Lifespan   啟動時清潔汙染（定期維護）
```

### 修改檔案清單（Phase 6.1）

| 檔案 | 變更 |
|------|------|
| `agents/analyst.py` | 新增 `_harness_filter_ancient_cves()` + Layer 3.5 呼叫 |
| `ui/server.py` | 加 FastAPI `lifespan=_lifespan` 啟動清潔 |

---

*版本 v4.4 — Phase 6.1 CVE 年份過濾 + Memory 啟動清潔 — 2026-04-18*
*遵守：project_CONSTITUTION.md + HARNESS_ENGINEERING.md + AGENTS.md*

---

## Phase 7 — OSV.dev + EPSS Tool 整合（2026-04-18）

### 背景

截圖顯示系統持續回傳 CVE-2000 ~ CVE-2005 的無關漏洞。根本原因是 NVD `keywordSearch` 的架構設計問題，補丁無法根治：

- 業界工具（Trivy、Grype、Dependabot）都不用 NVD keywordSearch
- `search_nvd("eval")` → 返回 1999 年 ColdFusion 的 CVE，因為描述文字中有 "eval"
- 真正專業做法：`package + ecosystem` 精確查詢

### 新增工具

#### `tools/osv_tool.py` — OSV.dev 精確查詢
- **API**：`POST https://api.osv.dev/v1/query` + `{"package": {"name": "foo", "ecosystem": "npm"}}`
- **效果**：只返回該套件的真實漏洞，express → 5 個 CVE（無 1999 年廢棄軟體）
- **功能**：`ECOSYSTEM_MAP`（80+ 套件自動識別）+ `CANONICAL_NAME_MAP`（log4j → log4j-core）
- **快取**：24 小時本地快取（`data/osv_cache_*.json`）

#### `tools/epss_tool.py` — FIRST.org EPSS 真實分數
- **API**：`GET https://api.first.org/data/v1/epss?cve=CVE-2021-44228`
- **效果**：Log4Shell EPSS = 0.9436（94.36% 機率在 30 天內被野外利用）
- **整合**：`intel_fusion.py _verify_and_recalculate` 現在優先用真實 EPSS，不靠 LLM 猜

### 六維分析真實資料覆蓋（修復前 vs 後）

| 維度 | 之前 | 之後 |
|------|------|------|
| CVSS (20%) | NVD API ✅ | NVD API ✅ |
| **EPSS (30%)** | **LLM 猜測 ❌** | **FIRST.org API ✅** |
| KEV (25%) | CISA API ✅ | CISA API ✅ |
| GHSA (10%) | LLM 猜測 ❌ | **OSV 提供 GHSA severity ✅** |
| ATT&CK (10%) | LLM 猜測 ❌ | LLM（暫，待整合 ATT&CK API）|
| OTX (5%) | AlienVault API ✅ | AlienVault API ✅ |

### 測試結果（40/40 通過）

```
OSV Tool 匯入 + ecosystem 偵測:        7/7 PASS
EPSS Tool 匯入 + 解讀函式:              6/6 PASS
OSV.dev API 真實呼叫（express/npm）:    9/9 PASS  → 5 vulns, 無1999年CVE
EPSS API 真實呼叫（Log4Shell）:         5/5 PASS  → EPSS 0.9436
tools/__init__.py 匯出驗證:             5/5 PASS
快取機制驗證:                            3/3 PASS  → EPSS cache < 0.5s
系統健康檢查（graceful degrade）:       6/6 PASS

TOTAL: 40/40 ALL PASSED
```

### 修改檔案（Phase 7）

| 檔案 | 變更 |
|------|------|
| `tools/osv_tool.py` | [NEW] OSV.dev ecosystem-aware 漏洞查詢 |
| `tools/epss_tool.py` | [NEW] FIRST.org EPSS 真實機率查詢 |
| `tools/__init__.py` | 加入 `search_osv` + `fetch_epss_score` 匯出 |
| `agents/intel_fusion.py` | `_verify_and_recalculate` EPSS 從 API 取得 |

---

*版本 v4.5 — Phase 7 OSV+EPSS 整合 — 2026-04-18*
*遵守：project_CONSTITUTION.md + HARNESS_ENGINEERING.md + AGENTS.md*

---

## Phase 7.5 — Scout OSV優先 + ATT&CK映射 + OSV Batch（2026-04-18）

### 新增功能

#### 1. `tools/attck_tool.py` — CWE→CAPEC→ATT&CK 確定性映射
- 涵蓋 25+ 最常見 CWE（XSS→T1059.007、SQLi→T1190、Log4Shell→T1059 等）
- 來源：MITRE CTID Mappings Explorer + CAPEC 3.9 官方對應
- 路徑：CWE ID 或描述關鍵字 → CAPEC → ATT&CK Technique + Tactic
- 用於：Intel Fusion `_verify_and_recalculate` 補全 ATT&CK 10% 維度

#### 2. `tools/osv_tool.py` — OSV Batch API
- `search_osv_batch(["express", "lodash"])` 單次 API 呼叫查詢多套件
- 快取優先：先命中快取的不重複呼叫 API
- Fallback：Batch 失敗時自動降回逐一查詢

#### 3. `agents/scout.py` — OSV 優先 + EPSS 步驟
- 工具清單更新：`search_osv`（主力）+ `fetch_epss_score` 加入
- Task description 改為 search_osv 優先，NVD 作 fallback
- 新增 Step 3：高 CVSS CVE 自動查詢 EPSS 真實機率

### 六維分析資料覆蓋（最終狀態）

| 維度 | 權重 | 資料來源 | 類型 |
|------|------|---------|------|
| CVSS | 20% | NVD API | API ✅ |
| EPSS | 30% | FIRST.org API | API ✅ |
| KEV | 25% | CISA API | API ✅ |
| GHSA | 10% | OSV.dev API | API ✅ |
| ATT&CK | 10% | CWE→CAPEC→ATT&CK 靜態映射 | 確定性 ✅ |
| OTX | 5% | AlienVault API | API ✅ |

**六維全部資料驅動，0% LLM 猜測。**

### 測試結果（50/50）

```
ATT&CK CWE Mapping Tool:          10/10 PASS
OSV Batch API:                      7/7  PASS
Scout Agent Tool Registration:      7/7  PASS
Intel Fusion ATT&CK Integration:    5/5  PASS
tools/__init__.py Full Export:     14/14 PASS
Six-Dimension Coverage:             6/6  PASS  → 6/6 = 100% API-driven

TOTAL: 50/50 ALL TESTS PASSED
```

### 修改檔案（Phase 7.5）

| 檔案 | 變更 |
|------|------|
| `tools/attck_tool.py` | [NEW] CWE→CAPEC→ATT&CK 靜態映射，25+ CWE |
| `tools/osv_tool.py` | 加入 `search_osv_batch()` Batch API |
| `tools/__init__.py` | 加入所有新工具匯出 |
| `agents/scout.py` | OSV 優先 / NVD fallback / EPSS 步驟 |
| `agents/intel_fusion.py` | ATT&CK 從 CWE→ATT&CK 確定性映射取代 LLM |

---

*版本 v5.0 — Phase 7.5 六維全資料驅動完成 — 2026-04-18*
*遵守：project_CONSTITUTION.md + HARNESS_ENGINEERING.md + AGENTS.md*

---

## Phase 7.5 最終驗證記錄（2026-04-19）

### 本次新增功能

#### 1. OSV Batch 整合到 Harness 層（Code-level Prefetch）

**問題**：Scout Agent 是一個一個套件呼叫 `search_osv()`，延遲 = N × API RTT。

**解法**：在 `run_scout_pipeline()` 的 **Harness 0** 層，LLM 啟動前就執行 OSV Batch 預熱：

```python
# Harness 0：OSV Batch 預熱（LLM 之前）
_osv_batch_cache = search_osv_batch(_pkg_list)  # 1次 API請求，結果全存快取
```

- 當 Agent 呼叫 `search_osv("express")` → 直接命中快取（`[OK] OSV cache hit: npm_express`）
- 延遲優化：N × 300ms → 1 × 300ms（express + 其他套件同時批量）

#### 2. GHSA Severity 從 OSV database_specific 解析

**問題**：GHSA 維度之前由 LLM 猜測，不可靠。

**解法**：OSV API 回傳的 `database_specific.severity` 直接是 GitHub Advisory 官方等級：

```python
# tools/osv_tool.py _parse_osv_vuln()
ghsa_severity = db_spec.get("severity", "").upper()  # → "HIGH", "MODERATE", "LOW"
```

Intel Fusion `_verify_and_recalculate()` 的 GHSA 維度優先使用此值：
- 優先級：`fusion["ghsa_severity"]`（OSV解析）→ `dims["ghsa_severity"]`（LLM）→ `"UNKNOWN"`

#### 3. Harness 2.5 改用 OSV Batch 快取資料

**問題**：LLM 輸出 0 CVE 時，舊 fallback 從 NVD cache 注入，NVD 可能包含 CVE-1999 廢棄資料。

**解法**：Harness 2.5 優先從 `_osv_batch_cache` 注入（更精確），NVD 只作二次 fallback：

```
OSV Batch cache（精確） → NVD cache（寬鬆 fallback） → 不注入
```

### 實測驗證 — XSS Express 範例掃描

**輸入**：Express.js XSS 程式碼（`res.send('<h1>Results for: ' + query + '</h1>')`）

**Log 確認**：
```
[HARNESS 0] OSV Batch warmup: ['express']
[OK] OSV cache hit: npm_express       ← Scout 呼叫 search_osv 命中快取
Tool: search_osv                      ← Scout Agent 使用 search_osv（非 search_nvd）
Tool: fetch_epss_score                ← FIRST.org EPSS API 真實查詢
```

**掃描結果**（scan_id: 5c9cfda4）：

| CVE | 描述 | 來源 |
|-----|------|------|
| CVE-2024-10491 | Express resource injection | OSV (GHSA-cm5g-3pgc-8rg4) |
| CVE-2024-43796 | **XSS via response.redirect()** | OSV (GHSA-qw6h-vgh9-j6wx) |
| CVE-2024-29041 | Open Redirect in malformed URLs (XSS chain) | OSV (GHSA-rv95-896h-c2vc) |
| CVE-2024-9266 | Open Redirect vulnerability | OSV (GHSA-jj78-5fmv-mv28) |
| CVE-2014-6393 | No Charset in Content-Type Header | OSV (GHSA-gpvr-g6gh-9mc2) |

✅ **0 個 CVE-1999 廢棄漏洞**（OSV ecosystem-aware 精確過濾）
✅ **5/5 CVE 全為 express 相關漏洞**（無誤報）
✅ **pipeline_meta.scout.vuln_count = 5**

### 修改文件清單

| 檔案 | 異動 |
|------|------|
| `tools/osv_tool.py` | `_parse_osv_vuln()` 加入 `ghsa_severity` 欄位 |
| `agents/scout.py` | Harness 0 OSV Batch 預熱 + `_extract_ghsa_severity_from_osv()` + Harness 2.5 改用 OSV cache |
| `agents/intel_fusion.py` | GHSA 維度優先使用 OSV 解析的 `ghsa_severity` |
| `docs/architecture_diagrams.html` | 更新為 v5.0，加入 OSV/EPSS/ATT\&CK 工具卡、六維覆蓋列 |
| `docs/first_principles_analysis.html` | 更新為 v5.0，加入 §1.3 六維覆蓋比較表、OSV-first SOP 流程圖 |

---

*版本 v5.0 — Phase 7.5 完整驗證 — 2026-04-19*
*遵守：project_CONSTITUTION.md + HARNESS_ENGINEERING.md + AGENTS.md*

---

## Phase 7.15 — Go Pipeline Hardening + Null Safety 全修 + UI 程式碼片段比較（2026-04-20）

### 背景

測試 Go Command Injection、Java SQL Injection / Deserialization、Python eval/hardcoded secret 時發現三類問題：

1. **Go 標準庫被當成第三方套件查 NVD**：`fmt`、`net/http`、`os/exec` 通過 `package_extractor.py` 過濾器 → 查到 OpenSSL、ncurses、VLC 等完全無關的 CVE
2. **Analyst / Advisor 持續 DEGRADED**：LLM 回傳 `cve_id: null`（合法——CODE-pattern 沒有 CVE），但 Harness 驗證層用 `re.match(pattern, None)` / `None.startswith()` 崩潰
3. **UI 顯示 "UNKNOWN"**：Advisor 正確產出 `vulnerable_snippet` + `fixed_snippet`，但前端沒有渲染此資料、`cve_id=null` 顯示為 "UNKNOWN"

---

### 根本原因分析

| # | 問題 | 檔案:行 | 根因 |
|---|------|---------|------|
| 1 | Go stdlib 當第三方套件 | `package_extractor.py` | 只有 Python/Node.js 黑名單，無 Go 黑名單 |
| 2 | Intel Fusion `re` 未定義 | `intel_fusion.py:514` | 使用 `re.search()` 但缺少 `import re` |
| 3 | Analyst 崩潰 (DEGRADED) | `analyst.py:716` | `item.get("cve_id", "")` 回傳 `None` → `re.match(pattern, None)` 拋 TypeError |
| 4 | Advisor 崩潰 (DEGRADED) | `advisor.py:498` | 同上 → `None.startswith("CVE-")` 拋 AttributeError |
| 5 | Analyst 降級丟棄 code_patterns | `main.py:240-276` | 降級 fallback 只處理 CVE，忽略 Security Guard 的確定性偵測 |
| 6 | Advisor 降級回空 actions | `main.py:384-394` | 降級 fallback 回傳 `{"urgent": [], "important": []}` |
| 7 | UI 顯示 UNKNOWN | `app.js:583` | `cve_id || 'UNKNOWN'`，CODE-pattern 無 CVE ID |

> **Null Safety 系統性問題**：Python `dict.get("key", "")` 當 key 存在但值為 `None` 時，回傳 `None` 而非預設值 `""`。這是所有 5 個 Null crash 的共同根因。

---

### 修復內容

#### Fix 1：Go 標準庫黑名單（`tools/package_extractor.py`）

新增 `GO_STDLIB_BLACKLIST`（47 個模組）：

```python
GO_STDLIB_BLACKLIST = {
    "fmt", "os", "io", "net", "log", "math", "sync", "time",
    "sort", "flag", "path", "hash", "mime", "errors", "bytes",
    "bufio", "context", "embed", "image", "regexp", "strconv",
    "strings", "unicode", "testing", "runtime", "reflect",
    "unsafe", "syscall", "archive", "compress", "container",
    "crypto", "debug", "encoding", "go", "html", "index",
    "internal", "plugin", "text",
    # 複合路徑
    "net/http", "os/exec", "io/ioutil", "path/filepath",
    "encoding/json", "encoding/xml", "crypto/tls",
    "database/sql", "html/template", "text/template",
}
```

整合到 `extract_third_party_packages()` 的過濾邏輯，Go 程式碼的 `fmt`、`net`、`os` 全部被過濾，不再傳給 NVD。

---

#### Fix 2：Intel Fusion 缺少 `import re`（`agents/intel_fusion.py`）

```diff
 import json
 import logging
+import re
 import time
```

修復 L514 `re.search(r'\{[\s\S]*\}', result_str)` 的 `NameError: name 're' is not defined`。

---

#### Fix 3：Null Safety 全修（4 個檔案 5 處）

**模式**：`item.get("cve_id", "")` → `item.get("cve_id") or ""`

| 檔案 | 行 | 修復前 | 修復後 |
|------|-----|--------|--------|
| `analyst.py` | L715 | `item.get("cve_id", "")` | `item.get("cve_id") or ""` |
| `analyst.py` | L957 | `item.get("cve_id", "")` | `item.get("cve_id") or ""` |
| `advisor.py` | L351 | `item.get("cve_id", "")` | `item.get("cve_id") or ""` |
| `advisor.py` | L497 | `item.get("cve_id", "")` | `item.get("cve_id") or ""` |
| `advisor.py` | L498 | 無 null guard | `if not cve_id or ...` |

**技術原因**：Python `dict.get(key, default)` 只有在 key **不存在**時才回傳 default。當 LLM 回傳 `{"cve_id": null}` 時，key 存在、值為 `None`，`get()` 回傳 `None`，而 `or ""` 會正確兜底。

---

#### Fix 4：Analyst 降級 Fallback 保留 code_patterns（`main.py:240-276`）

**修復前**：Analyst 降級只處理 `scout_output.vulnerabilities`（CVE），Security Guard 的 `code_patterns`（CMD_INJECTION / EVAL_EXEC / SQL_INJECTION 等）全部遺失。

**修復後**：遍歷 `scout_output.code_patterns`，為每個 pattern 生成帶 CWE / severity / snippet 的 analysis entry：

```python
_PATTERN_CWE = {
    "CMD_INJECTION": ("CWE-78", "CRITICAL"),
    "SQL_INJECTION": ("CWE-89", "CRITICAL"),
    "EVAL_EXEC":     ("CWE-95", "CRITICAL"),
    "UNSAFE_DESER":  ("CWE-502", "CRITICAL"),
    "HARDCODED_SECRET": ("CWE-798", "HIGH"),
    # ...更多
}
```

---

#### Fix 5：Advisor 降級 Fallback 從 analyst_output 生成 actions（`main.py:384-460`）

**修復前**：Advisor 降級回傳 `{"urgent": [], "important": []}`——用戶什麼都看不到。

**修復後**：遍歷 `advisor_input.analysis`，提取 CODE-patterns 和 CVE findings，分配到 urgent/important buckets：

```python
_SEVERITY_MAP = {"CRITICAL": "urgent", "HIGH": "important"}
for entry in advisor_input.get("analysis", []):
    if finding_id.startswith("CODE-") or entry.get("pattern_type"):
        # 生成 CWE-based action entry
    elif cve_id:
        # 生成 CVE-based action entry
```

---

#### Fix 6：UI 支援 CWE Badge + 程式碼片段比較（`app.js` + `style.css`）

**app.js `renderActionList()`**：
- CODE-pattern 用 **CWE-XX**（紫色 badge）而非 "UNKNOWN"
- 新增 `vulnerable_snippet` + `fixed_snippet` **對比顯示面板**
- 新增 `why_this_works` 說明欄

**style.css 新增**：
- `.action-cwe` — 紫色 CWE badge（與藍色 CVE badge 區分）
- `.snippet-compare` — 程式碼對比容器
- `.snippet-vuln` — 紅色標題 ❌ Vulnerable
- `.snippet-fix` — 綠色標題 ✅ Fixed
- `.snippet-code` — monospace 程式碼區塊
- `.snippet-why` — teal 色 Why 說明

---

### 防禦深度更新（至此共十層）

```
層 1  PackageExtractor   Python/Node.js/Go 內建模組黑名單過濾（確定性）
層 2  NVD Tool           CPE 優先搜尋（減少源頭誤報）
層 3  Scout task_desc    LLM 禁止詞約束（機率性）
層 4  Analyst L3.5       CVE 年份過濾（確定性 + 審計軌跡）
層 5  Memory Lifespan    啟動時清潔汙染（定期維護）
層 6  Analyst Fallback   降級時保留 code_patterns（確定性偵測永不丟失）
層 7  Advisor Fallback   降級時從 analysis 生成 actions（保底輸出）
層 8  Harness L4.5       憲法 CI-1/CI-2 守衛：CODE-pattern 不進 URGENT/IMPORTANT  ← NEW v5.3
層 9  Intel Fusion L3    超長輸出保護（>50k chars 自動從尾部提取 JSON）           ← NEW v5.3
層 10 Advisor Layer 5    REPEATED 機制修正：CODE-pattern 永遠 is_repeated=false    ← NEW v5.2
```

---

### 修改檔案清單（Phase 7.15）

| 檔案 | 變更類型 | 說明 |
|------|---------|------|
| `tools/package_extractor.py` | +47 個 Go 黑名單 | Go stdlib 模組過濾，防止 `fmt`/`net` 查 NVD |
| `agents/intel_fusion.py` | +1 行 | 加 `import re`，修復 `NameError` |
| `agents/analyst.py` | 2 行修正 | Null safety：`cve_id` 從 `.get(k, "")` 改為 `.get(k) or ""` |
| `agents/advisor.py` | 3 行修正 | 同上 + `startswith` null guard |
| `main.py` | +36 行（L240-276） | Analyst 降級 fallback 保留 code_patterns |
| `main.py` | +67 行（L384-460） | Advisor 降級 fallback 從 analysis 生成 actions |
| `ui/static/app.js` | 重寫 `renderActionList()` | CWE badge + snippet 對比 + why_this_works |
| `ui/static/style.css` | +13 行 | `.action-cwe` / `.snippet-*` 系列樣式 |

---

### Phase 7.16 修復紀錄（2026-04-20）

#### 問題 1：CODE-001 被誤標 REPEATED + 捏造 eval() 輸出

| 根因 | 修復 |
|------|------|
| `_harness_check_repeated` 把 `cve_id=null` 空字串加進 `prev_vulns set`，導致所有 CODE-pattern 都命中 | `advisor.py`：CODE-pattern（`cve_id` 非 `CVE-`/`GHSA-` 開頭）絕對不進 `prev_vulns` |
| LLM 讀到 `read_memory` 前次 CODE-001 歷史 → 自行加 `is_repeated=true` | Task prompt 加入 ANTI-FABRICATION RULES：CODE-pattern `is_repeated` 永遠 false |
| `code_action_report.md` 包含 `eval()` 範例 → LLM 直接套用 | SOP 重寫：移除所有具體程式碼範例，改為抽象規則 + 嵌入 ANTI-FABRICATION |

#### 問題 2：PHP SQL Injection 漏報

| 根因 | 修復 |
|------|------|
| Universal `SQL_INJECTION` regex 只匹配 `+` 拼接，PHP 使用 `.` 拼接 | `security_guard.py`：新增 `SQL_CONCAT_PHP` pattern 兩段匹配 `"..." . $var . "..."` |

---

### Phase 7.17 修復紀錄（2026-04-20）

#### 問題 1：Intel Fusion LLM 輸出 139,613 chars 非 JSON

**影響**：Scout Agent 遭 Graceful Degradation

| 根因 | 修復 |
|------|------|
| CrewAI forceRun 觸發後 LLM 輸出大量解說文字夾著 JSON | `intel_fusion.py`：50,000 chars 閾值保護，超長時從末尾 10k chars 提取 JSON |
| `re.search(r'\{[\s\S]*\}')` 貪婪匹配對 13 萬字耗盡記憶體 | 改用 `re.findall(r'\{[\s\S]+?\}')` 非貪婪 + `reversed()` 從最後一個候選嘗試 |

#### 問題 2：CODE-001/002/003 出現在 URGENT — 憲法 CI-1/CI-2 違規

**憲法條文**：`規則 CI-1：所有 CVE 編號必須來自 Tool 回傳的真實 API 資料` / `規則 CI-2：禁止 LLM 自行編造任何 CVE 編號或漏洞細節`

| 位置 | 修復 |
|------|------|
| Advisor Harness 都沒有機制阻止 LLM 把 CODE-pattern 放進 URGENT | 新增 **Harness Layer 4.5 `_harness_constitution_guard()`**：`cve_id=null` 或 `finding_id=CODE-xxx` 的項目強制移出，轉存至 `code_patterns_summary` |
| `main.py` Advisor 降級 fallback 把 CODE-001 直接進入 `urgent_actions` | CODE-pattern 改存 `code_patterns_fallback`，只有真實 `CVE-`/`GHSA-` ID 才進入 urgent/important |
| Layer 4 對 CODE-pattern 補 `pip install --upgrade` | 改為 `Manual code fix required (see fixed_snippet)` |

---

### 修改檔案清單（Phase 7.16~7.17）

| 檔案 | 變更類型 | 說明 |
|------|---------|------|
| `agents/security_guard.py` | +SQL_CONCAT_PHP | PHP `.` 拼接式 SQL Injection 偵測 |
| `agents/advisor.py` | Harness Layer 4 修正 | CODE-pattern command 改為 `Manual code fix` |
| `agents/advisor.py` | +Harness Layer 4.5 | `_harness_constitution_guard()` 憲法 CI-1/CI-2 |
| `agents/advisor.py` | Harness Layer 5 修正 | REPEATED 機制只套用真實 CVE-/GHSA- |
| `agents/advisor.py` | Task prompt v5.1 | ANTI-FABRICATION RULES 嵌入 + CODE is_repeated=false |
| `agents/intel_fusion.py` | JSON 解析共 3 層 | 50k chars 閾值保護 + 非貪婪 findall |
| `main.py` | Advisor fallback v5.1 | CODE-pattern 不進 URGENT，移至 code_patterns_fallback |
| `skills/code_action_report.md` | SOP v5.1 重寫 | ANTI-FABRICATION RULES，移除易誤導 LLM 的範例 |
| `tests/test_sg_to_advisor_flow.py` | 測試更新 | `TestCodeActionReportSkill` 為新 SOP v5.1 對法，新增 2 個防捏造區塊 |

---

### 測試驗證

```
uv run pytest tests/test_sg_to_advisor_flow.py tests/test_security_guard.py \
            tests/test_attack_multidim.py tests/test_input_sanitizer.py \
            tests/test_advisor_agent.py -v
# → 180/180 ALL PASSED ✅

# Constitution Guard 單元驗證：
# URGENT 後：1 項（CVE-2023-44981 ✅）
# IMPORTANT 後：1 項（CVE-2024-1234 ✅）
# code_patterns_summary：3 項（CODE-001/002/003 完全隔離出 URGENT ✅）
```

---

*版本 v5.3 — Phase 7.17 Constitution Guard + Intel Fusion Hardening — 2026-04-20*
*遵守：project_CONSTITUTION.md + HARNESS_ENGINEERING.md + AGENTS.md*
