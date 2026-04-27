# ThreatHunter — Path A / C 協作指引
# 版本 v1.0 | 適用對象：成員 B（Path A）、成員 C（Path C）

> **閱讀須知**：本文件說明 Path A（套件掃描）和 Path C（設定檔掃描）的
> 業務邏輯、SOP 文件位置、可修改範圍與禁止修改的紅線。
> 請在開始任何修改前完整閱讀。

---

## 1. 快速定向地圖

```
使用者輸入
    │
    ├─ 套件清單（Django 4.2, Redis 7.0...）──────→ Path A  ← 成員 B 負責
    ├─ 原始碼（PHP/Python/JS...）────────────────→ Path B  ← 組長負責
    ├─ 設定檔（Dockerfile, nginx.conf...）────────→ Path C  ← 成員 C 負責
    └─ Judge 補充驗證（自動觸發）────────────────→ Path D  ← 勿動
```

### Path A 完整執行流程

```
IntelFusion（NVD + OSV + GHSA + OTX + EPSS 並行富化）
    ↓ fusion_results（已評分的 CVE 清單）
Scout（以套件名稱為單位，查 OSV / NVD，並重用 Intel Fusion 富化結果）
    ↓ vulnerabilities[]
Analyst（攻擊鏈分析 + KEV/Exploit 確認）
    ↓ attack_chains[]
Critic / Debate Engine（3 輪辯論 + Judge 仲裁）
    ↓ verified_risks[]
Advisor（最終行動報告）
    ↓ urgent[] / important[]  →  前端 UI 顯示
```

### Path C 完整執行流程

```
Scout（以 config_audit.md SOP 掃描設定檔）
    ↓ misconfigurations[] + hardcoded_secrets[]
Analyst（設定錯誤攻擊鏈分析）
    ↓ config_attack_chains[]
Critic / Debate Engine
    ↓ verified_config_risks[]
Advisor（最終行動報告 config_action_report.md）
    ↓ urgent[] / important[]  →  前端 UI 顯示
```

> **注意**：Path C **不啟動** Security Guard 和 IntelFusion 的 Layer 1 並行，
> 因為設定檔不是程式碼，不需要 AST 分析和套件 CVE 查詢。

---

## 2. SOP 文件位置（你們的主戰場）

### Path A — `skills/` 目錄下的 4 個文件

| Agent | SOP 文件 | 用途 |
|-------|----------|------|
| Scout | `skills/threat_intel.md` | 套件 CVE 查詢流程 (v3.8) |
| Analyst | `skills/chain_analysis.md` | 套件漏洞攻擊鏈分析 |
| Critic | `skills/debate_sop.md` | 辯論/紅隊驗證 SOP |
| Advisor | `skills/action_report.md` | 最終行動報告格式 |

### Path C — `skills/` 目錄下的 4 個文件

| Agent | SOP 文件 | 用途 |
|-------|----------|------|
| Scout | `skills/config_audit.md` | 設定檔稽核（Docker/K8s/.env/nginx）|
| Analyst | `skills/config_chain_analysis.md` | 設定錯誤攻擊鏈分析 |
| Critic | `skills/config_debate_sop.md` | 設定風險辯論 SOP |
| Advisor | `skills/config_action_report.md` | 設定修復行動報告 |

> **重要**：SOP 文件用 **熱載入** 方式注入 Agent Prompt，
> 修改 `.md` 後**無需重啟 Server**，重新掃描即生效（TTL = 5 秒）。

---

## 3. 各 SOP 文件的業務邏輯說明

### `skills/threat_intel.md`（Scout · Path A）

**核心規則（請牢記）：**

1. **只用套件名稱查 OSV / NVD**
   - ✅ `search_osv("express")`、`search_nvd("express")`
   - ❌ `search_nvd("eval")` / `search_nvd("innerHTML")` — 這是 JS 語法，不是套件！

2. **Scout 先查 OSV，無結果再 fallback 到 NVD**

3. **若 Layer 1 已有 Intel Fusion 結果，Scout 必須重用 EPSS / OTX / KEV / GHSA 證據，不可重複 enrich**

4. **不可捏造 CVE ID**（Quality Redlines 第 1 條）

5. **write_memory 必須在 Final Answer 前呼叫**（否則記憶系統不更新）

**Output JSON 結構必須包含：**
```json
{
  "scan_id": "...",
  "vulnerabilities": [...],
  "summary": { "total": 0, "critical": 0, "high": 0, ... },
  "scan_path": "A"
}
```

---

### `skills/chain_analysis.md`（Analyst · Path A）

**CPE 相關性過濾（v3.8 新增，最容易出 Bug 的地方）：**

每個 CVE 都要檢查 `cpe_vendors` 是否符合技術棧：

```
tech_stack = Node.js/Express:
  KEEP:    cpe_vendors 含 "expressjs", "nodejs"
  DISCARD: cpe_vendors 含 "microsoft", "adobe"（平台不符）
```

KEV 中的 CVE **不可**被 Critic 降級 → `"in_cisa_kev": true` 的 risk 必須保為 CRITICAL

**常見 Bug：** Analyst 把 Python 的 CVE 給 Node.js 技術棧，造成誤報。  
**修法：** 在 SOP Step 2 加強 `cpe_vendors` 過濾條件敘述。

---

### `skills/config_audit.md`（Scout · Path C）

**支援的設定檔類型：**
- Docker / docker-compose.yml
- Kubernetes YAML
- `.env` 檔案（Django/Flask/通用）
- `nginx.conf`
- `.github/workflows/*.yml`（CI/CD 供應鏈）
- AWS/GCP/Azure IAM JSON

**Step 3（Hardcoded Secrets 掃描）是純 LLM Reasoning，不呼叫工具：**
```
Pattern match for:
- password=, passwd=, secret=, api_key=, token=
- Base64 字串
- AWS AKIA* key
- JWT eyJ* 開頭
- -----BEGIN RSA PRIVATE KEY-----
```

**Quality Redlines（嚴格遵守）：**
1. CIS Control ID 只用文件內的表格裡的 — **不可捏造**
2. 輸出不可包含真實 secret 值，只記錄欄位名
3. 輸出 MUST 是純 JSON

---

### `skills/config_chain_analysis.md`（Analyst · Path C）

**5 大預定義攻擊鏈（新增攻擊鏈要加在這裡）：**

| 鏈 | 起點 | 終點 | 嚴重度 |
|----|------|------|--------|
| Chain 1 | `privileged: true` | Docker 逃逸 → 完整 host | CRITICAL |
| Chain 2 | Hardcoded API Key | Git 洩漏 → 橫向移動 | CRITICAL |
| Chain 3 | `DEBUG=True` | 資訊洩漏 → 精準攻擊 | HIGH |
| Chain 4 | Port 0.0.0.0 binding | 內網服務暴露 → 資料存取 | CRITICAL |
| Chain 5 | `image: latest` | 供應鏈攻擊 → CI 污染 | HIGH |

**注意**：Path C 不檢查 CISA KEV（設定錯誤不是 CVE）。  
只有在 Scout 發現版本化軟體有 CVE 時才呼叫 check_cisa_kev。

---

## 4. 工具對應表

### Path A 使用的工具

| 工具 | 對應檔案 | 誰在用 | 呼叫條件 |
|------|----------|--------|----------|
| `search_nvd` | `tools/nvd_tool.py` | IntelFusion + Scout | Scout fallback 查詢；Intel Fusion 視情況使用 |
| `search_otx` | `tools/otx_tool.py` | IntelFusion | Intel Fusion 視情況 enrich |
| `check_cisa_kev` | `tools/kev_tool.py` | Analyst | CRITICAL/HIGH CVE |
| `search_exploits` | `tools/exploit_tool.py` | Analyst | KEV 命中時 |
| `search_epss` | `tools/epss_tool.py` | IntelFusion（選用）| 未命中 KEV 時 |
| `search_osv` | `tools/osv_tool.py` | IntelFusion + Scout | ecosystem-aware 查詢 |
| `check_ghsa` | `tools/ghsa_tool.py` | IntelFusion（選用）| GitHub 套件 |
| `read_memory` | `tools/memory_tool.py` | 所有 Agent | Step 1 固定呼叫 |
| `write_memory` | `tools/memory_tool.py` | 所有 Agent | Final Answer 前固定呼叫 |

### Path C 使用的工具

| 工具 | 對應檔案 | 誰在用 | 呼叫條件 |
|------|----------|--------|----------|
| `search_nvd` | `tools/nvd_tool.py` | Scout | 找到版本化軟體時（選用）|
| `check_cisa_kev` | `tools/kev_tool.py` | Analyst | 有 package_cves 時 |
| `read_memory` | `tools/memory_tool.py` | 所有 Agent | Step 1 固定呼叫 |
| `write_memory` | `tools/memory_tool.py` | 所有 Agent | Final Answer 前固定呼叫 |

---

## 5. 可修改 vs 不可修改

### ✅ 可以自由修改的

| 檔案 | 修改目的 | 注意事項 |
|------|----------|----------|
| `skills/threat_intel.md` | 調整 Scout 查詢邏輯、Intel Fusion 重用規則、Output Schema | 保留 Quality Redlines |
| `skills/chain_analysis.md` | 新增攻擊鏈 Pattern、調整風險評估邏輯 | KEV 命中不可降級 |
| `skills/config_audit.md` | 新增設定檔類型支援、新增 CIS 規則 | CIS ID 不可捏造 |
| `skills/config_chain_analysis.md` | 新增攻擊鏈（Chain 6, 7...）| 格式要與現有 Chain 一致 |
| `skills/debate_sop.md` | 調整辯論輪數、Judge 仲裁標準 | 不可改 conservative arbitration 原則 |
| `skills/config_debate_sop.md` | 同上（Path C 版本）| 同上 |
| `skills/action_report.md` | 調整行動報告格式、優先度標準 | 不可移除 urgent/important 欄位 |
| `skills/config_action_report.md` | 同上（Path C 版本）| 同上 |
| `tools/nvd_tool.py` | 調整 NVD API 查詢參數、快取邏輯 | 不可改 rate limiting |
| `tools/kev_tool.py` | 調整 KEV 快取 TTL | 保留 in_cisa_kev 欄位名稱 |
| `tools/epss_tool.py` | 調整 EPSS 閾值 | 保留 epss_score 欄位名 |

---

### ❌ 禁止修改的（紅線）

> [!CAUTION]
> 以下檔案修改前**必須**與組長確認，否則可能導致整個 Pipeline 崩潰。

| 檔案 | 原因 |
|------|------|
| `main.py` | Pipeline 主程式，路由邏輯、Harness Layer 7 注入都在這裡 |
| `agents/orchestrator.py` | Path 路由決策，改錯會讓 A/C 路由失效 |
| `agents/intel_fusion.py` | IntelFusion 多維評分邏輯，改錯影響所有 CVE 評分 |
| `agents/debate_engine.py` | 3-輪辯論引擎，Judge 仲裁邏輯 |
| `core/config.py` | LLM 配置、API Key 管理、降級瀑布 |
| `core/checkpoint.py` | JSONL 事件記錄系統 |
| `core/input_sanitizer.py` | L0 輸入淨化（安全層）|
| `harness/` (全部) | Harness 架構邊界規則，改了會讓 arch_linter 失敗 |
| `sandbox/` (全部) | 多層安全沙箱 |
| `rust/` (全部) | Rust 安全層，需要重新編譯 |
| `tools/memory_tool.py` | 記憶持久化，改錯所有 Agent 失憶 |
| `agents/advisor.py` 的 `_harness_enrich_cwe_evidence` | Harness CI-1/CI-2 守衛 |

---

## 6. Debug 流程

### 當 Path A 結果不對時

**Step 1：確認路由是否正確**
```
在 Live Monitor 看 scan_path 是否為 "A"
如果顯示 "B"：輸入被判斷為原始碼 → 確認輸入格式（只用套件名稱列表）
```

**Step 2：確認 IntelFusion 沒有 degraded**
```
Pipeline Meta > Intel Fusion > Status
如果 DEGRADED：看 _error 欄位
常見原因：NVD API 超時 → 查 data/nvd_cache_*.json 是否有快取
```

**Step 3：確認 Scout 套件提取是否正確**
```python
# 在 main.py L990-L1040 附近加 log：
logger.info("[DEBUG] scout_input: %s", scout_input[:500])
```

**Step 4：確認 Analyst CPE 過濾**
```
如果 URGENT 裡出現跟技術棧不符的 CVE：
→ 修改 skills/chain_analysis.md Step 2 的過濾規則
```

---

### 當 Path C 結果不對時

**Step 1：確認路由是否為 "C"**
```
Checkpoint Viewer 查 orchestrator stage 的 scan_path
如果不是 C：輸入需要更明確的設定檔特徵（FROM / services: / server { 等）
```

**Step 2：Scout 沒有找到 misconfigurations**
```
可能原因：
a) 設定檔格式不被識別 → 在 skills/config_audit.md 新增該格式的識別規則
b) LLM 未執行 Hardcoded Secret Scan → 強化 Step 3 的指令描述
```

**Step 3：Output JSON 格式錯誤**
```
常見錯誤：Scout 回傳了 markdown prose 而非純 JSON
修法：在 skills/config_audit.md 的 Quality Redlines 加強 "output MUST be pure JSON" 敘述
```

---

## 7. 快速啟動 Debug 環境

```bash
# 1. 確認在 yun193 分支
git branch  # 應顯示 * yun193

# 2. 啟動 Server（會自動 load .env）
uv run python ui/server.py

# 3. 測試 Path A（在 UI 貼入）
Django 4.2, Redis 7.0, PostgreSQL 16, Nginx 1.24

# 4. 測試 Path C（在 UI 貼入）
# docker-compose.yml 範例
version: '3'
services:
  app:
    image: myapp:latest
    privileged: true
    environment:
      - DB_PASSWORD=mysecretpassword123
    ports:
      - "0.0.0.0:5432:5432"

# 5. 查看 API 直接回傳
curl -X POST http://localhost:1000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"tech_stack": "Django 4.2, Redis 7.0"}'
```

---

## 8. 常見錯誤 & 修法速查

| 錯誤現象 | 可能原因 | 修改位置 |
|----------|----------|----------|
| Path A 結果沒有 CVE，但套件有漏洞 | Scout 用語法字詞查 NVD | `skills/threat_intel.md` Step 0 |
| Path A CPE 不符的 CVE 出現在報告 | Analyst CPE 過濾邏輯不夠嚴 | `skills/chain_analysis.md` Step 2 |
| Path A Intel Fusion DEGRADED | NVD API Timeout，查快取 | `tools/nvd_tool.py` 快取設定 |
| Path C 沒辨識到 Docker-compose | Orchestrator 分類失敗 | `skills/orchestrator.md` Path C 特徵 |
| Path C Scout 回傳 Markdown 不是 JSON | LLM 格式指令不夠強 | `skills/config_audit.md` Quality Redlines |
| KEV 命中的 CVE 被降為 HIGH | Critic 違反 KEV 不降規則 | `skills/debate_sop.md` KEV 規則 |
| write_memory 沒有呼叫 | Agent 漏掉 Step 5 | 對應的 SOP Step 5 加強強調 |
| URGENT 為空但有漏洞 | Advisor 分類邏輯問題 | `skills/action_report.md` 優先度規則 |

---

## 9. 架構邊界驗證（必須通過後才能 PR）

```bash
# 架構邊界檢查（改了 harness 相關一定要跑）
uv run python harness/constraints/arch_linter.py

# 熵防掃描
uv run python harness/entropy/entropy_scanner.py

# 快速語法測試
uv run python -m pytest tests/test_security_guard.py tests/test_redteam.py -v --timeout=30

# 如果有改 tools/：
uv run python -m pytest tests/test_nvd_tool.py tests/test_epss_tool.py -v --timeout=60
```

**提交到 yun193 前確認：**
- [ ] `arch_linter.py` 通過
- [ ] 相關 test 通過
- [ ] `.env` 沒有被 `git add`（`git status` 確認）
- [ ] 沒有 hardcoded API Key 在程式碼中

---

## 10. 聯絡分工

| 角色 | 負責 | 遇到問題先看 |
|------|------|------------|
| 組長 | Path B（原始碼）、main.py Pipeline、UI | `agents/security_guard.py`, `ui/static/app.js` |
| **成員 B** | **Path A（套件 CVE 掃描）** | `skills/threat_intel.md`, `skills/chain_analysis.md`, `tools/nvd_tool.py` |
| **成員 C** | **Path C（設定檔稽核）** | `skills/config_audit.md`, `skills/config_chain_analysis.md` |

> [!NOTE]
> 任何 `main.py`、`core/`、`agents/` 下的 `.py` 修改，  
> 請先開一個 issue 或在群組討論後再動手。  
> Skills `.md` 文件可以自由修改、測試，風險最低。
