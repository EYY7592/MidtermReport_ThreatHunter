# ThreatHunter v3.0 — 六 Agent 架構設計說明

> **文件目的**：說明哪些設計應升級為 Agent、哪些應保留為基礎設施，以及為什麼
> **版本**：2026-04-09
> **讀者**：領頭人、Hackathon 評審

---

## 第一性原理：什麼東西應該是 Agent？

判斷標準（來自 OpenAI Agentic System 設計原則）：

| 判斷標準 | 是 Agent | 不是 Agent（基礎設施） |
|---|---|---|
| 需要 LLM 推理？ | ✅ | ❌ |
| 需要自主判斷 / 條件決策？ | ✅ | ❌ |
| 需要記憶與上下文？ | ✅ | ❌ |
| 是否有固定確定性邏輯？ | ❌（程式碼就夠了）| ✅ |
| 是否在 LLM 進入前執行？ | ❌（不能信任 LLM 守衛 LLM）| ✅ |

---

## 三個新設計的架構分析

### 一、六維情報融合 → 應升級為 Intel Fusion Agent

**原本設計**：5 個 Tool 函式 → Scout Agent 的 SOP 寫死呼叫順序

**問題**：
- Scout 需要「懂得」根據情境選擇查哪幾個維度（例：老 CVE 的 EPSS 數據少，應降權）
- 寫死順序 = 工具包裝器，不是 Agentic
- OTX 可信度參差不齊，應該有自主過濾邏輯

**升級後：Intel Fusion Agent**

```
職責：根據漏洞特徵，自主選擇情報維度組合，並融合評分
SOP 核心決策邏輯：
  IF cve_year < 2020: EPSS 數據較少 → 降低 EPSS 權重，提高 CVSS 權重
  IF package_ecosystem == 'python': GHSA 優先 → 先查 GHSA
  IF in_cisa_kev == true: 跳過 EPSS（已確認在野，概率已無意義）
  IF otx_signal < threshold: 降低 OTX 權重 → 避免誤報
  記憶：記錄哪個 API 這次失敗 → 下次 fallback 更快

輸出：six_dim_score + source_weights + confidence
Skill 檔案：skills/intel_fusion.md（待建立）
```

**對 Hackathon 的展示價值**：
> 「我們的情報融合 Agent 會根據 CVE 類型自主調整查詢策略，而不是寫死的順序調用。」

---

### 二、防禦四層縱深 → 部分升級，部分保留基礎設施

**四層的本質不同，不能一刀切**：

| 層 | 能否做成 Agent | 原因 | 結論 |
|---|---|---|---|
| L1 輸入層（input_sanitizer） | ❌ | 在 LLM 之前執行，不能用 LLM 守衛 LLM | 保留基礎設施 |
| L2 Dual LLM（隔離 LLM） | ✅ | 是個 LLM，可賦予 SOP | 升級為 Security Guard Agent |
| L3 Schema 驗證 | ❌ | 確定性程式碼（jsonschema.validate），不需要 LLM 推理 | 保留基礎設施 |
| L4 執行沙盒 | ❌ | 作業系統層（Rate Limit / Audit Log） | 保留基礎設施 |

**升級後：Security Guard Agent（即原 Quarantined LLM）**

```
職責：從不可信的用戶輸入中提取結構化資訊，不做任何推理
SOP：
  Step 1: 接受原始程式碼（不可信輸入）
  Step 2: 只執行結構化提取（函式清單、import 清單、字串模式）
  Step 3: 輸出只能是預定義 JSON 格式
  Step 4: 任何輸出不符合格式 → 拋出 SecurityExtractionError
禁止：呼叫任何外部 Tool、讀取記憶、做任何推理

WHY：即使 Security Guard Agent 被完全劫持，
     它也只能讓 JSON 格式錯誤，無法影響後續分析。

Skill 檔案：skills/security_guard.md（待建立）
```

**L1/L3/L4 保留為基礎設施的理由**：
> 「讓 AI Agent 去執行 Schema 驗證」是反模式——確定性邏輯比 LLM 更可靠、更快、更省費用。

---

### 三、七層防幻覺 → 大部分已是 Agent，其餘是基礎設施

| 層 | 目前狀態 | 應該是什麼 |
|---|---|---|
| 層1 Tool-First 原則 | 所有 Agent SOP 的第一步 | ✅ 已是 Agent 行為（All Agents） |
| 層2 CVE 憲法 CI-1~4 | 所有 Agent 的 System Prompt | ✅ 已是 Agent 行為（All Agents） |
| 層3 Schema 驗證 | 確定性程式碼 | ❌ 保留基礎設施（更可靠） |
| 層4 信心度標記 | 輸出格式規範 | ✅ 已是 Agent 輸出格式（All Agents） |
| 層5 三方辯論 | Critic Agent 的 Skill | ✅ 已是 Agent（Critic） |
| 層6 記憶比對 | 所有 Agent SOP 的 read_memory → write_memory | ✅ 已是 Agent 行為 |
| 層7 DVWA 測試 | 外部驗證流程（非執行時） | 可升級為 Evaluation Agent（選擇性） |

**結論：七層防幻覺大部分已是 Agent 行為，不需要重構。**

---

## 升級後的完整六 Agent 架構

```
輸入層（基礎設施，L1）            輸出層（基礎設施，L3/L4）
  input_sanitizer.py                jsonschema.validate
        │                                    ▲
        ▼                                    │
┌─────────────────────────────────────────────────────────┐
│                    六 Agent 管線                         │
│                                                          │
│  [AG1] Security Guard Agent                              │
│         隔離 LLM，從不可信輸入提取結構化 JSON             │
│         Skill: skills/security_guard.md（待建）          │
│                    │                                     │
│                    ▼ 結構化 JSON（已清潔）                │
│  [AG2] Intel Fusion Agent                                │
│         自主選擇六維情報查詢策略，融合評分                 │
│         Skill: skills/intel_fusion.md（待建）            │
│                    │                                     │
│                    ▼ six_dim_results + composite_score   │
│  [AG3] Scout Agent                                       │
│         六維評分 + CVE 格式驗證 + is_new 標記             │
│         Skill: skills/threat_intel.md（已有）            │
│                    │                                     │
│                    ▼ standardized_vuln_objects[]          │
│  [AG4] Analyst Agent                                     │
│         連鎖攻擊路徑推理 + Map-Reduce 跨函式追蹤          │
│         Skill: skills/chain_analysis.md（已有）          │
│                    │                                     │
│                    ▼ attack_chain_graph                  │
│  [AG5] Critic Agent（三角色辯論）                        │
│         Analyst + Skeptic + ThreatHunter 三方辯論        │
│         Skill: skills/debate_sop.md（已有）             │
│                    │                                     │
│                    ▼ debate_record + weighted_verdict    │
│  [AG6] Advisor Agent                                     │
│         最終裁決 + 業務語言翻譯 + 行動計畫                │
│         Skill: skills/action_report.md（已有）           │
└─────────────────────────────────────────────────────────┘
```

---

## 四個 Skill 文件的建立優先序

| 優先 | Skill 文件 | 狀態 | 工時 |
|---|---|---|---|
| P0 | `skills/threat_intel.md` | ✅ 已有 | — |
| P0 | `skills/chain_analysis.md` | ✅ 已有 | — |
| P0 | `skills/debate_sop.md` | ✅ 已有 | — |
| P0 | `skills/action_report.md` | ✅ 已有 | — |
| **P1** | `skills/intel_fusion.md` | ❌ 待建立 | ~2 小時 |
| **P1** | `skills/security_guard.md` | ❌ 待建立 | ~1 小時 |

---

## 為什麼不把所有東西都做成 Agent？

**反模式警告**（AMD Hackathon 評審會注意到這個）：

```
❌ 把 Schema 驗證做成 Agent：
   "讓 AI 驗證 AI 的輸出" → 可靠性低於 jsonschema.validate
   → 評審會問：「為什麼不直接用 Python？」

❌ 把 Rate Limiting 做成 Agent：
   Rate Limiting 需要毫秒級響應，LLM 需要秒級
   → 本末倒置

✅ 正確原則：
   「需要推理和判斷的 → Agent」
   「有確定性答案的 → 確定性程式碼」
   這才是成熟的 Agentic Architecture 設計。
```

---

## 給評審的說詞（示範）

> "ThreatHunter 採用六 Agent 管線，每個 Agent 有明確的職責邊界和 Skill SOP。
> 我們刻意讓 Schema 驗證和 Rate Limiting 保留為確定性基礎設施，
> 因為「Agent 應該做需要推理的事，而不是用 LLM 做確定性邏輯」。
> 這個設計決策體現了我們對 Agentic Architecture 的理解：
> 不是所有東西都要用 AI，而是在正確的地方用 AI。"

---

*版本：2026-04-09 | 決策依據：OpenAI Agentic System 設計原則 + HARNESS_ENGINEERING.md*
