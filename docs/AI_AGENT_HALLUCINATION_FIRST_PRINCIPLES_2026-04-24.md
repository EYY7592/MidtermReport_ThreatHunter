# AI Agent 幻覺防護第一性原理解釋

> 日期：2026-04-24  
> 狀態：說明文件  
> 目的：用第一性原理解釋 ThreatHunter 如何降低 AI Agent 幻覺，以及為何目前不把向量資料庫作為主約束。

---

## 1. 第一性原理：AI Agent 為什麼會幻覺

AI Agent 的輸出本質上不是「資料庫查詢結果」，而是「模型根據上下文產生最可能的文字」。因此，只要缺少外部約束，模型就可能把看起來合理的內容補完。

幻覺通常來自三個根因：

- 缺少可驗證資料：模型沒有被迫引用工具、API、程式碼行號或 checkpoint。
- 缺少輸出邊界：模型可以自由產生 CVE、CVSS、修復建議或原因。
- 缺少失敗標記：模型或工具失敗時，系統仍把結果包裝成正常成功。

所以防幻覺的核心不是「叫模型不要幻覺」，而是把模型限制在可驗證資料流內。

---

## 2. 第一性原理：有效防幻覺需要哪些約束

### 2.1 Source Constraint：來源約束

任何 CVE / CWE / CVSS / KEV / EPSS 結論，都必須能回答：

```text
這個結論從哪裡來？
```

ThreatHunter 目前使用：

- NVD / OTX / KEV / EPSS / Exploit tools 作為外部漏洞資料來源。
- Security Guard deterministic scanner 作為 code-level finding 來源。
- checkpoint JSONL 作為 Agent 行為紀錄來源。
- report_sources / enriched_by / source 欄位標記來源。

這能避免模型憑空說「某套件有 CVE」或「某行 code 是 CRITICAL」。

### 2.2 Evidence Constraint：證據約束

每個安全結論都必須有可檢查 evidence：

- package CVE 需要 tool-returned CVE ID。
- code finding 需要 pattern、snippet、line number、CWE mapping。
- advisory action 需要對應 analysis 或 deterministic pattern。
- fallback result 必須標示 fallback source。

如果沒有 evidence，結論不能被標成 verified，只能是 `NEEDS_VERIFICATION`。

### 2.3 Schema Constraint：格式約束

模型輸出必須符合 JSON contract。

這不是為了漂亮，而是為了讓系統可以檢查：

- 必填欄位是否存在。
- severity 是否在允許範圍。
- risk_score 是否在 0 到 100。
- CVE ID 是否格式合理。
- fallback / degraded metadata 是否存在。

沒有 schema，幻覺會混在自然語言裡，很難被程式攔截。

### 2.4 Execution Constraint：執行約束

Agent 不應只靠語言推理完成任務，必須經過 pipeline stage：

```text
Input Sanitizer -> Orchestrator -> Security Guard / Intel Fusion -> Scout -> Analyst -> Critic -> Advisor
```

每個 stage 有固定職責：

- Security Guard 只做 deterministic code extraction，不做自由安全判決。
- Scout 查漏洞情報。
- Analyst 做風險分析。
- Critic 做反方檢查。
- Advisor 產生修復建議。

職責拆開後，模型就比較難在單一步驟中同時捏造資料、判斷風險、產生修復方案。

### 2.5 Observability Constraint：可觀測約束

如果系統不知道 Agent 做了什麼，就無法判斷是否幻覺。

ThreatHunter 使用 checkpoint / Thinking Path 記錄：

- Agent input。
- Agent output。
- LLM call。
- Tool call。
- retry。
- error。
- degradation。

這讓評審或工程師可以回頭檢查「這個結論是否真的經過工具或 scanner」。

### 2.6 Failure Constraint：失敗約束

模型當掉時，最危險的不是失敗，而是「失敗卻假裝成功」。

所以 fallback 必須：

- 標記 `_degraded=true`。
- 保存 `_error`。
- 顯示 fallback strategy。
- 降低 confidence。
- 不新增未驗證 CVE。
- 不把 fallback 結論標成 fully verified。

---

## 3. ThreatHunter 目前的防幻覺措施

### 3.1 Constitution

`SYSTEM_CONSTITUTION` 要求：

- CVE 必須來自 Tool。
- 禁止捏造。
- 必須用 JSON schema。
- 不確定時標成 `NEEDS_VERIFICATION`。

這是語義層防線，但不是唯一防線。

### 3.2 Tool-first pipeline

漏洞情報由 tools 查詢，不讓模型單靠記憶回答。

這可以降低：

- fake CVE。
- 錯誤 CVSS。
- 過時 KEV 狀態。
- 沒有 evidence 的 exploit claim。

### 3.3 Deterministic Security Guard

code-level finding 由 deterministic scanner 產生，而不是 LLM 自由判定。

例如 CWE-78 command injection 必須來自：

- pattern match。
- snippet。
- line number。
- CWE mapping。

這比向量相似度或模型直覺更可審計。

### 3.4 Harness validation

各 Agent 會做：

- JSON extraction。
- schema validation。
- fallback merge。
- score repair。
- verdict repair。
- degradation metadata。

這是把模型輸出轉成可控工程資料的關鍵。

### 3.5 Redteam tests

目前測試包含：

- jailbreak。
- fake CVE fabrication。
- prompt override。
- role hijack。
- memory poison。
- AST bomb。
- sandbox fallback。

這些不是一般 happy path 測試，而是專門測 Agent 是否會被輸入帶偏。

---

## 4. 為什麼不把向量資料庫作為主防幻覺約束

### 4.1 第一性原理：向量資料庫解決的是「相似性」，不是「真實性」

向量資料庫的核心能力是：

```text
找出語意上相似的歷史內容。
```

但防幻覺需要的是：

```text
證明這次結論來自本次可驗證證據。
```

相似不等於真實。相似案例也不等於本次掃描證據。

例如：

- 歷史案例有 Django CVE，不代表本次 Django 版本一定受影響。
- 歷史案例有 CWE-78，不代表本次 code line 就是 command injection。
- 歷史修復建議相似，不代表能套用到目前 snippet。

所以向量資料庫不能當作主約束，只能當輔助 context。

### 4.2 向量約束可能造成「記憶污染」

如果向量資料庫召回舊資料，模型可能把舊專案的漏洞帶到新掃描。

這會造成：

- 舊 CVE 被誤報成新 finding。
- 相似 package 的漏洞被套到不同 version。
- 其他專案的 code pattern 被誤認為目前 code。
- 歷史修復方法覆蓋本次 scanner evidence。

在安全產品中，這比普通 hallucination 更危險，因為它看起來有「資料來源」，但來源其實不是本次 evidence。

### 4.3 向量資料庫不適合做 CVE/CVSS/NVD 的真值來源

CVE / CVSS / NVD 類資料需要：

- 精確 ID。
- 精確 version range。
- 更新日期。
- vendor / product matching。
- reference URL。
- source timestamp。

向量檢索會把資料轉成 embedding，適合找語意相近，不適合保證精確匹配。

因此 ThreatHunter 的原則是：

```text
CVE/CVSS/NVD 結論必須來自工具或 scan-scoped JSON，不來自 vector similarity。
```

### 4.4 向量資料庫可以用在哪裡

向量資料庫不是不用，而是不作為主證據。

適合用途：

- 搜尋歷史修復案例。
- 幫 Advisor 找相似 remediation pattern。
- 幫 Analyst 找過去類似 chain risk。
- 幫 UI 顯示「historical context」。

但必須標記：

```text
retrieved_historical_context
```

而且不能標成：

```text
verified finding
```

### 4.5 向量約束如果要加入，需要哪些條件

未來可以加入 vector constraint，但必須滿足：

- 每筆向量資料有 provenance：來源檔案、scan_id、timestamp、agent、tool。
- 本次 scan evidence 優先於 vector context。
- vector result 只能補充 explanation，不可新增 finding。
- UI 必須標示 retrieved context。
- schema 必須區分 `verified_evidence` 與 `retrieved_context`。
- redteam 測試必須驗證舊 memory 不會污染新 scan。

---

## 5. 建議的防幻覺架構原則

ThreatHunter 應採用以下優先序：

```text
1. Deterministic scanner evidence
2. Tool-returned vulnerability evidence
3. Current scan JSON/checkpoint evidence
4. Agent reasoning under schema
5. Historical/vector context
```

也就是：

```text
工具與 scanner 是證據。
LLM 是解釋器。
向量資料庫是輔助記憶。
UI 必須顯示證據等級。
```

---

## 6. 結論

防 AI Agent 幻覺的核心不是增加更多模型，也不是把記憶塞進向量資料庫，而是建立可驗證的 evidence pipeline。

ThreatHunter 目前正確方向是：

- 用 Tool 約束 CVE。
- 用 deterministic scanner 約束 code finding。
- 用 schema 約束輸出。
- 用 checkpoint 約束過程。
- 用 fallback/degradation 約束失敗。
- 把向量資料庫保留為歷史 context，而不是 verified evidence。

因此，目前不把向量資料庫作為主防幻覺約束，是因為它解決的是「相似性」問題，不是「真實性」與「本次掃描可審計性」問題。

