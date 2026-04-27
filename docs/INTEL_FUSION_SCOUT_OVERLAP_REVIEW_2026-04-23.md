# Intel Fusion 與 Scout 功能重疊檢查與改進提案

日期：2026-04-23  
狀態：待審批  
範圍：`agents/intel_fusion.py`、`agents/scout.py`、`main.py`、`docs/data_contracts.md`

## 結論

是，`Intel Fusion` 與 `Scout` 目前存在**實質功能重疊**，而且重疊已經影響到架構清晰度與執行效率。

重點不是「兩者都有碰 threat intel」這麼簡單，而是它們現在都在做下列工作：

1. 查同一批外部資料源
2. 嘗試找出同一批 CVE
3. 對同一批 CVE 補 exploitation / threat context
4. 各自輸出一份與漏洞清單高度相關的結果

目前 pipeline 雖然有把 `intel_fusion_result` 掛進 `scout_output`，但那是在 Scout 已經跑完之後才注入，沒有真正避免重工。

## 我看到的重疊證據

### 1. 兩邊都在做 CVE 發現

`Intel Fusion` 會直接用套件或 CWE 去查 CVE：

- [agents/intel_fusion.py](D:/code/team-project/hackthon/ThreatHunter/agents/intel_fusion.py:259)
- [agents/intel_fusion.py](D:/code/team-project/hackthon/ThreatHunter/agents/intel_fusion.py:457)
- [agents/intel_fusion.py](D:/code/team-project/hackthon/ThreatHunter/agents/intel_fusion.py:486)

這裡明確要求它呼叫：

- `search_osv`
- `search_nvd`
- `check_cisa_kev`

而 `Scout` 也在做同樣的 CVE 發現流程：

- [agents/scout.py](D:/code/team-project/hackthon/ThreatHunter/agents/scout.py:237)
- [agents/scout.py](D:/code/team-project/hackthon/ThreatHunter/agents/scout.py:290)
- [agents/scout.py](D:/code/team-project/hackthon/ThreatHunter/agents/scout.py:317)

也就是說，兩個 Agent 都把自己當成「漏洞來源查詢者」。

### 2. 兩邊都在做 exploitation / threat enrichment

`Intel Fusion` 的工具與任務內容包含：

- `fetch_epss_score`
- `search_otx`
- `query_ghsa`
- KEV shortcut / composite score

參考：

- [agents/intel_fusion.py](D:/code/team-project/hackthon/ThreatHunter/agents/intel_fusion.py:243)
- [agents/intel_fusion.py](D:/code/team-project/hackthon/ThreatHunter/agents/intel_fusion.py:278)
- [agents/intel_fusion.py](D:/code/team-project/hackthon/ThreatHunter/agents/intel_fusion.py:463)

但 `Scout` 也在對高風險 CVE 做：

- `fetch_epss_score`
- `search_otx`

參考：

- [agents/scout.py](D:/code/team-project/hackthon/ThreatHunter/agents/scout.py:240)
- [agents/scout.py](D:/code/team-project/hackthon/ThreatHunter/agents/scout.py:293)
- [agents/scout.py](D:/code/team-project/hackthon/ThreatHunter/agents/scout.py:327)

所以這不是「一個找 CVE、另一個補風險」的分工；目前是兩邊都在補風險。

### 3. Pipeline 目前沒有真正把 Intel Fusion 變成 Scout 的前置輸入

在 `main.py`，Scout 先執行：

- [main.py](D:/code/team-project/hackthon/ThreatHunter/main.py:1043)
- [main.py](D:/code/team-project/hackthon/ThreatHunter/main.py:1051)

之後才把 Intel Fusion 結果掛回去：

- [main.py](D:/code/team-project/hackthon/ThreatHunter/main.py:1053)

這表示：

1. Scout 執行時看不到 Intel Fusion 的結果
2. Scout 無法用 Intel Fusion 結果來減少查詢
3. Intel Fusion 的價值目前比較像「附加資訊」，不是「上游 evidence provider」

### 4. 輸出所有權不夠清楚

`Intel Fusion` 輸出 `fusion_results[]`，裡面有：

- `cve_id`
- `composite_score`
- `dimension_scores`
- `confidence`

參考：

- [agents/intel_fusion.py](D:/code/team-project/hackthon/ThreatHunter/agents/intel_fusion.py:293)

`Scout` 則輸出 `vulnerabilities[]`，裡面也有：

- `cve_id`
- `package`
- `cvss_score`
- `severity`
- `is_new`

參考：

- [docs/data_contracts.md](D:/code/team-project/hackthon/ThreatHunter/docs/data_contracts.md:335)
- [docs/data_contracts.md](D:/code/team-project/hackthon/ThreatHunter/docs/data_contracts.md:352)

這讓系統現在有兩份「很像主資料」的漏洞結果，但沒有一個明確的 single source of truth。

## 不重疊的部分

也不能說兩者完全重複。它們仍各自有獨特價值：

### Intel Fusion 的獨特價值

1. 多維度 composite scoring
2. KEV 權重重分配與 floor 規則
3. GHSA / ATT&CK / OTX / EPSS 的融合邏輯
4. `_verify_and_recalculate()` 這類 deterministic score guard

參考：

- [agents/intel_fusion.py](D:/code/team-project/hackthon/ThreatHunter/agents/intel_fusion.py:60)
- [agents/intel_fusion.py](D:/code/team-project/hackthon/ThreatHunter/agents/intel_fusion.py:680)

### Scout 的獨特價值

1. Path-aware skill 切換
2. 記憶體讀寫與 `is_new` 判定
3. hallucination 清理與 NVD/OSV 驗證
4. 最終 `vulnerabilities[] + summary` 正式輸出

參考：

- [agents/scout.py](D:/code/team-project/hackthon/ThreatHunter/agents/scout.py:40)
- [agents/scout.py](D:/code/team-project/hackthon/ThreatHunter/agents/scout.py:356)

## 建議改法

### 建議採用方案

**保留兩個 Agent，但重新切責任邊界：**

- `Intel Fusion`：改成「Layer 1 情報富化器 / 評分器」
- `Scout`：改成「唯一漏洞清單擁有者 / 正式輸出組裝者」

這是我最推薦的方案，因為它同時保留：

1. 你現在很重視的並行架構
2. Intel Fusion 的 scoring 專長
3. Scout 的最終輸出與驗證專長

而且能大幅減少重工。

## 改進後的責任切分

### Intel Fusion 應該負責

1. 對 package / CWE / candidate CVE 做多源情報富化
2. 拉取 EPSS / KEV / GHSA / OTX / ATT&CK 類資訊
3. 計算 `composite_score`
4. 產出標準化 `fusion_results`

### Scout 應該負責

1. 產出最終 `vulnerabilities[]`
2. 做 `is_new`、memory、summary
3. 做 hallucination guard / schema repair
4. 只在 Intel Fusion 缺資料時做 fallback 查詢

## 關鍵設計原則

### 原則 1：Scout 是唯一漏洞清單 owner

最終只有 `Scout` 對 `vulnerabilities[]` 負責。  
`Intel Fusion` 不再被視為另一份並列漏洞主表，而是 evidence / scoring provider。

### 原則 2：Intel Fusion 結果要在 Scout 執行前就可用

現在的問題是 [main.py](D:/code/team-project/hackthon/ThreatHunter/main.py:1053) 才注入 `intel_fusion_result`，太晚了。  
應改成：

1. Layer 1 完成後先整理 Intel Fusion 結果
2. 再把整理後的 evidence 傳給 Scout
3. Scout 只補缺漏，不重查整套 API

### 原則 3：Scout 的外部查詢要分成 primary 與 fallback

建議改成：

- 若 `intel_fusion_result` 可用：Scout 不主動再查 `EPSS` / `OTX`
- 若 `intel_fusion_result` 缺 package 或缺 CVE：Scout 才做 fallback 查詢

## 具體重構提案

### Phase 1：先改資料流，不先大拆 Agent

先做最小可行改動：

1. `main.py` 在呼叫 Scout 前，把 `layer1_results["intel_fusion"]` 整理成 `scout_context`
2. `stage_scout()` / `run_scout_pipeline()` 接收 `intel_fusion_result`
3. Scout 優先消費 `fusion_results[]`

目標：

- 先停止「Intel Fusion 跑完了，但 Scout 完全沒用到」
- 先把架構接通

### Phase 2：拿掉 Scout 正常路徑中的重複 enrichment

建議把 Scout 的正常路徑改成：

- 不再主動查 `fetch_epss_score`
- 不再主動查 `search_otx`

這兩類資訊改由 Intel Fusion 提供。Scout 僅保留：

- OSV/NVD fallback
- verification
- memory/history
- final JSON 組裝

### Phase 3：把 Intel Fusion 輸出 schema 補到可直接被 Scout 吃

建議 `fusion_results[]` 至少固定補齊：

1. `package`
2. `cve_id`
3. `cvss_score`
4. `epss_score`
5. `in_kev`
6. `ghsa_severity`
7. `otx_threat`
8. `confidence`
9. `composite_score`

這樣 Scout 就不用再為了組 `vulnerabilities[]` 回頭重查一輪。

## 我建議不要採用的做法

### 不建議方案 A：直接刪掉 Intel Fusion

理由：

1. 會失去目前最有特色的多維 scoring 能力
2. 會讓 Scout 再次變成過胖 Agent
3. 會讓「並行架構」退化成單線調查

### 不建議方案 B：直接刪掉 Scout，讓 Intel Fusion 產最終輸出

理由：

1. 會把 memory / `is_new` / verification / schema repair 全塞回 Intel Fusion
2. 會讓 Intel Fusion 從 scoring agent 變成全能 agent
3. 會讓 Path-aware skill 邊界變模糊

## 我建議的最終責任圖

### 現況

`Intel Fusion`
查 CVE + 查 EPSS/OTX/KEV/GHSA + 打分

`Scout`
查 CVE + 查 EPSS/OTX + 驗證 + summary

### 建議調整後

`Intel Fusion`
查情報 + 補 exploitation evidence + 打分

`Scout`
整合 Layer 1 evidence + 補 fallback + 產最終漏洞清單

## 實作優先順序

如果你核准，我建議按這個順序改：

1. 先改 `main.py`，讓 Scout 在執行前就拿到 `intel_fusion_result`
2. 再改 `agents/scout.py`，加入 intel-assisted mode
3. 最後收斂 `Scout` 的 `EPSS/OTX` 正常查詢，只保留 fallback

這樣風險最低，也最容易驗證回歸。

## 審批項目

請你只要先核這 3 點就可以：

1. 是否同意 `Scout` 成為唯一 `vulnerabilities[]` owner
2. 是否同意 `Intel Fusion` 改為上游 evidence / scoring provider
3. 是否同意先做 Phase 1 資料流調整，再做工具重疊收斂

## 我的建議結論

**建議核准。**

原因是這不是小幅命名問題，而是已經出現：

1. 重複 API 查詢
2. 重複 CVE 發現
3. 結果所有權模糊
4. Layer 1 並行結果沒有真正餵給 Layer 2 消費

如果不處理，後面越補 feature，`Intel Fusion` 和 `Scout` 只會越來越像兩個都想當主角的 Agent。
