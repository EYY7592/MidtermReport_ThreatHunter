# 修復計劃：Code Review 與設計跑偏盤點（2026-04-23）

## 目的

這份文件整理本次 code review 發現的兩類問題：

1. 會直接影響行為正確性的實作缺陷
2. 已經與目前架構不一致的設計文件 / 導航文件

目標是先把「會產生錯誤結果」的問題排在前面，再處理文件與計劃同步。

---

## 一、必修正的實作問題

### P0-1：Scout 合併 Intel Fusion 後，注入的 CVE 沒有重新校正 `is_new`

- 證據：
  - `agents/scout.py:847-862`
  - `agents/scout.py:908`
- 現況：
  - `run_scout_pipeline()` 先做歷史記憶比對，校正既有漏洞的 `is_new`
  - 之後才呼叫 `_merge_intel_fusion_evidence()`
  - `_merge_intel_fusion_evidence()` 對「Scout 原本沒有、由 Intel Fusion 補進來」的 CVE 直接寫死 `is_new=True`
- 風險：
  - 如果該 CVE 其實早就存在於歷史記憶，UI / Advisor 仍會看到它是新漏洞
  - `summary.new_since_last_scan` 會被高估
- 修法：
  - 把 Intel Fusion merge 移到 `is_new` 校正之前，或在 merge 後再跑一次 `historical_cves` 校正
  - 補一個 regression test：歷史記憶已有某 CVE，但只由 Intel Fusion 注入時，`is_new` 必須為 `False`

### P0-2：FastAPI UI 仍從全域 `scout_memory.json` 補漏洞細節，可能讀到錯的掃描結果

- 證據：
  - `ui/server.py:121-127`
  - `ui/server.py:204-205`
  - `ui/server.py:259-260`
- 現況：
  - `_enrich_result()` 不使用本次 pipeline 內的 `scout_output`
  - 它直接讀 `memory/scout_memory.json`，再補成 `vulnerability_detail` / `vulnerability_summary`
- 風險：
  - 多掃描併發時，scan A 有機會讀到 scan B 的 Scout 記憶
  - UI 顯示可能與本次 Advisor / pipeline 的真實輸出不一致
- 修法：
  - 讓 `main.py` 在 `final_output` 中保留本次 scan 的 `scout_output` 摘要或 `vulnerabilities[]`
  - `ui/server.py` 優先使用本次 scan 的 pipeline result，只有缺值時才回退到 memory
  - 增加一個 server-side 測試：兩個 scan 同時存在時，不可共用同一份漏洞清單

### P1-1：真正並行後，Intel Fusion 以 raw `tech_stack` 起跑，與它自己的輸入假設不一致

- 證據：
  - `main.py:791-792`
  - `agents/intel_fusion.py:409-410`
- 現況：
  - `main.py` 為了實現真正並行，讓 Intel Fusion 在 Layer 1 一開始就吃 raw `tech_stack`
  - 但 `agents/intel_fusion.py` 自己明確寫著：這種情況代表輸入可能是原始碼，理想上應由 `PackageExtractor` 先提供 package names
- 風險：
  - 架構表面上是「真並行」，但 Intel Fusion 的資料品質可能下降
  - 對 Path B 而言，情報融合品質可能比原先串行版本更差
- 修法：
  - 在 Layer 1 啟動前，增加一個輕量、無 LLM 的 package extraction 預處理
  - `Security Guard` 與 `Intel Fusion` 保持並行，但兩者都吃同一份前置抽出的 packages / raw code context
  - 若抽不到 packages，再回退 raw `tech_stack`

---

## 二、已經跑偏的設計 / 文件

### P1-2：AGENTS.md 的 UI 導航已經不是現況

- 證據：
  - `AGENTS.md:65-66`
- 現況：
  - 文件仍寫 UI 在 `ui/app.py`，啟動方式是 `streamlit run ui/app.py`
  - 但目前實際入口是 `ui/server.py` + `ui/static/*`
- 風險：
  - 後續工程師按照導航會走錯入口
  - 會影響 review、debug、比賽 demo 操作
- 修法：
  - 更新 AGENTS.md 的 UI 區段為 FastAPI / SSE 架構
  - 明確標出：
    - 後端：`ui/server.py`
    - 前端：`ui/static/index.html`, `ui/static/app.js`, `ui/static/style.css`
    - 啟動方式：實際使用的 server 指令

### P1-3：Scout / Intel Fusion 職責已改，但核心設計文件仍在描述舊版重疊架構

- 證據：
  - `docs/AGENT_ESSENCE.md:27`
  - `docs/AGENT_ESSENCE.md:135`
  - `docs/AGENT_ESSENCE.md:175`
  - `docs/PATH_A_C_GUIDE.md:26`
  - `docs/PATH_A_C_GUIDE.md:179`
  - `docs/PATH_A_C_GUIDE.md:205`
- 現況：
  - 文件仍寫 `Scout` 會查 `OTX/EPSS`
  - 也仍把 `search_otx` 視為 Scout 的 Path A 常規工具
  - 但現行實作已改成：
    - `Intel Fusion` 是 evidence / scoring provider
    - `Scout` 重用 Intel Fusion 富化結果，不再主動重查 EPSS / OTX
- 風險：
  - 新成員會依文件把重疊設計補回去
  - 評審或 demo 文件會和實際產品行為不一致
- 修法：
  - 先同步 `docs/AGENT_ESSENCE.md`
  - 再同步 `docs/PATH_A_C_GUIDE.md`
  - 文件統一改成：
    - `Intel Fusion`：上游情報富化 / scoring owner
    - `Scout`：最終 `vulnerabilities[]` owner

### P1-4：前端設計也需要跟著調整，否則會繼續放大資料流跑偏

- 證據：
  - `ui/server.py:121-125`
  - `ui/static/app.js:701-717`
  - `ui/static/app.js:727-755`
  - `ui/static/index.html:159-201`
- 現況：
  - 前端主要依賴 `vulnerability_detail` / `vulnerability_summary`
  - 這兩個欄位目前是 `ui/server.py` 從 `scout_memory.json` 補出來的，不是 scan-scoped 的即時結果
  - 視覺上已經有「Layer 1 Parallel Runtime」，但漏洞表格與摘要仍沒有明確說明資料來自哪一條分支、是否來自 Intel Fusion merge、是否為 fallback
- 風險：
  - 就算後端 pipeline 已經修正，前端仍可能顯示錯掃描的漏洞明細
  - 使用者看得到「並行動畫」，卻看不到「並行結果如何匯入最終漏洞清單」的證據鏈
  - 評審會以為並行只是動畫，不是資料流設計
- 修法：
  - UI 改為以本次 scan 的 `final_output` 為主資料源，不再把 `memory/scout_memory.json` 當主要來源
  - 在結果區增加 scan-scoped source 標記，例如：
    - `Source: Scout final output`
    - `Enriched by Intel Fusion`
    - `Fallback from Advisor actions`
  - 在 Layer 1 視覺區塊或結果摘要加入「merge outcome」說明，讓使用者知道：
    - 哪些漏洞原本由 Scout 找到
    - 哪些欄位是 Intel Fusion 補強
    - 是否有 degraded lane
  - 若時間有限，至少先完成：
    - 正確資料源切換
    - 結果卡片上的 source / enrichment badge
    - degraded / fallback 的明確標示

### P2-1：流程規範要求全套測試綠燈，但目前 repo 不符合

- 證據：
  - `AGENTS.md:14`
  - `AGENTS.md:78`
- 現況：
  - AGENTS.md 要求每完成一個模組都跑 `python -m pytest tests/ -v` 並確認全過
  - 目前實際全套測試在 180 秒內已出現多個既有 `ERROR/FAILED`
- 風險：
  - 團隊以為規範有被滿足，但實際上沒有
  - 後續 PR / demo 前驗證標準不一致
- 修法：
  - 若這條規範要保留，就先做一輪「既有失敗清零計畫」
  - 若短期無法保證全綠，應在 AGENTS.md 加上：
    - 最低必跑 smoke set
    - 模組級 required tests
    - 全套測試目前已知 blocker

---

## 三、建議修復順序

### Phase 1：先修會影響結果正確性的問題

1. 修 `Scout` 的 `is_new` 校正順序
2. 修 `ui/server.py` 改吃本次 scan 的漏洞資料，而不是全域 memory

### Phase 2：修真正並行後的資料品質問題

1. 在 Layer 1 前加入輕量 package extraction
2. 讓 `Intel Fusion` 並行啟動時也能拿到合理的 package list

### Phase 3：同步文件與導航

1. 更新 `AGENTS.md` 的 UI 導航
2. 更新 `docs/AGENT_ESSENCE.md`
3. 更新 `docs/PATH_A_C_GUIDE.md`

### Phase 3.5：同步前端呈現與資料流

1. `ui/server.py` 改為傳遞 scan-scoped 漏洞資料
2. `ui/static/app.js` 改為優先讀取本次 scan 的漏洞來源
3. `ui/static/index.html` / `ui/static/style.css` 增加 source / enrichment / degraded badges
4. 讓 Layer 1 並行視覺不只顯示動畫，也顯示 merge 後的結果歸屬

### Phase 4：整理驗證規範

1. 盤點目前全套測試失敗來源
2. 決定是先清零既有失敗，還是先調整 AGENTS.md 驗證規範

---

## 四、我建議你先批准的最小修復包

如果要最小成本、最大收益，我建議先做這一包：

1. `agents/scout.py`：修 `is_new` 校正順序
2. `ui/server.py` + `main.py`：改為使用本次 scan 的漏洞資料
3. `ui/static/*`：補上 scan-scoped source / enrichment 呈現
4. `docs/AGENT_ESSENCE.md` + `docs/PATH_A_C_GUIDE.md` + `AGENTS.md`：同步文件

這一包可以同時解掉：

- 結果正確性風險
- UI 顯示錯資料風險
- 並行架構只停留在動畫層、沒有對應結果解釋的風險
- 架構文件跑偏風險
