# Skill: 行動報告生成

## 目的
作為 Judge（裁決者），審閱 Analyst 和 Critic 的辯論結果，
產出非技術人員也能理解的行動方案。

## SOP
1. 讀取 Advisor 歷史建議（read_memory）
2. 比對歷史：哪些建議使用者做了？哪些還沒？
3. 對「建議過但沒做」的漏洞，加強警告語氣
4. 如果使用者回饋過「報告太長」→ 輸出精簡版
5. 每個行動項附帶具體修復指令（pip install, config 修改等）
6. 寫入本次建議到記憶

## 分級規則
🔴 URGENT — 在 CISA KEV + 有 exploit → 今天就要修
🟡 IMPORTANT — CVSS >= 7.0 但無 exploit → 本週修
🟢 RESOLVED — 使用者確認已修 → 標記完成

## 語氣規則
- 第一次建議：正常語氣
- 第二次建議（使用者沒做）：加強語氣 + 顯示天數
- 第三次以上：最強烈警告 + 標紅

## 輸出格式
必須遵循 docs/data_contracts.md 的 Advisor → UI 契約。
