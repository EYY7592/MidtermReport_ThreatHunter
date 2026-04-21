# ThreatHunter — Agent 本質說明

> 每個 Agent 在做什麼？用一句話說清楚。

---

## 🎯 Orchestrator Agent
**本質：交通指揮員**

看你輸入的是什麼（套件清單？原始碼？設定檔？），
決定後面要走哪條路。它自己不做任何分析。

| 輸入 | 輸出 |
|------|------|
| 用戶的技術堆疊 / 原始碼 / 套件清單 | `Path A / B / C / D` 的路由決定 |

```
套件清單   → Path A（套件 CVE 掃描）
原始碼     → Path B（程式碼靜態審計）
設定檔     → Path C（設定錯誤審計）
回饋/補充  → Path D（記憶增強再分析）
```

---

## 🔍 Security Guard Agent
**本質：靜態掃描器（不用 LLM）**

用 AST + 正則表達式，確定性地找出程式碼裡的危險模式。
它**不猜測、不推理**，只比對已知的 20+ 種攻擊格式。

| 輸入 | 輸出 |
|------|------|
| 原始程式碼（PHP/Python/Java/JS） | 偵測到的 CWE 列表 + 行號 + 危險片段 |

```
原始碼中有 eval()    → CWE-95 (Code Injection)
有 SQL 字串拼接      → CWE-89 (SQL Injection)
有 shell_exec()      → CWE-78 (Command Injection)
有 include($var)     → CWE-98 (File Inclusion)
```

---

## 🌐 Intel Fusion Agent
**本質：CVE 情報聚合器（只對第三方套件有效）**

給它一個套件名稱（如 `requests`、`flask`），
它去查 NVD / OSV / KEV / EPSS 六個來源，
返回這個套件所有已知 CVE 的風險分數。

| 輸入 | 輸出 |
|------|------|
| 第三方套件名稱列表 | 每個 CVE 的六維複合分數（CVSS + EPSS + KEV + ...） |

```
requests → CVE-2023-32681 (CVSS 6.1, EPSS 0.03, not in KEV)
flask    → CVE-2023-30861 (CVSS 7.5, EPSS 0.12, not in KEV)
```

> ⚠️ **限制**：只對已知第三方套件有效。
> 自定義程式碼（PHP/Java 純 JDK）沒有 CVE，它找不到東西。

---

## 🕵️ Scout Agent
**本質：威脅情報彙整員 + 記憶比對員**

拿到 Security Guard + Intel Fusion 的結果，
整理成統一格式，並和記憶系統比對：
「這個漏洞是新的，還是上次就有？」

| 輸入 | 輸出 |
|------|------|
| SG 的 CWE 清單 + IF 的 CVE 分數 | 結構化威脅清單（new / repeated / resolved） |

```
上次有 CVE-2023-32681 → 這次還有 → REPEATED ⚠️
這次新出現 CVE-2024-X → NEW 🔴
上次有，這次沒有      → RESOLVED ✅
```

---

## 🧠 Analyst Agent
**本質：攻擊鏈推理師**

Scout 只是列清單，Analyst 負責**想攻擊者的思路**：
「這幾個漏洞組合起來，最壞情況是什麼？」

| 輸入 | 輸出 |
|------|------|
| 威脅清單（Scout 輸出） | 攻擊鏈分析 + 組合風險評估 |

```
SSRF (Medium) + Redis 無密碼 (Medium)
→ SSRF 打到內網 Redis → 寫入 crontab → shell 執行
→ 組合風險 = CRITICAL 🔴（兩個 Medium 組合 ≠ 中危）
```

---

## ⚔️ Critic Agent
**本質：魔鬼代言人**

用對抗式思維質疑 Analyst 的結論：
「這個攻擊鏈真的可行嗎？還是誇大了？」

| 輸入 | 輸出 |
|------|------|
| Analyst 的攻擊鏈分析 | 驗證後的風險評估（修正誤報 / 確認高風險） |

```
Analyst：這個 RCE 是 CRITICAL
Critic：攻擊者需要內網存取才能觸發
→ 降為 HIGH（修正誇大風險）
```

---

## 📋 Advisor Agent
**本質：行動報告產生器（最後一關）**

把所有分析轉換成**人看得懂、可直接執行的行動清單**。
並通過 Harness Layer 4.5 憲法守衛確保：
- `URGENT` 只放有真實 CVE 佐證的漏洞
- 沒有 CVE 來源的 CODE-pattern 不進入行動清單

| 輸入 | 輸出 |
|------|------|
| Analyst + Critic 結論 | URGENT / IMPORTANT / MONITOR 行動清單 |

```
URGENT：
  CVE-2023-32681 | requests 2.28.0 | CVSS 6.1
  → pip install requests>=2.31.0
```

---

## 整體流程

```
用戶輸入
  → Orchestrator 決定路徑
    → Security Guard 找危險模式（確定性）
    → Intel Fusion 查套件 CVE（LLM + API）
      → Scout 整理並比對記憶
        → Analyst 推理攻擊鏈
          → Critic 質疑是否誇大
            → Advisor 輸出行動報告
```

**每個 Agent 只做自己的事，不越界。**

---

*ThreatHunter v5.3 | AMD Developer Hackathon 2026*
