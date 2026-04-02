# ThreatHunter Skill 系統說明

## Skill 是什麼？

Skill = 寫在 Agent backstory 裡的 SOP（標準作業程序）。
告訴 Agent「怎麼思考」，不是「怎麼呼叫 API」。

## Skill 與 Tool 的差別

| | Skill | Tool |
|---|---|---|
| 本質 | .md 文件（自然語言指引） | Python 函式（@tool 裝飾器） |
| 位置 | 寫進 Agent 的 backstory | 掛在 Agent 的 tools 列表 |
| 作用 | 引導推理方向（SOP） | 執行具體操作（API 呼叫） |
| 範例 | 「比對歷史後判斷 is_new」 | `search_nvd("django 4.2")` |

## 本專案的 Skill 清單

| Skill 文件 | 負責人 | 對應 Agent |
|---|---|---|
| `threat_intel.md` | 成員 B | Scout Agent |
| `chain_analysis.md` | 成員 C | Analyst Agent |
| `action_report.md` | 組長 | Advisor Agent |

## 品質要求

Skill 是每個成員**最重要的產出之一**。
Agent 的推理品質 = Skill 的品質。
Code 可以用 AI 寫，但 Skill 的設計需要你自己想。
