# ?儭?ThreatHunter ??AI-Powered Cybersecurity Threat Intelligence Platform

<div align="center">

**An autonomous multi-agent system that scouts vulnerabilities, reasons about chained risks, and delivers actionable security reports ??with memory.**

[![AMD Developer Hackathon](https://img.shields.io/badge/AMD-Developer%20Hackathon%202026-ED1C24?style=for-the-badge&logo=amd&logoColor=white)](https://www.amd.com)
[![CrewAI](https://img.shields.io/badge/CrewAI-Multi--Agent-4A90D9?style=for-the-badge)](https://crewai.com)
[![vLLM](https://img.shields.io/badge/vLLM-AMD%20Cloud-00C853?style=for-the-badge)](https://vllm.ai)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)

[English](#english) | [銝剜?](#銝剜?)

</div>

---

<a id="english"></a>

## ?? English

### What is ThreatHunter?

**ThreatHunter is an AI cybersecurity advisor with memory.**

Traditional vulnerability scanners give you a list of CVEs sorted by CVSS score. ThreatHunter goes further ??it **reasons** about how vulnerabilities combine into attack chains, and it **remembers** your infrastructure across scans to track risk evolution over time.

### Key Features

| Feature | Description |
|---|---|
| ?? **Autonomous Threat Scouting** | AI agent queries NVD + OTX APIs, compares with historical scans, and flags new threats |
| ?? **Chain Vulnerability Analysis** | LLM-powered reasoning discovers that SSRF + Redis = RCE, even when individual CVSS scores say "Medium" |
| ?? **Actionable Reports** | Prioritized action plans with specific fix commands, not just CVE lists |
| ?妞 **Evolving Memory** | Every scan remembers the last. Risk trends, resolved issues, and user feedback improve future analysis |
| ? **Confidence Scoring** | Every finding is tagged HIGH / MEDIUM / NEEDS_VERIFICATION ??no silent hallucinations |

### Architecture

```
User Input: "Django 4.2, Redis 7.0, PostgreSQL 16"
                    ??    ????????????????????????????????????????    ??        CrewAI Sequential Process       ??    ??                                        ??    ?? ?????????????????????????????????????? ??    ?? ?? ?? Scout Agent                    ?? ??    ?? ?? NVD API ??OTX API ??Memory       ????? ??Threat Intel
    ?? ?? ReAct: Thought?ction?bserve    ?? ??    ?? ??????????????????砂???????????????????? ??    ??                  ??                     ??    ?? ??????????????????潑???????????????????? ??    ?? ?? ?? Analyst Agent                  ?? ??    ?? ?? CISA KEV ??Exploit DB ??Memory   ????? ??Risk Assessment
    ?? ?? Chain Analysis + Confidence       ?? ??    ?? ??????????????????砂???????????????????? ??    ??                  ??                     ??    ?? ??????????????????潑???????????????????? ??    ?? ?? ?? Advisor Agent                  ?? ??    ?? ?? Action Plan + Priority Ranking   ????? ??Final Report
    ?? ?? ? URGENT / ? IMPORTANT / ? OK ?? ??    ?? ?????????????????????????????????????? ??    ??                                        ??    ??????????????????????????????????????????                        ??                        ??              ????????????????????              ?? Streamlit UI    ??              ?? Report + Feedback??              ????????????????????```

### What Makes It Different?

```
Traditional Scanner:
  CVE-A (SSRF, CVSS 6.5) ??Medium ??
  CVE-B (Redis unauth, CVSS 5.3) ??Medium ??
  Result: Two medium vulnerabilities.

ThreatHunter:
  CVE-A (SSRF) + CVE-B (Redis unauth)
  ??SSRF reaches internal network
  ??Redis has no password
  ??Attacker writes crontab = shell access
  ??Result: Two mediums = ONE CRITICAL ?

  漎? Only an LLM can reason about this.
  Traditional tools can't.
```

### Tech Stack

| Component | Technology |
|---|---|
| Agent Framework | CrewAI (ReAct mode) |
| LLM | Llama 3.3 70B via vLLM on AMD Cloud |
| Threat Data | NVD API, AlienVault OTX |
| Risk Validation | CISA KEV, GitHub Exploit DB |
| Memory & Learning | JSON-based persistent storage |
| UI | Streamlit |
| Methodology | Harness Engineering (OpenAI) |

### Project Structure

```
ThreatHunter/
??? main.py                    # CrewAI Crew orchestration
??? config.py                  # LLM + API configuration
??? requirements.txt
????? tools/                     # @tool decorated functions
??  ??? nvd_tool.py            # NVD vulnerability lookup
??  ??? otx_tool.py            # OTX threat intelligence
??  ??? kev_tool.py            # CISA KEV verification
??  ??? exploit_tool.py        # GitHub exploit search
??  ??? memory_tool.py         # Persistent memory R/W
????? agents/
??  ??? scout.py               # Scout Agent definition
??  ??? analyst.py             # Analyst Agent definition
??  ??? advisor.py             # Advisor Agent definition
????? skills/                    # Agent SOP documents
??  ??? threat_intel.md        # Scout reasoning guide
??  ??? chain_analysis.md      # Chain vulnerability SOP
??  ??? action_report.md       # Report generation SOP
????? memory/                    # Persistent scan history
??? data/                      # Offline caches
??? ui/
    ??? app.py                 # Streamlit interface
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
streamlit run ui/app.py
```

### Development Methodology: Harness Engineering

We build agents using **Harness Engineering** ??a methodology focused on making AI agents **reliable**, not just powerful.

| Pillar | Implementation |
|---|---|
| **Constraints** | System Constitution in every agent's prompt |
| **Observability** | `verbose=True` ??full ReAct reasoning visible |
| **Feedback Loops** | Memory system ??agents learn from past scans |
| **Graceful Degradation** | Offline caches + fallback LLM providers |
| **Evaluation** | Confidence scoring (HIGH/MEDIUM/NEEDS_VERIFICATION) |

---

<a id="銝剜?"></a>

## ?? 銝剜?

### ThreatHunter ?臭?暻潘?

**ThreatHunter ?臭???閮??AI 鞈?憿批???*

?喟絞瞍????典?策雿?隞賣? CVSS ?????CVE 皜?hreatHunter ?湧脖?甇???摰?**?函?**瞍?銋?????餅???嚗?**閮?**雿??箇?閮剜嚗蕭頩日◢?芷??????
### ?詨??

| ? | 隤芣? |
|---|---|
| ?? **?芯蜓憡??萄?** | AI Agent ?芸??亥岷 NVD + OTX API嚗?撠風?脫???璅??啣???|
| ?? **???瞍???** | LLM ?函??潛 SSRF + Redis = RCE嚗雿踹 CVSS ?憿舐內?葉?晞?|
| ?? **?臬銵??* | ?葆?琿?靽桀儔?誘????獢?銝??CVE 皜 |
| ?妞 **?脣?閮** | 瘥活???質?雿?甈∠?蝯??◢?芾隅?Ｕ歇靽桀儔???蝙?刻?擖?蝥????|
| ? **靽∪?摨行?閮?* | 瘥?暸璅釣 HIGH / MEDIUM / NEEDS_VERIFICATION ??銝??瑕撟餉死 |

### ?箔?暻潸??喟絞撌亙銝?璅??

```
?喟絞???剁?
  CVE-A (SSRF, CVSS 6.5) ??銝剖 ??
  CVE-B (Redis ?芣?甈? CVSS 5.3) ??銝剖 ??
  蝯?嚗?葉?望?瘣?
ThreatHunter嚗?  CVE-A (SSRF) + CVE-B (Redis ?芣?甈?
  ??SSRF ?臭誑霈???啣蝬?  ???抒雯??Redis 瘝?蝣?  ???餅??隞亦?亙神??crontab = ?踹 shell
  ??蝯?嚗?葉??= 銝????

  漎? ????LLM ?賢???  ?喟絞撌亙???啜?```

### ?銵ㄖ

| ?辣 | ?銵?|
|---|---|
| Agent 獢 | CrewAI嚗eAct 璅∪?嚗?|
| LLM | Llama 3.3 70B嚗? vLLM ?函蔡??AMD Cloud |
| 憡?鞈? | NVD API?lienVault OTX |
| 憸券撽? | CISA KEV?itHub Exploit DB |
| 閮摮貊?蝟餌絞 | JSON ???摮?|
| 隞 | Streamlit |
| ??寞?隢?| Harness Engineering嚗penAI嚗?|

### ??寞?嚗arness Engineering

?蝙??**Harness Engineering** 靘???Agent ??撠釣?潸? AI Agent **?舫?蝛拙?**嚗??芣撘瑕之??
| ?舀 | 撖虫??孵? |
|---|---|
| **Constraints嚗???** | 蝟餌絞?脫?撖恍脫???Agent ??Prompt |
| **Observability嚗閫皜祆改?** | `verbose=True` ??摰 ReAct ?函??航? |
| **Feedback Loops嚗?擖艘??** | Memory 蝟餌絞 ??Agent 敺??餌???摮貊? |
| **Graceful Degradation嚗??蝝?** | ?Ｙ?敹怠? + ? LLM 靘???|
| **Evaluation嚗?霅?** | 靽∪?摨行?閮?HIGH/MEDIUM/NEEDS_VERIFICATION嚗?|

### ??

| 閫 | ?瑁痊 |
|---|---|
| ?? 蝯 | ?嗆?閮剛??rewAI 銝脫?treamlit UI?emory Tool |
| ?? ? B | Scout Agent Pipeline嚗VD Tool + OTX Tool + Skill嚗?|
| ?? ? C | Analyst Agent Pipeline嚗EV Tool + Exploit Tool + Chain Analysis Skill嚗?|

---

## ?? License

This project is developed for the AMD Developer Hackathon 2026.

## ?? Acknowledgments

- [AMD](https://www.amd.com) ??Cloud GPU infrastructure
- [CrewAI](https://crewai.com) ??Multi-agent orchestration framework
- [NVD](https://nvd.nist.gov) ??National Vulnerability Database
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) ??Known Exploited Vulnerabilities
- [AlienVault OTX](https://otx.alienvault.com) ??Open Threat Exchange
