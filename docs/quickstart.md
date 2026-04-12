# ThreatHunter 快速開始指南

> **版本**：v1.0  
> **日期**：2026-04-06  
> **適用對象**：所有團隊成員

---

## 1. 環境設定

### 1.1 安裝依賴

```bash
pip install -r requirements.txt
```

### 1.2 設定 API Key

```bash
# 複製範例檔案
cp .env.example .env

# 編輯 .env，填入你的 API Key
```

**必要 API Key：**

| 變數 | 用途 | 取得方式 |
|---|---|---|
| `OPENROUTER_API_KEY` | LLM 推理（推薦） | https://openrouter.ai/ |
| `NVD_API_KEY` | NVD 漏洞查詢 | https://nvd.nist.gov/developers/request-an-api-key |
| `OTX_API_KEY` | OTX 威脅情報 | https://otx.alienvault.com/ |

**選用 API Key：**

| 變數 | 用途 |
|---|---|
| `OPENAI_API_KEY` | LLM 備案（gpt-4o-mini） |
| `GITHUB_TOKEN` | Exploit 搜尋 |
| `VLLM_BASE_URL` | 比賽用 vLLM 端點 |

### 1.3 驗證設定

```bash
python -c "from config import validate_api_keys; validate_api_keys()"
```

---

## 2. 第一次執行

### 2.1 基本掃描

```bash
python main.py "Django 4.2, Redis 7.0"
```

### 2.2 指定技術堆疊

```bash
python main.py "nginx 1.24, postgresql 16, flask 3.0"
```

### 2.3 預設掃描

```bash
python main.py
# 等同於：python main.py "Django 4.2, Redis 7.0, PostgreSQL 16"
```

---

## 3. 功能開關

### 3.1 開啟 Critic 辯論

```bash
# Windows PowerShell
$env:ENABLE_CRITIC="true"; python main.py "Django 4.2"

# Linux/Mac
ENABLE_CRITIC=true python main.py "Django 4.2"
```

### 3.2 切換 LLM 供應商

```bash
# 使用 OpenAI（備案）
$env:LLM_PROVIDER="openai"; python main.py "Django 4.2"

# 使用 vLLM（比賽用）
$env:LLM_PROVIDER="vllm"; $env:VLLM_BASE_URL="http://your-vllm-endpoint:8000"; python main.py "Django 4.2"
```

---

## 4. 運行測試

```bash
# 全套測試
python -m pytest tests/ -v

# 單一模組測試
python -m pytest tests/test_nvd_tool.py -v
python -m pytest tests/test_pipeline_integration.py -v

# Harness 架構驗證
python harness/constraints/arch_linter.py
python harness/entropy/entropy_scanner.py
```

---

## 5. 輸出格式

執行成功後，終端機會輸出完整 JSON：

```json
{
  "executive_summary": "1 actively exploited chain detected...",
  "actions": {
    "urgent": [{"cve_id": "...", "action": "...", "command": "..."}],
    "important": [...],
    "resolved": []
  },
  "risk_score": 85,
  "risk_trend": "+10",
  "pipeline_meta": {
    "pipeline_version": "3.0",
    "stages_completed": 4,
    "stages_detail": {
      "scout": {"status": "SUCCESS", "vuln_count": 9},
      "analyst": {"status": "SUCCESS", "risk_score": 85},
      "critic": {"status": "SUCCESS", "verdict": "MAINTAIN"},
      "advisor": {"status": "SUCCESS", "urgent_count": 2}
    },
    "critic_verdict": "MAINTAIN",
    "critic_score": 80.5,
    "duration_seconds": 45.2,
    "degradation": {"level": 1, "label": "⚡ 全速運行"}
  }
}
```

---

## 6. 常見問題

### Q1: 出現 "未配置任何 LLM 供應商"

**解法**：在 `.env` 中設定 `OPENROUTER_API_KEY`。

### Q2: Scout 回傳 0 個漏洞

**可能原因**：
- NVD API Key 未設定或無效
- 套件名稱不正確（使用 `package_map.json` 對照）
- 網路連線問題

**解法**：檢查 `data/nvd_cache/` 是否有離線快取。

### Q3: LLM 回應太慢

**解法**：
- 檢查 `LLM_RPM` 設定（預設 20）
- 確認使用的是 `:free` 模型還是付費模型
- 考慮切換到 `gpt-4o-mini` 備案

### Q4: 記憶檔案遺失

**解法**：建立空的 JSON 檔案：
```bash
echo {} > memory/scout_memory.json
echo {} > memory/analyst_memory.json
echo {} > memory/advisor_memory.json
```

---

## 7. 架構一覽

```
main.py (Pipeline 控制器)
  ├── Stage 1: Scout    → agents/scout.py    → NVD + OTX 查詢
  ├── Stage 2: Analyst  → agents/analyst.py  → KEV + Exploit + Chain 分析
  ├── Stage 3: Critic   → agents/critic.py   → 對抗式辯論（可插拔）
  └── Stage 4: Advisor  → agents/advisor.py  → 行動報告生成
```

每個 Stage 內部使用 CrewAI Crew 執行，Stage 之間由 Python 程式碼串接，確保：
- 錯誤隔離（一個 Stage 失敗不影響其他）
- Graceful Degradation（降級路徑）
- 原子步驟日誌（StepLogger）

---

*更多細節請參考 `docs/pipeline_guide.md`*
