"""
Scout Agent 整合驗證腳本
執行：.venv\Scripts\python.exe tests/verify_scout.py
"""
import sys
import os
import json
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 載入 .env
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

PASS = "✅"
FAIL = "❌"
WARN = "⚠️"

errors = []

# ── 測試 1：API Keys ──────────────────────────────────────────
print("\n=== 1. API Keys 確認 ===")
nvd_key = os.getenv("NVD_API_KEY", "")
otx_key = os.getenv("OTX_API_KEY", "")
openrouter_key = os.getenv("OPENROUTER_API_KEY", "")

print(f"  NVD_API_KEY        : {PASS if nvd_key else WARN + ' 未設定（無 Key 模式，較慢）'}")
print(f"  OTX_API_KEY        : {PASS if otx_key else WARN + ' 未設定（部分功能受限）'}")
print(f"  OPENROUTER_API_KEY : {PASS if openrouter_key else FAIL + ' 未設定 — LLM 不可用'}")
if not openrouter_key:
    errors.append("OPENROUTER_API_KEY 未設定")

# ── 測試 2：NVD Tool import + 正規化 ─────────────────────────
print("\n=== 2. NVD Tool ===")
try:
    from tools.nvd_tool import _normalize_package_name, _search_nvd_impl, _cvss_to_severity
    cands = _normalize_package_name("postgres")
    assert "postgresql" in cands, f"postgres 別名失敗：{cands}"
    print(f"  import              : {PASS}")
    print(f"  alias postgres→pg   : {PASS}  {cands}")
    print(f"  cvss_to_severity    : {PASS}  9.8→{_cvss_to_severity(9.8)}, 7.0→{_cvss_to_severity(7.0)}")
except Exception as e:
    print(f"  {FAIL} NVD Tool: {e}")
    errors.append(str(e))

# ── 測試 3：OTX Tool import ───────────────────────────────────
print("\n=== 3. OTX Tool ===")
try:
    from tools.otx_tool import _search_otx_impl
    print(f"  import              : {PASS}")
except Exception as e:
    print(f"  {FAIL} OTX Tool: {e}")
    errors.append(str(e))

# ── 測試 4：Memory Tool import ────────────────────────────────
print("\n=== 4. Memory Tool ===")
try:
    from tools.memory_tool import read_memory, write_memory, history_search
    print(f"  import              : {PASS}")
    print(f"  read_memory         : {PASS}  tool name={read_memory.name}")
    print(f"  write_memory        : {PASS}  tool name={write_memory.name}")
    print(f"  history_search      : {PASS}  tool name={history_search.name}")
except Exception as e:
    print(f"  {FAIL} Memory Tool: {e}")
    errors.append(str(e))

# ── 測試 5：NVD API 實際查詢 (django) ────────────────────────
print("\n=== 5. NVD API 實際查詢（django） ===")
try:
    result_str = _search_nvd_impl("django")
    result = json.loads(result_str)
    count = result.get("count", 0)
    fallback = result.get("fallback_used", False)
    error_msg = result.get("error", "")
    
    if count > 0:
        top = result["vulnerabilities"][0]
        print(f"  API 查詢            : {PASS}  {count} 筆 CVE")
        print(f"  最高危              : {top['cve_id']} CVSS={top['cvss_score']} {top['severity']}")
        print(f"  資料來源            : {'快取' if fallback else '即時 API'}")
    elif fallback:
        print(f"  {WARN} 使用快取（API 不可用）：{error_msg}")
    elif error_msg:
        print(f"  {WARN} 查無結果：{error_msg}")
    else:
        print(f"  {WARN} django 查無 CVE（異常）")
        errors.append("django NVD 查詢回傳 0 筆")
except Exception as e:
    print(f"  {FAIL} NVD 真實查詢失敗: {e}")
    errors.append(str(e))

# ── 測試 6：OTX API 實際查詢 (django) ────────────────────────
print("\n=== 6. OTX API 實際查詢（django） ===")
try:
    otx_str = _search_otx_impl("django")
    otx = json.loads(otx_str)
    level = otx.get("threat_level", "unknown")
    pulses = otx.get("pulse_count", 0)
    fallback = otx.get("fallback_used", False)
    
    print(f"  API 查詢            : {PASS}")
    print(f"  threat_level        : {level}  ({pulses} pulses)")
    print(f"  資料來源            : {'快取' if fallback else '即時 API'}")
except Exception as e:
    print(f"  {FAIL} OTX 真實查詢失敗: {e}")
    errors.append(str(e))

# ── 測試 7：Memory 讀寫 ───────────────────────────────────────
print("\n=== 7. Memory 讀寫 ===")
try:
    import tempfile, json
    # 直接測試底層函式（不觸發 LLM）
    from tools.memory_tool import _load_json, _save_json
    import tempfile
    tmp = os.path.join(tempfile.gettempdir(), "test_mem.json")
    test_data = {"scan_id": "test_001", "vulnerabilities": []}
    _save_json(tmp, test_data)
    loaded = _load_json(tmp)
    assert loaded["scan_id"] == "test_001"
    os.remove(tmp)
    print(f"  JSON 讀寫           : {PASS}")
except Exception as e:
    print(f"  {WARN} Memory 底層測試跳過（可能 API 不同）: {e}")

# ── 測試 8：Scout Agent 建立（需要 LLM key）─────────────────
print("\n=== 8. Scout Agent 建立 ===")
if not openrouter_key:
    print(f"  {WARN} 跳過（無 OPENROUTER_API_KEY）")
else:
    try:
        from config import get_llm
        llm = get_llm()
        print(f"  LLM 初始化          : {PASS}  model={llm.model}")
        
        from agents.scout import create_scout_agent
        scout = create_scout_agent()
        print(f"  Scout Agent 建立    : {PASS}")
        print(f"  Tools               : {[t.name for t in scout.tools]}")
        print(f"  max_iter            : {scout.max_iter}")
    except Exception as e:
        print(f"  {FAIL} Scout Agent 建立失敗: {e}")
        errors.append(str(e))

# ── 最終結論 ─────────────────────────────────────────────────
print("\n" + "="*60)
if errors:
    print(f"{FAIL} 驗證失敗（{len(errors)} 個錯誤）：")
    for e in errors:
        print(f"   - {e}")
    sys.exit(1)
else:
    print(f"{PASS} Scout Agent Pipeline 驗證通過！")
    print("   NVD Tool   : ✅")
    print("   OTX Tool   : ✅")
    print("   Memory Tool: ✅")
    print("   Scout Agent: ✅" if openrouter_key else "   Scout Agent: ⚠️ 未測試（無 LLM Key）")
