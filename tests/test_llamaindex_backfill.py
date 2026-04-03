"""
測試 LlamaIndex 回填：開啟 RAG 後，現有 JSON 歷史是否自動向量化
"""
import sys, os, json, logging
sys.path.insert(0, '.')
logging.basicConfig(level=logging.INFO, format="%(message)s", handlers=[logging.StreamHandler(sys.stdout)])

from dotenv import load_dotenv
load_dotenv(override=True)

print("=== LlamaIndex Backfill Test ===")
print(f"ENABLE_MEMORY_RAG = {os.getenv('ENABLE_MEMORY_RAG')}")
print()

# 刪除現有 vector_store，讓 _init_rag 走「新建 + 回填」分支
import shutil
vector_store_path = "memory/vector_store"
if os.path.exists(vector_store_path):
    for f in os.listdir(vector_store_path):
        if f.endswith('.json'):
            os.remove(os.path.join(vector_store_path, f))
    print("[RESET] vector_store JSON 已清除，模擬首次開啟")
else:
    print("[INFO] vector_store 不存在，將新建")

# 觸發 _init_rag（通過呼叫 history_search）
from tools.memory_tool import history_search, write_memory

# 第一次呼叫 history_search 會觸發 _init_rag -> _backfill_from_json_history
print("\n=== Step 1: 觸發 _init_rag + 自動回填 ===")
result = history_search.run(query="Django 漏洞")
print("history_search 結果:", result[:200] if len(result) > 200 else result)

# 確認 vector_store 檔案是否建立
print("\n=== Step 2: 確認 vector_store 檔案 ===")
if os.path.exists(vector_store_path):
    files = os.listdir(vector_store_path)
    for f in files:
        if not f.endswith('.gitkeep'):
            size = os.path.getsize(os.path.join(vector_store_path, f))
            print(f"  {f}: {size} bytes")
    if any(f.endswith('.json') for f in files):
        print("[PASS] LlamaIndex 向量資料庫已建立！")
    else:
        print("[FAIL] 未找到向量資料庫檔案")
else:
    print("[FAIL] vector_store 目錄不存在")

# 測試語義搜尋
print("\n=== Step 3: 語義搜尋測試 ===")
queries = ["Django high severity", "Redis remote code execution", "CRITICAL vulnerability"]
for q in queries:
    r = history_search.run(query=q)
    found = "No history" not in r and "No relevant" not in r and len(r) > 20
    print(f"  query='{q}' -> {'[FOUND]' if found else '[EMPTY]'}")
    if found:
        print(f"    {r[:120]}...")
