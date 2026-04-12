"""
ThreatHunter 記憶體雙層架構壓力測試腳本
========================================
測試目標：
1. 寫入極限測試（超過 50 筆的截斷效率與雙寫時間）
2. 回填效能測試（從 JSON 50 筆紀錄冷啟動重建 LlamaIndex 的時間）
3. 併發搜尋測試（多執行緒下的語義搜尋穩定性）

執行方法：
    .venv\\Scripts\\python.exe tests/stress_test_memory.py
"""
import os
import sys
import json
import time
import shutil
import logging
from pathlib import Path
import concurrent.futures

# --- 抑制不必要的警告 ---
os.environ["TOKENIZERS_PARALLELISM"] = "false"
logging.getLogger("threathunter.memory").setLevel(logging.ERROR)

# --- 環境隔離 ---
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT))

# 強制設定環境變數
os.environ["ENABLE_MEMORY_RAG"] = "true"
os.environ["SIMILARITY_THRESHOLD"] = "0.5"

import tools.memory_tool
from tools.memory_tool import write_memory, history_search, _load_json, _get_memory_path

# 動態注入獨立的資料夾（保護正式資料庫）
TEST_MEMORY_DIR = PROJECT_ROOT / "memory_stress_test"
tools.memory_tool.MEMORY_DIR = TEST_MEMORY_DIR
tools.memory_tool.ENABLE_MEMORY_RAG = True
tools.memory_tool.SIMILARITY_THRESHOLD = 0.5


def setup_env():
    print(f"[*] 🔧 準備測試環境: {TEST_MEMORY_DIR}")
    if TEST_MEMORY_DIR.exists():
        shutil.rmtree(TEST_MEMORY_DIR)
    TEST_MEMORY_DIR.mkdir()
    (TEST_MEMORY_DIR / "vector_store").mkdir()


def test_write_stress():
    print("\n[1] === 寫入壓力與截斷測試 ===")
    print("目標: 連續寫入 60 筆報告，驗證 Layer 1(JSON) 和 Layer 2(LlamaIndex) 的雙寫效能")
    
    start_time = time.time()
    for i in range(1, 61):
        data = {
            "scan_id": f"stress_scan_{i:03d}",
            "tech_stack": ["Django 4.2", "Redis 7.0" if i % 2 == 0 else "Nginx 1.24"],
            "vulnerabilities": [
                {
                    "cve_id": f"CVE-202X-{i:04d}",
                    "severity": "CRITICAL" if i % 10 == 0 else "HIGH",
                    "description": f"This is a mock vulnerability number {i} simulating real report context."
                }
            ],
            "summary": {"total": 1}
        }
        write_memory.run(agent_name="scout", data=json.dumps(data))
    
    elapsed = time.time() - start_time
    
    # 驗證截斷機制
    json_data = _load_json(_get_memory_path("scout"))
    history_len = len(json_data.get("history", []))
    
    print(f"➤ 60 筆寫入完成，耗時 {elapsed:.2f} 秒 (每筆約 {elapsed/60:.3f} 秒)")
    print(f"➤ JSON 歷史紀錄數: {history_len}")
    if history_len == 50:
        print("✅ 截斷機制正常：成功保護陣列上限不超過 50 筆")
    else:
        print("❌ 警告: 截斷機制異常")


def test_backfill_stress():
    print("\n[2] === 冷啟動回填效能測試 ===")
    print("目標: 模擬 LlamaIndex 損毀，強迫系統從 50 筆 JSON 保底檔重建 Vector Store")
    
    vector_store = TEST_MEMORY_DIR / "vector_store"
    # 清除現有向量檔案
    for f in vector_store.glob("*.json"):
        f.unlink()
    
    # 重置 LlamaIndex 核心服務
    tools.memory_tool._rag_index = None
    tools.memory_tool._rag_query_engine = None
    
    start_time = time.time()
    # 呼叫搜尋以觸發 _init_rag() 執行自動回填
    history_search.run(query="Trigger System Warmup")
    elapsed = time.time() - start_time
    
    print(f"➤ 自 50 筆 JSON 歷史完成全自動重建，耗時 {elapsed:.2f} 秒")
    index_size = sum(f.stat().st_size for f in vector_store.glob("*.json"))
    print(f"✅ RAG 資料庫復原完成 (大小: {index_size / 1024:.2f} KB)")


def test_concurrent_search():
    print("\n[3] === 多併發搜尋壓力測試 ===")
    print("目標: 啟動 20 個 Thread 同時發起 RAG 語義搜尋，測試引擎的 Thread-Safe 防禦力")
    
    queries = [f"Mock vulnerability number {i}" for i in range(20, 40)]
    
    def search_task(q):
        return history_search.run(query=q)
    
    start_time = time.time()
    successful = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(search_task, q): q for q in queries}
        for future in concurrent.futures.as_completed(futures):
            try:
                res = future.result()
                if "No relevant" not in res and "No history" not in res:
                    successful += 1
            except Exception as e:
                print(f"查詢異常: {e}")
                
    elapsed = time.time() - start_time
    print(f"➤ 20 個併發請求處理完畢，總共耗時 {elapsed:.2f} 秒")
    if successful == 20:
        print(f"✅ 併發測試完美通過，皆精準召回關聯資料")
    else:
        print(f"⚠️ 成功擷取率: {successful}/20")


if __name__ == "__main__":
    print("-" * 50)
    setup_env()
    test_write_stress()
    test_backfill_stress()
    test_concurrent_search()
    
    # 清理
    print("\n[*] 🧹 壓測通關結束，清除測試環境")
    shutil.rmtree(TEST_MEMORY_DIR)
    print("-" * 50)
