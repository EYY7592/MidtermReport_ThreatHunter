import sys
import os
import json
import random
import time
import logging
from datetime import datetime
from unittest.mock import patch, MagicMock

# 關閉所有 logger 輸出，避免 20,000 筆測試的 console I/O 拖垮效能
logging.disable(logging.CRITICAL)

# 將專案根目錄加入 PATH，確保可成功 import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
config.ENABLE_CRITIC = True

from agents.advisor import run_advisor_pipeline
from agents.critic import run_critic_pipeline

random.seed(42)

advisor_results = {"success": 0, "fallback": 0, "exception_escaped": 0, "issues": [], "latency": []}
critic_results = {"success": 0, "fallback": 0, "exception_escaped": 0, "issues": [], "latency": []}

class MockKickoffResult:
    def __init__(self, raw_str):
        self.raw = raw_str

def advisor_semantic_fuzzing():
    print("🚀 [1/2] 啟動 Advisor Agent 破綻打擊測試 (10,000 次疊代)...")
    base_input = {
        "vulnerabilities": [{"cve_id": "CVE-2024-TEST", "severity": "CRITICAL", "cvss_score": 10.0}]
    }
    
    for i in range(10000):
        cat = i % 4
        """
        面向定義：
        0: 分數溢位與邊界 (Boundary Fuzzing)
        1: 強迫降級繞過 (Markdown/JSON breaking)
        2: 記憶體污染
        3: SOP 邏輯違規 (CRITICAL 被放到 resolved 中)
        """
        payload_str = ""
        mock_memory = "{}"
        
        if cat == 0:
            rand_score = random.choice([-999, -0.01, 100.1, 9999, "not_a_number", None])
            payload_str = json.dumps({
                "executive_summary": "Test", 
                "actions": {"urgent":[],"important":[],"resolved":[]}, 
                "risk_score": rand_score, 
                "risk_trend": "+0"
            })
        elif cat == 1:
            if random.random() > 0.5:
                # 破窗 JSON (缺括號)
                payload_str = "```json\n{ \"executive_summary\": \"Broken...", 
            else:
                # 根本沒有 JSON
                payload_str = "I cannot parse this, but the risk is high."
        elif cat == 2:
            # 測試: is_repeated 特徵是否能正確應對破損的記憶體
            payload_str = json.dumps({
                "executive_summary": "Test", 
                "actions": {"urgent":[{"cve_id": "CVE-2024-TEST", "package": "django", "action": "update"}],
                            "important":[],"resolved":[]}, 
                "risk_score": 85, 
                "risk_trend": "+0"
            })
            mock_memory = json.dumps({"history": [{"actions": {"urgent": [{"cve_id": "CVE-2024-TEST"}], "important": []}}]})
        elif cat == 3:
            # 悖論: 雖然分數是 10.0 CRITICAL，但被放入 resolved（錯誤的 SOP 判斷）
            payload_str = json.dumps({
                "executive_summary": "Test", 
                "actions": {"urgent":[],"important":[],
                            "resolved":[{"cve_id": "CVE-2024-TEST", "severity": "CRITICAL", "cvss_score": 10.0}]}, 
                "risk_score": 20, 
                "risk_trend": "+0"
            })
            
        start_time = time.time()
        
        # 不要去 patch read_memory.run 因為它是一個 Tool 物件的動態屬性，會造成 3.12 AttributeError
        # 我們直接寫入真實的檔案來塞入 mock_memory
        if mock_memory != "{}":
            with open("advisor_memory.json", "w", encoding="utf-8") as f:
                f.write(mock_memory)
                
        with patch('crewai.Crew.kickoff', return_value=MockKickoffResult(payload_str)):
             
            try:
                out = run_advisor_pipeline(base_input)
                dur = time.time() - start_time
                advisor_results["latency"].append(dur)
                
                if out.get("_harness_fallback"):
                    advisor_results["fallback"] += 1
                else:
                    advisor_results["success"] += 1
                    
                # ==========================
                # 核心分析：檢查 Agent 是否暴露出缺陷
                # ==========================
                if cat == 3:
                    resolved_len = len(out.get("actions", {}).get("resolved", []))
                    if resolved_len > 0:
                        advisor_results["issues"].append("SOP Fallback 缺陷: Harness 允許 CVSS 10.0 的 CVE 分派至 'resolved'，完全未糾正 LLM 的錯誤邏輯。")
                        
                if cat == 0:
                    score = out.get("risk_score")
                    # 如果不是數字、或小於 0、或大於 100
                    if not isinstance(score, (int, float)) or not (0 <= score <= 100):
                        advisor_results["issues"].append(f"邊界檢查缺陷: risk_score 溢出 ({score}) 未被 Layer 3 攔截。")
                        
            except Exception as e:
                advisor_results["exception_escaped"] += 1
                advisor_results["issues"].append(f"防護崩潰異常: {type(e).__name__} 穿透到了最外層。")


def critic_semantic_fuzzing():
    print("🚀 [2/2] 啟動 Critic Agent 破綻打擊測試 (10,000 次疊代)...")
    base_analyst = {
        "analysis": [{"cve_id": "CVE-Y", "chain_risk": {"is_chain": True, "confidence": "HIGH"}}]
    }
    
    for i in range(10000):
        cat = i % 4
        """
        面向定義：
        0: 五維評分卡極端邊界 (浮點數邊界與 verdict 枚舉)
        1: 強制拒絕對話/極端欄位
        2: Schema 嚴重缺失 (測試合併 fallback 邏輯)
        3: 無法解析的降級攻擊
        """
        payload_str = ""
        if cat == 0:
            rand_score = random.choice([49.999, 50.001, -2.5, 1.25, "NaN"])
            rand_verdict = random.choice(["MAINTAIN", "DOWNGRADE", "SKIPPED", "KILL_PROCESS", ""])
            payload_str = json.dumps({
                "debate_rounds": 1, "challenges": [],
                "scorecard": {"evidence": rand_score, "chain_completeness": 0.5, "critique_quality": 0.5, "defense_quality": 0.5, "calibration": 0.5},
                "weighted_score": rand_score, "verdict": rand_verdict, "reasoning": "Test."
            })
        elif cat == 1:
            # 空集合，刻意使 verdict 遺失
            payload_str = "{}"
        elif cat == 2:
            # 漏掉兩項維度，並測試這是否會導致 KeyError
            payload_str = json.dumps({
                "debate_rounds": 1, "challenges": [], 
                "scorecard": {"evidence": 0.5, "chain_completeness": 0.5}, 
                "weighted_score": 50, "verdict": "MAINTAIN"
            })
        elif cat == 3:
            # 攻擊正則表達式
            payload_str = "```json\n[This is definitely not a dict]```"
            
        start_time = time.time()
        
        with patch('crewai.Crew.kickoff', return_value=MockKickoffResult(payload_str)):
             
            try:
                out = run_critic_pipeline(base_analyst)
                dur = time.time() - start_time
                critic_results["latency"].append(dur)
                
                if out.get("_harness_fallback") or out.get("_harness_skipped"):
                    critic_results["fallback"] += 1
                else:
                    critic_results["success"] += 1
                    
                # ==========================
                # 核心分析：檢查 Agent 是否暴露出缺陷
                # ==========================
                if cat == 0:
                    v = out.get("verdict")
                    if v not in ["MAINTAIN", "DOWNGRADE", "SKIPPED"]:
                        critic_results["issues"].append(f"列舉值檢查缺陷: 不合法 verdict '{v}' 未被 Layer 3 替換。")
                        
                if cat == 2:
                    sc = out.get("scorecard", {})
                    if "calibration" not in sc:
                        critic_results["issues"].append("Schema 補全缺陷: Layer 2 合併 Fallback 時覆蓋失敗，遺漏了 calibration 等欄位。")
                        
            except Exception as e:
                import traceback
                tb_lines = traceback.format_exc().strip().splitlines()
                # 取最後兩行（錯誤類型 + 行號）
                short_tb = " | ".join(tb_lines[-2:]) if len(tb_lines) >= 2 else str(e)
                critic_results["exception_escaped"] += 1
                critic_results["issues"].append(f"防護崩潰異常: {type(e).__name__} — {short_tb}")

if __name__ == "__main__":
    t0 = time.time()
    advisor_semantic_fuzzing()
    critic_semantic_fuzzing()
    t1 = time.time()
    
    from collections import Counter
    ad_issues = dict(Counter(advisor_results["issues"]))
    cr_issues = dict(Counter(critic_results["issues"]))
    
    # 移除龐大的細節資料
    del advisor_results["issues"]
    del critic_results["issues"]
    del advisor_results["latency"]
    del critic_results["latency"]
    
    report = {
        "execution_time_seconds": round(t1 - t0, 3),
        "iterations_per_agent": 10000,
        "total_test_cases": 20000,
        "advisor": advisor_results,
        "advisor_defects_found": ad_issues,
        "critic": critic_results,
        "critic_defects_found": cr_issues
    }
    
    out_path = os.path.join("docs", "stress_test_data.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
        
    print(f"\n✅ 20,000 筆測試執行完成！總耗時: {t1-t0:.3f} 秒")
    print(f"📊 測試數據已保存至: {out_path}")
