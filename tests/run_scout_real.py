"""
真實 Scout Agent Pipeline 執行腳本 v2 (no emoji, full trace)
"""
import sys, os, json, logging, traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(name)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
for noisy in ["httpx", "httpcore", "litellm", "openai", "LiteLLM", "crewai"]:
    logging.getLogger(noisy).setLevel(logging.ERROR)

from dotenv import load_dotenv
load_dotenv()

print("=" * 60)
print("ThreatHunter - Scout Agent Real Run")
print("Tech Stack: Django 4.2, Redis 7.0")
print("=" * 60)

try:
    from agents.scout import run_scout_pipeline
    result = run_scout_pipeline("Django 4.2, Redis 7.0")

    print("\n=== SCAN RESULT ===")
    summary = result.get("summary", {})
    vulns = result.get("vulnerabilities", [])
    print(f"  Total CVE : {summary.get('total', 0)}")
    print(f"  New       : {summary.get('new_since_last_scan', 0)}")
    print(f"  CRITICAL  : {summary.get('critical', 0)}")
    print(f"  HIGH      : {summary.get('high', 0)}")
    print(f"  MEDIUM    : {summary.get('medium', 0)}")
    print(f"  LOW       : {summary.get('low', 0)}")

    print("\nTop 5 CVE:")
    for v in sorted(vulns, key=lambda x: x.get("cvss_score", 0), reverse=True)[:5]:
        new_tag = "[NEW]" if v.get("is_new") else "     "
        print(f"  {new_tag} {v.get('cve_id','?')} [{v.get('severity','?')}:{v.get('cvss_score',0):.1f}] pkg={v.get('package','?')}")

    mem_path = "memory/scout_memory.json"
    if os.path.exists(mem_path):
        size = os.path.getsize(mem_path)
        print(f"\n  [OK] scout_memory.json written ({size} bytes)")
    else:
        print(f"\n  [WARN] scout_memory.json not found")

    print("\n[OK] Scout Agent pipeline completed successfully")

except ValueError as e:
    if "None or empty" in str(e):
        print(f"\n[ERROR] LLM returned empty response.")
        print("Possible cause: context too long (NVD data > LLM token limit)")
        print("Fix: Reduce RESULTS_PER_PAGE in nvd_tool.py (currently 10)")
        print(f"Details: {e}")
    else:
        traceback.print_exc()
except Exception as e:
    print(f"\n[ERROR] {type(e).__name__}: {e}")
    traceback.print_exc()
