"""
快速驗證 CVE 年份過濾邏輯
"""
import sys
sys.path.insert(0, ".")

from agents.analyst import _harness_filter_ancient_cves, _CVE_YEAR_CUTOFF

output = {
    "analysis": [
        {"cve_id": "CVE-1999-0967", "chain_risk": {"confidence": "HIGH", "is_chain": False, "chain_with": [], "chain_description": ""}},
        {"cve_id": "CVE-2024-1234", "chain_risk": {"confidence": "HIGH", "is_chain": False, "chain_with": [], "chain_description": ""}},
        {"cve_id": "CVE-2003-0442", "chain_risk": {"is_chain": False, "chain_with": [], "chain_description": ""}},
        {"cve_id": "CVE-2005-0001", "chain_risk": {"confidence": "MEDIUM", "is_chain": False, "chain_with": [], "chain_description": ""}},
    ]
}

_harness_filter_ancient_cves(output)

print(f"CVE_YEAR_CUTOFF = {_CVE_YEAR_CUTOFF}")
print()
all_pass = True
for item in output["analysis"]:
    cve = item["cve_id"]
    conf = item.get("chain_risk", {}).get("confidence", "N/A")
    warn = item.get("_ancient_cve_warning", "")
    year = int(cve.split("-")[1])

    if year < _CVE_YEAR_CUTOFF:
        expected_conf = "NEEDS_VERIFICATION"
        expected_warn = True
    else:
        expected_conf = None  # unchanged
        expected_warn = False

    ok_warn = bool(warn) == expected_warn
    ok_conf = (conf == expected_conf) if expected_conf else True
    status = "PASS" if (ok_warn and ok_conf) else "FAIL"
    if status == "FAIL":
        all_pass = False

    print(f"  [{status}] {cve}: confidence={conf}, warning={'YES' if warn else 'NO'}")

print()
print("ALL PASS" if all_pass else "SOME TESTS FAILED")
