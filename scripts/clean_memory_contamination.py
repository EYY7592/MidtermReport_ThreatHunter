"""
scripts/clean_memory_contamination.py
清除 Memory 中 CVE-1999-xxxx 的汙染條目。
遵守 code.md: Surgical Changes — 只移除汙染，保留正確的 history 條目。
"""
import json
import os
import shutil
import re
import logging

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

# CVE-1999 是 NVD keywordSearch 誤報的典型特徵（年份過舊，與現代套件無關）
SUSPICIOUS_CVE_RE = re.compile(r'^CVE-19\d{2}-')

def _is_contaminated_item(item: dict) -> bool:
    """判斷一個 history 條目是否包含汙染 CVE。"""
    if not isinstance(item, dict):
        return False
    for cve in item.get("cves", []):
        if isinstance(cve, str) and SUSPICIOUS_CVE_RE.match(cve):
            return True
    for v in item.get("vulnerabilities", []):
        cid = v.get("cve_id", "") if isinstance(v, dict) else ""
        if isinstance(cid, str) and SUSPICIOUS_CVE_RE.match(cid):
            return True
    return False

def clean_memory_file(path: str) -> dict:
    """備份並清除汙染條目，回傳統計資訊。"""
    if not os.path.exists(path):
        return {"file": path, "status": "NOT_FOUND"}

    data = json.load(open(path, encoding="utf-8"))
    history = data.get("history", [])
    original_count = len(history)

    clean_history = [item for item in history if not _is_contaminated_item(item)]
    removed_count = original_count - len(clean_history)

    if removed_count == 0:
        return {"file": path, "status": "CLEAN", "removed": 0}

    # 備份
    bak_path = path + ".bak"
    shutil.copy2(path, bak_path)
    logger.info("備份到: %s", bak_path)

    # 寫回清潔版本
    data["history"] = clean_history
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    return {
        "file": path,
        "status": "CLEANED",
        "original": original_count,
        "removed": removed_count,
        "remaining": len(clean_history),
        "backup": bak_path,
    }


if __name__ == "__main__":
    targets = [
        "memory/scout_memory.json",
        "memory/advisor_memory.json",
    ]
    for path in targets:
        result = clean_memory_file(path)
        if result["status"] == "CLEANED":
            logger.info(
                "✅ %s: 移除 %d 個汙染條目，保留 %d 個",
                result["file"], result["removed"], result["remaining"]
            )
        elif result["status"] == "CLEAN":
            logger.info("✅ %s: 無汙染", result["file"])
        else:
            logger.info("⚠️  %s: %s", result["file"], result["status"])
