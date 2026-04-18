# sandbox/memory_sanitizer.py
# 功能：記憶快取寫入前的確定性毒素掃描（Sandbox Layer 3）
# 架構依據：project_CONSTITUTION.md 第七條 + Harness Engineering
#
# 防禦威脅：
#   - LLM 被 Secondary Prompt Injection 操控後輸出毒素到 memory/
#   - 下次掃描讀取受污染記憶 → 整條 Pipeline 被語義操控
#   - LLM 幻覺 CVE ID 被持久化到記憶中毒害下次分析
#
# 注意：此模組為純 Python 實作（Rust 版 memory_validator 的 fallback 亦為此）
#       在 Rust PyO3 版本不可用時自動作為主要防線

import re
import json
import logging
from typing import Any

logger = logging.getLogger("ThreatHunter.sandbox.memory_sanitizer")

# ══════════════════════════════════════════════════════════════
# 毒素模式（Prompt Injection 殘留 + XSS + SQL 殘留）
# ══════════════════════════════════════════════════════════════

_POISON_PATTERNS: list[tuple[str, re.Pattern]] = [
    # Prompt Injection 殘留
    ("PROMPT_INJECTION_IGNORE",  re.compile(r"ignore\s+(?:previous|all|above)\s+instructions?", re.I)),
    ("PROMPT_INJECTION_ROLE",    re.compile(r"you\s+are\s+now\s+(?:a|an)\s+\w+", re.I)),
    ("PROMPT_INJECTION_MODE",    re.compile(r"(?:developer|god|admin|root|jailbreak)\s+mode", re.I)),
    ("PROMPT_INJECTION_PRETEND", re.compile(r"(?:pretend|act|roleplay)\s+(?:you\s+are|as\s+if)", re.I)),
    ("PROMPT_INJECTION_DAN",     re.compile(r"\bDAN\b|\bJailbreak\b", re.I)),
    ("PROMPT_INJECTION_IGNORE2", re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)", re.I)),
    # 指令覆蓋
    ("OVERRIDE_SYSTEM",          re.compile(r"system\s+prompt\s*[:=]", re.I)),
    ("OVERRIDE_CONSTITUTION",    re.compile(r"(?:override|ignore|bypass)\s+(?:the\s+)?constitution", re.I)),
    # XSS 殘留
    ("XSS_SCRIPT",               re.compile(r"<script[^>]*>", re.I)),
    ("XSS_ONERROR",              re.compile(r"(?:onerror|onload|onclick)\s*=", re.I)),
    # SQL 殘留
    ("SQL_DROP",                 re.compile(r"\bDROP\s+TABLE\b", re.I)),
    ("SQL_DELETE_ALL",           re.compile(r"\bDELETE\s+FROM\b", re.I)),
    # 系統命令殘留
    ("CMD_RM_RF",                re.compile(r"rm\s+-rf\s+/", re.I)),
    ("CMD_SHELL",                re.compile(r"(?:;|\|)\s*(?:bash|sh|cmd|powershell)\s", re.I)),
]

# CVE ID 年份驗證正則（防幻覺 CVE 被持久化）
_CVE_YEAR_PATTERN = re.compile(r"\bCVE-(\d{4})-\d+\b", re.I)
_CVE_VALID_YEAR_MIN = 1999
_CVE_VALID_YEAR_MAX = 2027

# 快取大小上限（防 memory Bomb）
_MAX_MEMORY_SIZE_BYTES = 1_000_000   # 1 MB per agent memory entry


# ══════════════════════════════════════════════════════════════
# 主要函式
# ══════════════════════════════════════════════════════════════

def sanitize_memory_write(
    data: dict[str, Any],
    agent_name: str = "unknown",
) -> tuple[bool, dict[str, Any], str]:
    """
    驗證並淨化要寫入 memory/ 的資料。

    這是 Sandbox Layer 3 的核心函式，在所有 write_memory() 呼叫前執行。
    確保 LLM 輸出的毒素內容不被持久化到記憶快取。

    Args:
        data:       待寫入的記憶 dict（來自 LLM 輸出）
        agent_name: 呼叫的 Agent 名稱（用於日誌）

    Returns:
        tuple(is_safe: bool, cleaned_data: dict, reason: str)
            is_safe     — True 表示安全，可寫入
            cleaned_data — 清理後的資料（當 is_safe=True 時與 data 相同）
            reason      — 拒絕原因（is_safe=False 時填充）或 "ok"
    """
    # ── 1. 大小限制（防 memory Bomb）─────────────────────────
    try:
        data_str = json.dumps(data, ensure_ascii=False)
    except (TypeError, ValueError) as e:
        reason = f"Serialization failed: {e}"
        logger.warning("[SANDBOX][MEM][%s] Rejected — %s", agent_name, reason)
        return False, {}, reason

    if len(data_str.encode("utf-8")) > _MAX_MEMORY_SIZE_BYTES:
        reason = f"Memory entry too large: {len(data_str)} chars > {_MAX_MEMORY_SIZE_BYTES}"
        logger.warning("[SANDBOX][MEM][%s] Rejected — %s", agent_name, reason)
        return False, {}, reason

    # ── 2. Prompt Injection / 毒素模式掃描──────────────────────
    lower_str = data_str.lower()
    for pattern_name, regex in _POISON_PATTERNS:
        match = regex.search(data_str)
        if match:
            snippet = match.group(0)[:80]
            reason = f"Poison pattern [{pattern_name}]: '{snippet}'"
            logger.warning("[SANDBOX][MEM][%s] Rejected — %s", agent_name, reason)
            return False, {}, reason

    # ── 3. CVE ID 幻覺年份驗證──────────────────────────────────
    for m in _CVE_YEAR_PATTERN.finditer(data_str):
        year = int(m.group(1))
        if not (_CVE_VALID_YEAR_MIN <= year <= _CVE_VALID_YEAR_MAX):
            cve_full = m.group(0)
            reason = f"Hallucination CVE year {year}: '{cve_full}'"
            logger.warning("[SANDBOX][MEM][%s] Rejected — %s", agent_name, reason)
            return False, {}, reason

    # ── 4. 通過所有檢查────────────────────────────────────────
    logger.debug("[SANDBOX][MEM][%s] Write approved (%d bytes)", agent_name, len(data_str))
    return True, data, "ok"


def sanitize_memory_read(
    data: dict[str, Any],
    agent_name: str = "unknown",
) -> tuple[bool, dict[str, Any], str]:
    """
    驗證從 memory/ 讀取的資料（防止過去已寫入的毒素被載入）。

    多一道防線：即使寫入時沒被攔截（如 Sanitizer 更新前寫入的舊資料），
    讀取時也能阻止毒素注入現在的 Pipeline context。

    Args / Returns: 同 sanitize_memory_write
    """
    # 讀取時檢查條件相同，複用寫入邏輯
    return sanitize_memory_write(data, agent_name=f"{agent_name}[READ]")


# ══════════════════════════════════════════════════════════════
# 單元測試用輔助函式
# ══════════════════════════════════════════════════════════════

def is_memory_safe(data: dict[str, Any]) -> bool:
    """
    便捷函式：只返回 bool（供測試、斷言用）。
    """
    is_safe, _, _ = sanitize_memory_write(data)
    return is_safe
