"""
input_sanitizer.py — L0 確定性輸入净化器
==========================================
架構位置：Pipeline 最前端（在 CrewAI 啟動前執行）

依據：
  - FINAL_PLAN.md §3a：[⚙️ input_sanitizer.py] ← 確定性基礎設施（OWASP LLM01:2025）
  - OWASP LLM01:2025 Prompt Injection — 不可信輸入在進入 LLM 前必須先過濾

設計原則：
  - 純確定性運算（無 LLM、無外部 API）
  - 與 security_guard.py 的分工：
      input_sanitizer → 守門（Pipeline 前）：截斷 + L0 正則掃描 + 禁區關鍵字過濾
      security_guard  → 提取（CrewAI 內）：AST/正則程式碼結構提取，不做判斷

層級邊界：應用層（不引用 harness/entropy 層）
"""
from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("threathunter.input_sanitizer")

# ══════════════════════════════════════════════════════════════
# 常數
# ══════════════════════════════════════════════════════════════

MAX_INPUT_LENGTH = 50_000  # 超過此長度截斷（避免 prompt flooding）
MAX_LINE_COUNT   = 2_000   # 超過此行數截斷（避免超長函式轟炸）

# L0 正則掃描：確定性找可疑模式（SQL/Command Injection / 硬編碼憑證 / eval）
# 這些是「通報」而非「阻擋」——仍然繼續處理，但標記給 Security Guard
L0_PATTERNS: list[tuple[str, str, str]] = [
    # (name, regex_pattern, description)
    (
        "sql_injection",
        r"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|CREATE|ALTER)\s+.{0,100}?\s*['\";]",
        "SQL 語句疑似拼接（SQL Injection 風險）",
    ),
    (
        "os_command",
        r"(?i)(os\.system|subprocess\.call|subprocess\.run|popen|exec\(|eval\()\s*[\(\['\"]",
        "危險系統呼叫（OS Command Injection 風險）",
    ),
    (
        "hardcoded_secret",
        r"(?i)(password|passwd|pwd|secret|api_key|apikey|token|auth)\s*=\s*['\"][^'\"]{4,}['\"]",
        "硬編碼憑證（Credential Exposure 風險）",
    ),
    (
        "path_traversal",
        r"\.{2,}/|\.{2,}\\",
        "路徑穿越嘗試（Path Traversal 風險）",
    ),
    (
        "template_injection",
        r"\{\{.{0,100}?\}\}|\{%.*?%\}",
        "模板語法（Template Injection 風險）",
    ),
    (
        "xml_entity",
        r"<!ENTITY|<!DOCTYPE\s+\w+\s+\[",
        "XML 外部實體（XXE 風險）",
    ),
    (
        "prompt_override",
        r"(?i)(ignore\s+previous\s+instructions?|forget\s+all\s+previous|you\s+are\s+now\s+a|act\s+as\s+(a|an)\s+(different|new|evil|unrestricted))",
        "Prompt Injection 嘗試（OWASP LLM01）",
    ),
    (
        "jailbreak",
        r"(?i)(DAN|jailbreak|do\s+anything\s+now|no\s+restrictions?\s+mode|developer\s+mode)",
        "越獄嘗試（OWASP LLM01）",
    ),
]

# 完全禁止通過的關鍵字（比 L0 正則更嚴格）
# 這些是高信心惡意模式，直接拒絕而非標記
BLOCKLIST_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)\bDROP\s+TABLE\b",            "偵測到 DROP TABLE 語句"),
    (r"(?i)\bxp_cmdshell\b",             "SQL Server 命令執行指令"),
    (r"(?i)\bSHUTDOWN\s+WITH\s+NOWAIT\b", "資料庫關機指令"),
]


# ══════════════════════════════════════════════════════════════
# 資料結構
# ══════════════════════════════════════════════════════════════

@dataclass
class L0Finding:
    """L0 掃描的單一發現"""
    pattern_name: str
    description:  str
    line_no:      int
    matched_text: str     # 截斷至 100 字符，避免回顯惡意內容
    severity:     str     # "WARNING" | "INFO"


@dataclass
class SanitizeResult:
    """
    淨化結果。

    Attributes:
        safe:            是否允許進入 Pipeline（False 時應拒絕）
        blocked_reason:  若 safe=False，說明原因
        truncated:       輸入是否被截斷
        original_length: 原始長度
        sanitized_input: 截斷後的淨化輸入（供 Pipeline 使用）
        l0_findings:     L0 正則掃描發現（WARNING 級別，仍允許進入但標記）
        input_hash:      SHA-256 前 16 字元（用於去重 / 日誌追蹤）
        input_type:      推斷的輸入類型
    """
    safe:            bool
    sanitized_input: str
    truncated:       bool
    original_length: int
    l0_findings:     list[L0Finding] = field(default_factory=list)
    blocked_reason:  str = ""
    input_hash:      str = ""
    input_type:      str = "unknown"


# ══════════════════════════════════════════════════════════════
# 輸入類型推斷
# ══════════════════════════════════════════════════════════════

def _infer_input_type(text: str) -> str:
    """
    推斷輸入類型，供 Orchestrator 路由決策參考。

    v3.1：支援多語言程式碼偵測（Python/JS/TS/Java/Go/PHP/Ruby/Rust/C/C++）。

    Returns:
        "package_list"  → 套件清單（路徑 A）
        "source_code"   → 程式碼（路徑 B）
        "config_file"   → 配置文件（路徑 C）
        "mixed"         → 混合（預設路徑 B）
    """
    # 程式碼特徵（多語言）
    code_signals = [
        # Python
        bool(re.search(r"^\s*(def |class |import |from \w+\s+import )", text, re.MULTILINE)),
        # JavaScript / TypeScript
        bool(re.search(r"(?:const|let|var)\s+\w+\s*=|=>\s*\{|require\s*\(|export\s+(?:default|const|function)", text, re.MULTILINE)),
        # Java
        bool(re.search(r"(?:public|private|protected)\s+(?:static\s+)?(?:class|void|int|String)\s+\w+", text, re.MULTILINE)),
        # Go
        bool(re.search(r"^(?:package\s+\w+|func\s+\w+|:=)", text, re.MULTILINE)),
        # PHP
        bool(re.search(r"<\?php|\$\w+\s*=", text)),
        # Ruby
        bool(re.search(r"^\s*(?:def\s+\w+|require\s+['\"]|module\s+\w+|class\s+\w+\s*<)", text, re.MULTILINE)),
        # Rust
        bool(re.search(r"(?:fn\s+\w+|let\s+mut\s+|impl\s+\w+|use\s+\w+::)", text, re.MULTILINE)),
        # C / C++
        bool(re.search(r"#include\s*[<\"]|int\s+main\s*\(|printf\s*\(|std::", text, re.MULTILINE)),
        # Shebang
        bool(re.search(r"^#!\/", text)),
        # 通用：大括號語言 + 多行
        bool(re.search(r"[{}();]", text)) and text.count("\n") > 5,
    ]

    # 套件清單特徵：`name==version` 或 `name>=version` 或單純名稱列表
    pkg_signals = [
        bool(re.search(r"^[\w\-\.]+[>=<!~^]{0,2}[\d\.]*$", text.strip(), re.MULTILINE)),
        bool(re.search(r"(requirements|package|dependency|pip install|npm install|go get)", text, re.IGNORECASE)),
        "," in text and "\n" not in text,  # 逗號分隔套件名（單行）
    ]

    # 配置文件特徵
    config_signals = [
        bool(re.search(r"^\[.*\]$", text, re.MULTILINE)),  # INI [section]
        bool(re.search(r"^[\w\-]+:\s+\S", text, re.MULTILINE)),  # YAML key: value
        "<?xml" in text.lower(),
        bool(re.search(r"^FROM\s+\S+", text, re.MULTILINE)),  # Dockerfile FROM
        bool(re.search(r"^(WORKDIR|EXPOSE|ENV|ARG|CMD|RUN|COPY|ADD)\s+", text, re.MULTILINE)),  # Dockerfile 指令
    ]

    code_score   = sum(code_signals)
    pkg_score    = sum(pkg_signals)
    config_score = sum(config_signals)

    if config_score >= 2:
        return "config_file"
    if code_score >= 2:
        return "source_code"
    if pkg_score >= 2:
        return "package_list"
    if code_score >= 1:
        return "source_code"
    return "package_list"  # 預設：套件掃描（最安全的路徑 A）


# ══════════════════════════════════════════════════════════════
# 核心淨化函式
# ══════════════════════════════════════════════════════════════

def sanitize_input(raw_input: str) -> SanitizeResult:
    """
    對原始用戶輸入進行確定性淨化。

    流程：
    1. 計算 input_hash（用於日誌追蹤）
    2. 截斷超長輸入
    3. Blocklist 掃描（高信心惡意 → 直接拒絕）
    4. L0 正則掃描（标記，仍允許通過）
    5. 推斷輸入類型
    6. 返回 SanitizeResult

    Args:
        raw_input: 用戶原始輸入字串

    Returns:
        SanitizeResult — 淨化後結果
    """
    if not isinstance(raw_input, str):
        raw_input = str(raw_input)

    original_length = len(raw_input)

    # ── 步驟 1：計算 hash ──────────────────────────────────────
    input_hash = hashlib.sha256(raw_input.encode("utf-8", errors="replace")).hexdigest()[:16]
    logger.debug("[SANITIZE] hash=%s original_len=%d", input_hash, original_length)

    # ── 步驟 2：截斷 ────────────────────────────────────────────
    truncated = False
    text = raw_input

    if len(text) > MAX_INPUT_LENGTH:
        text = text[:MAX_INPUT_LENGTH]
        truncated = True
        logger.warning(
            "[SANITIZE][%s] Input truncated: %d → %d chars",
            input_hash, original_length, MAX_INPUT_LENGTH,
        )

    # 超過行數也截斷
    lines = text.splitlines()
    if len(lines) > MAX_LINE_COUNT:
        text = "\n".join(lines[:MAX_LINE_COUNT])
        truncated = True
        logger.warning(
            "[SANITIZE][%s] Input truncated to %d lines", input_hash, MAX_LINE_COUNT
        )

    # ── 步驟 3：Blocklist 掃描（直接拒絕） ──────────────────────
    for block_pattern, reason in BLOCKLIST_PATTERNS:
        if re.search(block_pattern, text):
            logger.warning("[SANITIZE][%s] BLOCKED: %s", input_hash, reason)
            return SanitizeResult(
                safe=False,
                sanitized_input="",
                truncated=truncated,
                original_length=original_length,
                blocked_reason=reason,
                input_hash=input_hash,
                input_type="blocked",
            )

    # ── 步驟 4：L0 正則掃描（標記，不拒絕） ─────────────────────
    l0_findings: list[L0Finding] = []
    text_lines = text.splitlines()

    for pattern_name, pattern, description in L0_PATTERNS:
        try:
            for match in re.finditer(pattern, text):
                # 計算行號
                line_no = text[: match.start()].count("\n") + 1
                matched_snippet = match.group(0)[:100]  # 截斷，避免回顯惡意內容

                finding = L0Finding(
                    pattern_name=pattern_name,
                    description=description,
                    line_no=line_no,
                    matched_text=matched_snippet,
                    severity="WARNING" if "injection" in pattern_name or "jailbreak" in pattern_name else "INFO",
                )
                l0_findings.append(finding)
                logger.info(
                    "[SANITIZE][%s] L0 finding: %s @ line %d",
                    input_hash, pattern_name, line_no,
                )
        except re.error as e:
            logger.error("[SANITIZE] Regex error for pattern %s: %s", pattern_name, e)

    # ── 步驟 5：推斷輸入類型 ────────────────────────────────────
    input_type = _infer_input_type(text)

    logger.info(
        "[SANITIZE][%s] Result: safe=True type=%s truncated=%s l0_count=%d",
        input_hash, input_type, truncated, len(l0_findings),
    )

    return SanitizeResult(
        safe=True,
        sanitized_input=text,
        truncated=truncated,
        original_length=original_length,
        l0_findings=l0_findings,
        input_hash=input_hash,
        input_type=input_type,
    )


def format_l0_report(result: SanitizeResult) -> dict[str, Any]:
    """
    將 SanitizeResult 轉換為 Pipeline 可用的字典格式。
    供 main.py 使用，注入至 Orchestrator 的路由決策。

    Returns:
        {
            "safe": bool,
            "input_type": str,
            "truncated": bool,
            "input_hash": str,
            "l0_findings": [{"pattern": str, "description": str, "line_no": int, "severity": str}],
            "l0_warning_count": int,
            "blocked_reason": str,
        }
    """
    return {
        "safe":             result.safe,
        "input_type":       result.input_type,
        "truncated":        result.truncated,
        "input_hash":       result.input_hash,
        "blocked_reason":   result.blocked_reason,
        "l0_findings":      [
            {
                "pattern":     f.pattern_name,
                "description": f.description,
                "line_no":     f.line_no,
                "severity":    f.severity,
            }
            for f in result.l0_findings
        ],
        "l0_warning_count": sum(1 for f in result.l0_findings if f.severity == "WARNING"),
    }
