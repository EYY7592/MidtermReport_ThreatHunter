# sandbox/ast_guard.py
# 功能：帶有節點數上限和 timeout 的安全 AST 解析（Sandbox Layer 1）
# 架構依據：project_CONSTITUTION.md 第七條 + Harness Engineering
#
# 防禦威脅：
#   - AST Bomb：攻擊者構造超深巢狀的 Python 語法（百萬節點）耗盡 CPython stack
#   - Infinite Parse Loop：某些刻意構造的語法讓 ast.parse 陷入超長解析
#   - 未來誤用：如果有人在 security_guard.py 加了 exec(compile(tree,...))，
#               經過此層的 timeout 保護，最多只阻塞 3 秒
#
# 設計要點：
#   - 使用 threading.Thread + join(timeout) 實現非阻塞超時
#   - 不使用 signal.alarm（Windows 不支援 SIGALRM）
#   - 節點數 > MAX_AST_NODES → 直接拒絕（不送給 LLM）
#   - 超時 → 返回 None（呼叫方回退正則模式提取）

import ast
import threading
import logging

logger = logging.getLogger("ThreatHunter.sandbox.ast_guard")

# ══════════════════════════════════════════════════════════════
# 安全限制常數
# ══════════════════════════════════════════════════════════════

MAX_AST_NODES = 50_000      # 超過此節點數拒絕（正常程式碼 << 10,000）
MAX_PARSE_SECONDS = 3.0     # 超過此秒數強制中斷（主執行緒不等待）
MAX_CODE_CHARS = 200_000    # 超過此長度（與 security_guard.py 一致）不解析


# ══════════════════════════════════════════════════════════════
# 核心安全解析函式
# ══════════════════════════════════════════════════════════════

def safe_ast_parse(code: str) -> ast.AST | None:
    """
    帶有節點數上限和 timeout 的 AST 解析（跨平台，支援 Windows）。

    相較於裸 ast.parse(code)，此函式提供：
      1. 長度前置檢查（防超大輸入）
      2. 節點數上限（防 AST Bomb）
      3. 3 秒 timeout（防無限解析，Windows 相容）

    使用方式：
        tree = safe_ast_parse(code)
        if tree is None:
            # 超時或 AST Bomb → 使用正則 fallback
            return _extract_functions_regex(code, lines, "python")
        # tree 是正常的 ast.AST，使用 ast.walk() 等

    Args:
        code: 待解析的 Python 原始碼字串

    Returns:
        ast.AST  — 解析成功
        None     — 超時或節點數超限（呼叫方應回退正則提取）

    Raises:
        SyntaxError — 語法錯誤（正常情況，呼叫方通常已有 except SyntaxError）
        ValueError  — AST Bomb 拒絕（節點數超限）
    """
    # ── 前置長度檢查──────────────────────────────────────────
    if len(code) > MAX_CODE_CHARS:
        logger.warning(
            "[AST_GUARD] Input too large (%d chars), skipping AST parse", len(code)
        )
        return None

    # ── 子執行緒解析（帶 timeout）──────────────────────────────
    result: list[ast.AST | None] = [None]
    error:  list[Exception | None] = [None]

    def _parse_worker():
        try:
            tree = ast.parse(code)

            # 節點數計算（遍歷所有子節點）
            node_count = sum(1 for _ in ast.walk(tree))

            if node_count > MAX_AST_NODES:
                error[0] = ValueError(
                    f"[AST_GUARD] AST Bomb rejected: "
                    f"{node_count} nodes > limit {MAX_AST_NODES}"
                )
                return

            result[0] = tree

        except SyntaxError as e:
            error[0] = e          # SyntaxError 正常傳遞給呼叫方
        except Exception as e:
            error[0] = e

    thread = threading.Thread(target=_parse_worker, daemon=True)
    thread.start()
    thread.join(timeout=MAX_PARSE_SECONDS)

    # ── 結果處理──────────────────────────────────────────────
    if thread.is_alive():
        # 超時：子執行緒仍在運行，主執行緒不再等待
        logger.warning(
            "[AST_GUARD] Parse timeout after %.1fs (code=%d chars). "
            "Caller will fallback to regex.",
            MAX_PARSE_SECONDS, len(code),
        )
        return None   # 呼叫方回退正則

    if error[0] is not None:
        if isinstance(error[0], ValueError):
            # AST Bomb 拒絕
            logger.warning("[AST_GUARD] %s", str(error[0]))
            raise error[0]
        # SyntaxError 或其他 Exception — 正常傳遞
        raise error[0]

    # 正常解析成功
    node_count = sum(1 for _ in ast.walk(result[0]))
    logger.debug(
        "[AST_GUARD] Parse OK: %d nodes (limit=%d)", node_count, MAX_AST_NODES
    )
    return result[0]


# ══════════════════════════════════════════════════════════════
# 單元測試用輔助函式
# ══════════════════════════════════════════════════════════════

def ast_parse_is_safe(code: str) -> bool:
    """
    便捷函式：只返回 bool（供測試、斷言用）。
    True  = 解析成功（節點數在限制內，無超時）
    False = 超時或 AST Bomb
    """
    try:
        result = safe_ast_parse(code)
        return result is not None
    except (SyntaxError, ValueError):
        return False


def generate_ast_bomb(depth: int = 1000) -> str:
    """
    生成指定深度的 AST Bomb Python 程式碼（用於測試）。
    例如 depth=1000 會生成 1 + (1 + (1 + ... 共 1000 層 ...))
    """
    expr = "0"
    for _ in range(depth):
        expr = f"(1 + {expr})"
    return f"x = {expr}"
