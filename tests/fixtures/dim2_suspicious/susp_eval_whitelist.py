# tests/fixtures/dim2_suspicious/susp_eval_whitelist.py
# 可疑 — 有 eval() 但有白名單驗證

import ast

ALLOWED_EXPRESSIONS = {"add", "sub", "mul", "div"}


def safe_eval(expression: str) -> float:
    """
    受限 eval — 只允許白名單中的函式。
    看起來有 eval 但實際上有保護。
    """
    # 先用 AST 驗證，只允許簡單算術
    tree = ast.parse(expression, mode="eval")
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if hasattr(node.func, "id") and node.func.id not in ALLOWED_EXPRESSIONS:
                raise ValueError(f"Function not allowed: {node.func.id}")
        if isinstance(node, ast.Attribute):
            raise ValueError("Attribute access not allowed")

    result = eval(expression)  # 看起來危險但有白名單保護
    return float(result)


def calculate(user_input: str) -> dict:
    """處理使用者計算請求"""
    try:
        result = safe_eval(user_input)
        return {"status": "ok", "result": result}
    except (ValueError, SyntaxError, TypeError) as e:
        return {"status": "error", "message": str(e)}
