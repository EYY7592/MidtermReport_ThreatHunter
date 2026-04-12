# tests/fixtures/dim3_vulnerable/vuln_cmdi.py
# 確實有漏洞 — Command Injection（os.system + subprocess）

import os
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/api/ping")
def ping_host():
    """Ping 主機 — Command Injection 漏洞"""
    host = request.args.get("host", "127.0.0.1")

    # 漏洞：使用者輸入直接傳入 os.system
    os.system(f"ping -c 4 {host}")

    return jsonify({"status": "ping sent"})


@app.route("/api/dns")
def dns_lookup():
    """DNS 查詢 — Command Injection 漏洞"""
    domain = request.args.get("domain", "")

    # 漏洞：使用者輸入直接傳入 subprocess
    result = subprocess.check_output(
        f"nslookup {domain}",
        shell=True,
        text=True,
    )
    return jsonify({"result": result})


@app.route("/api/eval")
def evaluate():
    """計算 — eval() 漏洞"""
    expr = request.args.get("expr", "1+1")

    # 漏洞：eval() 任意代碼執行
    result = eval(expr)

    return jsonify({"result": str(result)})
