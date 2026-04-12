# tests/fixtures/dim3_vulnerable/vuln_sqli.py
# 確實有漏洞 — SQL Injection（字串拼接）

import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/api/search")
def search():
    """搜尋使用者 — SQL Injection 漏洞"""
    name = request.args.get("name", "")
    conn = sqlite3.connect("app.db")

    # 漏洞：字串拼接 SQL（未參數化）
    query = "SELECT * FROM users WHERE name = '%s'" % name
    results = conn.execute(query).fetchall()

    return jsonify({"results": results})


@app.route("/api/login", methods=["POST"])
def login():
    """登入 — SQL Injection 漏洞"""
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

    conn = sqlite3.connect("app.db")
    # 漏洞：f-string 拼接（' OR '1'='1 可繞過）
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    user = conn.execute(query).fetchone()

    if user:
        return jsonify({"status": "ok", "user": user[0]})
    return jsonify({"status": "fail"}), 401
