# tests/fixtures/dim1_clean/clean_flask_app.py
# 正常程式碼 — 標準 Flask CRUD，使用參數化查詢，無漏洞

from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)
DATABASE = "app.db"


def get_db():
    """取得資料庫連線"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/api/users", methods=["GET"])
def list_users():
    """列出所有使用者（安全：無動態查詢）"""
    db = get_db()
    users = db.execute("SELECT id, name, email FROM users").fetchall()
    return jsonify([dict(u) for u in users])


@app.route("/api/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    """查詢單一使用者（安全：使用參數化查詢）"""
    db = get_db()
    user = db.execute(
        "SELECT id, name, email FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(dict(user))


@app.route("/api/users", methods=["POST"])
def create_user():
    """新增使用者（安全：使用參數化查詢 + 輸入驗證）"""
    data = request.get_json()
    name = data.get("name", "").strip()
    email = data.get("email", "").strip()

    if not name or not email:
        return jsonify({"error": "Name and email required"}), 400
    if len(name) > 100 or len(email) > 200:
        return jsonify({"error": "Input too long"}), 400

    db = get_db()
    db.execute(
        "INSERT INTO users (name, email) VALUES (?, ?)",
        (name, email)
    )
    db.commit()
    return jsonify({"status": "created"}), 201


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
