# tests/fixtures/dim5_mixed/mix_multi_vuln.py
# 混合場景 — 同時有多種漏洞（SQLi + CMDi + 硬編碼 + pickle + SSRF）

import os
import pickle
import sqlite3
import subprocess

import requests

# 硬編碼多組密鑰
API_KEY = "sk-or-v1-abcdef1234567890"
DB_PASSWORD = "production_db_pass_2024"
SECRET_TOKEN = "eyJhbGciOiJIUzI1NiJ9.secret"


def search_database(query_string):
    """SQL Injection"""
    conn = sqlite3.connect("production.db")
    sql = f"SELECT * FROM products WHERE name LIKE '%{query_string}%'"
    return conn.execute(sql).fetchall()


def execute_task(task_command):
    """Command Injection"""
    os.system(f"bash -c '{task_command}'")
    result = subprocess.check_output(task_command, shell=True)
    return result.decode()


def load_session(session_data):
    """不安全反序列化"""
    return pickle.loads(session_data)


def proxy_request(target_url):
    """SSRF"""
    response = requests.get(f"{target_url}/internal/data")
    return response.json()


def run_user_code(code_string):
    """eval 任意代碼執行"""
    return eval(code_string)


def hash_password(password):
    """弱雜湊"""
    import hashlib
    return hashlib.md5(password.encode()).hexdigest()
