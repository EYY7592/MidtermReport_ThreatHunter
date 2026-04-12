# tests/fixtures/dim3_vulnerable/vuln_secret_leak.py
# 確實有漏洞 — 硬編碼密鑰 + 不安全 pickle + yaml.load

import pickle
import yaml
import requests

# 漏洞 1：硬編碼 API Key
API_KEY = "sk-proj-1234567890abcdefghijklmnop"
SECRET_TOKEN = "ghp_AaBbCcDdEeFfGgHhIiJjKkLlMmNn1234"
DB_PASSWORD = "super_secret_db_pass_2024"

# 漏洞 2：不安全的 pickle 反序列化
def load_user_cache(data_bytes):
    """從快取載入使用者資料"""
    return pickle.loads(data_bytes)  # 任意代碼執行

# 漏洞 3：不安全的 YAML 載入
def load_config(config_path):
    """載入配置文件"""
    with open(config_path) as f:
        return yaml.load(f.read())  # 無 Loader — 可注入 Python 物件

# 漏洞 4：SSRF（伺服器端請求偽造）
def fetch_remote_data(url):
    """取得遠端資料"""
    response = requests.get(f"{url}/api/data")  # 使用者控制的 URL
    return response.json()

def connect_db():
    """連接資料庫"""
    password = "admin123"  # 硬編碼密碼
    return f"postgresql://admin:{password}@localhost:5432/mydb"
