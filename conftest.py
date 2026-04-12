"""
pytest 根目錄設定檔
============================
確保 tests/ 下的測試可以正確 import tools/, agents/, config 等模組。
"""
import sys
from pathlib import Path

# 將專案根目錄加入 sys.path
sys.path.insert(0, str(Path(__file__).parent))
