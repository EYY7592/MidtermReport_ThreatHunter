# ThreatHunter Tools 模組
# CrewAI @tool 裝飾器函式集合

from tools.nvd_tool import search_nvd
from tools.osv_tool import search_osv, search_osv_batch
from tools.otx_tool import search_otx
from tools.kev_tool import check_cisa_kev
from tools.exploit_tool import search_exploits
from tools.epss_tool import fetch_epss_score, get_epss_score
from tools.attck_tool import lookup_attck_by_cwe, lookup_attck_by_description, get_attck_for_cve
from tools.memory_tool import read_memory, write_memory, history_search

__all__ = [
    # 漏洞查詢（OSV 為主力，NVD 為 fallback）
    "search_nvd",
    "search_osv",
    "search_osv_batch",    # 批量查詢多套件
    "search_otx",
    "check_cisa_kev",
    "search_exploits",
    # EPSS — 六維分析 EPSS 維度（30% 權重），真實 API
    "fetch_epss_score",
    "get_epss_score",      # 程式碼層直接使用
    # ATT&CK — 六維分析 ATT&CK 維度（10% 權重），CWE->CAPEC->ATT&CK 映射
    "lookup_attck_by_cwe",
    "lookup_attck_by_description",
    "get_attck_for_cve",   # Intel Fusion 直接調用
    # 記憶系統
    "read_memory",
    "write_memory",
    "history_search",
]
