"""
ThreatHunter 配置模組
====================

三模式 LLM 切換引擎 + API Key 管理 + 降級瀑布

遵循文件：
  - FINAL_PLAN.md §六（LLM 策略：OpenRouter 同模型開發）
  - FINAL_PLAN.md §支柱 4（Graceful Degradation：五層降級瀑布）
  - leader_plan.md（組長交付清單：config.py）
"""

import os
import sys
import logging
from pathlib import Path
from datetime import datetime, timezone

from dotenv import load_dotenv

# ── 載入環境變數 ─────────────────────────────────────────────
load_dotenv()

# ── 專案路徑 ─────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).parent.resolve()
MEMORY_DIR = PROJECT_ROOT / "memory"
DATA_DIR = PROJECT_ROOT / "data"
SKILLS_DIR = PROJECT_ROOT / "skills"
DOCS_DIR = PROJECT_ROOT / "docs"
HARNESS_DIR = PROJECT_ROOT / "harness"
TESTS_DIR = PROJECT_ROOT / "tests"

# 確保執行時目錄存在
MEMORY_DIR.mkdir(exist_ok=True)
(MEMORY_DIR / "vector_store").mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)

# ── 日誌配置 ─────────────────────────────────────────────────
LOG_FORMAT = "[%(asctime)s] %(levelname)-8s %(name)s: %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"

logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    datefmt=LOG_DATE_FORMAT,
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("threathunter")

# ── LLM 供應商配置 ───────────────────────────────────────────
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openrouter")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
VLLM_BASE_URL = os.getenv("VLLM_BASE_URL", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

# ── API Keys ─────────────────────────────────────────────────
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

# ── Feature Flags ────────────────────────────────────────────
ENABLE_CRITIC = os.getenv("ENABLE_CRITIC", "false").lower() == "true"
ENABLE_MEMORY_RAG = os.getenv("ENABLE_MEMORY_RAG", "false").lower() == "true"

# ── Harness Engineering 參數 ─────────────────────────────────
MAX_DEBATE_ROUNDS = int(os.getenv("MAX_DEBATE_ROUNDS", "2"))
SIMILARITY_THRESHOLD = float(os.getenv("SIMILARITY_THRESHOLD", "0.75"))
CONSTRAINT_THRESHOLD = float(os.getenv("CONSTRAINT_THRESHOLD", "0.75"))

# ── 系統憲法（寫入每個 Agent 的 system prompt）───────────────
SYSTEM_CONSTITUTION = """=== ThreatHunter Constitution ===
1. All CVE IDs must come from Tool-returned data. Fabrication is prohibited.
2. You must use the provided Tools for queries. Skip is not allowed.
3. Output must conform to the specified JSON schema.
4. Uncertain reasoning must be tagged with confidence: HIGH / MEDIUM / NEEDS_VERIFICATION.
5. Each judgment must include a reasoning field.
6. Reports use English; technical terms are not translated.
7. Do not call the same Tool twice for the same data."""


# ── 降級狀態追蹤 ─────────────────────────────────────────────
class DegradationStatus:
    """
    降級狀態追蹤器

    追蹤系統當前的降級層級，供 UI 和日誌使用。

    層級定義（FINAL_PLAN.md §支柱 4）：
      Level 1: ⚡ 全速運行
      Level 2: ⚠️ LLM 降級（vLLM → OpenRouter → OpenAI）
      Level 3: ⚠️ API 降級（即時 API → 離線快取）
      Level 4: 🔶 Agent 降級（跳過故障 Agent）
      Level 5: 🔶 最低生存模式（離線摘要）
    """

    LEVEL_LABELS = {
        1: "⚡ 全速運行",
        2: "⚠️ LLM 降級",
        3: "⚠️ API 降級",
        4: "🔶 Agent 降級",
        5: "🔶 最低生存模式",
    }

    def __init__(self):
        self.current_level: int = 1
        self.degraded_components: list[str] = []
        self.timestamp: str = datetime.now(timezone.utc).isoformat()

    def degrade(self, component: str, reason: str) -> None:
        """記錄一個元件降級"""
        self.degraded_components.append(f"{component}: {reason}")
        if "LLM" in component:
            self.current_level = max(self.current_level, 2)
        elif "API" in component:
            self.current_level = max(self.current_level, 3)
        elif "Agent" in component:
            self.current_level = max(self.current_level, 4)
        self.timestamp = datetime.now(timezone.utc).isoformat()
        logger.warning(f"降級：{component} — {reason}（層級：{self.current_level}）")

    def get_display(self) -> str:
        """取得 UI 顯示用的降級狀態文字"""
        return self.LEVEL_LABELS.get(self.current_level, "❓ 未知")

    def to_dict(self) -> dict:
        """序列化為 dict"""
        return {
            "level": self.current_level,
            "label": self.get_display(),
            "degraded_components": self.degraded_components,
            "timestamp": self.timestamp,
        }

    def reset(self) -> None:
        """重設降級狀態"""
        self.current_level = 1
        self.degraded_components = []
        self.timestamp = datetime.now(timezone.utc).isoformat()


# 全域降級狀態實例
degradation_status = DegradationStatus()


# ── LLM 初始化（含降級瀑布）─────────────────────────────────
def _build_provider_chain() -> list[tuple[str, dict]]:
    """
    根據 LLM_PROVIDER 建立降級鏈

    降級順序（FINAL_PLAN.md §支柱 4 層級 2）：
      vLLM（AMD Cloud）→ OpenRouter（同模型）→ OpenAI（備案）
    """
    chain = []

    if LLM_PROVIDER == "vllm":
        if VLLM_BASE_URL:
            chain.append(("vLLM (AMD Cloud)", {
                "model": "hosted_vllm/meta-llama/llama-3.3-70b-instruct",
                "api_key": "dummy",
                "base_url": VLLM_BASE_URL,
            }))
        if OPENROUTER_API_KEY:
            chain.append(("OpenRouter (Llama 3.3 70B)", {
                "model": "openrouter/meta-llama/llama-3.3-70b-instruct",
                "api_key": OPENROUTER_API_KEY,
                "base_url": "https://openrouter.ai/api/v1",
            }))
        if OPENAI_API_KEY:
            chain.append(("OpenAI (gpt-4o-mini)", {
                "model": "gpt-4o-mini",
                "api_key": OPENAI_API_KEY,
            }))

    elif LLM_PROVIDER == "openrouter":
        if OPENROUTER_API_KEY:
            chain.append(("OpenRouter (Llama 3.3 70B)", {
                "model": "openrouter/meta-llama/llama-3.3-70b-instruct",
                "api_key": OPENROUTER_API_KEY,
                "base_url": "https://openrouter.ai/api/v1",
            }))
        if OPENAI_API_KEY:
            chain.append(("OpenAI (gpt-4o-mini)", {
                "model": "gpt-4o-mini",
                "api_key": OPENAI_API_KEY,
            }))

    elif LLM_PROVIDER == "openai":
        if OPENAI_API_KEY:
            chain.append(("OpenAI (gpt-4o-mini)", {
                "model": "gpt-4o-mini",
                "api_key": OPENAI_API_KEY,
            }))

    return chain


def get_llm():
    """
    取得 LLM 實例，含降級瀑布邏輯

    依序嘗試供應商，第一個成功即回傳。
    失敗的供應商記錄到 degradation_status。

    Returns:
        crewai.LLM 實例

    Raises:
        RuntimeError: 所有供應商均連接失敗
    """
    from crewai import LLM

    providers = _build_provider_chain()

    if not providers:
        raise RuntimeError(
            "未配置任何 LLM 供應商。\n"
            "請在 .env 中設定至少一個：\n"
            "  OPENROUTER_API_KEY（推薦）\n"
            "  VLLM_BASE_URL（比賽用）\n"
            "  OPENAI_API_KEY（備案）"
        )

    for provider_name, provider_config in providers:
        try:
            llm = LLM(**provider_config)
            logger.info(f"✅ LLM 已連接：{provider_name}")
            return llm
        except Exception as e:
            degradation_status.degrade(f"LLM:{provider_name}", str(e))
            logger.warning(f"❌ LLM {provider_name} 連接失敗：{e}")
            continue

    raise RuntimeError(
        f"所有 LLM 供應商均連接失敗。\n"
        f"已嘗試：{[name for name, _ in providers]}\n"
        f"降級詳情：{degradation_status.to_dict()}"
    )


def validate_api_keys() -> dict[str, bool]:
    """
    驗證所有 API Key 是否已設定（不驗證有效性）

    Returns:
        各 Key 名稱 → 是否已設定
    """
    status = {
        "OPENROUTER_API_KEY": bool(OPENROUTER_API_KEY),
        "VLLM_BASE_URL": bool(VLLM_BASE_URL),
        "OPENAI_API_KEY": bool(OPENAI_API_KEY),
        "NVD_API_KEY": bool(NVD_API_KEY),
        "OTX_API_KEY": bool(OTX_API_KEY),
        "GITHUB_TOKEN": bool(GITHUB_TOKEN),
    }
    missing = [k for k, v in status.items() if not v]
    if missing:
        logger.warning(f"⚠️ 未設定的 API Key：{', '.join(missing)}")
    else:
        logger.info("✅ 所有 API Key 已設定")
    return status
