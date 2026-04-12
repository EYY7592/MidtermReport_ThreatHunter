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
import time
import logging
import threading
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

# ── Windows cp950 安全日誌 Handler ────────────────────────────
# 根因：Windows 終端預設 cp950 編碼無法處理 emoji（✅⚡⚠️等），
# 導致 logging emit 拋 UnicodeEncodeError，CrewAI EventBus handler 連環 crash。
# 解法：自動將不可編碼的字元替換為 '?'，確保日誌永遠不會因編碼問題失敗。
class SafeStreamHandler(logging.StreamHandler):
    """Unicode 安全的 StreamHandler，防止 Windows cp950 編碼錯誤"""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            stream = self.stream
            # 嘗試編碼為終端編碼，不可編碼的字元替換為 '?'
            encoding = getattr(stream, 'encoding', None) or 'utf-8'
            try:
                msg.encode(encoding)
            except (UnicodeEncodeError, LookupError):
                msg = msg.encode(encoding, errors='replace').decode(encoding, errors='replace')
            stream.write(msg + self.terminator)
            self.flush()
        except Exception:
            self.handleError(record)


# 強制 stdout/stderr 使用 UTF-8（解決 Windows cp950 根因）
# 注意：pytest 執行時跳過，避免與 pytest capture 機制衝突
if sys.platform == 'win32' and 'pytest' not in sys.modules:
    import io
    if hasattr(sys.stdout, 'buffer'):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    if hasattr(sys.stderr, 'buffer'):
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    datefmt=LOG_DATE_FORMAT,
    handlers=[SafeStreamHandler(sys.stdout)],
)
logger = logging.getLogger("threathunter")

# ── LLM 供應商配置 ─────────────────────────────────────
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "google")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
VLLM_BASE_URL = os.getenv("VLLM_BASE_URL", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
# Google AI Studio API Key（圖靈AI Studio）
GOOGLE_API_KEY = os.getenv("Google_API_KEY", os.getenv("GOOGLE_API_KEY", ""))
# 讓 litellm 能找到 Google key
if GOOGLE_API_KEY:
    os.environ["GEMINI_API_KEY"] = GOOGLE_API_KEY
    os.environ["GOOGLE_API_KEY"] = GOOGLE_API_KEY

# ── API Keys ─────────────────────────────────────────
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

# ── Feature Flags ────────────────────────────────────
ENABLE_CRITIC = os.getenv("ENABLE_CRITIC", "true").lower() == "true"
ENABLE_MEMORY_RAG = os.getenv("ENABLE_MEMORY_RAG", "false").lower() == "true"

# ── Harness Engineering 參數 ─────────────────────────────────
MAX_DEBATE_ROUNDS = int(os.getenv("MAX_DEBATE_ROUNDS", "2"))
SIMILARITY_THRESHOLD = float(os.getenv("SIMILARITY_THRESHOLD", "0.75"))
CONSTRAINT_THRESHOLD = float(os.getenv("CONSTRAINT_THRESHOLD", "0.75"))
LLM_RPM = int(os.getenv("LLM_RPM", "60"))  # Google AI Studio 容許更高速率
# Gemini-2.0-Flash ~1秒回應，設 3 秒間隔防止 API 躃踩
LLM_MIN_INTERVAL_SEC = float(os.getenv("LLM_MIN_INTERVAL_SEC", "3.0"))
# 單次 LLM 呼叫最長等待秒數（AFC 卡死指標）
LLM_TIMEOUT_SEC = int(os.getenv("LLM_TIMEOUT_SEC", "90"))


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
        1: "[FULL] 全速運行",
        2: "[WARN] LLM 降級",
        3: "[WARN] API 降級",
        4: "[DEGRADE] Agent 降級",
        5: "[DEGRADE] 最低生存模式",
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
        logger.warning("[DEGRADE] %s -- %s (level: %d)", component, reason, self.current_level)

    def get_display(self) -> str:
        """取得 UI 顯示用的降級狀態文字"""
        return self.LEVEL_LABELS.get(self.current_level, "[?] 未知")

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


# ── 全局 LLM Rate Limiter ────────────────────────────────────
class LLMRateLimiter:
    """
    全局 LLM 請求速率限制器（Singleton）。

    目標：解決 OpenRouter Free Tier (8 req/min) 導致的 429 連鎖降級。

    所有 Agent 共享同一個實例，每次 LLM 呼叫前呼叫 wait_if_needed()。
    確保相鄰兩次 LLM 請求之間至少間隔 LLM_MIN_INTERVAL_SEC 秒。

    執行緒安全：使用 threading.Lock() 確保原子操作。
    """

    def __init__(self, min_interval: float = 10.0):
        self._min_interval = min_interval
        self._last_call_time: float = 0.0
        self._lock = threading.Lock()
        self._total_waited: float = 0.0
        self._call_count: int = 0

    def wait_if_needed(self, caller: str = "") -> float:
        """
        在 LLM 呼叫前自動等待，確保不超過速率限制。

        Args:
            caller: 呼叫者名稱（供日誌識別），如 "scout", "intel_fusion"

        Returns:
            實際等待的秒數（0.0 表示無需等待）
        """
        with self._lock:
            now = time.time()
            elapsed = now - self._last_call_time
            wait_sec = max(0.0, self._min_interval - elapsed)
            if wait_sec > 0.1:  # 大於 0.1 秒才算需要等待
                logger.info(
                    "[RATE_LIMITER] %s waiting %.1fs (interval=%.0fs, elapsed=%.1fs)",
                    caller or "unknown", wait_sec, self._min_interval, elapsed
                )
                time.sleep(wait_sec)
                self._total_waited += wait_sec
            self._last_call_time = time.time()
            self._call_count += 1
            return wait_sec

    def reset(self) -> None:
        """重設限速狀態（供測試使用）"""
        with self._lock:
            self._last_call_time = 0.0
            self._total_waited = 0.0
            self._call_count = 0

    @property
    def total_waited(self) -> float:
        """累計等待秒數（供監控使用）"""
        return self._total_waited

    @property
    def call_count(self) -> int:
        """累計 LLM 呼叫次數"""
        return self._call_count


# 全域 Rate Limiter 實例（所有 Agent 共享）
rate_limiter = LLMRateLimiter(LLM_MIN_INTERVAL_SEC)


# ── LLM 初始化（含降級瀑布）─────────────────────────────────
def _build_provider_chain() -> list[tuple[str, dict]]:
    """
    根據 LLM_PROVIDER 建立降級鏈

    全新主力供應商：Google AI Studio（Gemma-4-31B）
    備用降級順序：Google Gemini-2.0-Flash → vLLM → OpenRouter
    """
    chain = []

    if LLM_PROVIDER == "google":
        if GOOGLE_API_KEY:
            # ────────────────────────────────────────────────────────
            # v3.5 主力：Gemini-3-Flash-Preview（用戶確認，來源 AI Studio）
            #   優勢：最新架構（Gemini 3 系列），指令遵守強，~4秒回應
            # ────────────────────────────────────────────────────────
            chain.append(
                (
                    "Google AI (Gemini-3-Flash-Preview)",
                    {
                        "model": "gemini/gemini-3-flash-preview",
                        "api_key": GOOGLE_API_KEY,
                        "max_tokens": 8192,
                        "timeout": LLM_TIMEOUT_SEC,
                    },
                )
            )
            # 備用模型 1：Gemini-2.0-Flash（最快 ~0.9 秒，穩定可靠）
            chain.append(
                (
                    "Google AI (Gemini-2.0-Flash) [backup1]",
                    {
                        "model": "gemini/gemini-2.0-flash",
                        "api_key": GOOGLE_API_KEY,
                        "max_tokens": 8192,
                        "timeout": LLM_TIMEOUT_SEC,
                    },
                )
            )
            # 備用模型 2：Gemini-2.5-Flash-Lite（輕量快速 ~1.2 秒）
            chain.append(
                (
                    "Google AI (Gemini-2.5-Flash-Lite) [backup2]",
                    {
                        "model": "gemini/gemini-2.5-flash-lite",
                        "api_key": GOOGLE_API_KEY,
                        "max_tokens": 8192,
                        "timeout": LLM_TIMEOUT_SEC,
                    },
                )
            )
            # 備用模型 3：Gemini-2.5-Flash（最新穩定版）
            chain.append(
                (
                    "Google AI (Gemini-2.5-Flash) [backup3]",
                    {
                        "model": "gemini/gemini-2.5-flash",
                        "api_key": GOOGLE_API_KEY,
                        "max_tokens": 8192,
                        "timeout": LLM_TIMEOUT_SEC,
                    },
                )
            )
        # Google 不可用時，回落 OpenRouter（如果有 key）
        if OPENROUTER_API_KEY:
            chain.append(
                (
                    "OpenRouter (Llama-3.3-70B-Instruct Free) [fallback]",
                    {
                        "model": "openrouter/meta-llama/llama-3.3-70b-instruct:free",
                        "api_key": OPENROUTER_API_KEY,
                        "base_url": "https://openrouter.ai/api/v1",
                    },
                )
            )


    elif LLM_PROVIDER == "vllm":
        if VLLM_BASE_URL:
            chain.append(
                (
                    "vLLM (AMD Cloud)",
                    {
                        "model": "hosted_vllm/meta-llama/llama-3.3-70b-instruct",
                        "api_key": "dummy",
                        "base_url": VLLM_BASE_URL,
                    },
                )
            )
        # vLLM 降級到 Google Gemini-3-Flash
        if GOOGLE_API_KEY:
            chain.append((
                "Google AI (Gemini-3-Flash-Preview) [vllm-fallback]",
                {"model": "gemini/gemini-3-flash-preview", "api_key": GOOGLE_API_KEY,
                 "max_tokens": 8192, "timeout": LLM_TIMEOUT_SEC},
            ))
        if OPENROUTER_API_KEY:
            chain.append((
                "OpenRouter (Llama-3.3-70B-Instruct Free)",
                {"model": "openrouter/meta-llama/llama-3.3-70b-instruct:free",
                 "api_key": OPENROUTER_API_KEY, "base_url": "https://openrouter.ai/api/v1"},
            ))

    elif LLM_PROVIDER == "openrouter":
        if OPENROUTER_API_KEY:
            chain.append((
                "OpenRouter (Llama-3.3-70B-Instruct Free)",
                {"model": "openrouter/meta-llama/llama-3.3-70b-instruct:free",
                 "api_key": OPENROUTER_API_KEY, "base_url": "https://openrouter.ai/api/v1"},
            ))
            chain.append((
                "OpenRouter (DeepSeek R1 Free)",
                {"model": "openrouter/deepseek/deepseek-r1:free",
                 "api_key": OPENROUTER_API_KEY, "base_url": "https://openrouter.ai/api/v1"},
            ))
        # OpenRouter 降級到 Google Gemini-3-Flash
        if GOOGLE_API_KEY:
            chain.append((
                "Google AI (Gemini-3-Flash-Preview) [openrouter-fallback]",
                {"model": "gemini/gemini-3-flash-preview", "api_key": GOOGLE_API_KEY,
                 "max_tokens": 8192, "timeout": LLM_TIMEOUT_SEC},
            ))

    elif LLM_PROVIDER == "openai":
        if OPENAI_API_KEY:
            chain.append((
                "OpenAI (gpt-4o-mini)",
                {"model": "gpt-4o-mini", "api_key": OPENAI_API_KEY},
            ))

    return chain


# ── 模型健康狀態追蹤（自動輪替核心）──────────────────────────
# 記錄每個模型最後失敗的時間戳。冷卻期間內跳過該模型，優先選擇其他模型。
_model_health: dict[str, float] = {}  # model_name -> last_failure_timestamp
MODEL_COOLDOWN = 60  # 秒：模型限速後的冷卻時間


def mark_model_failed(model_name: str) -> None:
    """
    將模型標記為暫時不可用（冷卻中）。

    由各 Agent 的 run_*_pipeline() 在捕獲 429 錯誤時呼叫。
    冷卻 MODEL_COOLDOWN 秒後，該模型會再次被 get_llm() 嘗試。

    Args:
        model_name: 失敗的模型名稱（如 'openrouter/qwen/qwen3.6-plus:free'）
    """
    _model_health[model_name] = time.time()
    logger.warning("[COOLDOWN] Model marked as rate-limited: %s (cooldown %ds)", model_name, MODEL_COOLDOWN)


def _is_model_in_cooldown(model_name: str) -> bool:
    """檢查模型是否在冷卻期間內"""
    if model_name not in _model_health:
        return False
    elapsed = time.time() - _model_health[model_name]
    if elapsed >= MODEL_COOLDOWN:
        # 冷卻結束，清除記錄
        del _model_health[model_name]
        return False
    return True


def get_llm(exclude_models: list[str] | None = None):
    """
    取得 LLM 實例，含降級瀑布邏輯 + 模型健康狀態過濾。

    依序嘗試供應商：
    1. 跳過 exclude_models 列表中的模型（運行時被 429 的模型）
    2. 跳過冷卻中的模型（MODEL_COOLDOWN 秒內曾失敗）
    3. 第一個可用的即回傳

    Args:
        exclude_models: 明確排除的模型名稱列表（由 Agent 在 429 重試時傳入）

    Returns:
        crewai.LLM 實例

    Raises:
        RuntimeError: 所有供應商均不可用
    """
    from crewai import LLM

    providers = _build_provider_chain()
    exclude = set(exclude_models or [])

    if not providers:
        raise RuntimeError(
            "未配置任何 LLM 供應商。\n"
            "請在 .env 中設定至少一個：\n"
            "  OPENROUTER_API_KEY（推薦）\n"
            "  VLLM_BASE_URL（比賽用）\n"
            "  OPENAI_API_KEY（備案）"
        )

    # 動態優先權：基於歷史效能統計重排順序
    providers = model_stats.get_priority_order(providers)

    for provider_name, provider_config in providers:
        model = provider_config["model"]

        # 明確排除（429 重試時傳入的）
        if model in exclude:
            logger.info("[SKIP] %s excluded by caller", provider_name)
            continue

        # 冷卻檢查
        if _is_model_in_cooldown(model):
            remaining = MODEL_COOLDOWN - (time.time() - _model_health.get(model, 0))
            logger.info("[SKIP] %s in cooldown (%.0fs remaining)", provider_name, remaining)
            continue

        try:
            llm = LLM(**provider_config)
            logger.info("[OK] LLM connected: %s", provider_name)
            return llm
        except Exception as e:
            degradation_status.degrade(f"LLM:{provider_name}", str(e))
            logger.warning("[FAIL] LLM %s connection failed: %s", provider_name, e)
            continue

    # 所有模型都不可用 — 強制清除冷卻，最後機會重試
    if _model_health:
        logger.warning("[WARN] All models in cooldown, clearing cooldown for last-resort retry")
        _model_health.clear()
        return get_llm(exclude_models=list(exclude))  # 遞迴一次（冷卻已清除）

    raise RuntimeError(
        f"所有 LLM 供應商均連接失敗。\n"
        f"已嘗試：{[name for name, _ in providers]}\n"
        f"降級詳情：{degradation_status.to_dict()}"
    )


def get_current_model_name(llm) -> str:
    """
    從 CrewAI LLM 物件中提取模型名稱。
    用於 Agent 在捕獲 429 時標記失敗模型。
    """
    return getattr(llm, 'model', getattr(llm, 'model_name', 'unknown'))


def validate_api_keys() -> dict[str, bool]:
    """
    驗證所有 API Key 是否已設定（不驗證有效性）

    Returns:
        各 Key 名稱 → 是否已設定
    """
    status = {
        "GOOGLE_API_KEY (Gemma-4-31B)": bool(GOOGLE_API_KEY),
        "OPENROUTER_API_KEY": bool(OPENROUTER_API_KEY),
        "VLLM_BASE_URL": bool(VLLM_BASE_URL),
        "OPENAI_API_KEY": bool(OPENAI_API_KEY),
        "NVD_API_KEY": bool(NVD_API_KEY),
        "OTX_API_KEY": bool(OTX_API_KEY),
        "GITHUB_TOKEN": bool(GITHUB_TOKEN),
    }
    # Google API 是現在的主力，未設定則為倴命級錯誤
    if not GOOGLE_API_KEY and LLM_PROVIDER == "google":
        logger.error("[ERROR] Google_API_KEY 未設定！LLM_PROVIDER=google 但無效 key")
    missing = [k for k, v in status.items() if not v]
    if missing:
        logger.warning("[WARN] Missing API Keys: %s", ', '.join(missing))
    else:
        logger.info("[OK] All API Keys configured (provider=%s)", LLM_PROVIDER)
    return status


# ── 模型效能統計（動態優先權核心）+ JSON 持久化 ──────────────
import json as _json


class ModelStats:
    """
    模型效能統計追蹤器 + JSON 持久化。

    記錄每個模型的呼叫次數、成功率、平均延遲，
    據此動態調整模型優先順序（分數高者優先）。

    持久化路徑：data/model_stats.json
    """

    STATS_FILE = DATA_DIR / "model_stats.json"

    def __init__(self):
        self._stats: dict[str, dict] = self._load()

    def _load(self) -> dict:
        """從 JSON 載入歷史統計"""
        if self.STATS_FILE.exists():
            try:
                with open(self.STATS_FILE, encoding="utf-8") as f:
                    return _json.load(f)
            except (ValueError, OSError) as e:
                logger.warning("[WARN] ModelStats load failed: %s, starting fresh", e)
        return {}

    def _save(self) -> None:
        """持久化到 JSON"""
        try:
            with open(self.STATS_FILE, "w", encoding="utf-8") as f:
                _json.dump(self._stats, f, ensure_ascii=False, indent=2)
        except OSError as e:
            logger.warning("[WARN] ModelStats save failed: %s", e)

    def _ensure_entry(self, model_name: str) -> dict:
        """確保模型在統計表中有記錄"""
        if model_name not in self._stats:
            self._stats[model_name] = {
                "total_calls": 0,
                "success_count": 0,
                "fail_count": 0,
                "total_latency_ms": 0.0,
                "avg_latency_ms": 0.0,
                "success_rate": 0.0,
                "last_success": None,
                "last_failure": None,
                "last_error": None,
            }
        return self._stats[model_name]

    def record_success(self, model_name: str, latency_ms: float) -> None:
        """記錄一次成功呼叫"""
        entry = self._ensure_entry(model_name)
        entry["total_calls"] += 1
        entry["success_count"] += 1
        entry["total_latency_ms"] += latency_ms
        entry["avg_latency_ms"] = entry["total_latency_ms"] / entry["success_count"]
        entry["success_rate"] = entry["success_count"] / entry["total_calls"]
        entry["last_success"] = time.time()
        logger.info(
            "[STATS] %s success | latency=%.0fms | avg=%.0fms | rate=%.0f%%",
            model_name, latency_ms, entry["avg_latency_ms"], entry["success_rate"] * 100,
        )
        self._save()

    def record_failure(self, model_name: str, error: str) -> None:
        """記錄一次失敗呼叫"""
        entry = self._ensure_entry(model_name)
        entry["total_calls"] += 1
        entry["fail_count"] += 1
        entry["success_rate"] = entry["success_count"] / entry["total_calls"]
        entry["last_failure"] = time.time()
        entry["last_error"] = error[:200]
        logger.info(
            "[STATS] %s failure | error=%s | rate=%.0f%%",
            model_name, error[:80], entry["success_rate"] * 100,
        )
        self._save()

    def get_priority_order(self, providers: list[tuple[str, dict]]) -> list[tuple[str, dict]]:
        """
        基於效能統計重排模型優先權。

        排序公式：score = success_rate * 100 - avg_latency_ms * 0.01
        分數高者優先。無統計資料的模型保留原始順序但排在有統計者之後。
        """
        scored = []
        unscored = []

        for provider_name, config in providers:
            model = config["model"]
            if model in self._stats and self._stats[model]["total_calls"] >= 2:
                entry = self._stats[model]
                score = entry["success_rate"] * 100 - entry["avg_latency_ms"] * 0.001
                scored.append((score, provider_name, config))
            else:
                unscored.append((provider_name, config))

        # 分數高者優先
        scored.sort(key=lambda x: x[0], reverse=True)
        result = [(name, cfg) for _, name, cfg in scored] + unscored
        return result

    def get_report(self) -> dict:
        """取得效能報告（供 UI 顯示）"""
        return {
            model: {
                "calls": s["total_calls"],
                "success_rate": f"{s['success_rate']:.0%}",
                "avg_latency": f"{s['avg_latency_ms']:.0f}ms",
                "fails": s["fail_count"],
            }
            for model, s in self._stats.items()
            if s["total_calls"] > 0
        }


# 全域 ModelStats 實例
model_stats = ModelStats()

