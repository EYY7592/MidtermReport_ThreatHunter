# config.py
# 功能：統一管理 LLM 供應商，支援三模式無縫切換
# Harness 支柱：Graceful Degradation（LLM 供應商備案）

import os
import logging
from crewai import LLM

logger = logging.getLogger("ThreatHunter")

# ── 讀取環境變數，預設使用 OpenRouter ──────────────────────────
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openrouter")

def _create_llm() -> LLM:
    """
    根據 LLM_PROVIDER 環境變數建立對應的 LLM 實例。

    三種模式：
      openrouter → 開發期（Day 1-3），與比賽模型完全相同
      vllm       → 比賽期（Day 4-5），AMD Cloud vLLM
      openai     → 備案，當以上兩者都掛掉時自動降級

    使用方式（其他成員直接 import）：
      from config import llm
    """
    if LLM_PROVIDER == "openrouter":
        # ── 開發期：OpenRouter Llama 3.3 70B ─────────────────
        # 費用：約 $0.30/1M tokens，與比賽模型一模一樣
        api_key = os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            logger.warning("⚠️ OPENROUTER_API_KEY 未設定，嘗試降級到 OpenAI 備案")
            return LLM(model="gpt-4o-mini")

        logger.info("✅ LLM: OpenRouter Llama 3.3 70B（開發模式）")
        return LLM(
            model="openrouter/meta-llama/llama-3.3-70b-instruct",
            api_key=api_key,
            base_url="https://openrouter.ai/api/v1",
        )

    elif LLM_PROVIDER == "vllm":
        # ── 比賽期：AMD Cloud vLLM ──────────────────────────
        base_url = os.getenv("VLLM_BASE_URL", "http://localhost:8000")
        logger.info(f"✅ LLM: vLLM AMD Cloud（比賽模式）→ {base_url}")
        return LLM(
            model="hosted_vllm/meta-llama/llama-3.3-70b-instruct",
            api_key="dummy",  # vLLM 不需要真正的 API Key
            base_url=base_url,
        )

    else:
        # ── 備案：OpenAI gpt-4o-mini ────────────────────────
        logger.warning("⚠️ LLM: OpenAI gpt-4o-mini（備案模式）")
        return LLM(model="gpt-4o-mini")


# ── 全域 LLM 實例，其他模組直接 import ──────────────────────────
# 用法：from config import llm
llm = _create_llm()
