# sandbox/Dockerfile
# ThreatHunter 隔離分析容器
# 設計原則：最小化攻擊面 — 無網路、唯讀 FS、非 root、無 shell 工具
#
# Build:  docker build -t threathunter-sandbox:latest -f sandbox/Dockerfile .
# Test:   docker run --rm --network none threathunter-sandbox:latest --selftest

FROM python:3.12-slim-bookworm

LABEL maintainer="ThreatHunter Security Team"
LABEL description="Isolated sandbox for ThreatHunter pipeline execution"
LABEL version="1.0.0"

# ── 系統強化 ──────────────────────────────────────────────────
# 移除不必要的工具（攻擊面縮減）
RUN apt-get update && \
    apt-get purge -y --auto-remove \
        curl wget git vim nano \
        netcat-openbsd ncat nc \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# ── 非 root 用戶 ──────────────────────────────────────────────
RUN groupadd -r sandbox && \
    useradd -r -g sandbox -s /sbin/nologin -d /app sandbox

# ── Python 依賴（最小化）──────────────────────────────────────
WORKDIR /app

# 分層複製：先安裝依賴（利用 Docker cache）
COPY requirements.txt /tmp/requirements.txt

# 只安裝 pipeline 必要依賴（排除 UI / 開發工具）
RUN pip install --no-cache-dir \
        crewai \
        google-generativeai \
        pydantic \
        requests \
        python-dotenv \
    && pip cache purge \
    && rm -rf /root/.cache /root/.pip

# ── 應用程式碼（唯讀掛載為主，COPY 只做備用）───────────────────
# 核心模組（運行時會被 -v 掛載覆蓋）
COPY agents/    /app/agents/
COPY tools/     /app/tools/
COPY sandbox/   /app/sandbox/
COPY harness/   /app/harness/
COPY skills/    /app/skills/
COPY config.py  /app/config.py
COPY main.py    /app/main.py

# 確保 data 目錄存在（運行時掛載為 readonly）
RUN mkdir -p /app/data /app/memory

# ── 安全強化 ──────────────────────────────────────────────────
# 切換到非 root 用戶（所有後續操作在此用戶下執行）
USER sandbox

# 驗證 Python 可用
RUN python -c "import sys; print(f'Python {sys.version}')"

# ── 入口點 ────────────────────────────────────────────────────
# stdin  → JSON 任務 (tech_stack, input_type)
# stdout → JSON 結果
ENTRYPOINT ["python", "-m", "sandbox.sandbox_runner"]

# selftest 模式（docker run ... --selftest）
CMD []
