# ThreatHunter Dockerfile — 標準 CPU 版本
# ==========================================
# 多階段建置：
#   Stage 1 (builder): 安裝 Rust + maturin，編譯所有 PyO3 crates + WASM Guest
#   Stage 2 (runtime): 最小 Python 執行環境
#
# 使用：
#   docker build -t threathunter:latest .
#   docker run -p 1000:1000 --env-file .env threathunter:latest

# ── Stage 1: Rust + Python builder ──────────────────────────
FROM python:3.12-slim AS builder

ARG BUILD_DATE
ARG GIT_COMMIT
ARG VERSION

# 安裝 Rust 工具鏈（用於 PyO3 crate 編譯）
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    g++ \
    libpython3-dev \
    pkg-config \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 安裝 Rust（使用官方 rustup）
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain stable --profile minimal && \
    rustup target add wasm32-unknown-unknown

# 安裝 uv + maturin
RUN pip install --no-cache-dir uv maturin

WORKDIR /build

# 複製依賴檔案（layer cache 優化）
COPY requirements.txt .
RUN uv pip install --system -r requirements.txt

# 複製 Rust workspace 並編譯
COPY rust/ ./rust/

# Step 1: 編譯 WASM Guest
RUN cargo build \
    --target wasm32-unknown-unknown \
    --release \
    --manifest-path /build/rust/prompt_sandbox_guest/Cargo.toml 2>&1 || \
    echo "[WARN] WASM Guest build failed, prompt_sandbox will use Rust fallback"

# 複製 WASM 輸出到 assets/ 目錄
RUN mkdir -p /build/rust/prompt_sandbox/assets && \
    if [ -f "/build/rust/target/wasm32-unknown-unknown/release/prompt_guard.wasm" ]; then \
        cp /build/rust/target/wasm32-unknown-unknown/release/prompt_guard.wasm \
           /build/rust/prompt_sandbox/assets/prompt_guard.wasm && \
        echo "[OK] WASM Guest copied"; \
    else \
        echo "[INFO] WASM not built, running in Rust fallback mode"; \
    fi

# Step 2: 編譯所有 PyO3 crates
WORKDIR /build/rust
RUN for crate in memory_validator json_validator sanitizer url_builder checkpoint_writer prompt_sandbox; do \
    echo "=== Building $crate ==="; \
    maturin build --release \
        --strip \
        --manifest-path /build/rust/$crate/Cargo.toml \
        2>&1 || echo "[WARN] $crate build failed, using Python fallback"; \
    done

# 安裝所有 .whl 到系統 Python
RUN find /build/rust/target/wheels -name "*.whl" -exec pip install --force-reinstall {} \; 2>/dev/null || true

# ── Stage 2: Runtime ─────────────────────────────────────────
FROM python:3.12-slim AS runtime

ARG BUILD_DATE
ARG GIT_COMMIT
ARG VERSION

LABEL org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.title="ThreatHunter" \
      org.opencontainers.image.description="AI 多 Agent 資安威脅情報平台" \
      org.opencontainers.image.licenses="MIT"

# 最小執行時期依賴
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 從 builder 複製 Python 環境（含編譯好的 Rust wheels）
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# 複製應用程式源碼
COPY . .

# 建立必要目錄
RUN mkdir -p logs/checkpoints memory data

# 安全強化：非 root 使用者執行
RUN useradd -m -u 1001 -s /bin/bash threathunter && \
    chown -R threathunter:threathunter /app
USER threathunter

# 環境變數預設值
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    WASM_SANDBOX_ENABLED=true \
    SANDBOX_ENABLED=false \
    ENABLE_CRITIC=false \
    ENABLE_MEMORY_RAG=false

EXPOSE 1000

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:1000/api/health')" \
    || exit 1

CMD ["python3", "-m", "uvicorn", "ui.server:app", "--host", "0.0.0.0", "--port", "1000", "--workers", "2"]
