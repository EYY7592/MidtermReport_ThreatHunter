"""
build_rust_crates.py
一鍵建置並安裝全部 ThreatHunter Rust crates（供開發環境使用）
使用 maturin develop + MinGW-w64 GNU toolchain

Phase 4A: checkpoint_writer  — Rust parking_lot::Mutex BufWriter
Phase 4C: prompt_sandbox     — WASM Runtime Sandbox（含 WASM Guest 編譯步驟）
"""
import subprocess
import sys
import os
import pathlib
import shutil

PROJECT_ROOT = pathlib.Path(__file__).parent
RUST_DIR = PROJECT_ROOT / "rust"
PYTHON = str(PROJECT_ROOT / ".venv" / "Scripts" / "python.exe")
MINGW_BIN = r"C:\msys64\mingw64\bin"

# 確保 MINGW 在 PATH
env = os.environ.copy()
env["PATH"] = MINGW_BIN + os.pathsep + env.get("PATH", "")
env["PYO3_PYTHON"] = PYTHON

CRATES = [
    "memory_validator",
    "json_validator",
    "sanitizer",
    "url_builder",
    "checkpoint_writer",   # Phase 4A: Rust BufWriter 高效 checkpoint I/O
    "prompt_sandbox",      # Phase 4C: WASM Runtime Sandbox Host
]

TARGET = "x86_64-pc-windows-gnu"

# ══════════════════════════════════════════════════════════════
# Phase 4C：WASM Guest 編譯（獨立 cargo build，非 workspace 成員）
# ══════════════════════════════════════════════════════════════

WASM_GUEST_DIR     = RUST_DIR / "prompt_sandbox_guest"
WASM_TARGET        = "wasm32-unknown-unknown"
WASM_OUTPUT_DIR    = RUST_DIR / "target" / WASM_TARGET / "release"
WASM_OUTPUT_FILE   = WASM_OUTPUT_DIR / "prompt_guard.wasm"
WASM_DEST_DIR      = RUST_DIR / "prompt_sandbox" / "assets"
WASM_DEST_FILE     = WASM_DEST_DIR / "prompt_guard.wasm"


def build_wasm_guest() -> bool:
    """
    編譯 WASM Guest（prompt_guard.wasm）。
    需要 wasm32-unknown-unknown target 已安裝：
      rustup target add wasm32-unknown-unknown
    """
    print(f"\n{'='*60}")
    print("Building WASM Guest: prompt_guard")
    print(f"{'='*60}")

    # 確認 wasm32 target 是否已安裝
    check = subprocess.run(
        ["rustup", "target", "list", "--installed"],
        capture_output=True, text=True
    )
    if WASM_TARGET not in check.stdout:
        print(f"[INFO] Installing {WASM_TARGET} target...")
        subprocess.run(["rustup", "target", "add", WASM_TARGET], check=False)

    # 編譯 WASM Guest
    result = subprocess.run(
        [
            "cargo", "build",
            "--target", WASM_TARGET,
            "--release",
            "--manifest-path", str(WASM_GUEST_DIR / "Cargo.toml"),
        ],
        env=env,
        cwd=str(RUST_DIR),  # 使用 rust/ 作為工作目錄
    )

    if result.returncode != 0:
        print(f"[FAIL] WASM Guest build failed (exit {result.returncode})")
        print("       若要跳過 WASM 編譯，prompt_sandbox 將退回純 Rust 過濾模式")
        return False

    # 複製 .wasm 到 assets/
    if WASM_OUTPUT_FILE.exists():
        WASM_DEST_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(WASM_OUTPUT_FILE), str(WASM_DEST_FILE))
        size_kb = WASM_DEST_FILE.stat().st_size // 1024
        print(f"[OK] WASM Guest compiled: {WASM_DEST_FILE} ({size_kb}KB)")
        return True
    else:
        print(f"[FAIL] Expected .wasm not found: {WASM_OUTPUT_FILE}")
        return False


def build_crate(name: str) -> bool:
    manifest = RUST_DIR / name / "Cargo.toml"
    print(f"\n{'='*60}")
    print(f"Building: {name}")
    print(f"{'='*60}")

    result = subprocess.run(
        [
            sys.executable, "-m", "maturin", "develop",
            "--manifest-path", str(manifest),
            "--target", TARGET,
        ],
        env=env,
        capture_output=False,
    )

    if result.returncode in (0, 1):
        print(f"[{'OK' if result.returncode == 0 else 'WARN'}] {name}")
        return True

    print(f"[FAIL] {name} - exit code: {result.returncode}")
    return False


def verify_imports():
    print("\n" + "="*60)
    print("Verifying Python imports...")
    print("="*60)
    modules = {
        "threathunter_memory_validator": ["validate_memory_write", "validate_cve_id"],
        "threathunter_json_validator":   ["safe_parse_json", "validate_cve_id", "validate_cve_list"],
        "threathunter_sanitizer":        ["scan_blocklist", "infer_input_type", "sha256_hex"],
        "threathunter_url_builder":      ["build_api_url", "validate_url", "encode_query_value"],
        # Phase 4A
        "threathunter_checkpoint_writer": [
            "open_writer", "write_line", "flush_writer", "close_writer",
            "is_open", "get_lines_written", "get_current_path", "write_batch",
        ],
        # Phase 4C
        "threathunter_prompt_sandbox": [
            "sandbox_eval", "sandbox_version", "sandbox_reload_wasm", "sandbox_stats",
        ],
    }

    all_ok = True
    for mod, fns in modules.items():
        try:
            m = __import__(mod)
            for fn in fns:
                assert hasattr(m, fn), f"Missing function: {fn}"
            print(f"  [OK] {mod} ({', '.join(fns)})")
        except ImportError as e:
            print(f"  [FAIL] {mod}: {e}")
            all_ok = False
        except AssertionError as e:
            print(f"  [FAIL] {e}")
            all_ok = False

    return all_ok


if __name__ == "__main__":
    print("ThreatHunter Rust Crates Builder")
    print(f"Python: {PYTHON}")
    print(f"MinGW:  {MINGW_BIN}")
    print(f"Target: {TARGET}")

    failed = []

    # ── Step 1：先編譯 WASM Guest（prompt_sandbox 依賴它）──────────
    print("\n[Step 1] Building WASM Guest (prompt_guard.wasm)...")
    wasm_ok = build_wasm_guest()
    if not wasm_ok:
        print("[INFO] WASM Guest build failed/skipped. prompt_sandbox will use Rust fallback.")

    # ── Step 2：編譯所有 PyO3 crate ────────────────────────────────
    print("\n[Step 2] Building PyO3 crates...")
    for crate in CRATES:
        if not build_crate(crate):
            failed.append(crate)

    if failed:
        print(f"\n[PARTIAL] Failed crates: {failed}")
    else:
        print("\n[ALL BUILT]")

    # ── Step 3：驗證 Python import ─────────────────────────────────
    ok = verify_imports()
    if ok:
        print("\n[ALL IMPORTS OK] ThreatHunter Rust integration complete!")
    else:
        print("\n[SOME IMPORTS FAILED] Check above for details")
