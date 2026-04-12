"""
ui/server.py — ThreatHunter FastAPI Backend
=============================================
架構：FastAPI + Server-Sent Events (SSE)

端點：
  POST /api/scan          接收 tech_stack，啟動 pipeline，返回 scan_id
  GET  /api/stream/{id}   SSE 端點，即時推送 agent 進度
  GET  /api/result/{id}   返回最終報告 JSON
  GET  /api/health        健康檢查
  GET  /                  回傳靜態 index.html

SSE 事件類型：
  agent_start   → { agent: str }
  agent_log     → { agent: str, message: str }
  agent_done    → { agent: str, status: str, detail: dict }
  done          → 完整報告 JSON
  pipeline_error → { message: str }
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import queue
import sys
import threading
import uuid
import time
from pathlib import Path
from typing import Any

# ── 確保 project root 在 sys.path ──────────────────────────
_HERE = Path(__file__).parent
_ROOT = _HERE.parent
sys.path.insert(0, str(_ROOT))

from dotenv import load_dotenv
load_dotenv()

import fastapi
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

logger = logging.getLogger("ThreatHunter.server")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)

# ══════════════════════════════════════════════════════════════
# 掃描狀態管理（記憶體中，Demo 足夠）
# ══════════════════════════════════════════════════════════════

# scan_id → { "queue": Queue, "result": dict|None, "error": str|None }
_scan_store: dict[str, dict[str, Any]] = {}

# ══════════════════════════════════════════════════════════════
# FastAPI App
# ══════════════════════════════════════════════════════════════

app = FastAPI(
    title="ThreatHunter API",
    version="3.1",
    description="AI 多 Agent 資安威脅情報平台",
)

# ── 掛載靜態資源 ────────────────────────────────────────────
_STATIC_DIR = _HERE / "static"
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


# ══════════════════════════════════════════════════════════════
# Request / Response 模型
# ══════════════════════════════════════════════════════════════

class ScanRequest(BaseModel):
    tech_stack: str


class ScanResponse(BaseModel):
    scan_id: str
    message: str = "Scan started"


# ══════════════════════════════════════════════════════════════
# 報告組裝：從 Scout 記憶補充漏洞細節
# ══════════════════════════════════════════════════════════════

def _enrich_result(result: dict[str, Any]) -> dict[str, Any]:
    """
    Advisor 輸出只包含 actions，不含漏洞清單。
    從 memory/scout_memory.json 讀取漏洞資料，
    補充 vulnerability_detail 和 vulnerability_summary 供前端使用。
    """
    scout_path = _ROOT / "memory" / "scout_memory.json"
    vulns: list[dict] = []

    if scout_path.exists():
        try:
            with open(scout_path, encoding="utf-8") as f:
                raw = f.read().strip()
            if raw:
                scout_data = json.loads(raw)
                # scout_memory 可能直接是 {"data": {...}} 格式
                if isinstance(scout_data, dict):
                    inner = scout_data.get("data") or scout_data
                    if isinstance(inner, str):
                        inner = json.loads(inner)
                    vulns = inner.get("vulnerabilities", [])
        except Exception as exc:
            logger.warning("[ENRICH] Cannot read scout_memory: %s", exc)

    # 從 actions 也可以提取漏洞資訊作為備援
    if not vulns:
        actions = result.get("actions", {})
        seen = set()
        for level in ["urgent", "important", "resolved"]:
            for item in actions.get(level, []):
                cve_id = item.get("cve_id", "")
                if cve_id and cve_id not in seen:
                    seen.add(cve_id)
                    vulns.append({
                        "cve_id":      cve_id,
                        "package":     item.get("package", "unknown"),
                        "cvss_score":  item.get("cvss_score", 0),
                        "severity":    item.get("severity", "MEDIUM"),
                        "description": item.get("action", ""),
                        "is_new":      False,
                    })

    # 計算 vulnerability_summary
    summary = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "new": 0}
    for v in vulns:
        summary["total"] += 1
        sev = (v.get("severity") or "LOW").upper()
        if sev == "CRITICAL":
            summary["critical"] += 1
        elif sev == "HIGH":
            summary["high"] += 1
        elif sev == "MEDIUM":
            summary["medium"] += 1
        else:
            summary["low"] += 1
        if v.get("is_new"):
            summary["new"] += 1

    result["vulnerability_detail"]  = vulns
    result["vulnerability_summary"] = summary
    return result


# ══════════════════════════════════════════════════════════════
# Pipeline Worker（在背景執行緒）
# ══════════════════════════════════════════════════════════════

def _pipeline_worker(scan_id: str, tech_stack: str) -> None:
    """
    在獨立執行緒中執行完整 Pipeline。
    透過 Queue 推送 SSE 事件給主執行緒。
    """
    store = _scan_store[scan_id]
    q: queue.Queue = store["queue"]

    def emit(event_type: str, data: dict) -> None:
        q.put((event_type, data))

    try:
        from main import run_pipeline_with_callback

        def on_progress(agent: str, status: str, detail: dict) -> None:
            """main.py 呼叫的 callback，轉換為 SSE 事件"""
            if status == "RUNNING":
                emit("agent_start", {"agent": agent})
            elif status == "COMPLETE":
                emit("agent_done", {
                    "agent": agent,
                    "status": detail.get("status", "SUCCESS"),
                    "detail": detail,
                })
            elif status == "LOG":
                # 部分 stage 會發送中間日誌
                emit("agent_log", {"agent": agent, "message": str(detail)})

        logger.info("[SCAN:%s] Pipeline start | tech_stack=%s", scan_id, tech_stack)
        result = run_pipeline_with_callback(tech_stack, on_progress)

        # ── 組裝完整報告：從 scout_memory.json 讀取漏洞資料 ──
        result = _enrich_result(result)

        store["result"] = result
        emit("done", result)
        logger.info("[SCAN:%s] Pipeline DONE | risk=%s", scan_id, result.get("risk_score"))

    except Exception as exc:
        err_msg = str(exc)
        logger.error("[SCAN:%s] Pipeline ERROR: %s", scan_id, err_msg)
        store["error"] = err_msg
        emit("pipeline_error", {"message": err_msg})


# ══════════════════════════════════════════════════════════════
# SSE Generator
# ══════════════════════════════════════════════════════════════

async def _sse_generator(scan_id: str):
    """
    異步 SSE 生成器：
    - 從 Queue 拉取事件（由 pipeline worker 推入）
    - 格式化為 SSE 規格（event: xxx\\ndata: ...\\n\\n）
    - 直到 done / pipeline_error 或 timeout (15min)
    """
    if scan_id not in _scan_store:
        yield _sse_fmt("pipeline_error", {"message": f"scan_id {scan_id} not found"})
        return

    store = _scan_store[scan_id]
    q: queue.Queue = store["queue"]

    # 送出心跳，確認連線成功
    yield _sse_fmt("connected", {"scan_id": scan_id})

    deadline = time.time() + 900  # 15 min max
    terminal_events = {"done", "pipeline_error"}

    while time.time() < deadline:
        try:
            event_type, data = q.get(timeout=0.3)
        except queue.Empty:
            # 心跳，保持連線
            yield ": ping\n\n"
            await asyncio.sleep(0)
            continue

        yield _sse_fmt(event_type, data)

        # 終止條件
        if event_type in terminal_events:
            break

        await asyncio.sleep(0)  # yield to event loop

    # 清理（可選：延後 5 分鐘再刪，讓 /api/result 還能取到）
    asyncio.get_event_loop().call_later(300, lambda: _scan_store.pop(scan_id, None))


def _sse_fmt(event: str, data: Any) -> str:
    """格式化為標準 SSE 字串"""
    payload = json.dumps(data, ensure_ascii=False)
    return f"event: {event}\ndata: {payload}\n\n"


# ══════════════════════════════════════════════════════════════
# API Endpoints
# ══════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    """回傳主頁 HTML"""
    index_path = _STATIC_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="index.html not found")
    return HTMLResponse(content=index_path.read_text(encoding="utf-8"))


@app.get("/api/health")
async def health():
    """健康檢查端點"""
    return JSONResponse({
        "status": "ok",
        "pipeline_version": "3.1",
        "active_scans": len(_scan_store),
    })


# ══════════════════════════════════════════════════════════════
# Checkpoint Dashboard API
# ══════════════════════════════════════════════════════════════

@app.get("/checkpoints", response_class=HTMLResponse)
async def serve_checkpoint_dashboard():
    """回傳 Checkpoint Dashboard 頁面"""
    cp_path = _STATIC_DIR / "checkpoint.html"
    if not cp_path.exists():
        raise HTTPException(status_code=404, detail="checkpoint.html not found")
    return HTMLResponse(content=cp_path.read_text(encoding="utf-8"))


@app.get("/api/checkpoints")
async def list_checkpoint_files():
    """列出所有 checkpoint JSONL 檔案（含大小、修改時間、描述性標籤）"""
    cp_dir = _ROOT / "logs" / "checkpoints"
    files = []
    if cp_dir.exists():
        for f in sorted(cp_dir.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True):
            stat = f.stat()
            # 解析前幾行，提取描述性標籤
            label = _extract_scan_label(f)
            files.append({
                "name": f.name,
                "size": stat.st_size,
                "modified": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(stat.st_mtime)),
                "label": label,
            })
    return JSONResponse({"files": files, "total": len(files)})


@app.get("/api/checkpoints/latest")
async def get_latest_checkpoint():
    """回傳最新一個 checkpoint JSONL 檔案的資訊（供前端自動跳轉）"""
    cp_dir = _ROOT / "logs" / "checkpoints"
    if not cp_dir.exists():
        return JSONResponse({"latest": None})
    files = sorted(cp_dir.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        return JSONResponse({"latest": None})
    f = files[0]
    label = _extract_scan_label(f)
    stat = f.stat()
    return JSONResponse({
        "latest": {
            "name": f.name,
            "size": stat.st_size,
            "modified": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(stat.st_mtime)),
            "label": label,
        }
    })




def _extract_scan_label(filepath: Path) -> str:
    """
    從 JSONL 檔案前 10 行提取描述性掃描標籤。
    尋找順序：
    1. STAGE_ENTER(orchestrator) 的 tech_stack_preview → 取前 60 字元
    2. SCAN_END 的 final_status + duration
    3. SCAN_START 的 scan_id
    回傳格式示例：「Flask CRUD + sqlite3 | Path B | 2.2m」
    """
    try:
        target_preview = ""
        scan_path = ""
        duration = ""
        event_count = 0

        with open(filepath, "r", encoding="utf-8") as fh:
            for i, line in enumerate(fh):
                if i > 30:
                    break  # 只看前 30 行
                line = line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                except json.JSONDecodeError:
                    continue
                event_count += 1
                event_type = evt.get("event", "")
                data = evt.get("data", {})

                # 提取掃描目標描述
                if event_type == "STAGE_ENTER" and evt.get("agent") == "orchestrator":
                    raw = data.get("tech_stack_preview", "")
                    if raw:
                        # 同時處理 real newline (\n) 和 escaped \\n
                        lines = raw.replace("\\n", "\n").split("\n")
                        # 取第一行有意義的內容（跳過註解行和空行）
                        for text_line in lines:
                            text_line = text_line.strip()
                            if text_line and not text_line.startswith("#") and not text_line.startswith("//"):
                                target_preview = text_line[:60]
                                break
                        if not target_preview:
                            # 若都是註解，取第一行並去掉註解前綴
                            first = lines[0].strip() if lines else ""
                            first = first.lstrip("#/ ").strip()
                            target_preview = first[:60] if first else ""

                # 提取掃描路徑
                if event_type == "STAGE_EXIT" and evt.get("agent") == "orchestrator":
                    scan_path = data.get("scan_path", "")

                # 提取持續時間
                if event_type == "SCAN_END":
                    dur_s = data.get("total_duration_seconds", 0)
                    if dur_s:
                        duration = f"{dur_s / 60:.1f}m" if dur_s >= 60 else f"{dur_s:.0f}s"
                    event_count = data.get("total_checkpoints", event_count)

        # 組合標籤（確保無換行）
        parts = []
        if target_preview:
            # 清除換行和多餘空格
            clean = target_preview.replace("\n", " ").replace("\r", "").strip()
            if clean:
                parts.append(clean)
        if scan_path:
            parts.append(f"Path {scan_path}")
        if duration:
            parts.append(duration)
        if event_count:
            parts.append(f"{event_count} events")

        return " | ".join(parts) if parts else filepath.stem

    except Exception:
        return filepath.stem


@app.get("/api/checkpoints/{filename}")
async def get_checkpoint_events(filename: str):
    """讀取指定 JSONL 檔案的全部事件（供 Dashboard 渲染）"""
    # 安全性：只允許讀取 checkpoints 目錄下的 .jsonl 檔案
    if not filename.endswith(".jsonl") or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    cp_file = _ROOT / "logs" / "checkpoints" / filename
    if not cp_file.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {filename}")

    events = []
    try:
        with open(cp_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass  # 忽略損壞的行
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Read error: {e}")

    return JSONResponse({"filename": filename, "events": events, "total": len(events)})


@app.post("/api/scan", response_model=ScanResponse)
async def start_scan(req: ScanRequest):
    """觸發掃描：建立 scan_id，啟動背景執行緒"""
    tech_stack = req.tech_stack.strip()
    if not tech_stack:
        raise HTTPException(status_code=422, detail="tech_stack cannot be empty")

    scan_id = str(uuid.uuid4())[:8]

    # 初始化 store
    _scan_store[scan_id] = {
        "queue":  queue.Queue(),
        "result": None,
        "error":  None,
        "tech_stack": tech_stack,
    }

    # 啟動背景執行緒
    t = threading.Thread(
        target=_pipeline_worker,
        args=(scan_id, tech_stack),
        daemon=True,
        name=f"pipeline-{scan_id}",
    )
    t.start()

    logger.info("[API] Scan started | scan_id=%s | tech_stack=%s", scan_id, tech_stack)
    return ScanResponse(scan_id=scan_id)


@app.get("/api/stream/{scan_id}")
async def stream_scan(scan_id: str):
    """SSE 串流端點：即時推送 pipeline 進度"""
    if scan_id not in _scan_store:
        raise HTTPException(status_code=404, detail=f"scan_id '{scan_id}' not found")

    return StreamingResponse(
        _sse_generator(scan_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control":               "no-cache",
            "X-Accel-Buffering":           "no",
            "Access-Control-Allow-Origin": "*",
            "Connection":                  "keep-alive",
        },
    )


@app.get("/api/result/{scan_id}")
async def get_result(scan_id: str):
    """取得最終掃描結果 JSON"""
    store = _scan_store.get(scan_id)
    if not store:
        raise HTTPException(status_code=404, detail=f"scan_id '{scan_id}' not found")
    if store.get("error"):
        raise HTTPException(status_code=500, detail=store["error"])
    if store.get("result") is None:
        raise HTTPException(status_code=202, detail="Scan still in progress")
    return JSONResponse(store["result"])


# ══════════════════════════════════════════════════════════════
# 啟動入口
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    # 直接傳 app 物件（不用字串），無論從 project root 或 ui/ 目錄執行都正常
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=1000,
        reload=False,
        log_level="info",
    )
