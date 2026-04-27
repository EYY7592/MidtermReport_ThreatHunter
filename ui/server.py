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

from contextlib import asynccontextmanager


@asynccontextmanager
async def _lifespan(application):  # type: ignore[override]
    """Server 啟動時：自動清潔 Memory 中 year < 2005 的遠古 CVE 汙染。"""
    import sys as _sys
    _sys.path.insert(0, str(_HERE.parent))
    try:
        from scripts.clean_memory_contamination import clean_memory_file
        for _fname in ["memory/scout_memory.json", "memory/advisor_memory.json"]:
            _path = str(_HERE.parent / _fname)
            _r = clean_memory_file(_path)
            if _r.get("status") == "CLEANED":
                logger.info(
                    "[STARTUP] Memory cleaned: %s — removed %d ancient CVEs, kept %d",
                    _fname, _r.get("removed", 0), _r.get("remaining", 0),
                )
            else:
                logger.info("[STARTUP] Memory check: %s — %s", _fname, _r.get("status", "OK"))
    except Exception as _me:
        logger.warning("[STARTUP] Memory cleanup skipped: %s", _me)
    yield


app = FastAPI(
    title="ThreatHunter API",
    version="3.1",
    description="AI 多 Agent 資安威脅情報平台",
    lifespan=_lifespan,
)

# ── 掛載靜態資源 ────────────────────────────────────────────
_STATIC_DIR = _HERE / "static"
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


# ══════════════════════════════════════════════════════════════
# Request / Response 模型
# ══════════════════════════════════════════════════════════════

class ScanRequest(BaseModel):
    tech_stack: str
    input_type: str = "pkg"  # v3.7: forwarded from frontend input-type detector


class ScanResponse(BaseModel):
    scan_id: str
    message: str = "Scan started"


# ══════════════════════════════════════════════════════════════
# 報告組裝：從 Scout 記憶補充漏洞細節
# ══════════════════════════════════════════════════════════════

def _summarize_vulnerabilities(vulns: list[dict[str, Any]]) -> dict[str, int]:
    """把漏洞清單整理成前端摘要指標。"""
    summary = {
        "total": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "new": 0,
        "new_since_last_scan": 0,
    }

    for vuln in vulns:
        summary["total"] += 1
        severity = str(vuln.get("severity", "LOW")).upper()
        if severity == "CRITICAL":
            summary["critical"] += 1
        elif severity == "HIGH":
            summary["high"] += 1
        elif severity == "MEDIUM":
            summary["medium"] += 1
        else:
            summary["low"] += 1

        if vuln.get("is_new"):
            summary["new"] += 1
            summary["new_since_last_scan"] += 1

    return summary


def _extract_action_vulnerabilities(result: dict[str, Any]) -> list[dict[str, Any]]:
    """當 pipeline 沒帶漏洞明細時，從 Advisor actions 建立最小備援資料。"""
    vulns: list[dict[str, Any]] = []
    seen: set[str] = set()
    actions = result.get("actions", {})

    for level in ["urgent", "important", "resolved"]:
        for item in actions.get(level, []):
            cve_id = item.get("cve_id", "")
            if cve_id and cve_id not in seen:
                seen.add(cve_id)
                vulns.append({
                    "cve_id": cve_id,
                    "package": item.get("package") or "Package not provided",
                    "cvss_score": item.get("cvss_score", 0),
                    "severity": item.get("severity", "MEDIUM"),
                    "description": item.get("action", ""),
                    "is_new": item.get("is_new", False),
                    "source": "ADVISOR_ACTIONS",
                    "report_level": level.upper(),
                })

    return vulns


def _enrich_result(result: dict[str, Any]) -> dict[str, Any]:
    """
    優先使用本次 scan 的漏洞明細，只有缺資料時才回退到 memory/actions。
    """
    if "vulnerability_detail" in result:
        vulns = list(result.get("vulnerability_detail") or [])
        result["vulnerability_summary"] = _summarize_vulnerabilities(vulns)
        sources = result.setdefault("report_sources", {})
        sources.setdefault("vulnerability_detail", "pipeline_result")
        result["vulnerability_detail"] = vulns
        return result

    scout_path = _ROOT / "memory" / "scout_memory.json"
    vulns: list[dict[str, Any]] = []
    action_vulns = _extract_action_vulnerabilities(result)

    if action_vulns:
        vulns = action_vulns
    elif scout_path.exists():
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

    if not vulns:
        vulns = action_vulns

    # ── UI 最後防線：CVE 年份過濾（year < 2005 不顯示在 UI）──────────
    # 無論哪個 Agent 產生了舊 CVE，在呈現給前端前一律過濾
    CVE_YEAR_MIN_UI = 2005
    ancient_in_ui = []
    fresh_ui_vulns = []
    for v in vulns:
        cve_id = v.get("cve_id", "")
        if cve_id.startswith("GHSA-") or not cve_id.startswith("CVE-"):
            fresh_ui_vulns.append(v)
            continue
        try:
            yr = int(cve_id.split("-")[1])
            if yr < CVE_YEAR_MIN_UI:
                ancient_in_ui.append(cve_id)
                logger.warning("[UI FILTER] Ancient CVE hidden from UI (year=%d): %s", yr, cve_id)
            else:
                fresh_ui_vulns.append(v)
        except (IndexError, ValueError):
            fresh_ui_vulns.append(v)

    if ancient_in_ui:
        logger.warning("[UI FILTER] Total ancient CVEs removed from UI: %d — %s", len(ancient_in_ui), ancient_in_ui)
        vulns = fresh_ui_vulns
    # ────────────────────────────────────────────────────────────────

    result["vulnerability_detail"] = vulns
    result["vulnerability_summary"] = _summarize_vulnerabilities(vulns)
    result["report_sources"] = {
        "vulnerability_detail": "memory_or_actions_fallback",
        "fallbacks": ["memory_or_actions"],
        "layer1_state": "not_reported",
    }
    return result


# ══════════════════════════════════════════════════════════════
# Pipeline Worker（在背景執行緒）
# ══════════════════════════════════════════════════════════════

def _pipeline_worker(scan_id: str, tech_stack: str, input_type: str = "pkg") -> None:
    """
    在獨立執行緒中執行完整 Pipeline。
    透過 Queue 推送 SSE 事件給主執行緒。
    v3.7: 接受 input_type 參數，傳給 run_pipeline 做 Path-Aware Skills 路由。
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
                agent_status = detail.get("status", "SUCCESS")
                # 讖別 DEGRADED 狀態：_degraded=True 或 status=="DEGRADED" 均觸發
                is_degraded = (
                    detail.get("_degraded", False)
                    or str(agent_status).upper() == "DEGRADED"
                )
                if is_degraded:
                    agent_status = "DEGRADED"
                # 提取錯誤原因（供前端顯示）
                error_msg = detail.get("_error", "")
                if error_msg:
                    # 截短至 200 字元，确保 SSE JSON 不狀
                    error_msg = str(error_msg)[:200]
                emit("agent_done", {
                    "agent": agent,
                    "status": agent_status,
                    "detail": detail,
                    "error_msg": error_msg,
                })
            elif status == "LOG":
                # 部分 stage 會發送中間日誌
                emit("agent_log", {"agent": agent, "message": str(detail)})

        logger.info("[SCAN:%s] Pipeline start | tech_stack=%s | input_type=%s", scan_id, tech_stack, input_type)
        result = run_pipeline_with_callback(tech_stack, on_progress, input_type=input_type)

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
    finally:
        # v3.6: 存儲 checkpoint 檔名，供 Thinking Path API 查詢
        try:
            from checkpoint import recorder
            if recorder.current_filename:
                store["checkpoint_file"] = recorder.current_filename
                logger.info("[SCAN:%s] Checkpoint file: %s", scan_id, recorder.current_filename)
        except Exception as ex:
            logger.debug("[SCAN:%s] Cannot retrieve checkpoint filename: %s", scan_id, ex)


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


def _bool_env(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


def _build_runtime_capabilities() -> dict[str, Any]:
    """彙整 Rust / Sandbox 可用狀態，讓主 dashboard 可以直接顯示。"""
    try:
        from checkpoint import get_checkpoint_writer_status
        checkpoint_writer = get_checkpoint_writer_status()
    except Exception as exc:  # noqa: BLE001
        checkpoint_writer = {
            "available": False,
            "active": False,
            "preferred_backend": "rust_bufwriter",
            "current_backend": "python_lock",
            "fallback_backend": "python_lock",
            "error": str(exc),
        }

    try:
        import input_sanitizer as _input_sanitizer
        wasm_enabled = bool(getattr(_input_sanitizer, "_WASM_ENABLED", False))
        wasm_available = bool(getattr(_input_sanitizer, "_WASM_AVAILABLE", False))
        wasm_error = ""
    except Exception as exc:  # noqa: BLE001
        wasm_enabled = _bool_env("WASM_SANDBOX_ENABLED", "true")
        wasm_available = False
        wasm_error = str(exc)

    docker_enabled = _bool_env("SANDBOX_ENABLED", "true")
    docker_available = False
    docker_image_ready = False
    docker_error = ""
    try:
        from sandbox.docker_sandbox import SANDBOX_IMAGE, is_docker_available, is_sandbox_image_ready
        docker_available = is_docker_available()
        docker_image_ready = is_sandbox_image_ready() if docker_available else False
    except Exception as exc:  # noqa: BLE001
        SANDBOX_IMAGE = os.getenv("SANDBOX_IMAGE", "threathunter-sandbox:latest")
        docker_error = str(exc)

    docker_status = "disabled"
    if docker_enabled and docker_available and docker_image_ready:
        docker_status = "enabled"
    elif docker_enabled:
        docker_status = "not_ready"

    modules = {}
    for key, module_name in {
        "memory_sanitizer": "sandbox.memory_sanitizer",
        "ast_guard": "sandbox.ast_guard",
    }.items():
        try:
            __import__(module_name)
            modules[key] = {"active": True, "module": module_name}
        except Exception as exc:  # noqa: BLE001
            modules[key] = {"active": False, "module": module_name, "error": str(exc)}

    return {
        "status": "ok",
        "defaults": {
            "sandbox_enabled": docker_enabled,
            "wasm_sandbox_enabled": wasm_enabled,
        },
        "checkpoint_writer": checkpoint_writer,
        "wasm_prompt_sandbox": {
            "enabled": wasm_enabled,
            "available": wasm_available,
            "status": "enabled" if wasm_enabled and wasm_available else ("fallback" if wasm_enabled else "disabled"),
            "fallback": "python_l0_filter",
            "error": wasm_error,
        },
        "docker_sandbox": {
            "enabled": docker_enabled,
            "available": docker_available,
            "image_ready": docker_image_ready,
            "image": SANDBOX_IMAGE,
            "status": docker_status,
            "fallback": "in_process_pipeline",
            "error": docker_error,
        },
        "memory_sanitizer": modules["memory_sanitizer"],
        "ast_guard": modules["ast_guard"],
    }


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


@app.get("/api/runtime-capabilities")
async def runtime_capabilities():
    """主 dashboard Runtime Protection panel 使用的能力狀態。"""
    return JSONResponse(_build_runtime_capabilities())


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


# ══════════════════════════════════════════════════════════════
# Thinking Path API（v3.6 Observability)
# ══════════════════════════════════════════════════════════════

# 其他 Agent 的角色描述
_AGENT_META: dict[str, dict] = {
    "pipeline":        {"role": "Pipeline 管理",      "skill": None},
    "input_sanitizer": {"role": "L0 輸入淨化",     "skill": "security_guard.md"},
    "orchestrator":    {"role": "動態路由決策",  "skill": "orchestrator.md"},
    "security_guard":  {"role": "LLM 隔離提取",   "skill": "security_guard.md"},
    "intel_fusion":    {"role": "六維情報融合",  "skill": "intel_fusion.md"},
    "layer1_parallel": {"role": "Layer-1 並行",    "skill": None},
    "scout":           {"role": "威先情報偵察",  "skill": "scout.md"},
    "analyst":         {"role": "漏洞連鎖分析",  "skill": "analyst.md"},
    "critic":          {"role": "ColMAD 辩論",     "skill": "critic.md"},
    "advisor":         {"role": "行動報告生成",  "skill": "advisor.md"},
    "feedback_loop":   {"role": "回遈迴路",      "skill": None},
}


def _build_thinking_path(cp_file: Path) -> dict:
    """
    讀取 JSONL checkpoint 檔案，將事件依 Agent 分組。
    對每個 Agent 計算：
      - skill_applied: 是否有 LLM_RESULT 且 status=SUCCESS
      - 所有方式事件（LLM_CALL/LLM_RESULT/TOOL_CALL/STAGE_ENTER/STAGE_EXIT/HARNESS_CHECK/DEGRADATION）
    """
    # 展示給使用者看的事件類型（排除不相關的）
    DISPLAY_EVENTS = {
        "LLM_CALL", "LLM_RESULT", "LLM_RETRY", "LLM_ERROR",
        "TOOL_CALL", "STAGE_ENTER", "STAGE_EXIT",
        "HARNESS_CHECK", "DEGRADATION",
    }

    agents: dict[str, dict] = {}
    scan_meta: dict = {}

    try:
        with open(cp_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                except json.JSONDecodeError:
                    continue

                event_type = evt.get("event", "")
                agent = evt.get("agent", "pipeline")
                ts = evt.get("ts", "")
                data = evt.get("data", {})
                seq = evt.get("seq", 0)

                # 提取掃描元資料
                if event_type == "SCAN_START":
                    scan_meta["scan_id"] = data.get("scan_id", "")
                    scan_meta["start_ts"] = ts
                elif event_type == "SCAN_END":
                    scan_meta["end_ts"] = ts
                    scan_meta["duration_seconds"] = data.get("total_duration_seconds", 0)
                    scan_meta["total_events"] = data.get("total_checkpoints", seq)
                    scan_meta["event_summary"] = data.get("event_summary", {})

                # 將展示事件加入對應的 Agent
                if event_type in DISPLAY_EVENTS:
                    if agent not in agents:
                        meta = _AGENT_META.get(agent, {"role": agent, "skill": None})
                        agents[agent] = {
                            "role": meta["role"],
                            "skill_name": meta["skill"],
                            "skill_file": None,       # v3.7: raw .md filename from checkpoint
                            "input_type": None,       # v3.7: pkg/code/injection/config
                            "skill_applied": False,
                            "llm_calls": 0,
                            "tool_calls": 0,
                            "total_duration_ms": 0,
                            "steps": [],
                            "agent_record": {
                                "input": None,
                                "output": None,
                                "tool_calls": [],
                                "llm_calls": [],
                                "status": "RUNNING",
                                "duration_ms": 0,
                                "skill_file": None,
                                "input_type": None,
                                "degraded": False,
                                "degradation_reason": "",
                            },
                        }

                    step = {"seq": seq, "event": event_type, "ts": ts, "data": data}
                    agents[agent]["steps"].append(step)
                    record = agents[agent]["agent_record"]
                    if event_type in {"LLM_CALL", "LLM_RESULT", "LLM_RETRY", "LLM_ERROR"}:
                        record["llm_calls"].append({"seq": seq, "event": event_type, "ts": ts, "data": data})
                    elif event_type == "TOOL_CALL":
                        record["tool_calls"].append({"seq": seq, "event": event_type, "ts": ts, "data": data})

                # v3.7: extract skill_file + input_type from STAGE_ENTER
                if event_type == "STAGE_ENTER":
                    sf = data.get("skill_file", "")
                    if sf:
                        agents[agent]["skill_file"] = sf   # NEW: raw filename for badge
                        agents[agent]["skill_name"] = sf   # legacy compat
                        agents[agent]["skill_applied"] = True
                        agents[agent]["agent_record"]["skill_file"] = sf
                    it = data.get("input_type", "")
                    if it:
                        agents[agent]["input_type"] = it
                        agents[agent]["agent_record"]["input_type"] = it
                    agents[agent]["agent_record"]["input"] = data

                # 深化統計
                if event_type == "LLM_CALL":
                    agents[agent]["llm_calls"] += 1
                elif event_type == "LLM_RESULT":
                    if data.get("status") == "SUCCESS":
                        agents[agent]["skill_applied"] = True
                    agents[agent]["total_duration_ms"] += data.get("duration_ms", 0)
                elif event_type == "TOOL_CALL":
                    agents[agent]["tool_calls"] += 1
                elif event_type == "STAGE_EXIT":
                    record = agents[agent]["agent_record"]
                    record["output"] = data
                    record["status"] = data.get("status", record["status"])
                    record["duration_ms"] = data.get("duration_ms", record["duration_ms"])
                    if record["status"] not in {"SUCCESS", "COMPLETE", "COMPLETED"}:
                        record["degraded"] = True
                        record["degradation_reason"] = data.get("error") or data.get("reason") or record["status"]
                elif event_type == "LLM_ERROR":
                    record = agents[agent]["agent_record"]
                    record["degraded"] = True
                    record["degradation_reason"] = data.get("error", "LLM error")
                elif event_type == "DEGRADATION":
                    # v3.7: DEGRADATION means skill was NOT properly applied
                    agents[agent]["skill_applied"] = False
                    record = agents[agent]["agent_record"]
                    record["degraded"] = True
                    record["degradation_reason"] = data.get("reason") or data.get("error") or "Degraded"

    except Exception as e:
        logger.warning("[THINKING] 讀取 checkpoint 失敗: %s", e)

    # 按照 Agent 順序排列（主要 Pipeline 順序）
    order = ["input_sanitizer", "orchestrator", "security_guard", "intel_fusion",
             "layer1_parallel", "scout", "analyst", "critic", "advisor", "feedback_loop"]
    ordered_agents = {}
    for a in order:
        if a in agents:
            ordered_agents[a] = agents[a]
    # 加入其他未在預期順序中的 Agent
    for a, v in agents.items():
        if a not in ordered_agents:
            ordered_agents[a] = v

    return {"scan_meta": scan_meta, "agents": ordered_agents}


@app.get("/api/thinking/{scan_id}")
async def get_thinking_path(scan_id: str):
    """
    v3.6 Thinking Path API
    回傳指定掃描的完整思考軌跡：
    - 依 Agent 分組的 LLM 呼叫 / Tool 呼叭 / Stage 展允事件
    - 每個 Agent 的 skill_applied 狀態
    資料來源：_scan_store[scan_id]["checkpoint_file"] 記錄的 JSONL
    Graceful Degradation：尋找最新的 checkpoint 檔並回傳
    """
    cp_dir = _ROOT / "logs" / "checkpoints"
    cp_file: Path | None = None

    # 優先從 _scan_store 取對應檔名
    store = _scan_store.get(scan_id)
    if store and store.get("checkpoint_file"):
        candidate = cp_dir / store["checkpoint_file"]
        if candidate.exists():
            cp_file = candidate

    # Fallback：從 scan_id 模糊比對
    if cp_file is None and cp_dir.exists():
        # scan_id 格式：pipe_{timestamp_int}，檔名格式：scan_pipe_{8chars}_{timestamp}.jsonl
        short_id = scan_id[:8] if len(scan_id) >= 8 else scan_id
        candidates = sorted(
            [f for f in cp_dir.glob(f"scan_{short_id}*.jsonl")],
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if candidates:
            cp_file = candidates[0]

    # Fallback 最新 JSONL
    if cp_file is None and cp_dir.exists():
        all_files = sorted(cp_dir.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
        if all_files:
            cp_file = all_files[0]
            logger.warning("[THINKING] scan_id=%s 找不到對應 checkpoint，使用最新: %s", scan_id, cp_file.name)

    if cp_file is None:
        raise HTTPException(status_code=404, detail="尚無 checkpoint 檔案")

    thinking_data = _build_thinking_path(cp_file)
    thinking_data["scan_id"] = scan_id
    thinking_data["checkpoint_file"] = cp_file.name
    return JSONResponse(thinking_data)



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
        "queue":      queue.Queue(),
        "result":     None,
        "error":      None,
        "tech_stack": tech_stack,
        "input_type": req.input_type,
    }

    # 啟動背景執行緒
    t = threading.Thread(
        target=_pipeline_worker,
        args=(scan_id, tech_stack, req.input_type),
        daemon=True,
        name=f"pipeline-{scan_id}",
    )
    t.start()

    logger.info("[API] Scan started | scan_id=%s | input_type=%s | tech_stack=%s", scan_id, req.input_type, tech_stack)
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
# Phase 4D: Skill 熱載入管理 API
# ══════════════════════════════════════════════════════════════

# 延遲匯入 SkillLoader（避免在 import 時失敗影響整個 server）
def _get_skill_loader():
    """安全取得 SkillLoader 單例，若不可用回傳 None"""
    try:
        from skills.skill_loader import skill_loader
        return skill_loader
    except Exception as exc:
        logger.warning("[Skills API] SkillLoader 不可用: %s", exc)
        return None


@app.get("/api/skills")
async def list_skills():
    """
    列出所有 Skills 及其版本資訊（mtime、快取狀態）。

    回傳格式：
      { "skills": [{ "name": str, "mtime": float, "cached": bool, "size": int }],
        "total": int, "skill_loader": "available"|"unavailable" }
    """
    loader = _get_skill_loader()
    if loader is None:
        return JSONResponse({
            "skills": [],
            "total": 0,
            "skill_loader": "unavailable",
        })

    try:
        registry_data = loader.get_registry()
        skills_dir = _ROOT / "skills"
        skills_list = []

        for entry in registry_data.get("skills", []):
            name = entry.get("filename", "")
            skill_path = skills_dir / name
            skills_list.append({
                "name": name,
                "mtime": entry.get("mtime", 0),
                "cached": not entry.get("is_fallback", False),
                "size": skill_path.stat().st_size if skill_path.exists() else 0,
                "modified": time.strftime(
                    "%Y-%m-%dT%H:%M:%S",
                    time.localtime(entry.get("mtime", 0))
                ) if entry.get("mtime", 0) > 0 else None,
            })

        # 也補充 skills/ 目錄中存在但尚未快取的 .md 檔
        if skills_dir.exists():
            cached_names = {s["name"] for s in skills_list}
            for md_file in sorted(skills_dir.glob("*.md")):
                if md_file.name not in cached_names:
                    stat = md_file.stat()
                    skills_list.append({
                        "name": md_file.name,
                        "mtime": stat.st_mtime,
                        "cached": False,
                        "size": stat.st_size,
                        "modified": time.strftime("%Y-%m-%dT%H:%M:%S",
                                                  time.localtime(stat.st_mtime)),
                    })

        skills_list.sort(key=lambda s: s["name"])
        return JSONResponse({
            "skills": skills_list,
            "total": len(skills_list),
            "skill_loader": "available",
            "cache_ttl": registry_data.get("cache_ttl_seconds"),
        })

    except Exception as exc:
        logger.error("[Skills API] list_skills error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/skills/{skill_name}")
async def get_skill_content(skill_name: str):
    """
    取得指定 Skill 的 SOP 內容。

    Args:
        skill_name: .md 檔名（如 scout.md）

    回傳格式：
      { "name": str, "content": str, "cached": bool, "mtime": float }
    """
    # 安全性：只允許 .md 副檔名，且不含路徑分隔符
    if not skill_name.endswith(".md") or "/" in skill_name or "\\" in skill_name:
        raise HTTPException(status_code=400, detail="Invalid skill name")

    skills_dir = _ROOT / "skills"
    skill_path = skills_dir / skill_name
    if not skill_path.exists():
        raise HTTPException(status_code=404, detail=f"Skill not found: {skill_name}")

    loader = _get_skill_loader()
    content = ""
    cached = False

    if loader is not None:
        try:
            content = loader.load_skill(skill_name)
            registry_data = loader.get_registry()
            cached_entries = {e["filename"]: e for e in registry_data.get("skills", [])}
            cached = not cached_entries.get(skill_name, {}).get("is_fallback", True)
        except Exception as exc:
            logger.warning("[Skills API] SkillLoader.load_skill failed: %s", exc)

    # Fallback: 直接讀取
    if not content:
        try:
            content = skill_path.read_text(encoding="utf-8").strip()
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Read error: {exc}")

    stat = skill_path.stat()
    return JSONResponse({
        "name": skill_name,
        "content": content,
        "size": len(content),
        "cached": cached,
        "mtime": stat.st_mtime,
        "modified": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(stat.st_mtime)),
    })


class SkillReloadRequest(BaseModel):
    skill_name: str | None = None  # None → 強制重載所有


@app.post("/api/skills/reload")
async def reload_skills(req: SkillReloadRequest):
    """
    強制重載指定 Skill（或全部）的快取。

    Body: { "skill_name": "scout.md" }  ← 指定單一
          { "skill_name": null }         ← 全部重載

    回傳格式：
      { "reloaded": ["scout.md", ...], "errors": [...] }
    """
    loader = _get_skill_loader()
    if loader is None:
        raise HTTPException(status_code=503, detail="SkillLoader unavailable")

    reloaded = []
    errors = []

    try:
        if req.skill_name:
            # 單一重載
            if not req.skill_name.endswith(".md"):
                raise HTTPException(status_code=400, detail="skill_name must end with .md")
            loader.reload_skill(req.skill_name)
            reloaded.append(req.skill_name)
            logger.info("[Skills API] Force reloaded: %s", req.skill_name)
        else:
            # 全部重載：清空快取，下次 load_skill 自動重新讀取
            skills_dir = _ROOT / "skills"
            if skills_dir.exists():
                for md_file in skills_dir.glob("*.md"):
                    try:
                        loader.reload_skill(md_file.name)
                        reloaded.append(md_file.name)
                    except Exception as exc:
                        errors.append({"name": md_file.name, "error": str(exc)})
            logger.info("[Skills API] Force reloaded all: %d skills", len(reloaded))

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("[Skills API] reload error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    return JSONResponse({
        "reloaded": reloaded,
        "reloaded_count": len(reloaded),
        "errors": errors,
        "status": "ok" if not errors else "partial",
    })


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
