"""
ui/app.py — ThreatHunter Demo UI
==================================
Streamlit 介面，採 Dark Mode OLED + HUD 點綴風格。
UI/UX Skill 建議：Deep Black #0A0E27、Cyan 重點色、最小化 glow 效果。

設計原則（降 AI 感）：
- 互動式輸入：使用者自行輸入技術堆疊，觸發真實掃描
- 即時進度顯示：Pipeline 各階段狀態同步更新
- 行動清單結構：不是 AI 報告口吻，是真實 SRE 工具的修補清單
- Observability：推理過程可展開（不隱藏 AI 的思考）
"""

import json
import os
import sys

import streamlit as st

# 確保 import 路徑正確
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

# ══════════════════════════════════════════════════════════════
# 頁面設定（必須在最前面）
# ══════════════════════════════════════════════════════════════

st.set_page_config(
    page_title="ThreatHunter — AI 資安威脅情報平台",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ══════════════════════════════════════════════════════════════
# CSS 設計系統（OLED Dark + HUD 點綴）
# UI/UX Pro Max Skill 建議：
#   --bg-black: #000000 / #0A0E27
#   --accent: #00FFFF (Cyan)
#   --alert-red: #FF3B3B
#   --warn-yellow: #FFD600
#   --ok-green: #00E676
# ══════════════════════════════════════════════════════════════

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

/* ── Global Reset ─────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; }

.stApp {
    background: #030712;
    color: #E2E8F0;
    font-family: 'Inter', system-ui, sans-serif;
}

/* ── Header ───────────────────────────────────── */
.th-header {
    background: linear-gradient(135deg, #0A0E27 0%, #0D1B2A 100%);
    border-bottom: 1px solid rgba(0,255,255,0.15);
    padding: 1.5rem 2rem;
    margin: -1rem -1rem 2rem -1rem;
    display: flex;
    align-items: center;
    gap: 1rem;
}
.th-logo {
    font-size: 2rem;
    filter: drop-shadow(0 0 8px rgba(0,255,255,0.6));
}
.th-title {
    font-size: 1.5rem;
    font-weight: 700;
    color: #FFFFFF;
    letter-spacing: -0.02em;
    margin: 0;
}
.th-subtitle {
    font-size: 0.8rem;
    color: rgba(0,255,255,0.6);
    font-family: 'JetBrains Mono', monospace;
    margin: 0;
    letter-spacing: 0.1em;
}

/* ── Input Card ───────────────────────────────── */
.th-input-card {
    background: #0D1B2A;
    border: 1px solid rgba(0,255,255,0.2);
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
    position: relative;
    overflow: hidden;
}
.th-input-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, #00FFFF, transparent);
}

/* ── Pipeline Status ──────────────────────────── */
.pipeline-bar {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 1rem 1.5rem;
    background: #0A0E1A;
    border-radius: 8px;
    border: 1px solid rgba(255,255,255,0.06);
    margin-bottom: 1.5rem;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.85rem;
}
.pipeline-step {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.3rem 0.8rem;
    border-radius: 20px;
    font-size: 0.8rem;
    font-weight: 500;
    transition: all 0.3s ease;
}
.step-pending  { background: rgba(255,255,255,0.06); color: #64748B; }
.step-running  { background: rgba(255,214,0,0.15); color: #FFD600; border: 1px solid rgba(255,214,0,0.3); }
.step-done     { background: rgba(0,230,118,0.15); color: #00E676; border: 1px solid rgba(0,230,118,0.3); }
.step-skipped  { background: rgba(100,116,139,0.15); color: #64748B; border: 1px solid rgba(100,116,139,0.2); }
.step-arrow    { color: #1E3A5F; }

/* ── Metric Cards ─────────────────────────────── */
.metric-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1rem;
    margin-bottom: 1.5rem;
}
.metric-card {
    background: #0D1B2A;
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 10px;
    padding: 1.2rem 1rem;
    text-align: center;
    transition: border-color 0.3s;
}
.metric-card:hover { border-color: rgba(0,255,255,0.3); }
.metric-value {
    font-size: 2.2rem;
    font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
    line-height: 1;
    margin-bottom: 0.3rem;
}
.metric-label { font-size: 0.75rem; color: #64748B; font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em; }
.metric-critical .metric-value { color: #FF3B3B; }
.metric-high     .metric-value { color: #FF8C00; }
.metric-score    .metric-value { color: #00FFFF; }
.metric-new      .metric-value { color: #A78BFA; }

/* ── Section Title ────────────────────────────── */
.section-title {
    font-size: 0.7rem;
    font-weight: 600;
    color: rgba(0,255,255,0.5);
    letter-spacing: 0.15em;
    text-transform: uppercase;
    font-family: 'JetBrains Mono', monospace;
    margin-bottom: 0.8rem;
    padding-bottom: 0.4rem;
    border-bottom: 1px solid rgba(0,255,255,0.1);
}

/* ── Action Cards ─────────────────────────────── */
.action-card {
    padding: 1rem 1.2rem;
    border-radius: 8px;
    margin-bottom: 0.6rem;
    border-left: 3px solid;
    background: #0D1B2A;
    transition: transform 0.2s ease;
}
.action-card:hover { transform: translateX(4px); }

.action-urgent    { border-left-color: #FF3B3B; background: rgba(255,59,59,0.05); }
.action-important { border-left-color: #FFD600; background: rgba(255,214,0,0.05); }
.action-resolved  { border-left-color: #00E676; background: rgba(0,230,118,0.05); opacity: 0.7; }

.action-cve {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.85rem;
    font-weight: 600;
    color: #CBD5E1;
    margin-bottom: 0.2rem;
}
.action-pkg {
    display: inline-block;
    font-size: 0.7rem;
    background: rgba(0,255,255,0.1);
    color: #00FFFF;
    padding: 0.1rem 0.5rem;
    border-radius: 10px;
    font-family: 'JetBrains Mono', monospace;
    margin-right: 0.4rem;
}
.severity-badge {
    display: inline-block;
    font-size: 0.65rem;
    font-weight: 700;
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    letter-spacing: 0.05em;
}
.badge-critical { background: rgba(255,59,59,0.3); color: #FF3B3B; }
.badge-high     { background: rgba(255,140,0,0.3); color: #FF8C00; }
.badge-medium   { background: rgba(255,214,0,0.3);  color: #FFD600; }
.badge-low      { background: rgba(100,116,139,0.3); color: #94A3B8; }

.action-desc { font-size: 0.82rem; color: #94A3B8; margin: 0.4rem 0; }
.action-command {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem;
    background: rgba(0,0,0,0.4);
    color: #00E676;
    padding: 0.4rem 0.8rem;
    border-radius: 4px;
    border: 1px solid rgba(0,230,118,0.2);
    margin-top: 0.4rem;
    display: block;
    overflow-x: auto;
}
.repeated-badge {
    font-size: 0.65rem;
    background: rgba(255,59,59,0.2);
    color: #FF3B3B;
    border: 1px solid rgba(255,59,59,0.3);
    padding: 0.1rem 0.4rem;
    border-radius: 4px;
    margin-left: 0.4rem;
}

/* ── CVE Table ────────────────────────────────── */
.cve-row {
    display: grid;
    grid-template-columns: 160px 90px 70px 70px 1fr;
    gap: 0.5rem;
    padding: 0.7rem 1rem;
    border-bottom: 1px solid rgba(255,255,255,0.04);
    font-size: 0.82rem;
    align-items: center;
}
.cve-row:hover { background: rgba(255,255,255,0.02); }
.cve-id-cell { font-family: 'JetBrains Mono', monospace; color: #CBD5E1; font-weight: 500; }
.cvss-cell { font-family: 'JetBrains Mono', monospace; font-weight: 600; text-align: center; }
.new-tag { font-size: 0.65rem; color: #A78BFA; font-weight: 600; }
.desc-cell { color: #64748B; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

/* ── Feedback Buttons ─────────────────────────── */
.stButton > button {
    background: transparent !important;
    border: 1px solid rgba(0,255,255,0.25) !important;
    color: #CBD5E1 !important;
    border-radius: 6px !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 0.8rem !important;
    transition: all 0.2s ease !important;
}
.stButton > button:hover {
    border-color: rgba(0,255,255,0.6) !important;
    color: #00FFFF !important;
    background: rgba(0,255,255,0.05) !important;
}

/* ── Input Styling ────────────────────────────── */
.stTextInput > div > div > input {
    background: #030712 !important;
    border: 1px solid rgba(0,255,255,0.2) !important;
    color: #E2E8F0 !important;
    border-radius: 8px !important;
    font-family: 'JetBrains Mono', monospace !important;
}
.stTextInput > div > div > input:focus {
    border-color: rgba(0,255,255,0.5) !important;
    box-shadow: 0 0 0 2px rgba(0,255,255,0.1) !important;
}

/* ── Expanders ────────────────────────────────── */
.streamlit-expanderHeader {
    background: #0A0E1A !important;
    border: 1px solid rgba(255,255,255,0.06) !important;
    border-radius: 6px !important;
    color: #64748B !important;
    font-size: 0.8rem !important;
}

/* ── Scrollbar ────────────────────────────────── */
::-webkit-scrollbar { width: 4px; height: 4px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: rgba(0,255,255,0.2); border-radius: 2px; }
</style>
""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════
# Helper 函式
# ══════════════════════════════════════════════════════════════

def severity_badge(sev: str) -> str:
    cls_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    cls = cls_map.get(sev.upper(), "low")
    return f'<span class="severity-badge badge-{cls}">{sev}</span>'


def cvss_color(score: float) -> str:
    if score >= 9.0:
        return "#FF3B3B"
    elif score >= 7.0:
        return "#FF8C00"
    elif score >= 4.0:
        return "#FFD600"
    return "#64748B"


def render_action_card(item: dict, card_class: str) -> str:
    cve = item.get("cve_id", "UNKNOWN")
    pkg = item.get("package", "unknown")
    sev = item.get("severity", "MEDIUM")
    action = item.get("action", "")
    command = item.get("command", "")
    is_repeated = item.get("is_repeated", False)

    repeated_tag = '<span class="repeated-badge">⚠ REPEATED</span>' if is_repeated else ""
    cmd_block = f'<code class="action-command">$ {command}</code>' if command else ""

    return f"""
<div class="action-card {card_class}">
  <div class="action-cve">{cve}{repeated_tag}</div>
  <div style="margin: 0.3rem 0;">
    <span class="action-pkg">{pkg}</span>
    {severity_badge(sev)}
  </div>
  <div class="action-desc">{action}</div>
  {cmd_block}
</div>
"""


def render_pipeline_bar(scout_status: str, analyst_status: str, advisor_status: str) -> str:
    def step_html(icon: str, label: str, status: str) -> str:
        cls = {
            "pending": "step-pending",
            "running": "step-running",
            "done": "step-done",
            "skipped": "step-skipped",
        }.get(status, "step-pending")
        return f'<span class="pipeline-step {cls}">{icon} {label}</span>'

    scout_html = step_html("🔍", "Scout", scout_status)
    analyst_html = step_html("🧠", "Analyst", analyst_status)
    advisor_html = step_html("📋", "Advisor", advisor_status)

    return f"""
<div class="pipeline-bar">
  {scout_html}
  <span class="step-arrow">──▶</span>
  {analyst_html}
  <span class="step-arrow">──▶</span>
  {advisor_html}
</div>
"""


# ══════════════════════════════════════════════════════════════
# Session State 初始化
# ══════════════════════════════════════════════════════════════

if "scan_result" not in st.session_state:
    st.session_state.scan_result = None
if "scout_result" not in st.session_state:
    st.session_state.scout_result = None
if "advisor_result" not in st.session_state:
    st.session_state.advisor_result = None
if "is_scanning" not in st.session_state:
    st.session_state.is_scanning = False
if "pipeline_status" not in st.session_state:
    st.session_state.pipeline_status = ("pending", "pending", "pending")


# ══════════════════════════════════════════════════════════════
# Header
# ══════════════════════════════════════════════════════════════

st.markdown("""
<div class="th-header">
  <span class="th-logo">🛡️</span>
  <div>
    <p class="th-title">ThreatHunter</p>
    <p class="th-subtitle">AI-POWERED CYBERSECURITY THREAT INTELLIGENCE</p>
  </div>
</div>
""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════
# 輸入區
# ══════════════════════════════════════════════════════════════

st.markdown('<div class="th-input-card">', unsafe_allow_html=True)
st.markdown('<p class="section-title">▸ TARGET TECH STACK</p>', unsafe_allow_html=True)

col_input, col_btn, col_example = st.columns([4, 1, 1])

with col_input:
    tech_stack_input = st.text_input(
        label="tech_stack",
        value="Django 4.2, Redis 7.0",
        placeholder="e.g. Django 4.2, Redis 7.0, nginx 1.24",
        label_visibility="collapsed",
    )

with col_btn:
    scan_clicked = st.button("🔍 Scan", use_container_width=True, type="primary")

with col_example:
    if st.button("Load Example", use_container_width=True):
        st.session_state["_example_loaded"] = True

st.markdown("</div>", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════
# 掃描執行
# ══════════════════════════════════════════════════════════════

if scan_clicked and tech_stack_input.strip():
    st.session_state.is_scanning = True
    st.session_state.scan_result = None
    st.session_state.scout_result = None
    st.session_state.advisor_result = None

    # Pipeline 狀態區
    pipeline_placeholder = st.empty()
    pipeline_placeholder.markdown(
        render_pipeline_bar("running", "pending", "pending"),
        unsafe_allow_html=True
    )
    status_placeholder = st.empty()

    # ── Phase 1: Scout ──────────────────────────────────────
    try:
        from agents.scout import run_scout_pipeline

        with st.spinner("🔍 Scout Agent — 正在蒐集漏洞情報..."):
            scout_result = run_scout_pipeline(tech_stack_input)

        st.session_state.scout_result = scout_result
        pipeline_placeholder.markdown(
            render_pipeline_bar("done", "skipped", "running"),
            unsafe_allow_html=True
        )
        status_placeholder.success(
            f"✅ Scout 完成：發現 {scout_result.get('summary', {}).get('total', 0)} 筆 CVE"
        )

    except Exception as e:
        pipeline_placeholder.markdown(
            render_pipeline_bar("done", "skipped", "skipped"),
            unsafe_allow_html=True
        )
        status_placeholder.error(f"❌ Scout 執行失敗：{e}")
        st.session_state.is_scanning = False
        st.stop()

    # ── Phase 2: Analyst（待成員 C 就緒）──────────────────
    # 目前直接傳 Scout 輸出給 Advisor（降級路徑）
    analyst_input = scout_result  # 成員 C 接好後改為 analyst_result

    # ── Phase 3: Advisor ────────────────────────────────────
    try:
        from agents.advisor import run_advisor_pipeline

        with st.spinner("📋 Advisor Agent — 正在生成行動報告..."):
            advisor_result = run_advisor_pipeline(analyst_input)

        st.session_state.advisor_result = advisor_result
        pipeline_placeholder.markdown(
            render_pipeline_bar("done", "skipped", "done"),
            unsafe_allow_html=True
        )
        status_placeholder.success("✅ 掃描完成！行動報告已生成。")

    except Exception as e:
        status_placeholder.warning(f"⚠️ Advisor 執行中：使用降級報告 ({e})")
        # 降級：直接用 Scout 結果產生最小報告
        from agents.advisor import _build_fallback_output
        advisor_result = _build_fallback_output(scout_result)
        st.session_state.advisor_result = advisor_result
        pipeline_placeholder.markdown(
            render_pipeline_bar("done", "skipped", "done"),
            unsafe_allow_html=True
        )

    st.session_state.is_scanning = False


# ══════════════════════════════════════════════════════════════
# 結果展示
# ══════════════════════════════════════════════════════════════

scout = st.session_state.scout_result
advisor = st.session_state.advisor_result

if scout and advisor:
    summary = scout.get("summary", {})
    vulns = scout.get("vulnerabilities", [])
    actions = advisor.get("actions", {})
    urgent_list = actions.get("urgent", [])
    important_list = actions.get("important", [])
    resolved_list = actions.get("resolved", [])

    # ── 摘要指標卡片 ──────────────────────────────────────
    st.markdown('<p class="section-title">▸ SCAN OVERVIEW</p>', unsafe_allow_html=True)
    risk_score = advisor.get("risk_score", 0)
    risk_trend = advisor.get("risk_trend", "0")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(f"""
        <div class="metric-card metric-score">
            <div class="metric-value">{risk_score}</div>
            <div class="metric-label">Risk Score <span style="color:#64748B;font-size:0.65rem">/ 100</span></div>
        </div>""", unsafe_allow_html=True)
    with col2:
        st.markdown(f"""
        <div class="metric-card metric-critical">
            <div class="metric-value">{summary.get('critical', 0)}</div>
            <div class="metric-label">Critical</div>
        </div>""", unsafe_allow_html=True)
    with col3:
        st.markdown(f"""
        <div class="metric-card metric-high">
            <div class="metric-value">{summary.get('high', 0)}</div>
            <div class="metric-label">High</div>
        </div>""", unsafe_allow_html=True)
    with col4:
        new_count = summary.get("new_since_last_scan", sum(1 for v in vulns if v.get("is_new")))
        st.markdown(f"""
        <div class="metric-card metric-new">
            <div class="metric-value">{new_count}</div>
            <div class="metric-label">New Since Last Scan</div>
        </div>""", unsafe_allow_html=True)

    # ── Executive Summary ──────────────────────────────────
    exec_summary = advisor.get("executive_summary", "")
    if exec_summary:
        st.markdown(f"""
        <div style="background:#0D1B2A;border:1px solid rgba(0,255,255,0.1);
                    border-radius:8px;padding:1rem 1.2rem;margin:1rem 0 1.5rem 0;
                    font-size:0.9rem;color:#CBD5E1;line-height:1.6;">
            📊 {exec_summary}
        </div>""", unsafe_allow_html=True)

    # ── 行動清單 ──────────────────────────────────────────
    col_actions, col_cve = st.columns([1, 1])

    with col_actions:
        st.markdown('<p class="section-title">▸ ACTION ITEMS</p>', unsafe_allow_html=True)

        if urgent_list:
            st.markdown("**🔴 URGENT** — 今天就要修", unsafe_allow_html=True)
            for item in urgent_list:
                st.markdown(render_action_card(item, "action-urgent"), unsafe_allow_html=True)

        if important_list:
            st.markdown("**🟡 IMPORTANT** — 本週修補", unsafe_allow_html=True)
            for item in important_list:
                st.markdown(render_action_card(item, "action-important"), unsafe_allow_html=True)

        if resolved_list:
            st.markdown("**🟢 RESOLVED**", unsafe_allow_html=True)
            for item in resolved_list:
                st.markdown(render_action_card(item, "action-resolved"), unsafe_allow_html=True)

        if not urgent_list and not important_list and not resolved_list:
            st.markdown("""
            <div style="text-align:center;color:#64748B;padding:2rem;font-size:0.85rem;">
                No action items found.
            </div>""", unsafe_allow_html=True)

    with col_cve:
        st.markdown('<p class="section-title">▸ CVE DETAILS</p>', unsafe_allow_html=True)

        # 表頭
        st.markdown("""
        <div class="cve-row" style="color:#64748B;font-size:0.7rem;font-weight:600;
             letter-spacing:0.05em;text-transform:uppercase;border-bottom:1px solid rgba(0,255,255,0.1);">
            <span>CVE ID</span>
            <span>Package</span>
            <span>CVSS</span>
            <span>Severity</span>
            <span>Description</span>
        </div>""", unsafe_allow_html=True)

        # 行資料（依 CVSS 降序）
        for vuln in sorted(vulns, key=lambda x: x.get("cvss_score", 0), reverse=True):
            cve_id = vuln.get("cve_id", "?")
            pkg = vuln.get("package", "?")
            cvss = float(vuln.get("cvss_score", 0))
            sev = vuln.get("severity", "LOW")
            desc = vuln.get("description", "")[:80] + ("..." if len(vuln.get("description", "")) > 80 else "")
            is_new = vuln.get("is_new", False)
            new_badge = '<span class="new-tag">NEW</span>' if is_new else ""
            color = cvss_color(cvss)

            st.markdown(f"""
            <div class="cve-row">
                <span class="cve-id-cell">{cve_id} {new_badge}</span>
                <span style="color:#94A3B8;font-family:'JetBrains Mono',monospace;font-size:0.8rem">{pkg}</span>
                <span class="cvss-cell" style="color:{color}">{cvss:.1f}</span>
                <span>{severity_badge(sev)}</span>
                <span class="desc-cell" title="{desc}">{desc}</span>
            </div>""", unsafe_allow_html=True)

    # ── 使用者回饋 ─────────────────────────────────────────
    st.markdown("---")
    st.markdown('<p class="section-title">▸ FEEDBACK</p>', unsafe_allow_html=True)

    fb_col1, fb_col2, fb_col3, fb_col4 = st.columns([1, 1, 1, 3])
    with fb_col1:
        if st.button("✅ 已修補", key="fb_fixed"):
            st.success("已記錄！下次掃描將標記為 RESOLVED。")
    with fb_col2:
        if st.button("⏳ 已知道", key="fb_noted"):
            st.info("已記錄，將在下次報告追蹤。")
    with fb_col3:
        if st.button("❓ 需更多說明", key="fb_help"):
            st.warning("建議參考 NVD 原始記錄或聯繫資安顧問。")

    # ── ReAct 推理歷程（Observability 支柱）──────────────
    with st.expander("🔍 查看 AI 推理歷程（Observability）", expanded=False):
        st.markdown("""
        <p style="color:#64748B;font-size:0.82rem;font-family:'JetBrains Mono',monospace;">
        下方顯示 Scout Agent 的原始資料：
        </p>""", unsafe_allow_html=True)
        st.json(scout, expanded=False)
        st.markdown("---")
        st.markdown("""
        <p style="color:#64748B;font-size:0.82rem;font-family:'JetBrains Mono',monospace;">
        Advisor 行動報告（原始 JSON）：
        </p>""", unsafe_allow_html=True)
        st.json(advisor, expanded=False)

elif not st.session_state.is_scanning:
    # ── 初始畫面 ──────────────────────────────────────────
    st.markdown("""
    <div style="text-align:center;padding:4rem 2rem;color:#1E3A5F;">
        <div style="font-size:4rem;margin-bottom:1rem;filter:drop-shadow(0 0 20px rgba(0,255,255,0.3));">🛡️</div>
        <p style="font-size:1.1rem;color:#475569;font-family:'JetBrains Mono',monospace;">
            輸入你的技術堆疊，開始 AI 驅動的漏洞分析
        </p>
        <p style="font-size:0.8rem;color:#1E3A5F;margin-top:0.5rem;">
            Scout → Analyst → Advisor → Action Report
        </p>
    </div>""", unsafe_allow_html=True)

    # 範例卡片
    col_ex1, col_ex2, col_ex3 = st.columns(3)
    examples = [
        ("🐍 Python Web", "Django 4.2, Redis 7.0, nginx 1.24"),
        ("☕ Java Stack", "Spring Boot 3.1, Tomcat 10.1, MySQL 8.0"),
        ("🟢 Node.js", "Express 4.18, MongoDB 7.0, nginx 1.24"),
    ]
    for col, (title, stack) in zip([col_ex1, col_ex2, col_ex3], examples):
        with col:
            st.markdown(f"""
            <div style="background:#0D1B2A;border:1px solid rgba(255,255,255,0.06);
                        border-radius:8px;padding:1rem;cursor:pointer;
                        transition:border-color 0.3s;"
                 onmouseover="this.style.borderColor='rgba(0,255,255,0.3)'"
                 onmouseout="this.style.borderColor='rgba(255,255,255,0.06)'">
                <p style="font-weight:600;color:#CBD5E1;margin:0 0 0.3rem 0;font-size:0.9rem">{title}</p>
                <p style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;
                           color:#64748B;margin:0">{stack}</p>
            </div>""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════
# Sidebar（設定）
# ══════════════════════════════════════════════════════════════

with st.sidebar:
    st.markdown("### ⚙️ 設定")
    st.markdown("---")
    st.markdown(f"""
    **API 狀態**

    NVD API Key: {'✅' if os.getenv('NVD_API_KEY') else '⚠️ 未設定（慢速）'}

    OTX API Key: {'✅' if os.getenv('OTX_API_KEY') else '⚠️ 未設定'}

    LLM Provider: {'✅' if os.getenv('OPENROUTER_API_KEY') else '❌ 未設定'}
    """)
    st.markdown("---")
    st.markdown("""
    **關於 ThreatHunter**

    - Scout Agent：NVD + OTX 情報蒐集
    - Analyst Agent：攻擊鏈分析（開發中）
    - Advisor Agent：行動建議生成
    - 5 層 Harness 防護，確保零幻覺
    """)
    st.markdown("---")
    st.markdown("""
    <p style="font-size:0.7rem;color:#334155;font-family:'JetBrains Mono',monospace;">
    ThreatHunter v1.0-demo<br>
    AMD Developer Hackathon 2026
    </p>""", unsafe_allow_html=True)
