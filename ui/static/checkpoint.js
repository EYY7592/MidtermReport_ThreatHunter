/**
 * checkpoint.js — Checkpoint Dashboard 前端邏輯
 * =============================================
 * 功能：
 *   1. 載入掃描清單（/api/checkpoints）— 顯示描述性標籤
 *   2. 載入選定掃描的 JSONL 事件（/api/checkpoints/{filename}）
 *   3. 事件過濾（依 event type / agent / 搜尋文字）
 *   4. 統計摘要卡片計算
 *   5. 事件時間軸渲染 + 表格式詳細面板
 *
 * 遵守：AGENTS.md — 所有 .md 報告使用繁體中文；程式碼註解使用繁體中文
 */

// ══════════════════════════════════════════════════════════
// 全域狀態
// ══════════════════════════════════════════════════════════

let allEvents = [];         // 當前掃描的全部事件
let filteredEvents = [];    // 過濾後的事件

// DOM 元素快取
const $ = (id) => document.getElementById(id);
const scanSelector   = $('scanSelector');
const refreshBtn     = $('refreshBtn');
const eventFilter    = $('eventFilter');
const agentFilter    = $('agentFilter');
const searchInput    = $('searchInput');
const timeline       = $('timeline');
const filteredCount  = $('filteredCount');
const detailPanel    = $('detailPanel');
const detailTitle    = $('detailTitle');
const detailContent  = $('detailContent');
const closeDetail    = $('closeDetail');

// ══════════════════════════════════════════════════════════
// API 呼叫
// ══════════════════════════════════════════════════════════

/**
 * 取得掃描檔案清單
 */
async function fetchScanList() {
  try {
    const res = await fetch('/api/checkpoints');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    return data.files || [];
  } catch (e) {
    console.error('[CHECKPOINT] fetchScanList failed:', e);
    return [];
  }
}

/**
 * 取得指定掃描的事件清單
 * @param {string} filename — JSONL 檔名
 */
async function fetchScanEvents(filename) {
  try {
    const res = await fetch(`/api/checkpoints/${encodeURIComponent(filename)}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    return data.events || [];
  } catch (e) {
    console.error('[CHECKPOINT] fetchScanEvents failed:', e);
    return [];
  }
}

// ══════════════════════════════════════════════════════════
// 掃描選擇器（改善：使用描述性標籤）
// ══════════════════════════════════════════════════════════

async function loadScanList() {
  const files = await fetchScanList();
  scanSelector.innerHTML = '';

  if (files.length === 0) {
    scanSelector.innerHTML = '<option value="">No scans found</option>';
    return;
  }

  // 按更新時間倒序（最新在前）
  files.sort((a, b) => (b.modified || '').localeCompare(a.modified || ''));

  files.forEach((f, i) => {
    const opt = document.createElement('option');
    opt.value = f.name;
    // 使用描述性標籤（API 回傳的 label）
    const timeStr = f.modified ? f.modified.substring(5, 16).replace('T', ' ') : '';
    const label = f.label || f.name;
    opt.textContent = `${timeStr} — ${label}`;
    scanSelector.appendChild(opt);
  });

  // 自動載入最新的掃描
  if (files.length > 0) {
    scanSelector.value = files[0].name;
    await loadScanEvents(files[0].name);
  }
}

async function loadScanEvents(filename) {
  // 清空狀態
  allEvents = [];
  filteredEvents = [];
  renderTimeline([]);
  updateStats([]);

  if (!filename) return;

  // 載入事件
  allEvents = await fetchScanEvents(filename);

  // 建立 Agent 過濾選項
  buildAgentFilter();

  // 執行過濾
  applyFilters();
}

// ══════════════════════════════════════════════════════════
// 過濾邏輯
// ══════════════════════════════════════════════════════════

// 真正的 LLM Agent 白名單（Issue #3）
// pipeline / orchestrator / input_sanitizer 是基礎設施而非 Agent
// 不應出現在 Agent 過濾器中
const REAL_AGENTS = new Set([
  'scout', 'analyst', 'critic', 'advisor',
  'security_guard', 'intel_fusion'
]);

function buildAgentFilter() {
  // 只列出真正的 LLM Agent（白名單過濾）
  const agents = [...new Set(allEvents.map(e => e.agent).filter(Boolean))]
    .filter(a => REAL_AGENTS.has(a))
    .sort();
  agentFilter.innerHTML = '<option value="">All Agents</option>';
  agents.forEach(a => {
    const opt = document.createElement('option');
    opt.value = a;
    // 顯示友善名稱
    const displayNames = {
      scout: 'Scout (CVE 偵察)', analyst: 'Analyst (風險分析)',
      critic: 'Critic (辨論)', advisor: 'Advisor (裁身報告)',
      security_guard: 'Security Guard', intel_fusion: 'Intel Fusion'
    };
    opt.textContent = displayNames[a] || a;
    agentFilter.appendChild(opt);
  });
}

function applyFilters() {
  const eventType = eventFilter.value;
  const agent = agentFilter.value;
  const search = (searchInput.value || '').toLowerCase().trim();

  filteredEvents = allEvents.filter(e => {
    if (eventType && e.event !== eventType) return false;
    if (agent && e.agent !== agent) return false;
    if (search) {
      const haystack = JSON.stringify(e).toLowerCase();
      if (!haystack.includes(search)) return false;
    }
    return true;
  });

  renderTimeline(filteredEvents);
  updateStats(filteredEvents);
  filteredCount.textContent = `${filteredEvents.length} / ${allEvents.length} events`;
}

// ══════════════════════════════════════════════════════════
// 統計計算
// ══════════════════════════════════════════════════════════

function updateStats(events) {
  // 統計使用全部事件（非過濾後的），才能準確反映整次掃描
  const all = allEvents;

  // 總事件數（顯示過濾後 / 全部）
  $('statTotal').querySelector('.cp-stat-value').textContent =
    events.length === all.length ? (all.length || '—') : `${events.length}`;

  // LLM 呼叫數（全局）
  const llmCalls = all.filter(e => e.event === 'LLM_CALL').length;
  $('statLLM').querySelector('.cp-stat-value').textContent = llmCalls || '0';

  // 錯誤 / 重試（全局）
  const errors = all.filter(e => e.event === 'LLM_ERROR').length;
  const retries = all.filter(e => e.event === 'LLM_RETRY').length;
  $('statErrors').querySelector('.cp-stat-value').textContent = `${errors} / ${retries}`;

  // 持續時間
  const scanEnd = all.find(e => e.event === 'SCAN_END');
  if (scanEnd && scanEnd.data && scanEnd.data.total_duration_seconds != null) {
    const dur = scanEnd.data.total_duration_seconds;
    $('statDuration').querySelector('.cp-stat-value').textContent =
      dur >= 60 ? `${(dur / 60).toFixed(1)}m` : `${dur.toFixed(1)}s`;
  } else {
    $('statDuration').querySelector('.cp-stat-value').textContent = '—';
  }

  // Agent 數
  const uniqueAgents = new Set(all.map(e => e.agent).filter(a => a && a !== 'pipeline'));
  $('statAgents').querySelector('.cp-stat-value').textContent = uniqueAgents.size || '—';
}

// ══════════════════════════════════════════════════════════
// 時間軸渲染
// ══════════════════════════════════════════════════════════

function renderTimeline(events) {
  if (events.length === 0) {
    timeline.innerHTML = `
      <div class="cp-empty-state">
        <div class="cp-empty-icon">📡</div>
        <div class="cp-empty-text">No events to display</div>
      </div>`;
    return;
  }

  const html = events.map(e => {
    const ts = formatTimestamp(e.ts);
    const dataPreview = buildDataPreview(e);

    return `<div class="cp-event" data-seq="${e.seq}" onclick="showDetail(${e.seq})">
      <span class="cp-event-seq">#${e.seq}</span>
      <span class="cp-event-ts">${ts}</span>
      <span class="cp-event-type" data-type="${esc(e.event)}">${esc(e.event)}</span>
      <span class="cp-event-agent">${esc(e.agent)}</span>
      <span class="cp-event-data">${esc(dataPreview)}</span>
    </div>`;
  }).join('');

  timeline.innerHTML = html;
}

/**
 * 格式化 ISO 時間戳為 HH:MM:SS.mmm
 */
function formatTimestamp(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    const h = String(d.getHours()).padStart(2, '0');
    const m = String(d.getMinutes()).padStart(2, '0');
    const s = String(d.getSeconds()).padStart(2, '0');
    const ms = String(d.getMilliseconds()).padStart(3, '0');
    return `${h}:${m}:${s}.${ms}`;
  } catch { return iso.substring(11, 23); }
}

/**
 * 從事件資料建構預覽文字
 */
function buildDataPreview(event) {
  const d = event.data || {};
  switch (event.event) {
    case 'SCAN_START': return `scan_id=${d.scan_id || ''}`;
    case 'SCAN_END': return `status=${d.final_status || ''} | ${d.total_duration_seconds || 0}s | ${d.total_checkpoints || 0} events`;
    case 'STAGE_ENTER': return d.tech_stack_preview ? d.tech_stack_preview.split('\\n')[0].substring(0, 80) : (d.input_preview || `keys=${(d.input_keys || []).join(',')}`);
    case 'STAGE_EXIT': return `${d.status || 'OK'} | ${d.duration_ms || 0}ms${d.vuln_count != null ? ' | vulns=' + d.vuln_count : ''}${d.risk_score != null ? ' | risk=' + d.risk_score : ''}`;
    case 'LLM_CALL': return `model=${shortModel(d.model)} | ${d.task_preview || ''}`;
    case 'LLM_RESULT': return `${d.status || 'OK'} | ${d.duration_ms || 0}ms | ${d.output_length || 0} chars`;
    case 'LLM_RETRY': return `${shortModel(d.failed_model)} → retry #${d.retry_count || 0}`;
    case 'LLM_ERROR': return `${shortModel(d.model)} | ${(d.error || '').substring(0, 60)}`;
    case 'TOOL_CALL': return `${d.tool_name || '?'} | ${d.status || ''} | input=${(d.input || '').substring(0, 50)}`;
    case 'HARNESS_CHECK': return `${d.layer || ''} ${d.check_name || ''} → ${d.result || ''}`;
    case 'DEGRADATION': return d.reason || '';
    default: return JSON.stringify(d).substring(0, 100);
  }
}

/** 將長模型名縮短 */
function shortModel(m) {
  if (!m) return '?';
  // meta-llama/llama-3.3-70b-instruct:free → llama-3.3-70b:free
  return m.replace(/^[^\/]+\//, '').replace('-instruct', '');
}

// ══════════════════════════════════════════════════════════
// 詳細面板（改善：表格式，非 JSON）
// ══════════════════════════════════════════════════════════

function showDetail(seq) {
  const event = allEvents.find(e => e.seq === seq);
  if (!event) return;

  detailTitle.textContent = `#${event.seq} — ${event.event}`;
  detailContent.innerHTML = buildDetailTable(event);
  detailPanel.classList.remove('cp-hidden');
}

function hideDetail() {
  detailPanel.classList.add('cp-hidden');
}

/**
 * 將事件轉為結構化表格（取代 JSON 顯示）
 */
function buildDetailTable(event) {
  let html = '';

  // ── 基本資訊區 ──
  html += `<div class="cp-detail-section">
    <div class="cp-detail-section-title">基本資訊</div>
    <table class="cp-detail-table">
      <tr><td class="cp-dt-key">序號</td><td class="cp-dt-val">#${event.seq}</td></tr>
      <tr><td class="cp-dt-key">事件類型</td><td class="cp-dt-val"><span class="cp-event-type" data-type="${esc(event.event)}">${esc(event.event)}</span></td></tr>
      <tr><td class="cp-dt-key">Agent</td><td class="cp-dt-val">${esc(event.agent)}</td></tr>
      <tr><td class="cp-dt-key">時間</td><td class="cp-dt-val">${esc(event.ts)}</td></tr>
      <tr><td class="cp-dt-key">Scan ID</td><td class="cp-dt-val cp-mono">${esc(event.scan_id)}</td></tr>
    </table>
  </div>`;

  // ── 根據事件類型，用對應的表格呈現 ──
  const d = event.data || {};

  switch (event.event) {
    case 'SCAN_START':
      html += renderSection('掃描啟動', [
        ['Scan ID', d.scan_id],
      ]);
      break;

    case 'SCAN_END':
      html += renderSection('掃描結束', [
        ['最終狀態', d.final_status, d.final_status === 'COMPLETE' ? 'green' : 'red'],
        ['總持續時間', d.total_duration_seconds != null ? `${d.total_duration_seconds}s (${(d.total_duration_seconds/60).toFixed(1)} min)` : '—'],
        ['總 Checkpoint 數', d.total_checkpoints],
      ]);
      if (d.event_summary) {
        html += renderSection('事件統計', Object.entries(d.event_summary).map(([k, v]) => [k, v]));
      }
      break;

    case 'STAGE_ENTER':
      html += renderSection('Stage 進入', [
        ['輸入 Keys', d.input_keys],
        ['Input Hash', d.input_hash],
      ]);
      if (d.tech_stack_preview) {
        html += renderSection('掃描目標預覽', [], d.tech_stack_preview);
      }
      if (d.packages && d.packages.length > 0) {
        // v3.4: 顯示 PackageExtractor 萃取的套件
        html += renderSection('已萃取的第三方套件（協助 Intel Fusion 和 Scout 查詢）', [
          ['套件數量', d.packages.length],
          ['套件清單', d.packages.join(', ')],
        ]);
      }
      if (d.vuln_count != null) {
        html += renderSection('漏洞資訊', [['漏洞數量', d.vuln_count]]);
      }
      break;

    case 'STAGE_EXIT':
      html += renderSection('Stage 完成', [
        ['狀態', d.status, d.status === 'SUCCESS' ? 'green' : (d.status === 'DEGRADED' ? 'orange' : 'red')],
        ['耗時', d.duration_ms != null ? `${d.duration_ms}ms` : '—'],
        ['輸出 Keys', d.output_keys],
      ]);
      if (d.vuln_count != null) html += renderKV('漏洞數量', d.vuln_count);
      if (d.risk_score != null) html += renderKV('風險分數', d.risk_score);
      if (d.scan_path) html += renderKV('掃描路徑', d.scan_path);
      if (d.degraded != null) html += renderKV('是否降級', d.degraded ? '⚠️ 是' : '✅ 否');
      if (d.verdict) html += renderKV('裁決', d.verdict);
      // v3.4: Intel Fusion 套件請求資訊
      if (d.packages_used && d.packages_used.length > 0) {
        html += renderSection('已提交掃描的套件（Scout）', [
          ['套件數量', d.packages_used.length],
          ['套件名稱', d.packages_used.join(', ')],
        ]);
      }
      if (d.cves_scored != null) html += renderKV('CVEs Scored', d.cves_scored);
      break;

    case 'LLM_CALL':
      html += renderSection('LLM 呼叫', [
        ['模型', d.model],
        ['Provider', d.provider],
        ['任務描述', d.task_preview],
      ]);
      break;

    case 'LLM_RESULT':
      html += renderSection('LLM 回應', [
        ['模型', d.model],
        ['狀態', d.status, d.status === 'SUCCESS' ? 'green' : 'red'],
        ['回應長度', d.output_length != null ? `${d.output_length} 字元` : '—'],
        ['耗時', d.duration_ms != null ? `${d.duration_ms}ms (${(d.duration_ms/1000).toFixed(1)}s)` : '—'],
      ]);
      if (d.thinking) {
        html += renderSection('LLM 思考過程（前 1000 字元）', [], d.thinking);
      }
      break;

    case 'LLM_RETRY':
      html += renderSection('LLM 重試', [
        ['失敗模型', d.failed_model],
        ['重試次數', d.retry_count],
        ['下一個模型', d.next_model],
        ['錯誤原因', d.error],
      ]);
      break;

    case 'LLM_ERROR':
      html += renderSection('LLM 錯誤', [
        ['模型', d.model],
        ['錯誤訊息', d.error],
      ]);
      break;

    case 'TOOL_CALL':
      html += renderSection('工具呼叫', [
        ['工具名稱', d.tool_name],
        ['狀態', d.status, d.status === 'SUCCESS' ? 'green' : 'red'],
        ['輸入', d.input],
        ['輸出', d.output],
      ]);
      break;

    case 'HARNESS_CHECK':
      html += renderSection('Harness 檢查', [
        ['保障層', d.layer],
        ['檢查名稱', d.check_name],
        ['結果', d.result, d.result === 'PASS' ? 'green' : 'orange'],
      ]);
      if (d.details) {
        html += renderSection('詳細資料', Object.entries(d.details).map(([k, v]) => [k, v]));
      }
      break;

    case 'DEGRADATION':
      html += renderSection('降級事件', [
        ['原因', d.reason],
        ['層級', d.level],
      ]);
      break;

    default:
      // 未知事件類型：直接列出 data 的 key-value
      if (Object.keys(d).length > 0) {
        html += renderSection('事件資料', Object.entries(d).map(([k, v]) => [k, typeof v === 'object' ? JSON.stringify(v) : v]));
      }
  }

  return html;
}

/**
 * 渲染一個表格 section
 * @param {string} title — section 標題
 * @param {Array} rows — [[key, value, color?], ...]
 * @param {string} codeBlock — 如有，渲染為程式碼區塊
 */
function renderSection(title, rows, codeBlock) {
  let html = `<div class="cp-detail-section">
    <div class="cp-detail-section-title">${esc(title)}</div>`;

  if (rows.length > 0) {
    html += '<table class="cp-detail-table">';
    for (const [key, val, color] of rows) {
      const displayVal = val == null ? '—' : String(val);
      const colorClass = color ? ` cp-dt-${color}` : '';
      html += `<tr>
        <td class="cp-dt-key">${esc(key)}</td>
        <td class="cp-dt-val${colorClass}">${esc(displayVal)}</td>
      </tr>`;
    }
    html += '</table>';
  }

  if (codeBlock) {
    html += `<pre class="cp-detail-code">${esc(String(codeBlock))}</pre>`;
  }

  html += '</div>';
  return html;
}

/** 渲染單一 key-value（追加到前一個 section 下方） */
function renderKV(key, val) {
  return `<div class="cp-detail-section">
    <table class="cp-detail-table">
      <tr><td class="cp-dt-key">${esc(key)}</td><td class="cp-dt-val">${esc(String(val))}</td></tr>
    </table>
  </div>`;
}

/**
 * HTML 跳脫（防止 XSS）
 */
function esc(str) {
  if (str == null) return '';
  const div = document.createElement('div');
  div.textContent = String(str);
  return div.innerHTML;
}

// ══════════════════════════════════════════════════════════
// 事件繫結
// ══════════════════════════════════════════════════════════

scanSelector.addEventListener('change', () => loadScanEvents(scanSelector.value));
refreshBtn.addEventListener('click', () => loadScanList());
eventFilter.addEventListener('change', applyFilters);
agentFilter.addEventListener('change', applyFilters);
searchInput.addEventListener('input', applyFilters);
closeDetail.addEventListener('click', hideDetail);

// ESC 關閉詳細面板
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') hideDetail();
});

// ════════════════════════════════════════════════════════
// 初始化
// ════════════════════════════════════════════════════════

/** 顯示 Toast 通知 */
function showToast(msg, type = 'info') {
  const id = 'cp-toast-' + Date.now();
  const colors = {
    info: 'rgba(0,255,255,0.15)',
    success: 'rgba(0,230,118,0.15)',
    warning: 'rgba(255,214,0,0.15)',
  };
  const border = {
    info: 'rgba(0,255,255,0.3)',
    success: 'rgba(0,230,118,0.3)',
    warning: 'rgba(255,214,0,0.3)',
  };
  const toast = document.createElement('div');
  toast.id = id;
  toast.style.cssText = [
    'position:fixed', 'bottom:24px', 'right:24px', 'z-index:9999',
    'padding:10px 18px', 'border-radius:6px',
    `background:${colors[type] || colors.info}`,
    `border:1px solid ${border[type] || border.info}`,
    'color:var(--text-main)', 'font-family:var(--mono)', 'font-size:0.82rem',
    'backdrop-filter:blur(8px)', 'box-shadow:0 4px 20px rgba(0,0,0,0.3)',
    'animation:slideIn 0.2s ease-out',
    'max-width:360px',
  ].join(';');
  toast.textContent = msg;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}

/**
 * 自動輪詢：每 15 秒檢查是否有新揃描檔案（Issue #2）
 * 解決「先開 Checkpoint 頁 → 再跑揃描」工作流下，新揃描不出現的問題
 */
let _lastKnownFilenames = new Set();
let _autoRefreshInterval = null;

async function startAutoRefresh() {
  if (_autoRefreshInterval) return;  // 防止重複啟動
  _autoRefreshInterval = setInterval(async () => {
    try {
      const files = await fetchScanList();
      const currentNames = new Set(files.map(f => f.name));
      // 檢查是否有新檔案
      const newFiles = files.filter(f => !_lastKnownFilenames.has(f.name));
      if (newFiles.length > 0 && _lastKnownFilenames.size > 0) {
        // 有新揃描出現！更新選擇器並通知使用者
        await refreshScanListSilently(files);
        const newest = newFiles[0];
        const timeStr = newest.modified ? newest.modified.substring(5, 16).replace('T', ' ') : '';
        showToast(`🟢 新揃描完成：${timeStr} — ${newest.label || newest.name}`, 'success');
      }
      _lastKnownFilenames = currentNames;
    } catch (e) {
      // 身默失敗，不影響使用者
      console.warn('[CHECKPOINT] auto-refresh failed:', e);
    }
  }, 15000);  // 15 秒輪詢一次
  console.info('[CHECKPOINT] Auto-refresh started (15s interval)');
}

/**
 * 静默更新揃描　選擇器（不變動目前選定項）
 */
async function refreshScanListSilently(files) {
  const currentSelection = scanSelector.value;
  // 重建選項
  scanSelector.innerHTML = '';
  files.sort((a, b) => (b.modified || '').localeCompare(a.modified || ''));
  files.forEach(f => {
    const opt = document.createElement('option');
    opt.value = f.name;
    const timeStr = f.modified ? f.modified.substring(5, 16).replace('T', ' ') : '';
    const label = f.label || f.name;
    opt.textContent = `${timeStr} — ${label}`;
    scanSelector.appendChild(opt);
  });
  // 尝試保留原選擇
  if (currentSelection && files.some(f => f.name === currentSelection)) {
    scanSelector.value = currentSelection;
  } else if (files.length > 0) {
    scanSelector.value = files[0].name;
  }
}

loadScanList().then(() => {
  // 記錄初始已知檔案集
  fetchScanList().then(files => {
    _lastKnownFilenames = new Set(files.map(f => f.name));
  });
  // 啟動自動刷新
  startAutoRefresh();
});
