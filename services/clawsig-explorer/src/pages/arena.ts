import { esc, fmtNum, layout, relativeTime, statusBadge, type PageMeta } from '../layout.js';
import type { ArenaContenderView, ArenaMissionSummaryView, ArenaReportView } from '../api.js';

/* ------------------------------------------------------------------ */
/*  Arena Styles — injected into every arena page via arenaStyles()   */
/* ------------------------------------------------------------------ */

function arenaStyles(): string {
  return `
<style>
  /* ---- Glow / accent palette ---- */
  :root {
    --accent-cyan: #00e5ff;
    --accent-magenta: #ff2dce;
    --accent-amber: #ffb300;
    --accent-violet: #9d4edd;
    --glow-winner: 0 0 18px rgba(0,229,255,0.35), 0 0 4px rgba(0,229,255,0.55);
    --gradient-hero: linear-gradient(135deg, #0a0a0a 0%, #0d1117 40%, #111827 100%);
    --gradient-card: linear-gradient(145deg, rgba(20,20,20,0.95), rgba(16,16,20,0.9));
    --gradient-vs: linear-gradient(90deg, var(--accent-cyan), var(--accent-magenta));
  }

  /* ---- Arena card overrides ---- */
  .arena-card {
    background: var(--gradient-card);
    border: 1px solid #1e293b;
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 1.25rem;
    position: relative;
    overflow: hidden;
    transition: border-color 0.25s ease;
  }
  .arena-card:hover { border-color: #334155; }
  .arena-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: var(--gradient-vs);
    opacity: 0.5;
  }

  /* ---- Section headings ---- */
  .arena-section-title {
    font-size: 0.7rem;
    color: var(--accent-cyan);
    text-transform: uppercase;
    letter-spacing: 0.14em;
    margin-bottom: 0.85rem;
    font-weight: 700;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .arena-section-title::before {
    content: '';
    width: 3px; height: 14px;
    background: var(--accent-cyan);
    border-radius: 2px;
    flex-shrink: 0;
  }

  /* ---- VS Banner ---- */
  .vs-banner {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 1.5rem;
    margin-bottom: 2rem;
    padding: 1.5rem 1rem;
    background: linear-gradient(135deg, rgba(0,229,255,0.04), rgba(255,45,206,0.04));
    border: 1px solid #1e293b;
    border-radius: 14px;
    flex-wrap: wrap;
  }
  .vs-contender {
    text-align: center;
    flex: 1;
    min-width: 180px;
    max-width: 320px;
  }
  .vs-contender-name {
    font-family: var(--font-mono);
    font-size: 0.95rem;
    font-weight: 700;
    color: var(--text);
    margin-bottom: 0.25rem;
  }
  .vs-contender-meta {
    font-size: 0.72rem;
    color: var(--text-dim);
  }
  .vs-score {
    font-family: var(--font-mono);
    font-size: 2.2rem;
    font-weight: 800;
    line-height: 1;
    margin: 0.5rem 0 0.3rem;
  }
  .vs-winner-tag {
    display: inline-block;
    font-size: 0.65rem;
    font-weight: 700;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    padding: 0.2rem 0.7rem;
    border-radius: 999px;
    background: rgba(0,229,255,0.12);
    color: var(--accent-cyan);
    border: 1px solid rgba(0,229,255,0.3);
    box-shadow: var(--glow-winner);
    animation: winner-pulse 2.5s ease-in-out infinite;
  }
  @keyframes winner-pulse {
    0%, 100% { box-shadow: var(--glow-winner); }
    50% { box-shadow: 0 0 28px rgba(0,229,255,0.5), 0 0 8px rgba(0,229,255,0.7); }
  }
  .vs-badge-fail {
    display: inline-block;
    font-size: 0.65rem;
    font-weight: 700;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    padding: 0.2rem 0.7rem;
    border-radius: 999px;
    background: rgba(255,68,68,0.1);
    color: var(--fail);
    border: 1px solid rgba(255,68,68,0.3);
  }
  .vs-separator {
    font-size: 1.6rem;
    font-weight: 900;
    background: var(--gradient-vs);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    flex-shrink: 0;
  }

  /* ---- Score bar ---- */
  .score-bar-wrap {
    width: 100%;
    height: 6px;
    background: #1a1a2e;
    border-radius: 3px;
    overflow: hidden;
    margin-top: 0.4rem;
  }
  .score-bar-fill {
    height: 100%;
    border-radius: 3px;
    transition: width 0.8s cubic-bezier(0.22, 1, 0.36, 1);
  }

  /* ---- Metric chip redesign ---- */
  .arena-metric {
    display: flex;
    flex-direction: column;
    gap: 0.1rem;
    border: 1px solid #1e293b;
    border-radius: 8px;
    padding: 0.45rem 0.55rem;
    background: rgba(15,15,25,0.7);
    min-width: 0;
    transition: border-color 0.2s, background 0.2s;
  }
  .arena-metric:hover {
    border-color: #334155;
    background: rgba(20,20,35,0.9);
  }
  .arena-metric-label {
    font-size: 0.62rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: #64748b;
  }
  .arena-metric-value {
    font-size: 0.8rem;
    font-family: var(--font-mono);
    color: var(--text);
    overflow-wrap: anywhere;
    font-weight: 600;
  }

  /* ---- Check matrix grid ---- */
  .check-grid {
    display: grid;
    gap: 3px;
    grid-auto-flow: row;
  }
  .check-cell {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 100%;
    aspect-ratio: 1;
    border-radius: 4px;
    font-family: var(--font-mono);
    font-size: 0.68rem;
    font-weight: 700;
    transition: transform 0.15s, box-shadow 0.15s;
  }
  .check-cell:hover {
    transform: scale(1.15);
    z-index: 5;
  }
  .check-cell.pass { background: rgba(0,255,136,0.15); color: var(--pass); box-shadow: inset 0 0 0 1px rgba(0,255,136,0.3); }
  .check-cell.fail { background: rgba(255,68,68,0.15); color: var(--fail); box-shadow: inset 0 0 0 1px rgba(255,68,68,0.3); }
  .check-cell.na   { background: rgba(100,100,100,0.08); color: #555; }

  /* ---- Tab bar ---- */
  .arena-tabs {
    display: flex;
    gap: 0;
    border-bottom: 1px solid #1e293b;
    margin-bottom: 1rem;
    overflow-x: auto;
  }
  .arena-tab {
    padding: 0.55rem 1rem;
    font-size: 0.78rem;
    font-weight: 600;
    color: var(--text-dim);
    cursor: pointer;
    border-bottom: 2px solid transparent;
    transition: color 0.2s, border-color 0.2s;
    white-space: nowrap;
    background: none;
    border-top: none;
    border-left: none;
    border-right: none;
    font-family: var(--font-sans);
  }
  .arena-tab:hover { color: var(--text); }
  .arena-tab.active {
    color: var(--accent-cyan);
    border-bottom-color: var(--accent-cyan);
  }
  .arena-tab-panel { display: none; }
  .arena-tab-panel.active { display: block; }

  /* ---- Artifact iframe ---- */
  .artifact-iframe-wrap {
    position: relative;
    border: 1px solid #1e293b;
    border-radius: 10px;
    overflow: hidden;
    background: #000;
    margin-bottom: 1rem;
  }
  .artifact-iframe-wrap iframe {
    width: 100%;
    border: none;
    display: block;
    background: #fff;
  }
  .artifact-iframe-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.4rem 0.75rem;
    background: rgba(15,15,25,0.95);
    border-bottom: 1px solid #1e293b;
    font-size: 0.72rem;
    color: var(--text-dim);
  }
  .artifact-iframe-toolbar .toolbar-label {
    font-family: var(--font-mono);
  }
  .artifact-iframe-toolbar button {
    background: none;
    border: 1px solid #334155;
    color: var(--text-dim);
    padding: 0.2rem 0.55rem;
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.68rem;
    font-family: var(--font-sans);
    transition: border-color 0.2s, color 0.2s;
  }
  .artifact-iframe-toolbar button:hover { border-color: var(--accent-cyan); color: var(--text); }

  /* ---- Lightbox / modal ---- */
  .arena-lightbox {
    display: none;
    position: fixed;
    inset: 0;
    z-index: 9999;
    background: rgba(0,0,0,0.92);
    backdrop-filter: blur(8px);
    align-items: center;
    justify-content: center;
    flex-direction: column;
  }
  .arena-lightbox.open { display: flex; }
  .arena-lightbox img {
    max-width: 92vw;
    max-height: 82vh;
    border-radius: 8px;
    box-shadow: 0 0 40px rgba(0,229,255,0.15);
  }
  .arena-lightbox .lb-caption {
    color: var(--text-dim);
    font-size: 0.78rem;
    margin-top: 0.75rem;
    text-align: center;
  }
  .arena-lightbox .lb-close {
    position: absolute;
    top: 1.2rem; right: 1.5rem;
    font-size: 1.6rem;
    color: var(--text-dim);
    cursor: pointer;
    background: none;
    border: none;
    line-height: 1;
  }
  .arena-lightbox .lb-nav {
    position: absolute;
    top: 50%;
    transform: translateY(-50%);
    font-size: 2.2rem;
    color: rgba(255,255,255,0.5);
    cursor: pointer;
    background: none;
    border: none;
    padding: 0.5rem;
    transition: color 0.2s;
  }
  .arena-lightbox .lb-nav:hover { color: #fff; }
  .arena-lightbox .lb-prev { left: 1rem; }
  .arena-lightbox .lb-next { right: 1rem; }
  .arena-filmstrip {
    display: flex;
    gap: 6px;
    margin-top: 0.75rem;
    overflow-x: auto;
    padding: 0.3rem 0;
  }
  .arena-filmstrip img {
    width: 64px;
    height: 40px;
    object-fit: cover;
    border-radius: 4px;
    border: 2px solid transparent;
    cursor: pointer;
    opacity: 0.5;
    transition: opacity 0.2s, border-color 0.2s;
  }
  .arena-filmstrip img.active,
  .arena-filmstrip img:hover { opacity: 1; border-color: var(--accent-cyan); }

  /* ---- JSON tree viewer ---- */
  .json-tree { font-family: var(--font-mono); font-size: 0.74rem; line-height: 1.55; }
  .json-tree details { margin-left: 1rem; }
  .json-tree summary {
    cursor: pointer;
    color: var(--accent-cyan);
    list-style: none;
    display: flex;
    align-items: center;
    gap: 0.3rem;
  }
  .json-tree summary::before { content: '\\25B6'; font-size: 0.55rem; color: #555; transition: transform 0.15s; display: inline-block; }
  .json-tree details[open] > summary::before { transform: rotate(90deg); }
  .json-tree .json-key { color: var(--accent-cyan); }
  .json-tree .json-str { color: #a5d6a7; }
  .json-tree .json-num { color: var(--accent-amber); }
  .json-tree .json-bool { color: var(--accent-magenta); }
  .json-tree .json-null { color: #777; }
  .json-tree .json-leaf { margin-left: 1rem; padding: 0.05rem 0; }

  /* ---- Screenshot gallery grid ---- */
  .screenshot-grid {
    display: grid;
    gap: 1rem;
    margin-top: 0.75rem;
  }
  .screenshot-grid img {
    width: 100%;
    border-radius: 8px;
    border: 1px solid #1e293b;
    cursor: pointer;
    transition: border-color 0.2s, transform 0.15s;
  }
  .screenshot-grid img:hover {
    border-color: var(--accent-cyan);
    transform: scale(1.01);
  }
  .screenshot-label {
    font-size: 0.72rem;
    color: var(--text-dim);
    margin-bottom: 0.3rem;
    font-family: var(--font-mono);
  }

  /* ---- Hero stats ---- */
  .arena-hero-stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }
  .arena-stat {
    background: linear-gradient(145deg, rgba(20,20,30,0.95), rgba(12,12,20,0.9));
    border: 1px solid #1e293b;
    border-radius: 12px;
    padding: 1.25rem 1rem;
    text-align: center;
    position: relative;
    overflow: hidden;
  }
  .arena-stat::after {
    content: '';
    position: absolute;
    bottom: 0; left: 0; right: 0;
    height: 2px;
    background: var(--gradient-vs);
    opacity: 0.3;
  }
  .arena-stat-value {
    font-family: var(--font-mono);
    font-size: 1.7rem;
    font-weight: 800;
    color: var(--accent-cyan);
    line-height: 1.1;
  }
  .arena-stat-label {
    font-size: 0.68rem;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-top: 0.35rem;
  }

  /* ---- Index table ---- */
  .arena-index-row {
    transition: background 0.15s;
    cursor: pointer;
  }
  .arena-index-row:hover td { background: rgba(0,229,255,0.03); }
  .arena-winner-chip {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    font-family: var(--font-mono);
    font-size: 0.78rem;
    padding: 0.15rem 0.5rem;
    background: rgba(0,229,255,0.06);
    border: 1px solid rgba(0,229,255,0.2);
    border-radius: 999px;
    color: var(--accent-cyan);
  }

  /* ---- Mission pulse ---- */
  .mission-pulse {
    width: 10px; height: 10px;
    border-radius: 50%;
    display: inline-block;
    animation: pulse-dot 1.8s ease-in-out infinite;
  }
  .mission-pulse.green { background: var(--pass); box-shadow: 0 0 8px rgba(0,255,136,0.5); }
  .mission-pulse.red { background: var(--fail); box-shadow: 0 0 8px rgba(255,68,68,0.5); }
  @keyframes pulse-dot {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
  }

  /* ---- Responsive ---- */
  @media (max-width: 768px) {
    .vs-banner { flex-direction: column; gap: 0.75rem; }
    .vs-separator { display: none; }
    .vs-score { font-size: 1.6rem; }
    .arena-hero-stats { grid-template-columns: 1fr 1fr; }
  }

  /* ---- Score reveal animation ---- */
  @keyframes score-reveal {
    from { opacity: 0; transform: translateY(10px) scale(0.9); }
    to { opacity: 1; transform: translateY(0) scale(1); }
  }
  .score-animate {
    animation: score-reveal 0.6s cubic-bezier(0.22, 1, 0.36, 1) both;
  }

  /* ---- Collapsible sections ---- */
  .arena-collapse summary {
    cursor: pointer;
    list-style: none;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .arena-collapse summary::before {
    content: '\\25B6';
    font-size: 0.6rem;
    color: var(--accent-cyan);
    transition: transform 0.2s;
    display: inline-block;
  }
  .arena-collapse[open] > summary::before { transform: rotate(90deg); }
</style>
`;
}

/* ------------------------------------------------------------------ */
/*  Arena client-side JS — lightbox, tabs, JSON viewer, iframe toggle */
/* ------------------------------------------------------------------ */

function arenaScripts(): string {
  return `
<script>
(function() {
  // ---- Tab switching ----
  document.querySelectorAll('[data-tab-group]').forEach(function(group) {
    var tabs = group.querySelectorAll('.arena-tab');
    var panels = group.parentElement.querySelectorAll('.arena-tab-panel');
    tabs.forEach(function(tab) {
      tab.addEventListener('click', function() {
        var target = tab.getAttribute('data-tab');
        tabs.forEach(function(t) { t.classList.remove('active'); });
        panels.forEach(function(p) { p.classList.remove('active'); });
        tab.classList.add('active');
        var panel = document.getElementById(target);
        if (panel) panel.classList.add('active');
      });
    });
  });

  // ---- Lightbox ----
  var lb = document.getElementById('arena-lightbox');
  if (lb) {
    var lbImg = lb.querySelector('img');
    var lbCaption = lb.querySelector('.lb-caption');
    var allScreenshots = [];
    var currentIdx = 0;

    document.querySelectorAll('[data-lightbox]').forEach(function(img, idx) {
      allScreenshots.push({ src: img.getAttribute('data-lightbox'), alt: img.getAttribute('alt') || '' });
      img.addEventListener('click', function() {
        currentIdx = idx;
        showLightbox(currentIdx);
      });
    });

    function showLightbox(idx) {
      if (idx < 0 || idx >= allScreenshots.length) return;
      currentIdx = idx;
      lbImg.src = allScreenshots[idx].src;
      lbCaption.textContent = allScreenshots[idx].alt;
      lb.classList.add('open');
      updateFilmstrip();
    }

    function updateFilmstrip() {
      lb.querySelectorAll('.arena-filmstrip img').forEach(function(thumb, i) {
        thumb.classList.toggle('active', i === currentIdx);
      });
    }

    lb.querySelector('.lb-close').addEventListener('click', function() { lb.classList.remove('open'); });
    lb.querySelector('.lb-prev').addEventListener('click', function() { showLightbox(currentIdx - 1); });
    lb.querySelector('.lb-next').addEventListener('click', function() { showLightbox(currentIdx + 1); });

    lb.querySelectorAll('.arena-filmstrip img').forEach(function(thumb, i) {
      thumb.addEventListener('click', function() { showLightbox(i); });
    });

    lb.addEventListener('click', function(e) {
      if (e.target === lb) lb.classList.remove('open');
    });

    document.addEventListener('keydown', function(e) {
      if (!lb.classList.contains('open')) return;
      if (e.key === 'Escape') lb.classList.remove('open');
      if (e.key === 'ArrowLeft') showLightbox(currentIdx - 1);
      if (e.key === 'ArrowRight') showLightbox(currentIdx + 1);
    });
  }

  // ---- Iframe toggle ----
  document.querySelectorAll('[data-iframe-toggle]').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var iframe = document.getElementById(btn.getAttribute('data-iframe-toggle'));
      if (!iframe) return;
      var current = parseInt(iframe.style.height, 10) || 600;
      iframe.style.height = (current >= 900 ? '600px' : '900px');
      btn.textContent = (current >= 900 ? 'Expand' : 'Collapse');
    });
  });
})();
</script>
`;
}

/* ------------------------------------------------------------------ */
/*  Local render helpers                                              */
/* ------------------------------------------------------------------ */

interface ArenaIndexItem {
  arena_id: string;
  bounty_id: string;
  contract_id: string;
  generated_at: string;
  winner_contender_id: string;
  reason_code: string;
}

function renderMetricCell(label: string, value: string): string {
  return `
    <div class="arena-metric">
      <span class="arena-metric-label">${esc(label)}</span>
      <span class="arena-metric-value">${esc(value)}</span>
    </div>
  `;
}

function scoreColor(score: number): string {
  if (score >= 80) return 'var(--pass)';
  if (score >= 60) return 'var(--accent-amber)';
  return 'var(--fail)';
}

function contractCheckMatrix(report: ArenaReportView): string {
  const criterionIds = [...new Set(
    report.contenders.flatMap((contender) => contender.check_results.map((check) => check.criterion_id))
  )].sort((a, b) => a.localeCompare(b));

  if (criterionIds.length === 0) {
    return `
      <div class="runs-empty">
        <p class="dim" style="font-size:0.84rem">No per-criterion check results were provided. Showing mandatory gate outcomes only.</p>
      </div>
    `;
  }

  // Visual grid: rows = criteria, columns = contenders
  const cols = report.contenders.length;
  const gridCols = `repeat(${cols + 1}, minmax(0, 1fr))`;

  // Header row
  const headerCells = report.contenders
    .map((c) => `<div style="font-size:0.68rem;color:var(--text-dim);text-align:center;padding:0.3rem;font-family:var(--font-mono);overflow:hidden;text-overflow:ellipsis" title="${esc(c.contender_id)}">${esc(c.contender_id.replace('contender_', ''))}</div>`)
    .join('');

  const rows = criterionIds
    .map((criterionId) => {
      const cells = report.contenders
        .map((contender) => {
          const check = contender.check_results.find((entry) => entry.criterion_id === criterionId);
          if (!check) return `<div class="check-cell na" title="N/A">-</div>`;
          const cls = check.status === 'PASS' ? 'pass' : 'fail';
          const icon = check.status === 'PASS' ? '&#10003;' : '&#10007;';
          return `<div class="check-cell ${cls}" title="${esc(criterionId)}: ${esc(check.status)} (${esc(check.reason_code)})">${icon}</div>`;
        })
        .join('');

      return `<div style="font-size:0.68rem;color:#94a3b8;font-family:var(--font-mono);display:flex;align-items:center;padding:0.15rem 0.3rem;overflow:hidden;text-overflow:ellipsis" title="${esc(criterionId)}">${esc(criterionId.replace('ac_', ''))}</div>${cells}`;
    })
    .join('');

  return `
    <div class="check-grid" style="grid-template-columns: ${gridCols}; max-width: 500px">
      <div></div>
      ${headerCells}
      ${rows}
    </div>
  `;
}

/* Also keep the original table version for fallback/accessibility */
function contractCheckTable(report: ArenaReportView): string {
  const criterionIds = [...new Set(
    report.contenders.flatMap((contender) => contender.check_results.map((check) => check.criterion_id))
  )].sort((a, b) => a.localeCompare(b));

  if (criterionIds.length === 0) return '';

  const headerCells = report.contenders
    .map((contender) => `<th>${esc(contender.contender_id)}</th>`)
    .join('');

  const rows = criterionIds
    .map((criterionId) => {
      const cells = report.contenders
        .map((contender) => {
          const check = contender.check_results.find((entry) => entry.criterion_id === criterionId);
          if (!check) {
            return `<td class="dim">N/A</td>`;
          }
          const cls = check.status === 'PASS' ? 'pass' : 'fail';
          return `<td><span class="status-badge ${cls}" title="${esc(check.reason_code)}">${esc(check.status)}</span></td>`;
        })
        .join('');

      return `<tr><td class="mono">${esc(criterionId)}</td>${cells}</tr>`;
    })
    .join('');

  return `
    <details class="arena-collapse" style="margin-top:0.75rem">
      <summary style="font-size:0.75rem;color:var(--text-dim)">Show table view</summary>
      <div style="overflow-x:auto;margin-top:0.5rem">
        <table>
          <thead><tr><th>Contract Criterion</th>${headerCells}</tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </details>
  `;
}

function renderEvaluatorMetrics(raw: Record<string, unknown>): string {
  const ux = typeof raw.ux_score === 'number' ? raw.ux_score : null;
  const perf = typeof raw.perf_score === 'number' ? raw.perf_score : null;
  const a11y = typeof raw.a11y_score === 'number' ? raw.a11y_score : null;
  const visual = typeof raw.visual_score === 'number' ? raw.visual_score : null;
  const maint = typeof raw.maint_score === 'number' ? raw.maint_score : null;
  const lhPerf = typeof raw.lighthouse_performance === 'number' ? raw.lighthouse_performance : null;
  const lhA11y = typeof raw.lighthouse_accessibility === 'number' ? raw.lighthouse_accessibility : null;
  const lhCls = typeof raw.lighthouse_cls === 'number' ? raw.lighthouse_cls : null;
  const flowRate = typeof raw.flow_success_rate === 'number' ? raw.flow_success_rate : null;
  const flowsPassed = typeof raw.flows_passed === 'number' ? raw.flows_passed : null;
  const flowsTotal = typeof raw.flows_total === 'number' ? raw.flows_total : null;
  const avgTiming = typeof raw.avg_timing_ms === 'number' ? raw.avg_timing_ms : null;
  const runtimeErrors = typeof raw.runtime_error_count === 'number' ? raw.runtime_error_count : null;
  const criticalA11y = typeof raw.critical_a11y_violations === 'number' ? raw.critical_a11y_violations : null;
  const friction = typeof raw.friction_events === 'number' ? raw.friction_events : null;

  const cells: string[] = [];
  if (ux !== null) cells.push(renderMetricCell('UX', ux.toFixed(1)));
  if (perf !== null) cells.push(renderMetricCell('perf', perf.toFixed(1)));
  if (a11y !== null) cells.push(renderMetricCell('a11y', a11y.toFixed(1)));
  if (visual !== null) cells.push(renderMetricCell('visual', visual.toFixed(1)));
  if (maint !== null) cells.push(renderMetricCell('maint', maint.toFixed(1)));
  if (lhPerf !== null) cells.push(renderMetricCell('LH perf', (lhPerf * 100).toFixed(0) + '%'));
  if (lhA11y !== null) cells.push(renderMetricCell('LH a11y', (lhA11y * 100).toFixed(0) + '%'));
  if (lhCls !== null) cells.push(renderMetricCell('CLS', lhCls.toFixed(3)));
  if (flowRate !== null) cells.push(renderMetricCell('flows', `${flowRate * 100}%`));
  if (flowsPassed !== null && flowsTotal !== null) cells.push(renderMetricCell('flow pass', `${flowsPassed}/${flowsTotal}`));
  if (avgTiming !== null) cells.push(renderMetricCell('avg timing', `${avgTiming.toFixed(0)}ms`));
  if (runtimeErrors !== null) cells.push(renderMetricCell('RT errors', String(runtimeErrors)));
  if (criticalA11y !== null) cells.push(renderMetricCell('crit a11y', String(criticalA11y)));
  if (friction !== null) cells.push(renderMetricCell('friction', String(friction)));

  const hardGates = raw.hard_gates;
  if (hardGates && typeof hardGates === 'object') {
    const hg = hardGates as Record<string, unknown>;
    if (typeof hg.core_flows_pass === 'boolean') cells.push(renderMetricCell('core flows', hg.core_flows_pass ? 'PASS' : 'FAIL'));
    if (typeof hg.no_runtime_errors === 'boolean') cells.push(renderMetricCell('no RT err', hg.no_runtime_errors ? 'PASS' : 'FAIL'));
    if (typeof hg.no_a11y_critical === 'boolean') cells.push(renderMetricCell('no crit a11y', hg.no_a11y_critical ? 'PASS' : 'FAIL'));
  }

  const evalReasonCodes = Array.isArray(raw.reason_codes) ? raw.reason_codes : [];

  if (cells.length === 0) return '';

  return `
    <div class="diag-grid" style="grid-template-columns: repeat(3, minmax(100px, 1fr)); gap:0.25rem">
      ${cells.join('\n')}
    </div>
    ${evalReasonCodes.length > 0
      ? `<div class="dim" style="font-size:0.7rem; margin-top:0.3rem">${evalReasonCodes.map((rc) => esc(String(rc))).join(', ')}</div>`
      : ''}
  `;
}

function renderCanonicalMetrics(contender: ArenaContenderView): string {
  return `
    <div class="diag-grid" style="grid-template-columns: repeat(2, minmax(110px, 1fr)); gap:0.3rem">
      ${renderMetricCell('quality', contender.metrics.quality_score.toFixed(2))}
      ${renderMetricCell('risk', contender.metrics.risk_score.toFixed(2))}
      ${renderMetricCell('efficiency', contender.metrics.efficiency_score.toFixed(2))}
      ${renderMetricCell('cost', `$${contender.metrics.cost_usd.toFixed(4)}`)}
    </div>
  `;
}

function renderReviewPasteInline(paste: string): string {
  if (!paste || paste.length === 0) return '<span class="dim" style="font-size:0.75rem">No review paste</span>';
  const lines = paste.split('\n').map((line) => esc(line.trim())).filter((l) => l.length > 0);
  return `
    <div style="font-size:0.75rem; line-height:1.4; font-family:var(--font-mono); background:rgba(10,10,20,0.6); border:1px solid #1e293b; border-radius:8px; padding:0.5rem; max-height:6rem; overflow-y:auto; white-space:pre-wrap">
${lines.join('\n')}
    </div>
  `;
}

function contenderRows(report: ArenaReportView): string {
  return report.contenders
    .map((contender) => {
      const reviewPaste = contender.review_paste.length > 0
        ? contender.review_paste
        : `Decision Summary: ${contender.hard_gate_pass ? 'Promote contender' : 'Manual review required'}\nContract Compliance: mandatory_failed=${contender.mandatory_failed}`;

      const managerJson = contender.manager_review_json.length > 0
        ? contender.manager_review_json
        : JSON.stringify({
          contender_id: contender.contender_id,
          hard_gate_pass: contender.hard_gate_pass,
          mandatory_failed: contender.mandatory_failed,
          metrics: contender.metrics,
        }, null, 2);

      const hasEvaluatorMetrics = contender.raw_evaluator_metrics !== null
        && typeof contender.raw_evaluator_metrics === 'object'
        && Object.keys(contender.raw_evaluator_metrics).length > 0;

      const metricsHtml = hasEvaluatorMetrics
        ? renderEvaluatorMetrics(contender.raw_evaluator_metrics!)
        : renderCanonicalMetrics(contender);

      const isWinner = report.winner.contender_id === contender.contender_id;
      const rowBorder = isWinner ? 'border-left: 3px solid var(--accent-cyan);' : '';
      const scoreCl = scoreColor(contender.score);

      return `
        <tr style="${rowBorder}">
          <td>
            <div style="display:grid; gap:0.3rem">
              <span class="mono" style="font-weight:600">${esc(contender.contender_id)}</span>
              <span class="dim" style="font-size:0.78rem">${esc(contender.label)}</span>
              <div style="display:flex;gap:0.35rem;align-items:center">
                ${statusBadge(contender.hard_gate_pass ? 'PASS' : 'FAIL')}
                ${isWinner ? '<span class="vs-winner-tag" style="animation:none">WINNER</span>' : ''}
              </div>
            </div>
          </td>
          <td>
            <div class="mono" style="font-size:0.78rem">${esc(contender.model)}</div>
            <div class="dim" style="font-size:0.75rem">${esc(contender.harness)}</div>
          </td>
          <td>
            <div class="mono score-animate" style="font-size:1.1rem; font-weight:800; color:${scoreCl}">${contender.score.toFixed(1)}</div>
            <div class="score-bar-wrap">
              <div class="score-bar-fill" style="width:${Math.min(contender.score, 100)}%;background:${scoreCl}"></div>
            </div>
          </td>
          <td style="min-width:260px">
            ${metricsHtml}
          </td>
          <td style="min-width:240px">
            ${renderReviewPasteInline(reviewPaste)}
            <div style="display:flex; gap:0.35rem; margin-top:0.35rem">
              <button class="copy-btn" data-copy="${esc(reviewPaste)}" onclick="navigator.clipboard.writeText(this.getAttribute('data-copy') || ''); this.textContent='Copied';">Copy Paste</button>
              <button class="copy-btn" data-copy="${esc(managerJson)}" onclick="navigator.clipboard.writeText(this.getAttribute('data-copy') || ''); this.textContent='Copied';">Copy JSON</button>
            </div>
          </td>
        </tr>
      `;
    })
    .join('');
}

function renderReviewThreadCard(report: ArenaReportView): string {
  if (!Array.isArray(report.review_thread) || report.review_thread.length === 0) {
    return `
      <div class="arena-card">
        <p class="arena-section-title">Decision review thread</p>
        <p class="dim" style="font-size:0.82rem">No decision paste entries posted yet for this arena.</p>
      </div>
    `;
  }

  const rows = report.review_thread
    .map((entry) => {
      const recommendationBadge = statusBadge(entry.recommendation === 'APPROVE' ? 'PASS' : 'FAIL');
      const links = entry.links.length > 0
        ? entry.links.map((link) => `<a href="${esc(link.url)}" target="_blank" rel="noreferrer">${esc(link.label)} &#x2197;</a>`).join(' &middot; ')
        : 'none';

      return `
        <tr>
          <td><span class="mono">${esc(entry.contender_id)}</span></td>
          <td>${recommendationBadge} <span class="mono" style="margin-left:0.35rem">${esc(entry.recommendation)}</span></td>
          <td class="mono">${(entry.confidence * 100).toFixed(1)}%</td>
          <td>${links}</td>
          <td class="mono">${relativeTime(entry.created_at)}</td>
        </tr>
      `;
    })
    .join('');

  return `
    <div class="arena-card">
      <p class="arena-section-title">Decision review thread</p>
      <p class="dim" style="font-size:0.8rem; margin-bottom:0.55rem">PR/bounty recommendation history with confidence + one-click evidence links.</p>
      <div style="overflow-x:auto">
        <table>
          <thead>
            <tr>
              <th>Contender</th>
              <th>Recommendation</th>
              <th>Confidence</th>
              <th>Links</th>
              <th>Posted</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>
  `;
}

function renderCalibrationCard(report: ArenaReportView): string {
  const calibration = report.calibration;
  const totals = calibration?.totals;
  if (!totals || totals.samples <= 0) {
    return `
      <div class="arena-card">
        <p class="arena-section-title">Outcome calibration</p>
        <p class="dim" style="font-size:0.82rem">No outcome feedback recorded yet.</p>
      </div>
    `;
  }

  const reviewerDecisions = totals.reviewer_decisions;
  const topDecisionTags = calibration?.reviewer_decision_capture?.decision_taxonomy_tags ?? [];
  const topDecisionTagLine = topDecisionTags.length > 0
    ? topDecisionTags.slice(0, 4).map((entry) => `${entry.tag} (${entry.count})`).join(', ')
    : 'none';

  return `
    <div class="arena-card">
      <p class="arena-section-title">Outcome calibration</p>
      <div class="diag-grid" style="grid-template-columns: repeat(3, minmax(140px, 1fr)); gap:0.4rem">
        ${renderMetricCell('samples', String(totals.samples))}
        ${renderMetricCell('override rate', `${(totals.override_rate * 100).toFixed(1)}%`)}
        ${renderMetricCell('rework rate', `${(totals.rework_rate * 100).toFixed(1)}%`)}
        ${renderMetricCell('approve decisions', String(reviewerDecisions.approve))}
        ${renderMetricCell('request changes', String(reviewerDecisions.request_changes))}
        ${renderMetricCell('reject decisions', String(reviewerDecisions.reject))}
        ${renderMetricCell('avg review min', totals.review_time_avg_minutes.toFixed(1))}
        ${renderMetricCell('avg accept min', totals.time_to_accept_avg_minutes.toFixed(1))}
        ${renderMetricCell('cost/accepted', `$${totals.cost_per_accepted_bounty_usd.toFixed(4)}`)}
      </div>
      <p class="dim" style="font-size:0.78rem; margin-top:0.55rem"><strong>Top decision taxonomy tags:</strong> ${esc(topDecisionTagLine)}</p>
    </div>
  `;
}

function renderRoiDashboardCard(report: ArenaReportView): string {
  const roi = report.roi_dashboard;
  if (!roi) {
    return `
      <div class="arena-card">
        <p class="arena-section-title">Arena ROI dashboard</p>
        <p class="dim" style="font-size:0.82rem">ROI metrics are unavailable for this arena payload.</p>
      </div>
    `;
  }

  if (roi.status === 'INSUFFICIENT_SAMPLE' || !roi.metrics) {
    return `
      <div class="arena-card">
        <p class="arena-section-title">Arena ROI dashboard</p>
        <p class="dim" style="font-size:0.82rem">INSUFFICIENT_SAMPLE — sample_count=${roi.totals.sample_count}, arena_count=${roi.totals.arena_count}.</p>
        <p class="dim" style="font-size:0.78rem"><strong>Reason codes:</strong> ${esc(roi.reason_codes.join(', ') || 'none')}</p>
      </div>
    `;
  }

  const topReasons = roi.reason_code_drilldown
    .slice(0, 4)
    .map((entry) => `${entry.reason_code} (${entry.count})`)
    .join(', ') || 'none';

  const trend7 = roi.trends.window_7d;
  const trend30 = roi.trends.window_30d;

  // CSS bar chart for ROI metrics
  const barData = [
    { label: 'Accept', value: roi.metrics.first_pass_accept_rate, max: 1, fmt: `${(roi.metrics.first_pass_accept_rate * 100).toFixed(1)}%` },
    { label: 'Override', value: roi.metrics.override_rate, max: 1, fmt: `${(roi.metrics.override_rate * 100).toFixed(1)}%` },
    { label: 'Rework', value: roi.metrics.rework_rate, max: 1, fmt: `${(roi.metrics.rework_rate * 100).toFixed(1)}%` },
    { label: 'Stability', value: roi.metrics.winner_stability, max: 1, fmt: `${(roi.metrics.winner_stability * 100).toFixed(1)}%` },
  ];

  const bars = barData.map((d) => {
    const pct = Math.min(d.value / d.max * 100, 100);
    const color = d.value >= 0.7 ? 'var(--pass)' : d.value >= 0.4 ? 'var(--accent-amber)' : 'var(--fail)';
    return `
      <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.35rem">
        <span style="width:60px;font-size:0.68rem;color:#64748b;text-align:right;flex-shrink:0">${esc(d.label)}</span>
        <div style="flex:1;height:8px;background:#1a1a2e;border-radius:4px;overflow:hidden">
          <div style="width:${pct}%;height:100%;background:${color};border-radius:4px;transition:width 0.6s ease"></div>
        </div>
        <span style="width:48px;font-size:0.72rem;font-family:var(--font-mono);color:var(--text)">${esc(d.fmt)}</span>
      </div>
    `;
  }).join('');

  return `
    <div class="arena-card">
      <p class="arena-section-title">Arena ROI dashboard</p>
      <p class="dim" style="font-size:0.8rem; margin-bottom:0.55rem">Real persisted outcome metrics for autonomy + throughput quality.</p>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;margin-bottom:0.75rem">
        <div>
          <div class="diag-grid" style="grid-template-columns: repeat(2, minmax(130px, 1fr)); gap:0.35rem">
            ${renderMetricCell('median review min', roi.metrics.median_review_time_minutes.toFixed(2))}
            ${renderMetricCell('cost/accepted', `$${roi.metrics.cost_per_accepted_bounty_usd.toFixed(4)}`)}
            ${renderMetricCell('cycle time min', roi.metrics.cycle_time_minutes.toFixed(2))}
            ${renderMetricCell('samples', String(roi.totals.sample_count))}
          </div>
        </div>
        <div>${bars}</div>
      </div>
      <div class="detail-grid" style="margin-bottom:0.5rem">
        <dt>Trend 7d</dt><dd><span class="mono">${esc(trend7.status)}</span> (samples=${trend7.sample_count})</dd>
        <dt>Trend 30d</dt><dd><span class="mono">${esc(trend30.status)}</span> (samples=${trend30.sample_count})</dd>
      </div>
      <p class="dim" style="font-size:0.78rem"><strong>Top reason codes:</strong> ${esc(topReasons)}</p>
    </div>
  `;
}

function renderAutopilotCard(report: ArenaReportView): string {
  const autopilot = report.autopilot;
  if (!autopilot) {
    return `
      <div class="arena-card">
        <p class="arena-section-title">Routing autopilot</p>
        <p class="dim" style="font-size:0.82rem">Autopilot preview is unavailable for this arena payload.</p>
      </div>
    `;
  }

  const status = autopilot.status === 'auto_route_enabled' ? 'PASS' : 'FAIL';
  const violations = autopilot.violations.length > 0
    ? autopilot.violations.join(', ')
    : 'none';

  return `
    <div class="arena-card">
      <p class="arena-section-title">Routing autopilot</p>
      <p class="dim" style="font-size:0.8rem; margin-bottom:0.55rem">Default routing policy preview generated from winner + calibration guardrails.</p>
      <div class="detail-grid" style="margin-bottom:0.55rem">
        <dt>Status</dt><dd>${statusBadge(status)} <span class="mono" style="margin-left:0.35rem">${esc(autopilot.status)}</span></dd>
        <dt>Default contender</dt><dd class="mono">${esc(autopilot.default_contender_id ?? 'none')}</dd>
        <dt>Backups</dt><dd class="mono">${esc(autopilot.backup_contenders.join(', ') || 'none')}</dd>
        <dt>Task fingerprint</dt><dd class="mono">${esc(autopilot.task_fingerprint ?? 'unknown')}</dd>
      </div>
      <div class="diag-grid" style="grid-template-columns: repeat(3, minmax(120px, 1fr)); gap:0.35rem; margin-bottom:0.5rem">
        ${renderMetricCell('override rate', `${(autopilot.metrics.override_rate * 100).toFixed(1)}%`)}
        ${renderMetricCell('rework rate', `${(autopilot.metrics.rework_rate * 100).toFixed(1)}%`)}
        ${renderMetricCell('winner stability', `${(autopilot.metrics.winner_stability_ratio * 100).toFixed(1)}%`)}
      </div>
      <p class="dim" style="font-size:0.78rem"><strong>Violations:</strong> ${esc(violations)}</p>
      <p class="dim" style="font-size:0.78rem"><strong>Reason codes:</strong> ${esc(autopilot.reason_codes.join(', ') || 'none')}</p>
    </div>
  `;
}

function renderPolicyOptimizerCard(report: ArenaReportView): string {
  const optimizer = report.policy_optimizer;
  if (!optimizer) {
    return `
      <div class="arena-card">
        <p class="arena-section-title">Routing policy optimizer</p>
        <p class="dim" style="font-size:0.82rem">No optimizer state available for this arena fingerprint yet.</p>
      </div>
    `;
  }

  const active = optimizer.current_active_policy;
  const shadow = optimizer.candidate_shadow_policy;
  const promotion = optimizer.promotion;

  const activeContender = typeof active?.contender_id === 'string' ? active.contender_id : 'none';
  const shadowContender = typeof shadow?.contender_id === 'string' ? shadow.contender_id : 'none';
  const promotionStatus = typeof promotion?.status === 'string'
    ? promotion.status
    : (optimizer.promotion_status ?? optimizer.status);
  const promotionReasons = Array.isArray(promotion?.reason_codes)
    ? promotion.reason_codes.filter((entry): entry is string => typeof entry === 'string')
    : optimizer.reason_codes;

  return `
    <div class="arena-card">
      <p class="arena-section-title">Routing policy optimizer</p>
      <p class="dim" style="font-size:0.8rem; margin-bottom:0.55rem">Shadow policy is computed from real outcomes and promoted only when confidence gates pass.</p>
      <div class="detail-grid" style="margin-bottom:0.55rem">
        <dt>Status</dt><dd><span class="mono">${esc(optimizer.status)}</span></dd>
        <dt>Promotion status</dt><dd><span class="mono">${esc(promotionStatus ?? 'unknown')}</span></dd>
        <dt>Active policy contender</dt><dd class="mono">${esc(activeContender)}</dd>
        <dt>Shadow policy contender</dt><dd class="mono">${esc(shadowContender)}</dd>
      </div>
      <div class="diag-grid" style="grid-template-columns: repeat(4, minmax(120px, 1fr)); gap:0.35rem; margin-bottom:0.45rem">
        ${renderMetricCell('sample count', String(optimizer.gates.sample_count))}
        ${renderMetricCell('confidence', `${(optimizer.gates.confidence_score * 100).toFixed(1)}%`)}
        ${renderMetricCell('min samples', String(optimizer.gates.min_samples))}
        ${renderMetricCell('min confidence', `${(optimizer.gates.min_confidence * 100).toFixed(1)}%`)}
      </div>
      <p class="dim" style="font-size:0.78rem"><strong>Reason codes:</strong> ${esc((promotionReasons ?? []).join(', ') || 'none')}</p>
    </div>
  `;
}

function renderContractCopilotCard(report: ArenaReportView): string {
  const copilot = report.contract_copilot;
  if (!copilot) {
    return `
      <div class="arena-card">
        <p class="arena-section-title">Contract Copilot</p>
        <p class="dim" style="font-size:0.82rem">No copilot suggestions available for this arena payload.</p>
      </div>
    `;
  }

  if (copilot.status === 'empty') {
    return `
      <div class="arena-card">
        <p class="arena-section-title">Contract Copilot</p>
        <p class="dim" style="font-size:0.82rem">No persisted copilot suggestions for this task fingerprint yet.</p>
      </div>
    `;
  }

  if (copilot.status === 'INSUFFICIENT_SAMPLE') {
    return `
      <div class="arena-card">
        <p class="arena-section-title">Contract Copilot</p>
        <p class="dim" style="font-size:0.82rem">INSUFFICIENT_SAMPLE — waiting for more real failed outcomes before generating rewrite proposals.</p>
      </div>
    `;
  }

  if (copilot.status !== 'available') {
    return `
      <div class="arena-card">
        <p class="arena-section-title">Contract Copilot</p>
        <p class="dim" style="font-size:0.82rem">Copilot suggestions are temporarily unavailable.</p>
      </div>
    `;
  }

  const rankedSuggestions = [...copilot.global_suggestions, ...copilot.contender_suggestions]
    .sort((a, b) => b.confidence - a.confidence || b.evidence_count - a.evidence_count)
    .slice(0, 5);

  const suggestionRows = rankedSuggestions
    .map((entry) => {
      const impact = `${(entry.expected_impact.override_rate_reduction * 100).toFixed(1)}% / ${(entry.expected_impact.rework_rate_reduction * 100).toFixed(1)}%`;
      const sourceCount = entry.source_evidence.length;
      return `
        <tr>
          <td class="mono">${esc(entry.scope === 'global' ? 'global' : (entry.contender_id ?? 'n/a'))}</td>
          <td class="mono">${esc(entry.reason_code)}</td>
          <td class="mono">${(entry.confidence * 100).toFixed(1)}%</td>
          <td class="mono">${entry.evidence_count} (${sourceCount} refs)</td>
          <td class="mono">${impact}</td>
          <td>${esc(entry.before_text)}</td>
          <td>${esc(entry.after_text)}</td>
        </tr>
      `;
    })
    .join('');

  return `
    <div class="arena-card">
      <p class="arena-section-title">Contract Copilot</p>
      <p class="dim" style="font-size:0.8rem; margin-bottom:0.55rem">Rewrite proposals distilled from real override/rework evidence with traceable source rows.</p>
      <p class="dim" style="font-size:0.78rem; margin-bottom:0.4rem"><strong>Task fingerprint:</strong> <span class="mono">${esc(copilot.task_fingerprint ?? 'unknown')}</span></p>
      <div style="overflow-x:auto">
        <table>
          <thead>
            <tr>
              <th>Scope</th>
              <th>Reason code</th>
              <th>Confidence</th>
              <th>Evidence</th>
              <th>Expected impact (override/rework)</th>
              <th>Before</th>
              <th>After</th>
            </tr>
          </thead>
          <tbody>${suggestionRows || '<tr><td colspan="7" class="dim">No copilot suggestions available.</td></tr>'}</tbody>
        </table>
      </div>
    </div>
  `;
}

function renderContractLanguageOptimizerCard(report: ArenaReportView): string {
  const optimizer = report.contract_language_optimizer;
  if (!optimizer) {
    return `
      <div class="arena-card">
        <p class="arena-section-title">Contract language optimizer</p>
        <p class="dim" style="font-size:0.82rem">No contract-language optimizer preview available.</p>
      </div>
    `;
  }

  if (optimizer.status === 'empty') {
    return `
      <div class="arena-card">
        <p class="arena-section-title">Contract language optimizer</p>
        <p class="dim" style="font-size:0.82rem">No failed/overridden outcomes yet for optimizer suggestions.</p>
      </div>
    `;
  }

  if (optimizer.status !== 'available') {
    return `
      <div class="arena-card">
        <p class="arena-section-title">Contract language optimizer</p>
        <p class="dim" style="font-size:0.82rem">Optimizer suggestions are temporarily unavailable.</p>
      </div>
    `;
  }

  const globalRows = optimizer.global_suggestions
    .slice(0, 4)
    .map((entry) => `
      <tr>
        <td class="mono">${esc(entry.reason_code)}</td>
        <td class="mono">${entry.failures}</td>
        <td class="mono">${(entry.share * 100).toFixed(1)}%</td>
        <td>${esc(entry.contract_language_patch)}</td>
      </tr>
    `)
    .join('');

  const contenderRows = optimizer.contender_suggestions
    .slice(0, 6)
    .map((entry) => `
      <tr>
        <td class="mono">${esc(entry.contender_id ?? 'n/a')}</td>
        <td class="mono">${esc(entry.reason_code)}</td>
        <td class="mono">${entry.failures}</td>
        <td>${esc(entry.prompt_language_patch)}</td>
      </tr>
    `)
    .join('');

  return `
    <div class="arena-card">
      <p class="arena-section-title">Contract language optimizer</p>
      <p class="dim" style="font-size:0.8rem; margin-bottom:0.55rem">Persisted rewrite suggestions distilled from failed/overridden outcomes.</p>

      <p class="dim" style="font-size:0.78rem; margin-bottom:0.35rem"><strong>Task fingerprint:</strong> <span class="mono">${esc(optimizer.task_fingerprint ?? 'unknown')}</span></p>

      <p style="font-size:0.82rem; font-weight:600; margin:0.45rem 0 0.25rem; color:var(--accent-cyan)">Global contract rewrites</p>
      <div style="overflow-x:auto; margin-bottom:0.6rem">
        <table>
          <thead>
            <tr>
              <th>Reason code</th>
              <th>Failures</th>
              <th>Share</th>
              <th>Contract patch</th>
            </tr>
          </thead>
          <tbody>${globalRows || '<tr><td colspan="4" class="dim">No global suggestions.</td></tr>'}</tbody>
        </table>
      </div>

      <p style="font-size:0.82rem; font-weight:600; margin:0.45rem 0 0.25rem; color:var(--accent-cyan)">Contender prompt rewrites</p>
      <div style="overflow-x:auto">
        <table>
          <thead>
            <tr>
              <th>Contender</th>
              <th>Reason code</th>
              <th>Failures</th>
              <th>Prompt patch</th>
            </tr>
          </thead>
          <tbody>${contenderRows || '<tr><td colspan="4" class="dim">No contender-specific suggestions.</td></tr>'}</tbody>
        </table>
      </div>
    </div>
  `;
}

function renderOutcomeFeedCard(report: ArenaReportView): string {
  if (!Array.isArray(report.outcomes) || report.outcomes.length === 0) {
    return `
      <div class="arena-card">
        <p class="arena-section-title">Outcome feedback feed</p>
        <p class="dim" style="font-size:0.82rem">No recorded outcomes for this arena yet.</p>
      </div>
    `;
  }

  const rows = report.outcomes
    .map((outcome) => {
      const taxonomy = outcome.decision_taxonomy_tags.length > 0
        ? outcome.decision_taxonomy_tags.slice(0, 3).join(', ')
        : 'none';

      return `
        <tr>
          <td class="mono">${esc(outcome.contender_id)}</td>
          <td class="mono">${esc(outcome.outcome_status)}</td>
          <td class="mono">${esc(outcome.reviewer_decision)}</td>
          <td class="mono">${esc(outcome.recommendation)}</td>
          <td class="mono">${outcome.rework_required ? 'yes' : 'no'}</td>
          <td class="mono">${esc(outcome.override_reason_code ?? '\u2014')}</td>
          <td class="mono">${esc(taxonomy)}</td>
          <td>${esc(outcome.reviewer_rationale ?? '\u2014')}</td>
          <td class="mono">${relativeTime(outcome.created_at)}</td>
        </tr>
      `;
    })
    .join('');

  return `
    <div class="arena-card">
      <p class="arena-section-title">Outcome feedback feed</p>
      <div style="overflow-x:auto">
        <table>
          <thead>
            <tr>
              <th>Contender</th>
              <th>Outcome</th>
              <th>Reviewer decision</th>
              <th>Recommendation</th>
              <th>Rework?</th>
              <th>Override reason</th>
              <th>Decision tags</th>
              <th>Reviewer rationale</th>
              <th>Recorded</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>
  `;
}

function pct(value: number | null): string {
  if (value === null) return 'n/a';
  return `${(value * 100).toFixed(1)}%`;
}

/* ------------------------------------------------------------------ */
/*  Visual evidence + artifact viewer (screenshots, iframes, JSON)    */
/* ------------------------------------------------------------------ */

function renderVisualEvidence(report: ArenaReportView, artifactsBaseUrl: string | null): string {
  if (!artifactsBaseUrl || !report.contract?.bounty_id) return '';

  const bountyId = report.contract.bounty_id;
  const steps = ['browse', 'details', 'claim', 'submit'] as const;
  const stepFiles = ['01-browse.png', '02-details.png', '03-claim.png', '04-submit.png'];

  // Collect all screenshot URLs for the lightbox
  const allScreenshots: { url: string; alt: string }[] = [];
  report.contenders.forEach((c) => {
    steps.forEach((step, idx) => {
      allScreenshots.push({
        url: `${artifactsBaseUrl}/arena/${bountyId}/${c.contender_id}/journey/screenshots/${stepFiles[idx]}`,
        alt: `${c.contender_id} - ${step}`,
      });
    });
  });

  // Build side-by-side screenshot comparisons
  const screenshotRows = steps.map((step, idx) => {
    const cols = report.contenders.map((c) => {
      const url = `${artifactsBaseUrl}/arena/${bountyId}/${c.contender_id}/journey/screenshots/${stepFiles[idx]}`;
      return `
        <div style="flex:1; min-width:280px">
          <div class="screenshot-label">${esc(c.contender_id)} &mdash; ${esc(c.label)}</div>
          <img src="${esc(url)}" alt="${esc(step)} screenshot for ${esc(c.contender_id)}"
               data-lightbox="${esc(url)}"
               style="width:100%"
               loading="lazy"
               onerror="this.style.display='none';this.parentElement.insertAdjacentHTML('beforeend','<span class=dim>Screenshot not available</span>')" />
        </div>
      `;
    }).join('');

    return `
      <div style="margin-bottom:1.5rem">
        <p style="font-weight:600; font-size:0.85rem; margin-bottom:0.5rem; text-transform:capitalize; color:var(--accent-cyan)">${step}</p>
        <div style="display:flex; gap:1rem; flex-wrap:wrap">
          ${cols}
        </div>
      </div>
    `;
  }).join('');

  // Journey timing comparison
  const timingRows = report.contenders.map((c) => {
    const raw = c.raw_evaluator_metrics;
    const avgMs = raw && typeof raw.avg_timing_ms === 'number' ? raw.avg_timing_ms.toFixed(0) + 'ms' : 'N/A';
    const friction = raw && typeof raw.friction_events === 'number' ? String(raw.friction_events) : 'N/A';
    const rtErrors = raw && typeof raw.runtime_error_count === 'number' ? String(raw.runtime_error_count) : 'N/A';
    const journeyUrl = `${artifactsBaseUrl}/arena/${bountyId}/${c.contender_id}/journey/journey.json`;
    const lighthouseUrl = `${artifactsBaseUrl}/arena/${bountyId}/${c.contender_id}/lighthouse/lighthouse.summary.json`;
    return `
      <tr>
        <td class="mono">${esc(c.contender_id)}</td>
        <td>${esc(c.model)}</td>
        <td class="mono">${avgMs}</td>
        <td>${friction}</td>
        <td>${rtErrors}</td>
        <td>
          <a href="${esc(journeyUrl)}" target="_blank" class="dim" style="font-size:0.75rem">journey.json &#x2197;</a>
          &middot;
          <a href="${esc(lighthouseUrl)}" target="_blank" class="dim" style="font-size:0.75rem">lighthouse &#x2197;</a>
        </td>
      </tr>
    `;
  }).join('');

  // Lightbox with filmstrip
  const filmstripThumbs = allScreenshots.map((ss) =>
    `<img src="${esc(ss.url)}" alt="${esc(ss.alt)}" loading="lazy" onerror="this.style.display='none'" />`
  ).join('');

  return `
    <div class="arena-card">
      <p class="arena-section-title">Visual evidence &mdash; side-by-side screenshots</p>
      <p class="dim" style="font-size:0.78rem; margin-bottom:1rem">Playwright captured each UI flow step. Click any screenshot to open lightbox (arrow keys to navigate).</p>
      ${screenshotRows}
    </div>

    <div class="arena-card">
      <p class="arena-section-title">Journey + Lighthouse data</p>
      <div style="overflow-x:auto">
        <table>
          <thead>
            <tr><th>Contender</th><th>Model</th><th>Avg Timing</th><th>Friction</th><th>RT Errors</th><th>Raw Data</th></tr>
          </thead>
          <tbody>
            ${timingRows}
          </tbody>
        </table>
      </div>
    </div>

    <!-- Lightbox modal -->
    <div id="arena-lightbox" class="arena-lightbox">
      <button class="lb-close" aria-label="Close">&times;</button>
      <button class="lb-nav lb-prev" aria-label="Previous">&#8249;</button>
      <button class="lb-nav lb-next" aria-label="Next">&#8250;</button>
      <img src="" alt="" />
      <div class="lb-caption"></div>
      <div class="arena-filmstrip">${filmstripThumbs}</div>
    </div>
  `;
}

/* ------------------------------------------------------------------ */
/*  Interactive artifact viewer (iframes + JSON viewer)               */
/* ------------------------------------------------------------------ */

function renderArtifactViewer(report: ArenaReportView, artifactsBaseUrl: string | null): string {
  if (!artifactsBaseUrl || !report.contract?.bounty_id) return '';

  const bountyId = report.contract.bounty_id;

  // HTML artifact tabs (side-by-side live output embeds)
  const iframeTabs = report.contenders.map((c, idx) => {
    const tabId = 'artifact-tab-' + idx;
    const active = idx === 0 ? 'active' : '';
    return `<button class="arena-tab ${active}" data-tab="${tabId}">${esc(c.contender_id.replace('contender_', ''))}</button>`;
  }).join('');

  const iframePanels = report.contenders.map((c, idx) => {
    const tabId = 'artifact-tab-' + idx;
    const active = idx === 0 ? 'active' : '';
    const iframeId = 'artifact-iframe-' + idx;
    const outputUrl = `${artifactsBaseUrl}/arena/${bountyId}/${c.contender_id}/output/index.html`;
    return `
      <div class="arena-tab-panel ${active}" id="${tabId}">
        <div class="artifact-iframe-wrap">
          <div class="artifact-iframe-toolbar">
            <span class="toolbar-label">${esc(c.label)} &mdash; ${esc(c.model)}</span>
            <div style="display:flex;gap:0.4rem">
              <button data-iframe-toggle="${iframeId}">Expand</button>
              <a href="${esc(outputUrl)}" target="_blank" rel="noreferrer" style="font-size:0.68rem;color:var(--text-dim);display:flex;align-items:center">Open &#x2197;</a>
            </div>
          </div>
          <iframe id="${iframeId}" src="${esc(outputUrl)}" sandbox="allow-scripts" style="height:600px" loading="lazy" title="Live output for ${esc(c.contender_id)}"></iframe>
        </div>
      </div>
    `;
  }).join('');

  // JSON viewer for journey + lighthouse
  const jsonPanels = report.contenders.map((c, idx) => {
    const journeyUrl = `${artifactsBaseUrl}/arena/${bountyId}/${c.contender_id}/journey/journey.json`;
    const lighthouseUrl = `${artifactsBaseUrl}/arena/${bountyId}/${c.contender_id}/lighthouse/lighthouse.summary.json`;
    return `
      <div style="margin-bottom:1rem">
        <p style="font-size:0.78rem;font-weight:600;color:var(--text);margin-bottom:0.4rem">${esc(c.contender_id)}</p>
        <div style="display:flex;gap:0.75rem;flex-wrap:wrap">
          <a href="${esc(journeyUrl)}" target="_blank" style="font-size:0.72rem">journey.json &#x2197;</a>
          <a href="${esc(lighthouseUrl)}" target="_blank" style="font-size:0.72rem">lighthouse.summary.json &#x2197;</a>
        </div>
      </div>
    `;
  }).join('');

  return `
    <div class="arena-card">
      <p class="arena-section-title">Live output viewer</p>
      <p class="dim" style="font-size:0.78rem; margin-bottom:0.75rem">Agent-produced HTML pages rendered inline. Switch tabs to compare contender outputs side-by-side.</p>
      <div data-tab-group="artifact-tabs" class="arena-tabs">
        ${iframeTabs}
      </div>
      ${iframePanels}
    </div>

    <div class="arena-card">
      <p class="arena-section-title">JSON artifact data</p>
      <p class="dim" style="font-size:0.78rem; margin-bottom:0.75rem">Journey and Lighthouse report data for each contender.</p>
      ${jsonPanels}
    </div>
  `;
}

/* ------------------------------------------------------------------ */
/*  VS Banner — hero comparison for the compare page                  */
/* ------------------------------------------------------------------ */

function renderVsBanner(report: ArenaReportView): string {
  const sorted = [...report.contenders].sort((a, b) => b.score - a.score);

  const panels = sorted.map((c, idx) => {
    const isWinner = c.contender_id === report.winner.contender_id;
    const sc = scoreColor(c.score);
    return `
      <div class="vs-contender">
        <div class="vs-contender-name">${esc(c.contender_id.replace('contender_', ''))}</div>
        <div class="vs-contender-meta">${esc(c.model)} / ${esc(c.harness)}</div>
        <div class="vs-score score-animate" style="color:${sc};animation-delay:${idx * 0.15}s">${c.score.toFixed(1)}</div>
        <div class="score-bar-wrap" style="max-width:160px;margin:0 auto">
          <div class="score-bar-fill" style="width:${Math.min(c.score, 100)}%;background:${sc}"></div>
        </div>
        <div style="margin-top:0.55rem">
          ${isWinner ? '<span class="vs-winner-tag">WINNER</span>' : (c.hard_gate_pass ? statusBadge('PASS') : '<span class="vs-badge-fail">GATE FAIL</span>')}
        </div>
      </div>
      ${idx < sorted.length - 1 ? '<div class="vs-separator">VS</div>' : ''}
    `;
  }).join('');

  return `<div class="vs-banner">${panels}</div>`;
}

/* ------------------------------------------------------------------ */
/*  Exported page functions                                           */
/* ------------------------------------------------------------------ */

export function arenaMissionPage(summary: ArenaMissionSummaryView): string {
  const gateBadge = statusBadge(summary.kpi.gate_status === 'PASS' ? 'PASS' : 'FAIL');
  const gateIsPass = summary.kpi.gate_status === 'PASS';
  const submissionCoverageRate = summary.submissions_window.total > 0
    ? summary.submissions_window.with_submission / summary.submissions_window.total
    : null;

  const gapBountyIds = summary.backlog.claim_submission_gap_bounty_ids.slice(0, 6);
  const gateReasonCodes = summary.kpi.reason_codes.join(', ') || 'none';

  const meta: PageMeta = {
    title: 'Arena Mission Control',
    description: 'Autonomous Arena mission control dashboard',
    path: '/arena/mission',
  };

  return layout(meta, `
    ${arenaStyles()}
    <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.4rem">
      <h1 class="page-title" style="margin-bottom:0">Arena Mission Control</h1>
      <span class="mission-pulse ${gateIsPass ? 'green' : 'red'}"></span>
    </div>
    <p class="page-subtitle">Operational cockpit for claim &#x2192; submit throughput, proof quality, and live backlog pressure.</p>

    <div class="arena-hero-stats">
      <div class="arena-stat">
        <div class="arena-stat-value">${gateBadge}</div>
        <div class="arena-stat-label">KPI Gate</div>
      </div>
      <div class="arena-stat">
        <div class="arena-stat-value">${fmtNum(summary.fleet.online)}</div>
        <div class="arena-stat-label">Fleet Online</div>
      </div>
      <div class="arena-stat">
        <div class="arena-stat-value">${pct(submissionCoverageRate)}</div>
        <div class="arena-stat-label">Submission Coverage</div>
      </div>
      <div class="arena-stat">
        <div class="arena-stat-value">${pct(summary.kpi.proof_valid_rate)}</div>
        <div class="arena-stat-label">Proof Validity</div>
      </div>
    </div>

    <div class="arena-card">
      <p class="arena-section-title">Mission scope + gate rationale</p>
      <div class="detail-grid">
        <dt>Worker DID</dt><dd class="mono">${esc(summary.worker_did)}</dd>
        <dt>Window</dt><dd>${fmtNum(summary.window_hours)}h (since ${relativeTime(summary.window_started_at)})</dd>
        <dt>Computed</dt><dd>${relativeTime(summary.computed_at)}</dd>
      </div>
      <p class="dim" style="font-size:0.8rem; margin-top:0.55rem"><strong>Reason codes:</strong> ${esc(gateReasonCodes)}</p>
    </div>

    <div class="arena-card">
      <p class="arena-section-title">KPI posture</p>
      <div class="diag-grid" style="grid-template-columns: repeat(4, minmax(140px, 1fr)); gap:0.4rem">
        ${renderMetricCell('claim success', pct(summary.kpi.claim_success_rate))}
        ${renderMetricCell('submission success', pct(summary.kpi.submission_success_rate))}
        ${renderMetricCell('proof valid rate', pct(summary.kpi.proof_valid_rate))}
        ${renderMetricCell('claim\\u2192submit gap', String(summary.backlog.claim_submission_gap))}
      </div>
      <p class="dim" style="font-size:0.78rem; margin-top:0.45rem">Submission coverage is measured from actionable submissions (pending/approved/rejected) over claimed sample.</p>
    </div>

    <div class="arena-card">
      <p class="arena-section-title">Pipeline throughput</p>
      <div class="diag-grid" style="grid-template-columns: repeat(4, minmax(125px, 1fr)); gap:0.35rem">
        ${renderMetricCell('claims total', String(summary.claims_window.total))}
        ${renderMetricCell('claims failed', String(summary.claims_window.failed))}
        ${renderMetricCell('claims skipped', String(summary.claims_window.skipped))}
        ${renderMetricCell('claims processing', String(summary.claims_window.processing))}
        ${renderMetricCell('submissions total', String(summary.submissions_window.total))}
        ${renderMetricCell('with submission', String(summary.submissions_window.with_submission))}
        ${renderMetricCell('without submission', String(summary.submissions_window.without_submission))}
        ${renderMetricCell('proof invalid', String(summary.submissions_window.proof_invalid))}
        ${renderMetricCell('valid pending', String(summary.submissions_window.pending_review_valid))}
        ${renderMetricCell('pending invalid', String(summary.submissions_window.pending_review_invalid))}
        ${renderMetricCell('approved/rejected', `${summary.submissions_window.approved}/${summary.submissions_window.rejected}`)}
        ${renderMetricCell('accepted backlog', String(summary.backlog.accepted_without_valid_submission))}
      </div>
    </div>

    <div class="arena-card">
      <p class="arena-section-title">Claim gap queue</p>
      ${gapBountyIds.length === 0
        ? '<p class="dim" style="font-size:0.82rem">No claim&#x2192;submission gaps currently tracked in the mission window.</p>'
        : `
          <p class="dim" style="font-size:0.8rem; margin-bottom:0.45rem">Top bounty IDs currently counted in claim&#x2192;submission gap:</p>
          <ul style="margin-left:1.1rem; display:grid; gap:0.25rem">
            ${gapBountyIds.map((bountyId) => `<li class="mono">${esc(bountyId)}</li>`).join('')}
          </ul>
        `
      }
    </div>

    <div class="arena-card">
      <p class="arena-section-title">Gate thresholds</p>
      <div class="detail-grid">
        <dt>Min online workers</dt><dd>${fmtNum(summary.thresholds.min_online_workers)}</dd>
        <dt>Min claim success</dt><dd>${pct(summary.thresholds.min_claim_success_rate)}</dd>
        <dt>Min submission success</dt><dd>${pct(summary.thresholds.min_submission_success_rate)}</dd>
        <dt>Min proof valid</dt><dd>${pct(summary.thresholds.min_proof_valid_rate)}</dd>
        <dt>Max claim&#x2192;submit gap</dt><dd>${fmtNum(summary.thresholds.max_claim_submission_gap)}</dd>
        <dt>Max accepted backlog</dt><dd>${fmtNum(summary.thresholds.max_accepted_backlog)}</dd>
      </div>
    </div>
  `);
}

export function arenaComparePage(report: ArenaReportView, artifactsBaseUrl: string | null = null): string {
  const meta: PageMeta = {
    title: `Arena ${report.arena_id}`,
    description: `Bounty Arena comparison for ${report.contract.bounty_id}`,
    path: `/arena/${report.arena_id}`,
  };

  return layout(meta, `
    ${arenaStyles()}
    <h1 class="page-title" style="background:linear-gradient(135deg, var(--text), var(--accent-cyan));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text">Arena Compare: ${esc(report.arena_id)}</h1>
    <p class="page-subtitle">Transparent contender comparison across model/harness/tool stack, contract checks, and objective scoring.</p>

    ${renderVsBanner(report)}

    <div class="arena-hero-stats">
      <div class="arena-stat">
        <div class="arena-stat-value">${fmtNum(report.contenders.length)}</div>
        <div class="arena-stat-label">Contenders</div>
      </div>
      <div class="arena-stat">
        <div class="arena-stat-value" style="font-size:1rem">${esc(report.winner.contender_id)}</div>
        <div class="arena-stat-label">Winner</div>
      </div>
      <div class="arena-stat">
        <div class="arena-stat-value" style="font-size:1rem">${esc(report.objective_profile.name)}</div>
        <div class="arena-stat-label">Objective Profile</div>
      </div>
      <div class="arena-stat">
        <div class="arena-stat-value" style="font-size:1rem">${relativeTime(report.generated_at)}</div>
        <div class="arena-stat-label">Generated</div>
      </div>
    </div>

    <div class="arena-card">
      <p class="arena-section-title">Winner rationale + tradeoffs</p>
      <p style="margin-bottom:0.65rem">${esc(report.winner.reason)}</p>
      <ul style="margin-left:1.1rem; display:grid; gap:0.25rem; font-size:0.86rem">
        ${report.tradeoffs.map((line) => `<li>${esc(line)}</li>`).join('') || '<li>No tradeoff notes supplied.</li>'}
      </ul>
      <p class="dim" style="font-size:0.8rem; margin-top:0.65rem">Reason codes: ${esc(report.reason_codes.join(', ') || 'none')}</p>
    </div>

    ${report.delegation_insights ? `
      <div class="arena-card">
        <p class="arena-section-title">Delegation insights</p>
        <p class="dim" style="font-size:0.82rem; margin-bottom:0.5rem">Route future work using winner hints + observed bottlenecks.</p>
        <div class="detail-grid" style="margin-bottom:0.6rem">
          <dt>Default route</dt><dd class="mono">${esc(report.delegation_insights.manager_routing.default_contender_id ?? 'none')}</dd>
          <dt>Backups</dt><dd class="mono">${esc(report.delegation_insights.manager_routing.backup_contenders.join(', ') || 'none')}</dd>
        </div>
        <div style="display:grid; gap:0.45rem; font-size:0.82rem">
          <div><strong>Winner hints:</strong> ${esc(report.delegation_insights.winner_hints.join(' | ') || 'none')}</div>
          <div><strong>Bottlenecks:</strong> ${esc(report.delegation_insights.bottlenecks.join(' | ') || 'none')}</div>
          <div><strong>Contract improvements:</strong> ${esc(report.delegation_insights.contract_improvements.join(' | ') || 'none')}</div>
        </div>
      </div>
    ` : ''}

    ${renderReviewThreadCard(report)}

    ${renderCalibrationCard(report)}

    ${renderRoiDashboardCard(report)}

    ${renderAutopilotCard(report)}

    ${renderPolicyOptimizerCard(report)}

    ${renderContractCopilotCard(report)}

    ${renderContractLanguageOptimizerCard(report)}

    ${renderOutcomeFeedCard(report)}

    <div class="arena-card">
      <p class="arena-section-title">Contract binding</p>
      <div class="detail-grid">
        <dt>Bounty</dt><dd class="mono">${esc(report.contract.bounty_id)}</dd>
        <dt>Contract</dt><dd class="mono">${esc(report.contract.contract_id)}</dd>
        <dt>Contract hash</dt><dd class="mono">${esc(report.contract.contract_hash_b64u)}</dd>
        <dt>Task fingerprint</dt><dd class="mono">${esc(report.contract.task_fingerprint)}</dd>
      </div>
    </div>

    <div class="arena-card" id="proof-card">
      <p class="arena-section-title">Contenders table</p>
      <div style="overflow-x:auto">
        <table>
          <thead>
            <tr>
              <th>Contender</th>
              <th>Model/Harness</th>
              <th>Score</th>
              <th>Evaluator Metrics</th>
              <th>Review</th>
            </tr>
          </thead>
          <tbody>
            ${contenderRows(report)}
          </tbody>
        </table>
      </div>
    </div>

    <div class="arena-card">
      <p class="arena-section-title">Contract check matrix</p>
      ${contractCheckMatrix(report)}
      ${contractCheckTable(report)}
    </div>

    ${renderVisualEvidence(report, artifactsBaseUrl)}

    ${renderArtifactViewer(report, artifactsBaseUrl)}

    ${arenaScripts()}
  `);
}

export function arenaIndexPage(arenas: ArenaIndexItem[]): string {
  const meta: PageMeta = {
    title: 'Arena Index',
    description: 'Bounty Arena comparison history',
    path: '/arena',
  };

  const rows = arenas.length > 0
    ? arenas
      .map((row) => `
        <tr class="arena-index-row" onclick="window.location='/arena/${encodeURIComponent(row.arena_id)}'">
          <td><a href="/arena/${encodeURIComponent(row.arena_id)}" class="mono" style="color:var(--accent-cyan)">${esc(row.arena_id)}</a></td>
          <td class="mono">${esc(row.bounty_id)}</td>
          <td class="mono">${esc(row.contract_id)}</td>
          <td><span class="arena-winner-chip">${esc(row.winner_contender_id)}</span></td>
          <td><span class="mono">${esc(row.reason_code)}</span></td>
          <td>${relativeTime(row.generated_at)}</td>
        </tr>
      `)
      .join('')
    : `
      <tr>
        <td colspan="6">
          <div class="runs-empty">
            <p style="font-weight:600">No arena comparisons indexed yet</p>
            <p class="dim" style="font-size:0.82rem">Run <span class="mono">node scripts/arena/run-bounty-arena.mjs --contract ... --contenders ...</span> and publish arena outputs to activate this feed.</p>
          </div>
        </td>
      </tr>
    `;

  return layout(meta, `
    ${arenaStyles()}
    <h1 class="page-title" style="background:linear-gradient(135deg, var(--text), var(--accent-cyan));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text">Bounty Arena Index</h1>
    <p class="page-subtitle">Compare contender stacks and copy decision artifacts for human and manager review loops. <a href="/arena/mission">Open mission control &rarr;</a></p>

    <div class="arena-card">
      <div style="overflow-x:auto">
        <table>
          <thead>
            <tr>
              <th>Arena ID</th>
              <th>Bounty</th>
              <th>Contract</th>
              <th>Winner</th>
              <th>Reason Code</th>
              <th>Updated</th>
            </tr>
          </thead>
          <tbody>
            ${rows}
          </tbody>
        </table>
      </div>
    </div>
  `);
}

export function arenaNotFoundPage(arenaId: string): string {
  const meta: PageMeta = {
    title: 'Arena Not Found',
    description: `Arena ${arenaId} was not found.`,
    path: `/arena/${arenaId}`,
  };

  return layout(meta, `
    ${arenaStyles()}
    <div class="arena-card" style="text-align:center">
      <p class="arena-section-title" style="justify-content:center">Arena not found</p>
      <p class="mono" style="margin-bottom:0.5rem">${esc(arenaId)}</p>
      <p class="dim" style="font-size:0.85rem; margin-bottom:0.8rem">Publish an arena report first, then open this route again.</p>
      <p><a href="/arena">Open Arena Index &rarr;</a></p>
    </div>
  `);
}

/* ------------------------------------------------------------------ */
/*  Sample data fixtures (used by tests — do not break)               */
/* ------------------------------------------------------------------ */

export function sampleArenaMissionSummary(): ArenaMissionSummaryView {
  return {
    schema_version: 'arena_mission_summary.v1',
    computed_at: '2026-02-20T02:18:23.772Z',
    worker_did: 'did:key:z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7',
    window_hours: 24,
    window_started_at: '2026-02-19T02:18:23.772Z',
    thresholds: {
      min_online_workers: 3,
      min_claim_success_rate: 0.8,
      min_submission_success_rate: 0.8,
      min_proof_valid_rate: 0.95,
      max_claim_submission_gap: 5,
      max_accepted_backlog: 5,
    },
    fleet: {
      total: 6,
      online: 6,
      offline: 0,
      paused: 0,
    },
    claims_window: {
      processing: 0,
      claimed: 10,
      skipped: 0,
      failed: 0,
      total: 10,
    },
    submissions_window: {
      total: 10,
      with_submission: 10,
      without_submission: 0,
      pending_review_valid: 10,
      pending_review_invalid: 0,
      approved: 0,
      rejected: 0,
      proof_valid: 10,
      proof_invalid: 0,
    },
    backlog: {
      accepted_total: 0,
      accepted_without_valid_submission: 0,
      claim_submission_gap: 0,
      claim_submission_gap_bounty_ids: [],
    },
    kpi: {
      claim_success_rate: 1,
      submission_success_rate: 1,
      proof_valid_rate: 1,
      gate_status: 'PASS',
      reason_codes: ['ARENA_MISSION_KPI_PASS'],
    },
  };
}

export function sampleArenaReport(arenaId: string): ArenaReportView | null {
  if (arenaId !== 'arena_bty_arena_001') return null;

  const contenderChecks = {
    contender_codex_pi: [
      { criterion_id: 'ac_contract_binding', required: true, status: 'PASS' as const, reason_code: 'CHECK_OK' },
      { criterion_id: 'ac_reason_codes', required: true, status: 'PASS' as const, reason_code: 'CHECK_OK' },
      { criterion_id: 'ac_test_coverage', required: false, status: 'PASS' as const, reason_code: 'CHECK_OK' },
    ],
    contender_claude_codex_cli: [
      { criterion_id: 'ac_contract_binding', required: true, status: 'PASS' as const, reason_code: 'CHECK_OK' },
      { criterion_id: 'ac_reason_codes', required: true, status: 'PASS' as const, reason_code: 'CHECK_OK' },
      { criterion_id: 'ac_test_coverage', required: false, status: 'FAIL' as const, reason_code: 'ARENA_OPTIONAL_CRITERION_MISS' },
    ],
    contender_gemini_swarm: [
      { criterion_id: 'ac_contract_binding', required: true, status: 'FAIL' as const, reason_code: 'ARENA_ACCEPTANCE_CRITERION_FAILED' },
      { criterion_id: 'ac_reason_codes', required: true, status: 'FAIL' as const, reason_code: 'ARENA_ACCEPTANCE_CRITERION_FAILED' },
      { criterion_id: 'ac_test_coverage', required: false, status: 'PASS' as const, reason_code: 'CHECK_OK' },
    ],
  };

  return {
    arena_id: 'arena_bty_arena_001',
    generated_at: '2026-02-19T15:10:00.000Z',
    contract: {
      bounty_id: 'bty_arena_001',
      contract_id: 'contract_arena_001',
      contract_hash_b64u: 'RVGH8pYttabUqs0rewkHlUVnxFap8c7lc81vxZi2H7I',
      task_fingerprint: 'typescript:worker:api-hardening',
    },
    objective_profile: {
      name: 'balanced',
      weights: {
        quality: 0.35,
        speed: 0.25,
        cost: 0.2,
        safety: 0.2,
      },
      tie_breakers: ['mandatory_passed', 'quality_score', 'risk_score_low', 'cost_low', 'latency_low', 'contender_id'],
    },
    contenders: [
      {
        contender_id: 'contender_codex_pi',
        label: 'Codex + Pi + cloudflare skill',
        model: 'gpt-5.2-codex',
        harness: 'pi',
        tools: ['bash', 'read', 'edit', 'wrangler'],
        skills: ['cloudflare', 'wrangler'],
        plugins: ['did-work'],
        score: 85.5475,
        hard_gate_pass: true,
        mandatory_failed: 0,
        metrics: {
          quality_score: 92,
          risk_score: 26,
          efficiency_score: 81,
          latency_ms: 16000,
          cost_usd: 0.78,
          autonomy_score: 84,
        },
        check_results: contenderChecks.contender_codex_pi,
        score_explain: {
          final_score: 85.5475,
          reason_codes: ['ARENA_SCORE_EVIDENCE_GROUNDED'],
          evidence_links: [
            { label: 'CI', url: 'https://github.com/clawbureau/clawbureau/actions/runs/22186834424/job/64162890956', source: 'ci' },
            { label: 'Diff', url: 'https://github.com/clawbureau/clawbureau/pull/366/files', source: 'git' },
            { label: 'Trace', url: 'https://github.com/clawbureau/clawbureau/actions/runs/22186834313/job/64162891224', source: 'execution' },
          ],
        },
        review_paste: 'Decision Summary: Promote contender\nContract Compliance: PASS (2 mandatory passed, 0 mandatory failed)\nDelivery/Risk: quality=92.00, risk=26.00, efficiency=81.00, cost=$0.7800, latency=16000ms\nRecommendation: use for high-risk API hardening bounties',
        raw_evaluator_metrics: null,
        manager_review_json: '{\n  "decision": "promote",\n  "confidence": 0.782,\n  "reason_codes": ["ARENA_READY_TO_PROMOTE"]\n}',
      },
      {
        contender_id: 'contender_claude_codex_cli',
        label: 'Claude Opus + Codex CLI blend',
        model: 'claude-opus-4.5',
        harness: 'codex-cli',
        tools: ['bash', 'read', 'edit'],
        skills: ['ai-sdk'],
        plugins: ['did-work'],
        score: 83.0075,
        hard_gate_pass: true,
        mandatory_failed: 0,
        metrics: {
          quality_score: 86,
          risk_score: 38,
          efficiency_score: 90,
          latency_ms: 11200,
          cost_usd: 0.54,
          autonomy_score: 79,
        },
        check_results: contenderChecks.contender_claude_codex_cli,
        score_explain: {
          final_score: 83.0075,
          reason_codes: ['ARENA_SCORE_EVIDENCE_GROUNDED', 'ARENA_OPTIONAL_CHECK_FAILED'],
          evidence_links: [
            { label: 'CI', url: 'https://github.com/clawbureau/clawbureau/actions/runs/22187189036/job/64164221560', source: 'ci' },
            { label: 'Diff', url: 'https://github.com/clawbureau/clawbureau/pull/368/files', source: 'git' },
            { label: 'Trace', url: 'https://github.com/clawbureau/clawbureau/actions/runs/22187189036/job/64164221560', source: 'execution' },
          ],
        },
        review_paste: 'Decision Summary: Manual review required\nContract Compliance: PASS (2 mandatory passed, 0 mandatory failed)\nDelivery/Risk: quality=86.00, risk=38.00, efficiency=90.00, cost=$0.5400, latency=11200ms\nRecommendation: use for speed-oriented triage work',
        raw_evaluator_metrics: null,
        manager_review_json: '{\n  "decision": "conditional",\n  "confidence": 0.612,\n  "reason_codes": ["ARENA_OPTIONAL_CRITERION_MISS"]\n}',
      },
      {
        contender_id: 'contender_gemini_swarm',
        label: 'Gemini Deep Think + swarm orchestrator',
        model: 'gemini-3.1-pro-preview',
        harness: 'swarm-orchestrator',
        tools: ['bash', 'read', 'edit', 'parallel'],
        skills: ['deep-think-swarm', 'swarm-orchestrator'],
        plugins: ['did-work', 'artifact-tracer'],
        score: 74.655,
        hard_gate_pass: false,
        mandatory_failed: 2,
        metrics: {
          quality_score: 74,
          risk_score: 52,
          efficiency_score: 72,
          latency_ms: 22100,
          cost_usd: 0.31,
          autonomy_score: 69,
        },
        check_results: contenderChecks.contender_gemini_swarm,
        score_explain: {
          final_score: 74.655,
          reason_codes: ['ARENA_SCORE_EVIDENCE_GROUNDED', 'ARENA_EVIDENCE_LINT_FAILED', 'ARENA_MANDATORY_CHECK_FAILED'],
          evidence_links: [
            { label: 'CI', url: 'https://github.com/clawbureau/clawbureau/actions/runs/22188095506/job/64167593977', source: 'ci' },
            { label: 'Diff', url: 'https://github.com/clawbureau/clawbureau/pull/370/files', source: 'git' },
            { label: 'Trace', url: 'https://github.com/clawbureau/clawbureau/actions/runs/22188095506/job/64167593977', source: 'execution' },
          ],
        },
        review_paste: 'Decision Summary: Reject contender\nContract Compliance: FAIL (0 mandatory passed, 2 mandatory failed)\nDelivery/Risk: quality=74.00, risk=52.00, efficiency=72.00, cost=$0.3100, latency=22100ms\nRecommendation: tighten contract language and rerun',
        raw_evaluator_metrics: null,
        manager_review_json: '{\n  "decision": "reject",\n  "confidence": 0.361,\n  "reason_codes": ["ARENA_MANDATORY_CHECK_FAILED"]\n}',
      },
    ],
    winner: {
      contender_id: 'contender_codex_pi',
      reason: 'Winner contender_codex_pi passed all mandatory checks and achieved top weighted score (85.5475).',
    },
    tradeoffs: [
      'contender_codex_pi wins quality/safety but costs more than contender_claude_codex_cli.',
      'contender_codex_pi trades latency for stronger compliance confidence.',
    ],
    reason_codes: ['ARENA_WINNER_SELECTED', 'ARENA_HARD_GATES_PASSED'],
    delegation_insights: {
      winner_hints: ['use for high-risk API hardening bounties'],
      winner_bottlenecks: ['slower due to larger test matrix'],
      bottlenecks: ['slower due to larger test matrix', 'requires stricter contract language'],
      contract_improvements: ['clarify schema version lock in contract text'],
      next_delegation_hints: [
        'use for high-risk API hardening bounties',
        'pair with low-cost contender for quick reruns',
      ],
      manager_routing: {
        default_contender_id: 'contender_codex_pi',
        backup_contenders: ['contender_claude_codex_cli'],
      },
    },
    review_thread: [
      {
        thread_entry_id: 'art_sample_001',
        contender_id: 'contender_codex_pi',
        recommendation: 'APPROVE',
        confidence: 0.782,
        body_markdown: 'Recommendation: APPROVE',
        links: [
          { label: 'Proof card', url: '/arena/arena_bty_arena_001#proof-card' },
          { label: 'Arena comparison', url: '/arena/arena_bty_arena_001' },
          { label: 'Review paste', url: '/arena/arena_bty_arena_001#review-paste-contender_codex_pi' },
          { label: 'Manager review', url: '/arena/arena_bty_arena_001#manager-review-contender_codex_pi' },
        ],
        source: 'sample',
        created_at: '2026-02-19T15:12:00.000Z',
      },
    ],
    outcomes: [
      {
        outcome_id: 'aot_sample_001',
        contender_id: 'contender_codex_pi',
        outcome_status: 'ACCEPTED',
        review_time_minutes: 18,
        time_to_accept_minutes: 55,
        predicted_confidence: 0.782,
        recommendation: 'APPROVE',
        reviewer_decision: 'approve',
        rework_required: false,
        override_reason_code: null,
        reviewer_rationale: 'All acceptance checks passed with sufficient evidence.',
        decision_taxonomy_tags: ['decision:approve', 'outcome:accepted', 'arena-review'],
        created_at: '2026-02-19T16:00:00.000Z',
      },
    ],
    calibration: {
      totals: {
        samples: 1,
        accepted: 1,
        overridden: 0,
        rework: 0,
        disputed: 0,
        review_time_avg_minutes: 18,
        time_to_accept_avg_minutes: 55,
        cost_per_accepted_bounty_usd: 0.78,
        override_rate: 0,
        rework_rate: 0,
        reviewer_decisions: {
          approve: 1,
          request_changes: 0,
          reject: 0,
        },
      },
      reviewer_decision_capture: {
        decision_breakdown: [
          { reviewer_decision: 'approve', count: 1, share: 1 },
          { reviewer_decision: 'request_changes', count: 0, share: 0 },
          { reviewer_decision: 'reject', count: 0, share: 0 },
        ],
        decision_taxonomy_tags: [
          { tag: 'decision:approve', count: 1, share: 1 },
          { tag: 'outcome:accepted', count: 1, share: 1 },
        ],
      },
    },
    roi_dashboard: {
      status: 'available',
      reason_codes: ['ARENA_ROI_READY'],
      totals: {
        sample_count: 12,
        arena_count: 4,
        available_runs: 4,
      },
      metrics: {
        median_review_time_minutes: 19.5,
        first_pass_accept_rate: 0.6667,
        override_rate: 0.1667,
        rework_rate: 0.1667,
        cost_per_accepted_bounty_usd: 0.7125,
        cycle_time_minutes: 57,
        winner_stability: 0.75,
      },
      trends: {
        window_7d: {
          status: 'available',
          sample_count: 8,
          reason_codes: [],
          metrics: {
            median_review_time_minutes: 18,
            first_pass_accept_rate: 0.625,
            override_rate: 0.25,
            rework_rate: 0.125,
            cost_per_accepted_bounty_usd: 0.74,
            cycle_time_minutes: 55,
            winner_stability: 0.67,
          },
        },
        window_30d: {
          status: 'available',
          sample_count: 12,
          reason_codes: [],
          metrics: {
            median_review_time_minutes: 19.5,
            first_pass_accept_rate: 0.6667,
            override_rate: 0.1667,
            rework_rate: 0.1667,
            cost_per_accepted_bounty_usd: 0.7125,
            cycle_time_minutes: 57,
            winner_stability: 0.75,
          },
        },
      },
      reason_code_drilldown: [
        { reason_code: 'ARENA_OVERRIDE_SCOPE_MISMATCH', count: 3, share: 0.25 },
        { reason_code: 'ARENA_OVERRIDE_TEST_FAILURE', count: 2, share: 0.1667 },
      ],
    },
    autopilot: {
      status: 'auto_route_enabled',
      task_fingerprint: 'typescript:worker:api-hardening',
      default_contender_id: 'contender_codex_pi',
      backup_contenders: ['contender_claude_codex_cli'],
      reason_codes: ['ARENA_AUTOPILOT_PREVIEW_ENABLED'],
      violations: [],
      metrics: {
        override_rate: 0,
        rework_rate: 0,
        winner_stability_ratio: 1,
      },
    },
    contract_copilot: {
      status: 'available',
      task_fingerprint: 'typescript:worker:api-hardening',
      global_suggestions: [
        {
          suggestion_id: 'accs_sample_global_001',
          scope: 'global',
          contender_id: null,
          reason_code: 'ARENA_OVERRIDE_SCOPE_MISMATCH',
          before_text: 'Current contract language under-specifies scope alignment checks for reviewer handoff.',
          after_text: 'Add explicit scope-alignment acceptance criterion with fail-closed escalation and evidence binding.',
          rationale: 'Observed recurrent scope mismatch overrides across multiple arenas.',
          confidence: 0.82,
          evidence_count: 6,
          arena_count: 3,
          outcome_count: 6,
          expected_impact: {
            override_rate_reduction: 0.34,
            rework_rate_reduction: 0.21,
          },
          source_evidence: [
            {
              arena_id: 'arena_bty_arena_001',
              outcome_id: 'aot_sample_001',
              contender_id: 'contender_codex_pi',
              criterion_id: 'scope_alignment',
              reason_code: 'ARENA_OVERRIDE_SCOPE_MISMATCH',
            },
          ],
        },
      ],
      contender_suggestions: [
        {
          suggestion_id: 'accs_sample_contender_001',
          scope: 'contender',
          contender_id: 'contender_claude_codex_cli',
          reason_code: 'ARENA_OVERRIDE_TEST_FAILURE',
          before_text: 'Test completion criteria are too implicit for this contender profile.',
          after_text: 'Require explicit test matrix completion with criterion IDs and CI evidence links.',
          rationale: 'Contender-specific failure pattern shows repeated rework from missing coverage detail.',
          confidence: 0.74,
          evidence_count: 4,
          arena_count: 2,
          outcome_count: 4,
          expected_impact: {
            override_rate_reduction: 0.26,
            rework_rate_reduction: 0.29,
          },
          source_evidence: [
            {
              arena_id: 'arena_bty_arena_001',
              outcome_id: 'aot_sample_001',
              contender_id: 'contender_claude_codex_cli',
              criterion_id: 'test_coverage',
              reason_code: 'ARENA_OVERRIDE_TEST_FAILURE',
            },
          ],
        },
      ],
    },
    contract_language_optimizer: {
      status: 'available',
      task_fingerprint: 'typescript:worker:api-hardening',
      global_suggestions: [
        {
          suggestion_id: 'acls_sample_global_001',
          scope: 'global',
          contender_id: null,
          reason_code: 'ARENA_OVERRIDE_SCOPE_MISMATCH',
          failures: 3,
          overrides: 2,
          share: 0.5,
          priority_score: 3.15,
          contract_rewrite: 'Tighten acceptance criteria and explicit out-of-scope boundaries in the contract.',
          prompt_rewrite: 'Add a scope-check checklist before final answer generation.',
          contract_language_patch: 'Observed 3 failed/overridden outcomes tied to scope mismatch. Add explicit acceptance checklist and out-of-scope boundaries.',
          prompt_language_patch: 'Add a scope-check checklist before final answer generation and fail closed on unmet criteria.',
          sample_notes: ['Winner missed explicit out-of-scope checklist item.'],
          top_tags: ['scope-check', 'acceptance-criteria'],
        },
      ],
      contender_suggestions: [
        {
          suggestion_id: 'acls_sample_contender_001',
          scope: 'contender',
          contender_id: 'contender_codex_pi',
          reason_code: 'ARENA_OVERRIDE_SCOPE_MISMATCH',
          failures: 2,
          overrides: 2,
          share: 1,
          priority_score: 2.1,
          contract_rewrite: 'Tighten acceptance criteria and explicit out-of-scope boundaries in the contract.',
          prompt_rewrite: 'Add a scope-check checklist before final answer generation.',
          contract_language_patch: 'Add contender-specific acceptance checklist for scope-sensitive tasks.',
          prompt_language_patch: 'Require contender to enumerate acceptance criteria and scope exclusions before final output.',
          sample_notes: ['Scope ambiguity caused override for this contender.'],
          top_tags: ['scope-check'],
        },
      ],
    },
  };
}
