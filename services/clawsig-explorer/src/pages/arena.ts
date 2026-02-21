import { esc, fmtNum, layout, relativeTime, statusBadge, type PageMeta } from '../layout.js';
import type { ArenaContenderView, ArenaMissionSummaryView, ArenaReportView } from '../api.js';

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
    <div class="diag-chip">
      <span class="diag-chip-label">${esc(label)}</span>
      <span class="diag-chip-value">${esc(value)}</span>
    </div>
  `;
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

  return `
    <div class="matrix-grid" style="grid-template-columns: minmax(150px, 2fr) repeat(${report.contenders.length}, 1fr)">
      <div class="matrix-cell header">Criterion</div>
      ${report.contenders.map(c => `<div class="matrix-cell col-header mono">${esc(c.contender_id.replace('contender_', ''))}</div>`).join('')}
      
      ${criterionIds.map(crit => `
        <div class="matrix-cell header mono">${esc(crit)}</div>
        ${report.contenders.map(c => {
            const check = c.check_results.find(x => x.criterion_id === crit);
            if (!check) return '<div class="matrix-cell cell-na">N/A</div>';
            const cls = check.status === 'PASS' ? 'cell-pass' : 'cell-fail';
            const icon = check.status === 'PASS' ? '✓ PASS' : '✗ FAIL';
            return `<div class="matrix-cell ${cls}" title="${esc(check.reason_code)}">${icon}</div>`;
        }).join('')}
      `).join('')}
    </div>
  `;
}

function renderEvaluatorMetrics(raw: Record<string, unknown>): string {
  // Show the real evaluator metrics from Playwright duel evaluator
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

  // Hard gates sub-section
  const hardGates = raw.hard_gates;
  if (hardGates && typeof hardGates === 'object') {
    const hg = hardGates as Record<string, unknown>;
    if (typeof hg.core_flows_pass === 'boolean') cells.push(renderMetricCell('core flows', hg.core_flows_pass ? 'PASS' : 'FAIL'));
    if (typeof hg.no_runtime_errors === 'boolean') cells.push(renderMetricCell('no RT err', hg.no_runtime_errors ? 'PASS' : 'FAIL'));
    if (typeof hg.no_a11y_critical === 'boolean') cells.push(renderMetricCell('no crit a11y', hg.no_a11y_critical ? 'PASS' : 'FAIL'));
  }

  // Reason codes from evaluator
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
    <div style="font-size:0.75rem; line-height:1.4; font-family:var(--font-mono); background:var(--card-bg); border:1px solid var(--border); border-radius:var(--radius); padding:0.5rem; max-height:6rem; overflow-y:auto; white-space:pre-wrap">
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

      return `
        <tr>
          <td>
            <div style="display:grid; gap:0.3rem">
              <span class="mono">${esc(contender.contender_id)}</span>
              <span class="dim" style="font-size:0.78rem">${esc(contender.label)}</span>
              ${statusBadge(contender.hard_gate_pass ? 'PASS' : 'FAIL')}
            </div>
          </td>
          <td>
            <div class="mono" style="font-size:0.78rem">${esc(contender.model)}</div>
            <div class="dim" style="font-size:0.75rem">${esc(contender.harness)}</div>
          </td>
          <td>
            <div class="mono" style="font-size:0.84rem; font-weight:600">${contender.score.toFixed(1)}</div>
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
      <div class="card">
        <p class="section-title">Decision review thread</p>
        <p class="dim" style="font-size:0.82rem">No decision paste entries posted yet for this arena.</p>
      </div>
    `;
  }

  const rows = report.review_thread
    .map((entry) => {
      const recommendationBadge = statusBadge(entry.recommendation === 'APPROVE' ? 'PASS' : 'FAIL');
      const links = entry.links.length > 0
        ? entry.links.map((link) => `<a href="${esc(link.url)}" target="_blank" rel="noreferrer">${esc(link.label)} ↗</a>`).join(' · ')
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
    <div class="card">
      <p class="section-title">Decision review thread</p>
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
      <div class="card">
        <p class="section-title">Outcome calibration</p>
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
    <div class="card">
      <p class="section-title">Outcome calibration</p>
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
      <div class="card">
        <p class="section-title">Arena ROI dashboard</p>
        <p class="dim" style="font-size:0.82rem">ROI metrics are unavailable for this arena payload.</p>
      </div>
    `;
  }

  if (roi.status === 'INSUFFICIENT_SAMPLE' || !roi.metrics) {
    return `
      <div class="card">
        <p class="section-title">Arena ROI dashboard</p>
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

  return `
    <div class="card">
      <p class="section-title">Arena ROI dashboard</p>
      <p class="dim" style="font-size:0.8rem; margin-bottom:0.55rem">Real persisted outcome metrics for autonomy + throughput quality.</p>
      <div class="diag-grid" style="grid-template-columns: repeat(4, minmax(130px, 1fr)); gap:0.35rem; margin-bottom:0.5rem">
        ${renderMetricCell('median review min', roi.metrics.median_review_time_minutes.toFixed(2))}
        ${renderMetricCell('first-pass accept', `${(roi.metrics.first_pass_accept_rate * 100).toFixed(1)}%`)}
        ${renderMetricCell('override rate', `${(roi.metrics.override_rate * 100).toFixed(1)}%`)}
        ${renderMetricCell('rework rate', `${(roi.metrics.rework_rate * 100).toFixed(1)}%`)}
        ${renderMetricCell('cost/accepted', `$${roi.metrics.cost_per_accepted_bounty_usd.toFixed(4)}`)}
        ${renderMetricCell('cycle time min', roi.metrics.cycle_time_minutes.toFixed(2))}
        ${renderMetricCell('winner stability', `${(roi.metrics.winner_stability * 100).toFixed(1)}%`)}
        ${renderMetricCell('samples', String(roi.totals.sample_count))}
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
      <div class="card">
        <p class="section-title">Routing autopilot</p>
        <p class="dim" style="font-size:0.82rem">Autopilot preview is unavailable for this arena payload.</p>
      </div>
    `;
  }

  const status = autopilot.status === 'auto_route_enabled' ? 'PASS' : 'FAIL';
  const violations = autopilot.violations.length > 0
    ? autopilot.violations.join(', ')
    : 'none';

  return `
    <div class="card">
      <p class="section-title">Routing autopilot</p>
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
      <div class="card">
        <p class="section-title">Routing policy optimizer</p>
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
    <div class="card">
      <p class="section-title">Routing policy optimizer</p>
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
      <div class="card">
        <p class="section-title">Contract Copilot</p>
        <p class="dim" style="font-size:0.82rem">No copilot suggestions available for this arena payload.</p>
      </div>
    `;
  }

  if (copilot.status === 'empty') {
    return `
      <div class="card">
        <p class="section-title">Contract Copilot</p>
        <p class="dim" style="font-size:0.82rem">No persisted copilot suggestions for this task fingerprint yet.</p>
      </div>
    `;
  }

  if (copilot.status === 'INSUFFICIENT_SAMPLE') {
    return `
      <div class="card">
        <p class="section-title">Contract Copilot</p>
        <p class="dim" style="font-size:0.82rem">INSUFFICIENT_SAMPLE — waiting for more real failed outcomes before generating rewrite proposals.</p>
      </div>
    `;
  }

  if (copilot.status !== 'available') {
    return `
      <div class="card">
        <p class="section-title">Contract Copilot</p>
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
    <div class="card">
      <p class="section-title">Contract Copilot</p>
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
      <div class="card">
        <p class="section-title">Contract language optimizer</p>
        <p class="dim" style="font-size:0.82rem">No contract-language optimizer preview available.</p>
      </div>
    `;
  }

  if (optimizer.status === 'empty') {
    return `
      <div class="card">
        <p class="section-title">Contract language optimizer</p>
        <p class="dim" style="font-size:0.82rem">No failed/overridden outcomes yet for optimizer suggestions.</p>
      </div>
    `;
  }

  if (optimizer.status !== 'available') {
    return `
      <div class="card">
        <p class="section-title">Contract language optimizer</p>
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
    <div class="card">
      <p class="section-title">Contract language optimizer</p>
      <p class="dim" style="font-size:0.8rem; margin-bottom:0.55rem">Persisted rewrite suggestions distilled from failed/overridden outcomes.</p>

      <p class="dim" style="font-size:0.78rem; margin-bottom:0.35rem"><strong>Task fingerprint:</strong> <span class="mono">${esc(optimizer.task_fingerprint ?? 'unknown')}</span></p>

      <p style="font-size:0.82rem; font-weight:600; margin:0.45rem 0 0.25rem">Global contract rewrites</p>
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

      <p style="font-size:0.82rem; font-weight:600; margin:0.45rem 0 0.25rem">Contender prompt rewrites</p>
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
      <div class="card">
        <p class="section-title">Outcome feedback feed</p>
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
          <td class="mono">${esc(outcome.override_reason_code ?? '—')}</td>
          <td class="mono">${esc(taxonomy)}</td>
          <td>${esc(outcome.reviewer_rationale ?? '—')}</td>
          <td class="mono">${relativeTime(outcome.created_at)}</td>
        </tr>
      `;
    })
    .join('');

  return `
    <div class="card">
      <p class="section-title">Outcome feedback feed</p>
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

export function arenaMissionPage(summary: ArenaMissionSummaryView): string {
  const gateBadge = statusBadge(summary.kpi.gate_status === 'PASS' ? 'PASS' : 'FAIL');
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
    <h1 class="page-title">Arena Mission Control</h1>
    <p class="page-subtitle">Operational cockpit for claim → submit throughput, proof quality, and live backlog pressure.</p>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="value">${gateBadge}</div>
        <div class="label">KPI Gate</div>
      </div>
      <div class="stat-card">
        <div class="value">${fmtNum(summary.fleet.online)}</div>
        <div class="label">Fleet Online</div>
      </div>
      <div class="stat-card">
        <div class="value">${pct(submissionCoverageRate)}</div>
        <div class="label">Submission Coverage</div>
      </div>
      <div class="stat-card">
        <div class="value">${pct(summary.kpi.proof_valid_rate)}</div>
        <div class="label">Proof Validity</div>
      </div>
    </div>

    <div class="card">
      <p class="section-title">Mission scope + gate rationale</p>
      <div class="detail-grid">
        <dt>Worker DID</dt><dd class="mono">${esc(summary.worker_did)}</dd>
        <dt>Window</dt><dd>${fmtNum(summary.window_hours)}h (since ${relativeTime(summary.window_started_at)})</dd>
        <dt>Computed</dt><dd>${relativeTime(summary.computed_at)}</dd>
      </div>
      <p class="dim" style="font-size:0.8rem; margin-top:0.55rem"><strong>Reason codes:</strong> ${esc(gateReasonCodes)}</p>
    </div>

    <div class="card">
      <p class="section-title">KPI posture</p>
      <div class="diag-grid" style="grid-template-columns: repeat(4, minmax(140px, 1fr)); gap:0.4rem">
        ${renderMetricCell('claim success', pct(summary.kpi.claim_success_rate))}
        ${renderMetricCell('submission success', pct(summary.kpi.submission_success_rate))}
        ${renderMetricCell('proof valid rate', pct(summary.kpi.proof_valid_rate))}
        ${renderMetricCell('claim→submit gap', String(summary.backlog.claim_submission_gap))}
      </div>
      <p class="dim" style="font-size:0.78rem; margin-top:0.45rem">Submission coverage is measured from actionable submissions (pending/approved/rejected) over claimed sample.</p>
    </div>

    <div class="card">
      <p class="section-title">Pipeline throughput</p>
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

    <div class="card">
      <p class="section-title">Claim gap queue</p>
      ${gapBountyIds.length === 0
        ? '<p class="dim" style="font-size:0.82rem">No claim→submission gaps currently tracked in the mission window.</p>'
        : `
          <p class="dim" style="font-size:0.8rem; margin-bottom:0.45rem">Top bounty IDs currently counted in claim→submission gap:</p>
          <ul style="margin-left:1.1rem; display:grid; gap:0.25rem">
            ${gapBountyIds.map((bountyId) => `<li class="mono">${esc(bountyId)}</li>`).join('')}
          </ul>
        `
      }
    </div>

    <div class="card">
      <p class="section-title">Gate thresholds</p>
      <div class="detail-grid">
        <dt>Min online workers</dt><dd>${fmtNum(summary.thresholds.min_online_workers)}</dd>
        <dt>Min claim success</dt><dd>${pct(summary.thresholds.min_claim_success_rate)}</dd>
        <dt>Min submission success</dt><dd>${pct(summary.thresholds.min_submission_success_rate)}</dd>
        <dt>Min proof valid</dt><dd>${pct(summary.thresholds.min_proof_valid_rate)}</dd>
        <dt>Max claim→submit gap</dt><dd>${fmtNum(summary.thresholds.max_claim_submission_gap)}</dd>
        <dt>Max accepted backlog</dt><dd>${fmtNum(summary.thresholds.max_accepted_backlog)}</dd>
      </div>
    </div>
  `);
}

function renderVisualEvidence(report: ArenaReportView, artifactsBaseUrl: string | null): string {
  if (!artifactsBaseUrl || !report.contract?.bounty_id) return '';
  const bountyId = report.contract.bounty_id;
  
  const steps = ['browse', 'details', 'claim', 'submit'] as const;
  const stepFiles = ['01-browse.png', '02-details.png', '03-claim.png', '04-submit.png'];

  const rows = report.contenders.map(c => {
    return `
      <div style="margin-bottom: 2rem;">
        <h3 class="mono" style="margin-bottom:0.5rem; color:var(--text-main); font-size:1rem;">${esc(c.contender_id)}</h3>
        <div class="filmstrip">
          ${steps.map((step, idx) => {
            const url = `${artifactsBaseUrl}/arena/${bountyId}/${c.contender_id}/journey/screenshots/${stepFiles[idx]}`;
            return `
              <div class="filmstrip-col">
                <div class="dim mono" style="font-size:0.75rem; margin-bottom:0.4rem; text-transform:uppercase;">${step}</div>
                <img class="filmstrip-img" src="${esc(url)}" alt="${esc(step)}" loading="lazy" onclick="window.open(this.src, '_blank')" onerror="this.parentElement.style.display='none'" />
              </div>
            `;
          }).join('')}
        </div>
      </div>
    `;
  }).join('');
  
  return `
    <div class="card">
      <p class="section-title">Screenshot Journey</p>
      <p class="dim" style="font-size:0.8rem; margin-bottom:1rem;">Click any thumbnail to view full size screenshot.</p>
      ${rows}
    </div>
  `;
}


function renderArenaStyles() {
  return `<style>
    @import url('https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@400;600;700;800&family=Outfit:wght@400;500;600;700&family=JetBrains+Mono:wght@400;700&display=swap');

    :root {
      --bg-dark: #07070a;
      --bg-surface: #101016;  
      --bg-panel: #16161e;
      --accent-teal: #00d4aa;
      --accent-teal-glow: rgba(0, 212, 170, 0.3);
      --accent-red: #ff2a5f;
      --accent-red-glow: rgba(255, 42, 95, 0.3);
      --text-main: #f0f0f5;
      --text-dim: #8b8b99;
      --border: #22222d;
      --font-display: 'Chakra Petch', sans-serif;
      --font-body: 'Outfit', sans-serif;  
      --font-mono: 'JetBrains Mono', monospace;
      
      --bg: var(--bg-dark);
      --bg-card: var(--bg-panel);
      --text: var(--text-main);
      --font-sans: var(--font-body);
      --pass: var(--accent-teal);
      --fail: var(--accent-red);
    }
    
    body {
      background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noiseFilter'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.65' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noiseFilter)' opacity='0.02'/%3E%3C/svg%3E");
    }

    .page-title, .section-title, h1, h2, h3 {
      font-family: var(--font-display);
      text-transform: uppercase;
    }

    .page-title {
      font-size: 2.5rem;
      font-weight: 800;
      color: var(--text-main);
      text-shadow: 0 0 20px rgba(255,255,255,0.1);
      margin-bottom: 0.5rem;
    }
    
    .card {
      background: var(--bg-panel);
      border: 1px solid var(--border);
      box-shadow: inset 0 0 0 1px rgba(255,255,255,0.02), 0 4px 20px rgba(0,0,0,0.5);
      border-radius: 4px;
      clip-path: polygon(0 0, calc(100% - 15px) 0, 100% 15px, 100% 100%, 15px 100%, 0 calc(100% - 15px));
      padding: 1.5rem;
      position: relative;
    }

    .section-title {
      border-left: 3px solid var(--accent-teal);
      padding-left: 0.5rem;
      font-size: 1.1rem;
      letter-spacing: 0.05em;
      color: var(--text-main);
      margin-bottom: 1rem;
    }
    
    .vs-hero {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 2rem;
      margin: 3rem 0;
      padding: 2rem;
      background: var(--bg-surface);
      border: 1px solid var(--border);
      position: relative;
      overflow: hidden;
    }
    
    .vs-contender {
      flex: 1;
      text-align: center;
      z-index: 2;
      position: relative;
      padding: 2rem;
      background: rgba(0,0,0,0.4);
      border: 1px solid var(--border);
      border-radius: 4px;
    }
    
    .vs-contender.winner {
      border-color: var(--accent-teal);
      box-shadow: 0 0 30px var(--accent-teal-glow), inset 0 0 20px var(--accent-teal-glow);
    }
    
    .vs-contender.winner::before {
      content: 'WINNER';
      position: absolute;
      top: -12px;
      left: 50%;
      transform: translateX(-50%);
      background: var(--accent-teal);
      color: #000;
      font-family: var(--font-display);
      font-weight: 800;
      padding: 2px 10px;
      font-size: 0.8rem;
      letter-spacing: 0.1em;
      box-shadow: 0 0 10px var(--accent-teal);
      animation: pulse-crown 2s infinite;
    }
    
    @keyframes pulse-crown {
      0% { box-shadow: 0 0 5px var(--accent-teal); }
      50% { box-shadow: 0 0 20px var(--accent-teal), 0 0 40px var(--accent-teal); }
      100% { box-shadow: 0 0 5px var(--accent-teal); }
    }

    .vs-contender.loser {
      opacity: 0.8;
    }
    
    .vs-name {
      font-family: var(--font-display);
      font-size: 2rem;
      font-weight: 800;
      margin-bottom: 0.5rem;
      text-transform: uppercase;
      word-break: break-all;
    }
    
    .vs-harness {
      font-family: var(--font-mono);
      color: var(--text-dim);
      font-size: 0.85rem;
      margin-bottom: 1.5rem;
    }
    
    .vs-score-wrapper {
      margin-top: 1rem;
    }
    
    .vs-score-val {
      font-family: var(--font-display);
      font-size: 3rem;
      font-weight: 700;
      line-height: 1;
      margin-bottom: 0.5rem;
    }
    .winner .vs-score-val {
      color: var(--accent-teal);
      text-shadow: 0 0 15px var(--accent-teal-glow);
    }
    
    .score-bar {
      height: 8px;
      background: var(--border);
      border-radius: 4px;
      overflow: hidden;
      width: 100%;
      position: relative;
    }
    
    .score-fill {
      height: 100%;
      background: var(--text-dim);
      width: 0;
      animation: fill-bar 1.5s cubic-bezier(0.1, 0.8, 0.2, 1) forwards;
    }
    .winner .score-fill { background: var(--accent-teal); box-shadow: 0 0 10px var(--accent-teal-glow); }
    
    @keyframes fill-bar {
      to { width: var(--target-width); }
    }
    
    .vs-divider {
      font-family: var(--font-display);
      font-size: 4rem;
      font-weight: 800;
      color: var(--border);
      text-shadow: 0 0 20px rgba(0,0,0,0.8);
      z-index: 2;
      font-style: italic;
    }
    
    .viewer-tabs {
      display: flex;
      gap: 1rem;
      margin-bottom: 1rem;
    }
    .viewer-tab {
      background: var(--bg-surface);
      border: 1px solid var(--border);
      color: var(--text-dim);
      padding: 0.5rem 1rem;
      font-family: var(--font-display);
      font-size: 0.9rem;
      text-transform: uppercase;
      cursor: pointer;
      clip-path: polygon(10px 0, 100% 0, 100% calc(100% - 10px), calc(100% - 10px) 100%, 0 100%, 0 10px);
      transition: 0.2s;
    }
    .viewer-tab.active {
      background: rgba(0, 212, 170, 0.1);
      border-color: var(--accent-teal);
      color: var(--accent-teal);
      box-shadow: inset 0 0 15px var(--accent-teal-glow);
    }
    
    .iframe-split {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1rem;
      height: 600px;
    }
    .iframe-split.full {
      grid-template-columns: 1fr;
    }
    .iframe-pane {
      display: flex;
      flex-direction: column;
      border: 1px solid var(--border);
      background: #000;
      border-radius: 4px;
      overflow: hidden;
    }
    .iframe-header {
      background: var(--bg-surface);
      border-bottom: 1px solid var(--border);
      padding: 0.5rem;
      font-family: var(--font-mono);
      font-size: 0.75rem;
      color: var(--text-dim);
      display: flex;
      justify-content: space-between;
    }
    .iframe-pane iframe {
      flex: 1;
      width: 100%;
      border: none;
      background: #fff;
    }

    .filmstrip {
      display: flex;
      gap: 1rem;
      overflow-x: auto;
      padding-bottom: 1rem;
    }
    .filmstrip-col {
      min-width: 250px;
      border: 1px solid var(--border);
      background: var(--bg-surface);
      padding: 0.5rem;
      border-radius: 4px;
    }
    .filmstrip-img {
      width: 100%;
      cursor: pointer;
      border: 1px solid transparent;
      transition: 0.2s border-color;
    }
    .filmstrip-img:hover {
      border-color: var(--accent-teal);
    }
    
    .gauges-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 1rem;
    }
    .gauge-card {
      background: var(--bg-surface);
      border: 1px solid var(--border);
      padding: 1rem;
      text-align: center;
      border-radius: 4px;
    }
    .gauge-circle {
      width: 80px;
      height: 80px;
      border-radius: 50%;
      background: conic-gradient(var(--accent-teal) var(--deg), var(--border) 0deg);
      margin: 0 auto 0.5rem;
      display: flex;
      align-items: center;
      justify-content: center;
      position: relative;
    }
    .gauge-circle::after {
      content: '';
      position: absolute;
      inset: 6px;
      background: var(--bg-surface);
      border-radius: 50%;
    }
    .gauge-val {
      position: relative;
      z-index: 2;
      font-family: var(--font-display);
      font-weight: 700;
      font-size: 1.2rem;
    }
    .gauge-label {
      font-size: 0.75rem;
      color: var(--text-dim);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    
    .matrix-grid {
      display: grid;
      gap: 2px;
      background: var(--border);
      border: 1px solid var(--border);
      border-radius: 4px;
      overflow: hidden;
    }
    .matrix-cell {
      background: var(--bg-surface);
      padding: 0.5rem;
      font-size: 0.8rem;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .matrix-cell.header {
      font-family: var(--font-display);
      color: var(--text-dim);
      text-transform: uppercase;
      justify-content: flex-start;
    }
    .matrix-cell.col-header {
      justify-content: center;
      font-size: 0.7rem;
      text-align: center;
    }
    .cell-pass {
      background: rgba(0, 212, 170, 0.1);
      color: var(--accent-teal);
      box-shadow: inset 0 0 10px var(--accent-teal-glow);
    }
    .cell-fail {
      background: rgba(255, 42, 95, 0.1);
      color: var(--accent-red);
      box-shadow: inset 0 0 10px var(--accent-red-glow);
    }
    .cell-na {
      color: var(--text-dim);
    }
    
    table { background: var(--bg-surface); border: 1px solid var(--border); }
    th { background: rgba(0,0,0,0.3); font-family: var(--font-display); color: var(--text-main); border-bottom: 1px solid var(--border); }
    td { border-bottom: 1px solid var(--border); }
  </style>`;
}



function renderVSHero(report: ArenaReportView): string {
  const c = report.contenders;
  if (c.length < 2) return '';
  const winnerId = report.winner.contender_id;
  
  const top2 = [...c].sort((a,b) => b.score - a.score).slice(0,2);
  
  const htmls = top2.map((contender) => {
    const isWinner = contender.contender_id === winnerId;
    const cls = isWinner ? 'winner' : 'loser';
    const percent = Math.min(100, Math.max(0, contender.score));
    
    return `
      <div class="vs-contender ${cls}">
        <div class="vs-name">${esc(contender.contender_id.replace('contender_', ''))}</div>
        <div class="vs-harness">${esc(contender.harness)} &middot; ${esc(contender.model)}</div>
        <div class="vs-score-wrapper">
          <div class="vs-score-val">${contender.score.toFixed(1)}</div>
          <div class="score-bar">
             <div class="score-fill" style="--target-width: ${percent}%"></div>
          </div>
        </div>
      </div>
    `;
  });

  return `
    <div class="vs-hero">
      ${htmls[0]}
      <div class="vs-divider">VS</div>
      ${htmls[1]}
    </div>
  `;
}



function renderLiveOutputViewer(report: ArenaReportView, artifactsBaseUrl: string | null): string {
  if (!artifactsBaseUrl || !report.contract?.bounty_id) return '';
  const bountyId = report.contract.bounty_id;
  const c = report.contenders;
  
  if (c.length < 2) return '';
  
  const c1 = c[0];
  const c2 = c[1];
  
  const c1Url = `${artifactsBaseUrl}/arena/${bountyId}/${c1.contender_id}/output/index.html`;
  const c2Url = `${artifactsBaseUrl}/arena/${bountyId}/${c2.contender_id}/output/index.html`;

  return `
    <div class="card" id="live-viewer">
      <p class="section-title">Live Output Viewer</p>
      
      <div class="viewer-controls" style="margin-bottom:1rem; display:flex; justify-content:space-between;">
        <div class="viewer-tabs" id="viewer-tabs">
          ${c.map((contender, idx) => `
            <button class="viewer-tab ${idx < 2 ? 'active' : ''}" data-id="${esc(contender.contender_id)}" data-url="${esc(`${artifactsBaseUrl}/arena/${bountyId}/${contender.contender_id}/output/index.html`)}">
              ${esc(contender.contender_id.replace('contender_', ''))}
            </button>
          `).join('')}
        </div>
        <button class="viewer-tab" id="toggle-split" style="border-color:var(--text-dim); color:var(--text-main)">Toggle Full Width</button>
      </div>
      
      <div class="iframe-split" id="iframe-split">
        <div class="iframe-pane" id="pane-1">
          <div class="iframe-header"><span class="pane-title">${esc(c1.contender_id)}</span><a href="${esc(c1Url)}" target="_blank" class="pass">↗ Open</a></div>
          <iframe id="iframe-1" src="${esc(c1Url)}" sandbox="allow-scripts allow-same-origin"></iframe>
        </div>
        <div class="iframe-pane" id="pane-2">
          <div class="iframe-header"><span class="pane-title">${esc(c2.contender_id)}</span><a href="${esc(c2Url)}" target="_blank" class="pass">↗ Open</a></div>
          <iframe id="iframe-2" src="${esc(c2Url)}" sandbox="allow-scripts allow-same-origin"></iframe>
        </div>
      </div>
      
      <script>
        (function() {
           var split = document.getElementById('iframe-split');
           var toggle = document.getElementById('toggle-split');
           if(!split || !toggle) return;
           
           toggle.addEventListener('click', function() {
             split.classList.toggle('full');
             var isFull = split.classList.contains('full');
             document.getElementById('pane-2').style.display = isFull ? 'none' : 'flex';
           });
           
           var tabs = document.querySelectorAll('.viewer-tab[data-id]');
           for (var i = 0; i < tabs.length; i++) {
             tabs[i].addEventListener('click', function() {
                if (this.classList.contains('active')) return;
                
                var activeTabs = document.querySelectorAll('.viewer-tab.active[data-id]');
                var isFull = split.classList.contains('full');
                
                var url = this.getAttribute('data-url');
                var id = this.getAttribute('data-id');
                
                if (isFull) {
                  for (var j = 0; j < activeTabs.length; j++) {
                     activeTabs[j].classList.remove('active');
                  }
                  this.classList.add('active');
                  
                  document.getElementById('iframe-1').src = url;
                  document.querySelector('#pane-1 .pane-title').textContent = id;
                  document.querySelector('#pane-1 a').href = url;
                } else {
                  var t1 = activeTabs[0];
                  var t2 = activeTabs.length > 1 ? activeTabs[1] : null;
                  
                  if(t1) t1.classList.remove('active');
                  if(t2) {
                     t2.classList.add('active');
                     document.getElementById('iframe-1').src = t2.getAttribute('data-url');
                     document.querySelector('#pane-1 .pane-title').textContent = t2.getAttribute('data-id');
                     document.querySelector('#pane-1 a').href = t2.getAttribute('data-url');
                  }
                  
                  this.classList.add('active');
                  document.getElementById('iframe-2').src = url;
                  document.querySelector('#pane-2 .pane-title').textContent = id;
                  document.querySelector('#pane-2 a').href = url;
                }
             });
           }
        })();
      </script>
    </div>
  `;
}



function renderScoreBreakdown(report: ArenaReportView): string {
  const winner = report.contenders.find(c => c.contender_id === report.winner.contender_id) || report.contenders[0];
  const m = winner.metrics;
  
  return `
    <div class="card">
      <p class="section-title">Score Breakdown (${esc(winner.contender_id)})</p>
      <div class="gauges-grid">
         <div class="gauge-card">
           <div class="gauge-circle" style="--deg: ${m.quality_score * 3.6}deg">
             <div class="gauge-val">${m.quality_score}</div>
           </div>
           <div class="gauge-label">Quality</div>
         </div>
         <div class="gauge-card">
           <div class="gauge-circle" style="--deg: ${(100 - m.risk_score) * 3.6}deg">
             <div class="gauge-val">${m.risk_score}</div>
           </div>
           <div class="gauge-label">Risk</div>
         </div>
         <div class="gauge-card">
           <div class="gauge-circle" style="--deg: ${m.efficiency_score * 3.6}deg">
             <div class="gauge-val">${m.efficiency_score}</div>
           </div>
           <div class="gauge-label">Efficiency</div>
         </div>
         <div class="gauge-card">
           <div class="gauge-circle" style="--deg: ${m.autonomy_score * 3.6}deg">
             <div class="gauge-val">${m.autonomy_score}</div>
           </div>
           <div class="gauge-label">Autonomy</div>
         </div>
      </div>
    </div>
  `;
}


export function arenaComparePage(report: ArenaReportView, artifactsBaseUrl: string | null = null): string {
  const meta: PageMeta = {
    title: `Arena ${report.arena_id}`,
    description: `Bounty Arena comparison for ${report.contract.bounty_id}`,
    path: `/arena/${report.arena_id}`,
  };

  return layout(meta, `
    ${renderArenaStyles()}
    
    ${renderVSHero(report)}
    
    

    ${renderLiveOutputViewer(report, artifactsBaseUrl)}
    
    ${renderScoreBreakdown(report)}
    <h1 class="page-title">Arena Compare: ${esc(report.arena_id)}</h1>
    <p class="page-subtitle">Transparent contender comparison across model/harness/tool stack, contract checks, and objective scoring.</p>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="value">${fmtNum(report.contenders.length)}</div>
        <div class="label">Contenders</div>
      </div>
      <div class="stat-card">
        <div class="value mono">${esc(report.winner.contender_id)}</div>
        <div class="label">Winner</div>
      </div>
      <div class="stat-card">
        <div class="value">${esc(report.objective_profile.name)}</div>
        <div class="label">Objective Profile</div>
      </div>
      <div class="stat-card">
        <div class="value">${relativeTime(report.generated_at)}</div>
        <div class="label">Generated</div>
      </div>
    </div>

    <div class="card">
      <p class="section-title">Winner rationale + tradeoffs</p>
      <p style="margin-bottom:0.65rem">${esc(report.winner.reason)}</p>
      <ul style="margin-left:1.1rem; display:grid; gap:0.25rem; font-size:0.86rem">
        ${report.tradeoffs.map((line) => `<li>${esc(line)}</li>`).join('') || '<li>No tradeoff notes supplied.</li>'}
      </ul>
      <p class="dim" style="font-size:0.8rem; margin-top:0.65rem">Reason codes: ${esc(report.reason_codes.join(', ') || 'none')}</p>
    </div>

    ${report.delegation_insights ? `
      <div class="card">
        <p class="section-title">Delegation insights</p>
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

    <div class="card">
      <p class="section-title">Contract binding</p>
      <div class="detail-grid">
        <dt>Bounty</dt><dd class="mono">${esc(report.contract.bounty_id)}</dd>
        <dt>Contract</dt><dd class="mono">${esc(report.contract.contract_id)}</dd>
        <dt>Contract hash</dt><dd class="mono">${esc(report.contract.contract_hash_b64u)}</dd>
        <dt>Task fingerprint</dt><dd class="mono">${esc(report.contract.task_fingerprint)}</dd>
      </div>
    </div>

    <div class="card" id="proof-card">
      <p class="section-title">Contenders table</p>
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

    <div class="card">
      <p class="section-title">Contract check matrix</p>
      ${contractCheckMatrix(report)}
    </div>

    ${renderVisualEvidence(report, artifactsBaseUrl)}

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
        <tr>
          <td><a href="/arena/${encodeURIComponent(row.arena_id)}" class="mono">${esc(row.arena_id)}</a></td>
          <td class="mono">${esc(row.bounty_id)}</td>
          <td class="mono">${esc(row.contract_id)}</td>
          <td class="mono">${esc(row.winner_contender_id)}</td>
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
    <h1 class="page-title">Bounty Arena Index</h1>
    <p class="page-subtitle">Compare contender stacks and copy decision artifacts for human and manager review loops. <a href="/arena/mission">Open mission control &rarr;</a></p>

    <div class="card">
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
    <div class="card" style="text-align:center">
      <p class="section-title">Arena not found</p>
      <p class="mono" style="margin-bottom:0.5rem">${esc(arenaId)}</p>
      <p class="dim" style="font-size:0.85rem; margin-bottom:0.8rem">Publish an arena report first, then open this route again.</p>
      <p><a href="/arena">Open Arena Index &rarr;</a></p>
    </div>
  `);
}

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
