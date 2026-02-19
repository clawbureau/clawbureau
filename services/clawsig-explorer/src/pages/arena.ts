import { esc, fmtNum, layout, relativeTime, statusBadge, type PageMeta } from '../layout.js';
import type { ArenaReportView } from '../api.js';

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
    <div style="overflow-x:auto">
      <table>
        <thead>
          <tr>
            <th>Contract Criterion</th>
            ${headerCells}
          </tr>
        </thead>
        <tbody>
          ${rows}
        </tbody>
      </table>
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

      const reasonCodes = contender.score_explain.reason_codes.length > 0
        ? contender.score_explain.reason_codes.join(', ')
        : 'none';

      const evidenceLinks = contender.score_explain.evidence_links.length > 0
        ? contender.score_explain.evidence_links
          .slice(0, 2)
          .map((entry) => `<a href="${esc(entry.url)}" target="_blank" rel="noreferrer">${esc(entry.label)} ↗</a>`)
          .join(' · ')
        : 'no evidence link';

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
            <div class="mono" style="font-size:0.75rem; display:grid; gap:0.12rem">
              <span>${esc(contender.tools.join(', ') || 'none')}</span>
              <span>${esc(contender.skills.join(', ') || 'none')}</span>
            </div>
          </td>
          <td>
            <div class="mono">${contender.score.toFixed(4)}</div>
            <div class="dim" style="font-size:0.74rem">${evidenceLinks}</div>
            <div class="dim" style="font-size:0.7rem">${esc(reasonCodes)}</div>
          </td>
          <td>
            <div class="diag-grid" style="grid-template-columns: repeat(2, minmax(110px, 1fr)); gap:0.3rem">
              ${renderMetricCell('quality', contender.metrics.quality_score.toFixed(2))}
              ${renderMetricCell('risk', contender.metrics.risk_score.toFixed(2))}
              ${renderMetricCell('efficiency', contender.metrics.efficiency_score.toFixed(2))}
              ${renderMetricCell('cost', `$${contender.metrics.cost_usd.toFixed(4)}`)}
            </div>
          </td>
          <td>
            <div style="display:grid; gap:0.35rem">
              <button class="copy-btn" data-copy="${esc(reviewPaste)}" onclick="navigator.clipboard.writeText(this.getAttribute('data-copy') || ''); this.textContent='Copied';">Copy Review Paste</button>
              <button class="copy-btn" data-copy="${esc(managerJson)}" onclick="navigator.clipboard.writeText(this.getAttribute('data-copy') || ''); this.textContent='Copied';">Copy Manager JSON</button>
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

export function arenaComparePage(report: ArenaReportView): string {
  const meta: PageMeta = {
    title: `Arena ${report.arena_id}`,
    description: `Bounty Arena comparison for ${report.contract.bounty_id}`,
    path: `/arena/${report.arena_id}`,
  };

  return layout(meta, `
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
              <th>Tools/Skills</th>
              <th>Score</th>
              <th>Quality/Risk/Efficiency</th>
              <th>Review Artifacts</th>
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
    <p class="page-subtitle">Compare contender stacks and copy decision artifacts for human and manager review loops.</p>

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
        manager_review_json: '{\n  "decision": "conditional",\n  "confidence": 0.612,\n  "reason_codes": ["ARENA_OPTIONAL_CRITERION_MISS"]\n}',
      },
      {
        contender_id: 'contender_gemini_swarm',
        label: 'Gemini Deep Think + swarm orchestrator',
        model: 'gemini-2.5-pro',
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
          { label: 'Manager review JSON', url: '/arena/arena_bty_arena_001#proof-card' },
        ],
        source: 'sample',
        created_at: '2026-02-19T15:12:00.000Z',
      },
    ],
  };
}
