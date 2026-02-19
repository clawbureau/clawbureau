import {
  layout,
  esc,
  statusBadge,
  tierBadge,
  relativeTime,
  fmtNum,
  type PageMeta,
} from '../layout.js';
import type { RunsFeedFilters, RunsFeedRun } from '../api.js';

export interface RunsFeedPageData {
  runs: RunsFeedRun[];
  filters: RunsFeedFilters;
  limit: number;
  has_next: boolean;
  next_cursor: string | null;
}

function selected(value: string | undefined, expected: string): string {
  return value === expected ? ' selected' : '';
}

function buildRunsQuery(
  filters: RunsFeedFilters,
  extra: { limit?: number; cursor?: string | null } = {}
): string {
  const params = new URLSearchParams();

  if (filters.status) params.set('status', filters.status);
  if (filters.tier) params.set('tier', filters.tier);
  if (filters.reason_code) params.set('reason_code', filters.reason_code);
  if (filters.agent_did) params.set('agent_did', filters.agent_did);
  if (extra.limit && Number.isFinite(extra.limit)) params.set('limit', String(extra.limit));
  if (extra.cursor) params.set('cursor', extra.cursor);

  const query = params.toString();
  return query.length > 0 ? `?${query}` : '';
}

function diagnosticsChip(value: string | null): string {
  if (!value) {
    return `<span class="dim" style="font-size:0.75rem">n/a</span>`;
  }
  return `<span class="hash">${esc(value)}</span>`;
}

function runsRows(rows: RunsFeedRun[]): string {
  if (rows.length === 0) {
    return `<p class="dim">No runs match these filters.</p>`;
  }

  return rows
    .map((run) => {
      const shortDid = run.agent_did.length > 28
        ? `${run.agent_did.slice(0, 16)}...${run.agent_did.slice(-8)}`
        : run.agent_did;

      return `
      <div class="run-item" style="align-items: flex-start; gap: 0.75rem; flex-wrap: wrap">
        <div style="min-width: 130px">
          <a href="/run/${encodeURIComponent(run.run_id)}" class="run-id">${esc(run.run_id.slice(0, 16))}...</a>
        </div>

        <div class="run-meta" style="min-width: 220px; flex: 2">
          <div>
            <a href="/agent/${encodeURIComponent(run.agent_did)}" class="dim" style="font-size: 0.8125rem">${esc(shortDid)}</a>
          </div>
          <div class="dim" style="font-size: 0.75rem">${relativeTime(run.created_at)}</div>
        </div>

        <div style="display:flex; gap:0.5rem; flex-wrap:wrap; align-items:center">
          ${statusBadge(run.status)}
          ${tierBadge(run.proof_tier)}
        </div>

        <div style="display:flex; gap:0.5rem; flex-wrap:wrap; align-items:center; margin-left:auto">
          ${diagnosticsChip(run.reason_code)}
          ${diagnosticsChip(run.failure_class)}
        </div>
      </div>
      `;
    })
    .join('');
}

export function runsFeedPage(data: RunsFeedPageData): string {
  const meta: PageMeta = {
    title: 'Runs Feed',
    description: 'Filterable feed of recent verification runs with diagnostics.',
    path: '/runs',
  };

  const currentQuery = buildRunsQuery(data.filters, { limit: data.limit });
  const nextQuery = data.has_next
    ? buildRunsQuery(data.filters, { limit: data.limit, cursor: data.next_cursor })
    : '';

  const body = `
    <h1 class="page-title">Runs Feed (Triage Mode)</h1>
    <p class="page-subtitle">Filter and inspect failures without opening raw JSON.</p>

    <div class="card">
      <p class="section-title">Filters</p>
      <form method="GET" action="/runs" style="display:grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap:0.75rem; align-items:end">
        <label style="display:flex; flex-direction:column; gap:0.25rem; font-size:0.75rem; color:var(--text-dim)">
          Status
          <select name="status" style="background:var(--bg-card); color:var(--text); border:1px solid var(--border); border-radius:6px; padding:0.5rem">
            <option value="">Any</option>
            <option value="PASS"${selected(data.filters.status, 'PASS')}>PASS</option>
            <option value="FAIL"${selected(data.filters.status, 'FAIL')}>FAIL</option>
          </select>
        </label>

        <label style="display:flex; flex-direction:column; gap:0.25rem; font-size:0.75rem; color:var(--text-dim)">
          Tier
          <select name="tier" style="background:var(--bg-card); color:var(--text); border:1px solid var(--border); border-radius:6px; padding:0.5rem">
            <option value="">Any</option>
            <option value="self"${selected(data.filters.tier, 'self')}>self</option>
            <option value="gateway"${selected(data.filters.tier, 'gateway')}>gateway</option>
            <option value="sandbox"${selected(data.filters.tier, 'sandbox')}>sandbox</option>
            <option value="tee"${selected(data.filters.tier, 'tee')}>tee</option>
            <option value="witnessed_web"${selected(data.filters.tier, 'witnessed_web')}>witnessed_web</option>
            <option value="unknown"${selected(data.filters.tier, 'unknown')}>unknown</option>
          </select>
        </label>

        <label style="display:flex; flex-direction:column; gap:0.25rem; font-size:0.75rem; color:var(--text-dim)">
          Reason Code
          <input name="reason_code" value="${esc(data.filters.reason_code ?? '')}" placeholder="HASH_MISMATCH" style="background:var(--bg-card); color:var(--text); border:1px solid var(--border); border-radius:6px; padding:0.5rem" />
        </label>

        <label style="display:flex; flex-direction:column; gap:0.25rem; font-size:0.75rem; color:var(--text-dim)">
          Agent DID
          <input name="agent_did" value="${esc(data.filters.agent_did ?? '')}" placeholder="did:key:..." style="background:var(--bg-card); color:var(--text); border:1px solid var(--border); border-radius:6px; padding:0.5rem" />
        </label>

        <label style="display:flex; flex-direction:column; gap:0.25rem; font-size:0.75rem; color:var(--text-dim)">
          Limit
          <input name="limit" value="${esc(String(data.limit))}" type="number" min="1" max="100" style="background:var(--bg-card); color:var(--text); border:1px solid var(--border); border-radius:6px; padding:0.5rem" />
        </label>

        <div style="display:flex; gap:0.5rem; align-items:center">
          <button type="submit" style="background:var(--pass); color:#000; border:0; border-radius:6px; padding:0.5rem 0.75rem; font-weight:600; cursor:pointer">Apply</button>
          <a href="/runs" class="dim" style="font-size:0.8125rem">Reset</a>
        </div>
      </form>
    </div>

    <div class="card">
      <p class="section-title">Runs (${fmtNum(data.runs.length)})</p>
      ${runsRows(data.runs)}
    </div>

    <div style="display:flex; justify-content:space-between; align-items:center; gap:0.75rem; margin-top:1rem">
      <a href="/${currentQuery}" class="dim" style="font-size:0.8125rem">Back to Home</a>
      ${data.has_next && nextQuery
        ? `<a href="/runs${nextQuery}" style="font-size:0.875rem">Next page &rarr;</a>`
        : `<span class="dim" style="font-size:0.8125rem">End of feed</span>`}
    </div>
  `;

  return layout(meta, body);
}
