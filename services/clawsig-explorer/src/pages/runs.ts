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
  current_cursor?: string | null;
  cursor_history?: string[];
  fetch_error?: string | null;
}

interface RunsPaginationState {
  previousHref: string | null;
  nextHref: string | null;
  resetHref: string;
  pageLabel: string;
}

function selected(value: string | undefined, expected: string): string {
  return value === expected ? ' selected' : '';
}

function asArray(input: string[] | undefined): string[] {
  if (!input || input.length === 0) return [];
  return input.filter((item) => item.trim().length > 0);
}

function buildRunsQuery(
  filters: RunsFeedFilters,
  extra: {
    limit?: number;
    cursor?: string | null;
    history?: string[];
  } = {}
): string {
  const params = new URLSearchParams();

  if (filters.status) params.set('status', filters.status);
  if (filters.tier) params.set('tier', filters.tier);
  if (filters.reason_code) params.set('reason_code', filters.reason_code);
  if (filters.agent_did) params.set('agent_did', filters.agent_did);
  if (extra.limit && Number.isFinite(extra.limit)) params.set('limit', String(extra.limit));
  if (extra.cursor) params.set('cursor', extra.cursor);

  const history = asArray(extra.history);
  if (history.length > 0) {
    params.set('history', history.join(','));
  }

  const query = params.toString();
  return query.length > 0 ? `?${query}` : '';
}

function diagnosticsChip(label: string, value: string | null, href?: string): string {
  if (!value) {
    return `<span class="diag-chip diag-chip-muted"><span class="diag-chip-label">${esc(label)}</span><span class="diag-chip-value">n/a</span></span>`;
  }

  const valueHtml = href
    ? `<a href="${href}" class="diag-chip-value" style="color:var(--text)">${esc(value)}</a>`
    : `<span class="diag-chip-value">${esc(value)}</span>`;

  return `<span class="diag-chip"><span class="diag-chip-label">${esc(label)}</span>${valueHtml}</span>`;
}

function activeFilterChips(filters: RunsFeedFilters, limit: number): string {
  const chips: string[] = [];

  const pushChip = (
    key: keyof RunsFeedFilters,
    label: string,
    value: string | undefined,
  ) => {
    if (!value) return;
    const next: RunsFeedFilters = { ...filters };
    delete next[key];

    chips.push(
      `<a class="filter-chip" href="/runs${buildRunsQuery(next, { limit })}"><span>${esc(label)}: ${esc(value)}</span><span aria-hidden="true">&times;</span></a>`
    );
  };

  pushChip('status', 'Status', filters.status);
  pushChip('tier', 'Tier', filters.tier);
  pushChip('reason_code', 'Reason', filters.reason_code);
  pushChip('agent_did', 'Agent', filters.agent_did);

  if (chips.length === 0) {
    return `<span class="dim" style="font-size:0.8125rem">No active filters.</span>`;
  }

  return chips.join('');
}

function summarize(rows: RunsFeedRun[]): { total: number; pass: number; fail: number } {
  let pass = 0;
  let fail = 0;

  for (const row of rows) {
    if (row.status === 'PASS') pass += 1;
    if (row.status === 'FAIL') fail += 1;
  }

  return {
    total: rows.length,
    pass,
    fail,
  };
}

function runsRows(rows: RunsFeedRun[]): string {
  return rows
    .map((run) => {
      const shortDid = run.agent_did.length > 28
        ? `${run.agent_did.slice(0, 16)}...${run.agent_did.slice(-8)}`
        : run.agent_did;

      const rowClass = run.status === 'FAIL' ? 'run-item run-item-fail' : 'run-item';
      const reasonFilterHref = run.reason_code
        ? `/runs${buildRunsQuery({ status: 'FAIL', reason_code: run.reason_code })}`
        : undefined;

      return `
      <div class="${rowClass}" style="align-items: flex-start; gap: 0.75rem; flex-wrap: wrap">
        <div style="min-width: 130px">
          <a href="/run/${encodeURIComponent(run.run_id)}" class="run-id">${esc(run.run_id.slice(0, 16))}...</a>
          <div class="dim" style="font-size:0.75rem; margin-top:0.2rem">${relativeTime(run.created_at)}</div>
        </div>

        <div class="run-meta" style="min-width: 220px; flex: 2">
          <div>
            <a href="/agent/${encodeURIComponent(run.agent_did)}" class="dim" style="font-size: 0.8125rem">${esc(shortDid)}</a>
          </div>
          <div style="display:flex; gap:0.5rem; flex-wrap:wrap; margin-top:0.4rem">
            ${statusBadge(run.status)}
            ${tierBadge(run.proof_tier)}
          </div>
        </div>

        <div class="diag-grid" style="margin-left:auto; min-width: min(420px, 100%);">
          ${diagnosticsChip('reason', run.reason_code, reasonFilterHref)}
          ${diagnosticsChip('class', run.failure_class)}
          ${diagnosticsChip('source', run.verification_source)}
          ${diagnosticsChip('auth', run.auth_mode)}
        </div>
      </div>
      `;
    })
    .join('');
}

function paginationState(data: RunsFeedPageData): RunsPaginationState {
  const currentCursor = data.current_cursor ?? null;
  const history = asArray(data.cursor_history);

  const previousCursor = currentCursor ? (history[history.length - 1] ?? null) : null;
  const previousHistory = currentCursor ? history.slice(0, Math.max(0, history.length - 1)) : [];

  const previousHref = currentCursor !== null
    ? `/runs${buildRunsQuery(data.filters, {
      limit: data.limit,
      cursor: previousCursor,
      history: previousHistory,
    })}`
    : null;

  const nextHistory = data.next_cursor
    ? [
      ...history,
      ...(currentCursor ? [currentCursor] : []),
    ]
    : history;

  const nextHref = data.has_next && data.next_cursor
    ? `/runs${buildRunsQuery(data.filters, {
      limit: data.limit,
      cursor: data.next_cursor,
      history: nextHistory,
    })}`
    : null;

  const pageLabel = `Page ${history.length + 1}`;
  const resetHref = `/runs${buildRunsQuery(data.filters, {
    limit: data.limit,
  })}`;

  return {
    previousHref,
    nextHref,
    resetHref,
    pageLabel,
  };
}

export function runsFeedPage(data: RunsFeedPageData): string {
  const meta: PageMeta = {
    title: 'Runs Feed',
    description: 'Filterable feed of recent verification runs with diagnostics.',
    path: '/runs',
  };

  const summary = summarize(data.runs);
  const pagination = paginationState(data);

  const body = `
    <h1 class="page-title">Runs Feed (Triage Mode)</h1>
    <p class="page-subtitle">Filter, page, and isolate repeated failures without leaving the explorer.</p>

    ${data.fetch_error
      ? `<div class="card" style="border-color:rgba(255, 68, 68, 0.45)">
          <p class="section-title">Runs Feed Error</p>
          <p class="fail">${esc(data.fetch_error)}</p>
          <p class="dim" style="font-size:0.8125rem; margin-top:0.5rem">
            Data fetch is fail-closed. Existing filters are preserved so you can retry safely.
          </p>
        </div>`
      : ''}

    <div class="card sticky-filter-card">
      <div style="display:flex; justify-content:space-between; align-items:center; gap:0.75rem; flex-wrap:wrap">
        <p class="section-title" style="margin-bottom:0">Filters</p>
        <div style="display:flex; gap:0.6rem; flex-wrap:wrap; font-size:0.78rem">
          <a href="${pagination.resetHref}" class="dim">Reset pagination</a>
          <a href="/runs" class="dim">Clear all</a>
        </div>
      </div>
      <form method="GET" action="/runs" style="display:grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap:0.75rem; align-items:end; margin-top:0.75rem">
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

        <div style="display:flex; gap:0.5rem; align-items:center; flex-wrap:wrap">
          <button type="submit" style="background:var(--pass); color:#000; border:0; border-radius:6px; padding:0.5rem 0.75rem; font-weight:600; cursor:pointer">Apply</button>
          <a href="${pagination.resetHref}" class="dim" style="font-size:0.8125rem">Reset filters</a>
        </div>
      </form>

      <div style="display:flex; flex-wrap:wrap; gap:0.5rem; margin-top:0.9rem">
        ${activeFilterChips(data.filters, data.limit)}
      </div>

      <div style="display:flex; flex-wrap:wrap; gap:0.45rem; margin-top:0.75rem">
        <a class="filter-chip" href="/runs${buildRunsQuery({ ...data.filters, status: 'FAIL' }, { limit: data.limit })}">status: FAIL</a>
        <a class="filter-chip" href="/runs${buildRunsQuery({ ...data.filters, status: 'PASS' }, { limit: data.limit })}">status: PASS</a>
        <a class="filter-chip" href="/runs${buildRunsQuery({ ...data.filters, tier: 'gateway' }, { limit: data.limit })}">tier: gateway</a>
      </div>
    </div>

    <div class="stats-grid" style="margin-bottom:1rem">
      <div class="stat-card">
        <div class="value">${fmtNum(summary.total)}</div>
        <div class="label">Rows in Current Page</div>
      </div>
      <div class="stat-card">
        <div class="value" style="color: var(--pass)">${fmtNum(summary.pass)}</div>
        <div class="label">PASS Rows</div>
      </div>
      <div class="stat-card">
        <div class="value" style="color: var(--fail)">${fmtNum(summary.fail)}</div>
        <div class="label">FAIL Rows</div>
      </div>
      <div class="stat-card">
        <div class="value">${esc(pagination.pageLabel)}</div>
        <div class="label">Cursor Page</div>
      </div>
    </div>

    <div class="card">
      <p class="section-title">Runs</p>
      ${data.runs.length > 0
        ? runsRows(data.runs)
        : `<div class="runs-empty">
            <p class="dim" style="margin-bottom:0.4rem">No runs match these filters.</p>
            <p class="dim" style="font-size:0.8125rem">Try removing one filter or increasing the page limit.</p>
          </div>`}
    </div>

    <div style="display:flex; justify-content:space-between; align-items:center; gap:0.75rem; margin-top:1rem; flex-wrap:wrap">
      <a href="/" class="dim" style="font-size:0.8125rem">Back to Home</a>
      <div style="display:flex; align-items:center; gap:0.75rem; margin-left:auto; flex-wrap:wrap">
        ${pagination.previousHref
          ? `<a href="${pagination.previousHref}" style="font-size:0.875rem">&larr; Newer</a>`
          : `<span class="dim" style="font-size:0.8125rem">Start of feed</span>`}
        <span class="dim" style="font-size:0.8125rem">${esc(pagination.pageLabel)}</span>
        ${pagination.nextHref
          ? `<a href="${pagination.nextHref}" style="font-size:0.875rem">Older &rarr;</a>`
          : `<span class="dim" style="font-size:0.8125rem">End of feed</span>`}
        ${pagination.previousHref
          ? `<a href="${pagination.resetHref}" class="dim" style="font-size:0.8125rem">Jump to newest</a>`
          : ''}
      </div>
    </div>
  `;

  return layout(meta, body);
}
