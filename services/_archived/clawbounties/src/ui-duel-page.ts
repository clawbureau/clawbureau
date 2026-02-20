function esc(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function bountyUiDuelPage(params: {
  origin: string;
  environment: string;
  version: string;
  defaultWorkerDid: string;
}): string {
  const origin = esc(params.origin);
  const environment = esc(params.environment);
  const version = esc(params.version);
  const defaultWorkerDid = esc(params.defaultWorkerDid);

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>clawbounties duel workbench</title>
    <style>
      /* ===== Reset & tokens ===== */
      :root {
        color-scheme: dark;
        --c-bg:        #080c14;
        --c-surface-0: #0d1424;
        --c-surface-1: #121d33;
        --c-surface-2: #182842;
        --c-border:    #1e2f50;
        --c-border-hi: #2d4570;
        --c-text:      #e4ecf7;
        --c-text-2:    #9ab0cc;
        --c-text-3:    #6a8099;
        --c-accent:    #38bdf8;
        --c-accent-2:  #818cf8;
        --c-teal:      #2dd4bf;
        --c-green:     #34d399;
        --c-amber:     #fbbf24;
        --c-red:       #f87171;
        --c-white-a5:  rgba(255,255,255,0.05);
        --c-white-a10: rgba(255,255,255,0.10);
        --r-sm: 6px;
        --r-md: 10px;
        --r-lg: 14px;
        --r-xl: 20px;
        --shadow-card: 0 1px 3px rgba(0,0,0,0.4), 0 0 0 1px var(--c-border);
        --shadow-float: 0 8px 32px rgba(0,0,0,0.5);
        --font-sans: 'Inter', ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
        --font-mono: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        --transition-fast: 120ms ease;
        --transition-med:  200ms ease;
      }

      *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

      body {
        font-family: var(--font-sans);
        font-size: 14px;
        line-height: 1.55;
        color: var(--c-text);
        background: var(--c-bg);
        -webkit-font-smoothing: antialiased;
        -moz-osx-font-smoothing: grayscale;
      }

      /* ===== Layout shell ===== */
      .shell {
        max-width: 1240px;
        margin: 0 auto;
        padding: 24px 20px 48px;
      }

      /* ===== Top bar ===== */
      .topbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        padding-bottom: 20px;
        border-bottom: 1px solid var(--c-border);
        margin-bottom: 24px;
      }
      .topbar-brand {
        display: flex;
        align-items: center;
        gap: 10px;
      }
      .topbar-logo {
        width: 28px; height: 28px;
        border-radius: var(--r-sm);
        background: linear-gradient(135deg, var(--c-accent), var(--c-accent-2));
        display: grid; place-items: center;
        font-weight: 700; font-size: 13px; color: #000;
      }
      .topbar h1 {
        font-size: 16px;
        font-weight: 700;
        letter-spacing: -0.02em;
      }
      .topbar-meta {
        display: flex;
        align-items: center;
        gap: 16px;
        font-size: 12px;
        color: var(--c-text-3);
      }
      .topbar-meta a { color: var(--c-accent); text-decoration: none; }
      .topbar-meta a:hover { text-decoration: underline; }
      .env-badge {
        display: inline-flex; align-items: center; gap: 5px;
        padding: 2px 8px;
        border-radius: 999px;
        border: 1px solid var(--c-border);
        font-size: 11px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        color: var(--c-text-2);
      }
      .env-badge::before {
        content: '';
        width: 6px; height: 6px;
        border-radius: 50%;
        background: var(--c-green);
      }

      /* ===== Grid layout ===== */
      .main-grid {
        display: grid;
        grid-template-columns: 320px minmax(0,1fr);
        grid-template-rows: auto auto 1fr;
        gap: 16px;
      }
      .sidebar { grid-row: 1 / 4; }

      @media (max-width: 900px) {
        .main-grid {
          grid-template-columns: 1fr;
          grid-template-rows: auto;
        }
        .sidebar { grid-row: auto; }
      }

      /* ===== Card ===== */
      .card {
        background: var(--c-surface-0);
        border: 1px solid var(--c-border);
        border-radius: var(--r-lg);
        overflow: hidden;
      }
      .card-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 12px 16px;
        border-bottom: 1px solid var(--c-border);
        background: var(--c-white-a5);
      }
      .card-header h2 {
        font-size: 12px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        color: var(--c-text-2);
      }
      .card-body { padding: 16px; }

      .card-count {
        font-size: 11px;
        font-variant-numeric: tabular-nums;
        color: var(--c-text-3);
        background: var(--c-surface-2);
        padding: 1px 7px;
        border-radius: 999px;
      }

      /* ===== Form fields ===== */
      .field { margin-bottom: 14px; }
      .field:last-child { margin-bottom: 0; }
      .field-label {
        display: block;
        margin-bottom: 5px;
        font-size: 11px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        color: var(--c-text-3);
      }
      .field-input {
        width: 100%;
        padding: 8px 10px;
        border: 1px solid var(--c-border);
        border-radius: var(--r-md);
        background: var(--c-surface-1);
        color: var(--c-text);
        font-family: var(--font-mono);
        font-size: 12.5px;
        transition: border-color var(--transition-fast);
        outline: none;
      }
      .field-input:focus {
        border-color: var(--c-accent);
        box-shadow: 0 0 0 2px rgba(56,189,248,0.15);
      }
      .field-input::placeholder { color: var(--c-text-3); }

      /* ===== Buttons ===== */
      .btn-row {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 8px;
        margin-top: 14px;
      }
      .btn {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 6px;
        padding: 8px 12px;
        border: 1px solid var(--c-border);
        border-radius: var(--r-md);
        background: var(--c-surface-2);
        color: var(--c-text);
        font-family: var(--font-sans);
        font-size: 12.5px;
        font-weight: 600;
        cursor: pointer;
        transition: all var(--transition-fast);
        outline: none;
        line-height: 1.3;
      }
      .btn:hover { background: var(--c-border-hi); border-color: var(--c-border-hi); }
      .btn:focus-visible { box-shadow: 0 0 0 2px rgba(56,189,248,0.25); }
      .btn:active { transform: scale(0.98); }

      .btn-primary {
        background: linear-gradient(135deg, rgba(56,189,248,0.20), rgba(129,140,248,0.15));
        border-color: rgba(56,189,248,0.35);
        color: var(--c-accent);
      }
      .btn-primary:hover {
        background: linear-gradient(135deg, rgba(56,189,248,0.30), rgba(129,140,248,0.22));
        border-color: rgba(56,189,248,0.5);
      }

      .btn-icon {
        display: inline-flex;
        font-size: 14px;
        line-height: 1;
        opacity: 0.7;
      }

      /* ===== Status log ===== */
      .status-log {
        margin-top: 14px;
        min-height: 56px;
        max-height: 120px;
        overflow-y: auto;
        padding: 10px 12px;
        border: 1px solid var(--c-border);
        border-radius: var(--r-md);
        background: var(--c-bg);
        font-family: var(--font-mono);
        font-size: 11.5px;
        line-height: 1.6;
        white-space: pre-wrap;
        word-break: break-word;
        color: var(--c-text-2);
      }

      /* ===== Bounty list ===== */
      .bounty-list {
        display: flex;
        flex-direction: column;
        gap: 6px;
        max-height: 520px;
        overflow-y: auto;
        padding: 2px;
      }
      .bounty-list::-webkit-scrollbar { width: 5px; }
      .bounty-list::-webkit-scrollbar-track { background: transparent; }
      .bounty-list::-webkit-scrollbar-thumb { background: var(--c-border); border-radius: 999px; }

      .bounty-row {
        display: flex;
        align-items: center;
        gap: 12px;
        width: 100%;
        text-align: left;
        padding: 10px 14px;
        border: 1px solid var(--c-border);
        border-radius: var(--r-md);
        background: var(--c-surface-1);
        color: var(--c-text);
        font-family: var(--font-sans);
        font-size: 13px;
        cursor: pointer;
        transition: all var(--transition-fast);
        outline: none;
      }
      .bounty-row:hover {
        background: var(--c-surface-2);
        border-color: var(--c-border-hi);
      }
      .bounty-row:focus-visible {
        box-shadow: 0 0 0 2px rgba(56,189,248,0.25);
      }
      .bounty-row.is-selected {
        border-color: var(--c-accent);
        background: rgba(56,189,248,0.06);
        box-shadow: inset 0 0 0 1px rgba(56,189,248,0.12);
      }

      .bounty-row-indicator {
        flex-shrink: 0;
        width: 3px;
        height: 28px;
        border-radius: 999px;
        background: var(--c-border);
        transition: background var(--transition-fast);
      }
      .bounty-row.is-selected .bounty-row-indicator { background: var(--c-accent); }

      .bounty-row-body { flex: 1; min-width: 0; }
      .bounty-row-title {
        font-weight: 600;
        font-size: 13px;
        line-height: 1.35;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      .bounty-row-meta {
        display: flex;
        align-items: center;
        gap: 8px;
        margin-top: 3px;
        font-size: 11.5px;
        color: var(--c-text-3);
      }
      .bounty-row-reward {
        font-family: var(--font-mono);
        font-variant-numeric: tabular-nums;
      }

      /* ===== Pills ===== */
      .pill {
        display: inline-flex;
        align-items: center;
        padding: 1px 7px;
        border-radius: 999px;
        border: 1px solid var(--c-border);
        font-size: 10.5px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.03em;
      }
      .pill-open {
        border-color: rgba(52,211,153,0.4);
        color: var(--c-green);
        background: rgba(52,211,153,0.06);
      }
      .pill-other {
        border-color: rgba(251,191,36,0.4);
        color: var(--c-amber);
        background: rgba(251,191,36,0.06);
      }

      /* ===== Detail view ===== */
      .detail-empty {
        padding: 32px 16px;
        text-align: center;
        color: var(--c-text-3);
        font-size: 13px;
      }
      .detail-grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
        gap: 10px;
      }
      .detail-cell {
        padding: 10px 12px;
        border: 1px solid var(--c-border);
        border-radius: var(--r-md);
        background: var(--c-surface-1);
      }
      .detail-cell-label {
        font-size: 10.5px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        color: var(--c-text-3);
        margin-bottom: 4px;
      }
      .detail-cell-value {
        font-family: var(--font-mono);
        font-size: 12.5px;
        word-break: break-all;
        color: var(--c-text);
        line-height: 1.45;
      }

      /* ===== Empty state ===== */
      .empty-state {
        padding: 28px 16px;
        text-align: center;
        color: var(--c-text-3);
        font-size: 13px;
      }

      /* ===== Utility ===== */
      .visually-hidden {
        position: absolute;
        width: 1px; height: 1px;
        padding: 0; margin: -1px;
        overflow: hidden;
        clip: rect(0,0,0,0);
        white-space: nowrap;
        border: 0;
      }
    </style>
  </head>
  <body>
    <main class="shell" role="main">

      <!-- ===== Top bar ===== -->
      <header class="topbar">
        <div class="topbar-brand">
          <div class="topbar-logo" aria-hidden="true">C</div>
          <h1>Clawbounties Duel Workbench</h1>
        </div>
        <nav class="topbar-meta" aria-label="Service metadata">
          <span class="env-badge">${environment}</span>
          <span>v${version}</span>
          <a href="${origin}/docs">Docs</a>
        </nav>
      </header>

      <!-- ===== Main grid ===== -->
      <div class="main-grid">

        <!-- Sidebar: Control Plane -->
        <aside class="sidebar card" aria-label="Control plane">
          <div class="card-header">
            <h2>Control Plane</h2>
          </div>
          <div class="card-body">
            <div class="field">
              <label class="field-label" for="adminKey">Admin Key</label>
              <input id="adminKey" class="field-input" type="password" autocomplete="off" placeholder="BOUNTIES_ADMIN_KEY" />
            </div>
            <div class="field">
              <label class="field-label" for="workerDid">Worker DID</label>
              <input id="workerDid" class="field-input" type="text" value="${defaultWorkerDid}" autocomplete="off" />
            </div>

            <div class="btn-row">
              <button id="loadBounties" class="btn btn-primary" type="button">
                <span class="btn-icon" aria-hidden="true">&#8635;</span> Load
              </button>
              <button id="seedBounties" class="btn" type="button">
                <span class="btn-icon" aria-hidden="true">&#43;</span> Seed
              </button>
              <button id="claimBounty" class="btn btn-primary" type="button">
                <span class="btn-icon" aria-hidden="true">&#10003;</span> Claim
              </button>
              <button id="submitBounty" class="btn btn-primary" type="button">
                <span class="btn-icon" aria-hidden="true">&#9654;</span> Submit
              </button>
            </div>

            <div id="actionStatus" class="status-log" aria-live="polite" role="log">Ready.</div>
          </div>
        </aside>

        <!-- Bounty list -->
        <section class="card">
          <div class="card-header">
            <h2>Open Bounties</h2>
            <span id="bountyCount" class="card-count">0</span>
          </div>
          <div class="card-body" style="padding:10px">
            <div id="bountyList" class="bounty-list" role="listbox" aria-label="Open bounties"></div>
            <p id="bountyListEmpty" class="empty-state" hidden>No open bounties found. Use <strong>Seed</strong> to populate.</p>
          </div>
        </section>

        <!-- Selected bounty details -->
        <section class="card" style="grid-column:2">
          <div class="card-header">
            <h2>Bounty Details</h2>
          </div>
          <div class="card-body">
            <div id="bountyDetails" class="detail-empty">Select a bounty to view details.</div>
          </div>
        </section>
      </div>
    </main>

    <script>
      (() => {
        'use strict';

        const state = {
          selectedBountyId: null,
          bounties: [],
        };

        const els = {
          adminKey: document.getElementById('adminKey'),
          workerDid: document.getElementById('workerDid'),
          loadBounties: document.getElementById('loadBounties'),
          seedBounties: document.getElementById('seedBounties'),
          claimBounty: document.getElementById('claimBounty'),
          submitBounty: document.getElementById('submitBounty'),
          bountyList: document.getElementById('bountyList'),
          bountyListEmpty: document.getElementById('bountyListEmpty'),
          bountyDetails: document.getElementById('bountyDetails'),
          actionStatus: document.getElementById('actionStatus'),
          bountyCount: document.getElementById('bountyCount'),
        };

        /* ---- helpers ---- */

        function stableStringify(value) {
          if (value === null || typeof value !== 'object') return JSON.stringify(value);
          if (Array.isArray(value)) return '[' + value.map(stableStringify).join(',') + ']';
          var keys = Object.keys(value).sort();
          return '{' + keys.map(function (key) { return JSON.stringify(key) + ':' + stableStringify(value[key]); }).join(',') + '}';
        }

        function status(message, payload) {
          var line = typeof payload === 'undefined'
            ? String(message)
            : String(message) + '\\n' + JSON.stringify(payload, null, 2);
          if (els.actionStatus) els.actionStatus.textContent = line;
        }

        function adminKey() {
          return (els.adminKey && typeof els.adminKey.value === 'string') ? els.adminKey.value.trim() : '';
        }

        /* ---- API wrapper (fail-closed) ---- */

        async function api(path, init) {
          if (!init) init = {};
          var key = adminKey();
          if (!key) {
            throw new Error('Admin key is required.');
          }

          var headers = new Headers(init.headers || {});
          headers.set('x-admin-key', key);
          if (!headers.has('content-type') && init.body) {
            headers.set('content-type', 'application/json');
          }

          var response = await fetch(path, Object.assign({}, init, { headers: headers }));
          var text = await response.text();
          var json;
          try {
            json = JSON.parse(text);
          } catch (_e) {
            json = { raw: text };
          }

          if (!response.ok) {
            throw new Error('HTTP ' + response.status + ': ' + JSON.stringify(json));
          }

          return json;
        }

        /* ---- rendering ---- */

        function escText(str) {
          var d = document.createElement('div');
          d.textContent = str;
          return d.innerHTML;
        }

        function renderBountyList() {
          if (!els.bountyList || !els.bountyListEmpty) return;
          els.bountyList.innerHTML = '';

          if (!Array.isArray(state.bounties) || state.bounties.length === 0) {
            els.bountyListEmpty.hidden = false;
            if (els.bountyCount) els.bountyCount.textContent = '0';
            return;
          }

          els.bountyListEmpty.hidden = true;
          if (els.bountyCount) els.bountyCount.textContent = String(state.bounties.length);

          state.bounties.forEach(function (bounty) {
            var row = document.createElement('button');
            row.type = 'button';
            row.className = 'bounty-row' + (state.selectedBountyId === bounty.bounty_id ? ' is-selected' : '');
            row.setAttribute('data-testid', 'bounty-row');
            row.dataset.bountyId = bounty.bounty_id;
            row.setAttribute('role', 'option');
            row.setAttribute('aria-selected', state.selectedBountyId === bounty.bounty_id ? 'true' : 'false');

            var title = escText(String(bounty.title || bounty.bounty_id));
            var rewardAmount = (bounty.reward && bounty.reward.amount_minor) ? escText(String(bounty.reward.amount_minor)) : '-';
            var rewardCurrency = (bounty.reward && bounty.reward.currency) ? ' ' + escText(String(bounty.reward.currency)) : '';
            var statusVal = bounty.status || 'unknown';
            var pillClass = statusVal === 'open' ? 'pill-open' : 'pill-other';

            row.innerHTML = [
              '<div class="bounty-row-indicator" aria-hidden="true"></div>',
              '<div class="bounty-row-body">',
                '<div class="bounty-row-title">' + title + '</div>',
                '<div class="bounty-row-meta">',
                  '<span class="bounty-row-reward">' + rewardAmount + rewardCurrency + '</span>',
                  '<span class="pill ' + pillClass + '">' + escText(String(statusVal)) + '</span>',
                '</div>',
              '</div>',
            ].join('');

            row.addEventListener('click', function () {
              state.selectedBountyId = bounty.bounty_id;
              renderBountyList();
              loadDetails();
            });

            els.bountyList.appendChild(row);
          });
        }

        function renderDetails(detail) {
          if (!els.bountyDetails) return;

          if (!detail) {
            els.bountyDetails.innerHTML = '<div class="detail-empty">Select a bounty to view details.</div>';
            return;
          }

          var tags = Array.isArray(detail.tags) ? detail.tags.join(', ') : '';
          var data = [
            ['bounty_id', detail.bounty_id],
            ['status', detail.status],
            ['requester_did', detail.requester_did],
            ['worker_did', detail.worker_did || '(unassigned)'],
            ['reward', (detail.reward && detail.reward.amount_minor ? detail.reward.amount_minor + ' ' + detail.reward.currency : '-')],
            ['closure_type', detail.closure_type],
            ['min_proof_tier', detail.min_proof_tier],
            ['tags', tags || '(none)'],
          ];

          els.bountyDetails.innerHTML = '<div class="detail-grid">' + data.map(function (pair) {
            return '<article class="detail-cell">' +
              '<div class="detail-cell-label">' + escText(String(pair[0])) + '</div>' +
              '<div class="detail-cell-value">' + escText(String(pair[1] || '-')) + '</div>' +
              '</article>';
          }).join('') + '</div>';
        }

        /* ---- data operations (wired to live API, no mocks) ---- */

        async function loadOpenBounties() {
          status('Loading open bounties...');
          var payload = await api('/v1/bounties?status=open&is_code_bounty=false&limit=50');
          state.bounties = Array.isArray(payload.bounties) ? payload.bounties : [];

          if (state.selectedBountyId && !state.bounties.some(function (e) { return e.bounty_id === state.selectedBountyId; })) {
            state.selectedBountyId = null;
          }
          if (!state.selectedBountyId && state.bounties.length > 0) {
            state.selectedBountyId = state.bounties[0].bounty_id;
          }

          renderBountyList();
          await loadDetails();
          status('Loaded open bounties.', { count: state.bounties.length, selected_bounty_id: state.selectedBountyId });
        }

        async function loadDetails() {
          if (!state.selectedBountyId) {
            renderDetails(null);
            return;
          }

          var detail = await api('/v1/bounties/' + encodeURIComponent(state.selectedBountyId));
          renderDetails(detail);
        }

        async function seedIfEmpty() {
          status('Seeding open bounties if below target...');
          var payload = await api('/v1/arena/desk/discover-loop', {
            method: 'POST',
            body: stableStringify({
              target_open_bounties: 4,
              seed_limit: 4,
              seed_reward_minor: '25',
              dry_run: false,
            }),
          });

          status('Discovery loop completed.', payload.totals || payload);
          await loadOpenBounties();
        }

        function selectedBountyIds() {
          if (!state.selectedBountyId) {
            throw new Error('Select a bounty first.');
          }
          return [state.selectedBountyId];
        }

        async function claimSelected() {
          var workerDid = (els.workerDid && typeof els.workerDid.value === 'string') ? els.workerDid.value.trim() : '';
          if (!workerDid.startsWith('did:')) {
            throw new Error('worker DID must start with did:');
          }

          var payload = await api('/v1/arena/desk/claim-loop', {
            method: 'POST',
            body: stableStringify({
              limit: 12,
              target_claims: 1,
              budget_minor: '1000000',
              bounty_ids: selectedBountyIds(),
              requested_worker_did: workerDid,
              max_fleet_cost_tier: 'high',
              max_fleet_risk_tier: 'high',
              allow_route_fallback: true,
              include_code_bounties: false,
              dry_run: false,
            }),
          });

          status('Claim loop completed.', payload.totals || payload);
          await loadDetails();
          await loadOpenBounties();
        }

        async function submitSelected() {
          var workerDid = (els.workerDid && typeof els.workerDid.value === 'string') ? els.workerDid.value.trim() : '';
          if (!workerDid.startsWith('did:')) {
            throw new Error('worker DID must start with did:');
          }

          var payload = await api('/v1/arena/desk/submit-loop', {
            method: 'POST',
            body: stableStringify({
              worker_did: workerDid,
              target_submissions: 1,
              limit: 10,
              bounty_ids: selectedBountyIds(),
              dry_run: false,
            }),
          });

          status('Submit loop completed.', payload.totals || payload);
          await loadDetails();
        }

        async function withStatus(label, fn) {
          try {
            status(label + '...');
            await fn();
          } catch (err) {
            status(label + ' failed.', {
              error: err instanceof Error ? err.message : String(err),
            });
          }
        }

        /* ---- event bindings ---- */

        if (els.loadBounties) els.loadBounties.addEventListener('click', function () { withStatus('Refresh open list', loadOpenBounties); });
        if (els.seedBounties) els.seedBounties.addEventListener('click', function () { withStatus('Seed open bounties', seedIfEmpty); });
        if (els.claimBounty) els.claimBounty.addEventListener('click', function () { withStatus('Claim selected bounty', claimSelected); });
        if (els.submitBounty) els.submitBounty.addEventListener('click', function () { withStatus('Submit selected bounty', submitSelected); });
      })();
    </script>
  </body>
</html>`;
}
