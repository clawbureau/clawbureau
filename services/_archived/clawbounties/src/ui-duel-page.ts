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
    <title>clawbounties duel UI</title>
    <style>
      :root {
        color-scheme: dark;
        --bg: #0b1220;
        --panel: #111b2f;
        --panel-soft: #15233b;
        --text: #e6edf6;
        --muted: #9eb1c8;
        --accent: #4ecdc4;
        --accent-2: #7aa2ff;
        --danger: #ff7b72;
        --ok: #3fb950;
        --border: #263a5d;
      }

      * { box-sizing: border-box; }

      body {
        margin: 0;
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
        background: radial-gradient(1200px 600px at 10% 0%, #152545, transparent 70%), var(--bg);
        color: var(--text);
      }

      .shell {
        max-width: 1200px;
        margin: 0 auto;
        padding: 20px;
      }

      .hero {
        border: 1px solid var(--border);
        border-radius: 16px;
        padding: 18px;
        background: linear-gradient(160deg, rgba(122, 162, 255, 0.18), rgba(78, 205, 196, 0.08));
        margin-bottom: 16px;
      }

      .hero h1 {
        margin: 0;
        font-size: 1.5rem;
      }

      .hero p {
        margin: 8px 0 0;
        color: var(--muted);
      }

      .grid {
        display: grid;
        grid-template-columns: 360px minmax(0, 1fr);
        gap: 14px;
      }

      .panel {
        border: 1px solid var(--border);
        border-radius: 14px;
        background: rgba(17, 27, 47, 0.86);
        backdrop-filter: blur(8px);
        padding: 14px;
      }

      .panel h2 {
        margin: 0 0 10px;
        font-size: 1rem;
      }

      .field {
        margin-bottom: 10px;
      }

      .field label {
        display: block;
        margin-bottom: 6px;
        font-size: 0.8rem;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        color: var(--muted);
      }

      .field input {
        width: 100%;
        padding: 9px 10px;
        border-radius: 10px;
        border: 1px solid var(--border);
        background: var(--panel-soft);
        color: var(--text);
      }

      .actions {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 8px;
        margin-bottom: 10px;
      }

      button {
        cursor: pointer;
        border: 1px solid transparent;
        border-radius: 10px;
        padding: 9px 10px;
        background: #203454;
        color: var(--text);
        font-weight: 600;
      }

      button:hover {
        border-color: var(--accent-2);
      }

      button.primary {
        background: linear-gradient(135deg, #2a4a77, #2f6f8a);
      }

      button.secondary {
        background: #22314a;
      }

      .status {
        min-height: 48px;
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 10px;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 0.75rem;
        white-space: pre-wrap;
        background: #0e182b;
      }

      .bounty-list {
        display: grid;
        gap: 8px;
        max-height: 400px;
        overflow: auto;
      }

      .bounty-row {
        width: 100%;
        text-align: left;
        border: 1px solid var(--border);
        background: #13213a;
        border-radius: 10px;
        padding: 10px;
      }

      .bounty-row:hover {
        border-color: var(--accent);
      }

      .bounty-row.is-selected {
        border-color: var(--accent);
        box-shadow: inset 0 0 0 1px rgba(78, 205, 196, 0.45);
      }

      .bounty-meta {
        display: flex;
        justify-content: space-between;
        margin-top: 4px;
        color: var(--muted);
        font-size: 0.78rem;
      }

      .pill {
        display: inline-flex;
        align-items: center;
        padding: 2px 8px;
        border-radius: 999px;
        border: 1px solid var(--border);
        font-size: 0.72rem;
      }

      .pill.ok { border-color: rgba(63, 185, 80, 0.5); color: #8be28f; }
      .pill.warn { border-color: rgba(255, 123, 114, 0.5); color: #ffb4ab; }

      .detail-grid {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 8px;
      }

      .detail-item {
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 10px;
        background: #101d33;
      }

      .detail-item .label {
        color: var(--muted);
        font-size: 0.72rem;
        text-transform: uppercase;
        letter-spacing: 0.06em;
      }

      .detail-item .value {
        margin-top: 4px;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 0.85rem;
        word-break: break-word;
      }

      .muted { color: var(--muted); }

      @media (max-width: 980px) {
        .grid { grid-template-columns: 1fr; }
      }
    </style>
  </head>
  <body>
    <main class="shell">
      <section class="hero">
        <h1>Clawbounties Duel UI</h1>
        <p>Real-data operator surface for the UI duel contract. Browse open bounties, inspect details, execute claim path, and trigger submit path with evidence-first telemetry.</p>
        <p class="muted">Environment: ${environment} · Version: ${version} · <a href="${origin}/docs" style="color:#9ac7ff">docs</a></p>
      </section>

      <section class="grid">
        <aside class="panel">
          <h2>Control Plane</h2>
          <div class="field">
            <label for="adminKey">Admin key</label>
            <input id="adminKey" type="password" autocomplete="off" placeholder="BOUNTIES_ADMIN_KEY" />
          </div>
          <div class="field">
            <label for="workerDid">Worker DID</label>
            <input id="workerDid" type="text" value="${defaultWorkerDid}" autocomplete="off" />
          </div>
          <div class="actions">
            <button id="loadBounties" class="primary" type="button">Refresh open list</button>
            <button id="seedBounties" class="secondary" type="button">Seed if empty</button>
            <button id="claimBounty" class="primary" type="button">Claim selected</button>
            <button id="submitBounty" class="primary" type="button">Submit selected</button>
          </div>
          <div id="actionStatus" class="status" aria-live="polite">Ready.</div>
        </aside>

        <section class="panel">
          <h2>Open bounties</h2>
          <div id="bountyList" class="bounty-list"></div>
          <p id="bountyListEmpty" class="muted" hidden>No open bounties found.</p>
        </section>
      </section>

      <section class="panel" style="margin-top:14px;">
        <h2>Selected bounty details</h2>
        <div id="bountyDetails" class="muted">Select a bounty row to inspect details.</div>
      </section>
    </main>

    <script>
      (() => {
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
        };

        function stableStringify(value) {
          if (value === null || typeof value !== 'object') return JSON.stringify(value);
          if (Array.isArray(value)) return '[' + value.map(stableStringify).join(',') + ']';
          const keys = Object.keys(value).sort();
          return '{' + keys.map((key) => JSON.stringify(key) + ':' + stableStringify(value[key])).join(',') + '}';
        }

        function status(message, payload) {
          const line = typeof payload === 'undefined'
            ? String(message)
            : String(message) + '\\n' + JSON.stringify(payload, null, 2);
          if (els.actionStatus) els.actionStatus.textContent = line;
        }

        function adminKey() {
          return (els.adminKey && typeof els.adminKey.value === 'string') ? els.adminKey.value.trim() : '';
        }

        async function api(path, init = {}) {
          const key = adminKey();
          if (!key) {
            throw new Error('Admin key is required.');
          }

          const headers = new Headers(init.headers || {});
          headers.set('x-admin-key', key);
          if (!headers.has('content-type') && init.body) {
            headers.set('content-type', 'application/json');
          }

          const response = await fetch(path, { ...init, headers });
          const text = await response.text();
          let json;
          try {
            json = JSON.parse(text);
          } catch {
            json = { raw: text };
          }

          if (!response.ok) {
            throw new Error('HTTP ' + response.status + ': ' + JSON.stringify(json));
          }

          return json;
        }

        function renderBountyList() {
          if (!els.bountyList || !els.bountyListEmpty) return;
          els.bountyList.innerHTML = '';

          if (!Array.isArray(state.bounties) || state.bounties.length === 0) {
            els.bountyListEmpty.hidden = false;
            return;
          }

          els.bountyListEmpty.hidden = true;

          state.bounties.forEach((bounty) => {
            const row = document.createElement('button');
            row.type = 'button';
            row.className = 'bounty-row' + (state.selectedBountyId === bounty.bounty_id ? ' is-selected' : '');
            row.dataset.testid = 'bounty-row';
            row.setAttribute('data-testid', 'bounty-row');
            row.dataset.bountyId = bounty.bounty_id;

            row.innerHTML = [
              '<div><strong>' + String(bounty.title || bounty.bounty_id) + '</strong></div>',
              '<div class="bounty-meta">',
              '<span>' + String((bounty.reward && bounty.reward.amount_minor) || '-') + ' ' + String((bounty.reward && bounty.reward.currency) || '') + '</span>',
              '<span class="pill ' + ((bounty.status === 'open') ? 'ok' : 'warn') + '">' + String(bounty.status || 'unknown') + '</span>',
              '</div>',
            ].join('');

            row.addEventListener('click', () => {
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
            els.bountyDetails.textContent = 'Select a bounty row to inspect details.';
            return;
          }

          const tags = Array.isArray(detail.tags) ? detail.tags.join(', ') : '';
          const data = [
            ['bounty_id', detail.bounty_id],
            ['status', detail.status],
            ['requester_did', detail.requester_did],
            ['worker_did', detail.worker_did || '(unassigned)'],
            ['reward', (detail.reward && detail.reward.amount_minor ? detail.reward.amount_minor + ' ' + detail.reward.currency : '-')],
            ['closure_type', detail.closure_type],
            ['min_proof_tier', detail.min_proof_tier],
            ['tags', tags || '(none)'],
          ];

          els.bountyDetails.innerHTML = '<div class="detail-grid">' + data.map(([label, value]) => {
            return '<article class="detail-item"><div class="label">' + String(label) + '</div><div class="value">' + String(value || '-') + '</div></article>';
          }).join('') + '</div>';
        }

        async function loadOpenBounties() {
          status('Loading open bounties...');
          const payload = await api('/v1/bounties?status=open&is_code_bounty=false&limit=50');
          state.bounties = Array.isArray(payload.bounties) ? payload.bounties : [];

          if (state.selectedBountyId && !state.bounties.some((entry) => entry.bounty_id === state.selectedBountyId)) {
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

          const detail = await api('/v1/bounties/' + encodeURIComponent(state.selectedBountyId));
          renderDetails(detail);
        }

        async function seedIfEmpty() {
          status('Seeding open bounties if below target...');
          const payload = await api('/v1/arena/desk/discover-loop', {
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
          const workerDid = (els.workerDid && typeof els.workerDid.value === 'string') ? els.workerDid.value.trim() : '';
          if (!workerDid.startsWith('did:')) {
            throw new Error('worker DID must start with did:');
          }

          const payload = await api('/v1/arena/desk/claim-loop', {
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
          const workerDid = (els.workerDid && typeof els.workerDid.value === 'string') ? els.workerDid.value.trim() : '';
          if (!workerDid.startsWith('did:')) {
            throw new Error('worker DID must start with did:');
          }

          const payload = await api('/v1/arena/desk/submit-loop', {
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

        els.loadBounties && els.loadBounties.addEventListener('click', () => withStatus('Refresh open list', loadOpenBounties));
        els.seedBounties && els.seedBounties.addEventListener('click', () => withStatus('Seed open bounties', seedIfEmpty));
        els.claimBounty && els.claimBounty.addEventListener('click', () => withStatus('Claim selected bounty', claimSelected));
        els.submitBounty && els.submitBounty.addEventListener('click', () => withStatus('Submit selected bounty', submitSelected));
      })();
    </script>
  </body>
</html>`;
}
