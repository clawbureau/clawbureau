import { layout, type PageMeta } from '../layout.js';

interface InspectAuthState {
  authenticated: boolean;
  login?: string;
  name?: string | null;
}

interface InspectPageOptions {
  auth: InspectAuthState;
  authStatus?: string | null;
}

function serializeForScript(value: unknown): string {
  return JSON.stringify(value).replace(/</g, '\\u003c');
}

export function inspectPage(options: InspectPageOptions): string {
  const meta: PageMeta = {
    title: 'Inspector',
    description: 'Proof bundle inspector with OAuth-gated EPV decryption.',
    path: '/inspect',
  };

  const authState = serializeForScript(options.auth);
  const authStatus = serializeForScript(options.authStatus ?? null);

  const body = /* html */`
<div class="inspect-root">
  <style>
    .inspect-root {
      display: grid;
      gap: 1rem;
    }

    .inspect-grid {
      display: grid;
      gap: 1rem;
      grid-template-columns: 1fr;
    }

    @media (min-width: 1024px) {
      .inspect-grid {
        grid-template-columns: minmax(0, 1.1fr) minmax(0, 0.9fr);
      }
    }

    .inspect-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem;
    }

    .inspect-card h2 {
      font-size: 0.95rem;
      margin-bottom: 0.75rem;
      color: var(--text);
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }

    .inspect-actions {
      display: grid;
      gap: 0.75rem;
    }

    .inspect-row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      align-items: center;
    }

    .inspect-input,
    .inspect-textarea {
      width: 100%;
      background: #0d0d0d;
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.6rem 0.7rem;
      font-family: var(--font-mono);
      font-size: 0.8rem;
    }

    .inspect-textarea {
      min-height: 140px;
      resize: vertical;
    }

    .inspect-btn {
      appearance: none;
      border: 1px solid var(--border);
      background: #111;
      color: var(--text);
      border-radius: 6px;
      padding: 0.5rem 0.75rem;
      cursor: pointer;
      font-size: 0.8rem;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
    }

    .inspect-btn:hover {
      border-color: #3a3a3a;
      background: #171717;
      text-decoration: none;
    }

    .inspect-btn.primary {
      border-color: rgba(0, 255, 136, 0.45);
      background: rgba(0, 255, 136, 0.08);
      color: var(--pass);
    }

    .inspect-btn.danger {
      border-color: rgba(255, 68, 68, 0.5);
      color: var(--fail);
      background: rgba(255, 68, 68, 0.07);
    }

    .inspect-btn[disabled] {
      opacity: 0.5;
      cursor: not-allowed;
      pointer-events: none;
    }

    .inspect-banner {
      border-radius: 6px;
      padding: 0.6rem 0.7rem;
      border: 1px solid var(--border);
      background: #121212;
      font-size: 0.82rem;
      color: var(--text);
      display: none;
    }

    .inspect-banner.show {
      display: block;
    }

    .inspect-banner.pass {
      border-color: rgba(0, 255, 136, 0.45);
      color: var(--pass);
      background: rgba(0, 255, 136, 0.08);
    }

    .inspect-banner.fail {
      border-color: rgba(255, 68, 68, 0.5);
      color: var(--fail);
      background: rgba(255, 68, 68, 0.07);
    }

    .inspect-banner.warn {
      border-color: rgba(255, 170, 0, 0.5);
      color: var(--warn);
      background: rgba(255, 170, 0, 0.07);
    }

    .kv-grid {
      display: grid;
      grid-template-columns: 160px 1fr;
      gap: 0.45rem 0.75rem;
      font-size: 0.82rem;
      align-items: start;
    }

    .kv-grid dt {
      color: var(--text-dim);
      font-family: var(--font-mono);
      font-size: 0.74rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }

    .kv-grid dd {
      margin: 0;
      font-family: var(--font-mono);
      word-break: break-word;
      color: var(--text);
    }

    .inspect-list {
      margin: 0;
      padding-left: 1.2rem;
      display: grid;
      gap: 0.35rem;
      font-family: var(--font-mono);
      font-size: 0.78rem;
      color: var(--text);
    }

    .inspect-pre {
      border: 1px solid var(--border);
      border-radius: 6px;
      background: #0d0d0d;
      padding: 0.7rem;
      overflow: auto;
      max-height: 380px;
      font-size: 0.74rem;
      line-height: 1.5;
      font-family: var(--font-mono);
      color: #cfcfcf;
      white-space: pre-wrap;
    }

    .inspect-subtitle {
      font-size: 0.78rem;
      color: var(--text-dim);
      margin-top: -0.2rem;
      margin-bottom: 0.7rem;
    }

    .inspect-empty {
      color: var(--text-dim);
      font-size: 0.82rem;
      border: 1px dashed var(--border);
      border-radius: 6px;
      padding: 0.65rem;
      background: #101010;
    }
  </style>

  <div class="card">
    <h1 class="page-title" style="margin-bottom:0.25rem">Proof Bundle Inspect</h1>
    <p class="dim" style="max-width:70ch">
      Public verification layer is always visible. Full plaintext forensics is shown only after GitHub OAuth and viewer-key authorization.
    </p>
  </div>

  <div id="status-banner" class="inspect-banner"></div>

  <div class="inspect-grid">
    <section class="inspect-card">
      <h2>Load Bundle</h2>
      <div class="inspect-actions">
        <label class="dim" for="bundle-url" style="font-size:0.8rem">Bundle URL</label>
        <div class="inspect-row">
          <input id="bundle-url" class="inspect-input" type="url" placeholder="https://.../proof_bundle.v2.json" />
          <button id="load-url-btn" class="inspect-btn">Load URL</button>
        </div>

        <div class="inspect-row">
          <input id="bundle-file" type="file" accept="application/json" style="display:none" />
          <button id="upload-btn" class="inspect-btn">Upload JSON</button>
          <button id="reset-btn" class="inspect-btn danger">Reset</button>
        </div>

        <label class="dim" for="bundle-paste" style="font-size:0.8rem">Paste Raw Bundle JSON</label>
        <textarea id="bundle-paste" class="inspect-textarea" placeholder="{ ...proof bundle json... }"></textarea>
        <div class="inspect-row">
          <button id="parse-paste-btn" class="inspect-btn">Parse JSON</button>
        </div>
      </div>
    </section>

    <section class="inspect-card" id="auth-panel">
      <h2>Viewer Auth</h2>
      <p class="inspect-subtitle" id="auth-subtitle"></p>
      <div class="inspect-row" id="auth-actions"></div>
      <div class="inspect-row" style="margin-top:0.5rem">
        <button id="decrypt-btn" class="inspect-btn primary" disabled>Decrypt Plaintext</button>
      </div>
      <p class="dim" style="font-size:0.75rem; margin-top:0.6rem">
        Decrypt uses authenticated GitHub identity -> DID binding attestations -> viewer_keys authorization.
      </p>
    </section>
  </div>

  <section class="inspect-card">
    <h2>Public Layer</h2>
    <p class="inspect-subtitle">Visible to everyone. Includes signatures, hashes, DIDs, timestamps, and visibility metadata.</p>
    <dl id="public-layer" class="kv-grid"></dl>
  </section>

  <section class="inspect-card">
    <h2>Public Forensics Surface</h2>
    <p class="inspect-subtitle">Hash-only structure and envelope-level metadata.</p>
    <pre id="public-json" class="inspect-pre"></pre>
  </section>

  <section class="inspect-card">
    <h2>Decrypted Plaintext Forensics</h2>
    <p class="inspect-subtitle">Tool calls, commands, file paths, network hosts, and full decrypted payload object.</p>
    <div id="decrypted-highlights" class="inspect-empty">No decrypted plaintext loaded.</div>
    <pre id="decrypted-json" class="inspect-pre" style="margin-top:0.7rem; display:none"></pre>
  </section>

  <script id="inspect-auth-state" type="application/json">${authState}</script>
  <script id="inspect-auth-status" type="application/json">${authStatus}</script>

  <script>
    (function() {
      const authState = JSON.parse(document.getElementById('inspect-auth-state').textContent || '{}');
      const authStatus = JSON.parse(document.getElementById('inspect-auth-status').textContent || 'null');

      const bannerEl = document.getElementById('status-banner');
      const bundleUrlEl = document.getElementById('bundle-url');
      const bundleFileEl = document.getElementById('bundle-file');
      const bundlePasteEl = document.getElementById('bundle-paste');
      const loadUrlBtn = document.getElementById('load-url-btn');
      const uploadBtn = document.getElementById('upload-btn');
      const resetBtn = document.getElementById('reset-btn');
      const parsePasteBtn = document.getElementById('parse-paste-btn');

      const authSubtitleEl = document.getElementById('auth-subtitle');
      const authActionsEl = document.getElementById('auth-actions');
      const decryptBtn = document.getElementById('decrypt-btn');

      const publicLayerEl = document.getElementById('public-layer');
      const publicJsonEl = document.getElementById('public-json');
      const decryptedHighlightsEl = document.getElementById('decrypted-highlights');
      const decryptedJsonEl = document.getElementById('decrypted-json');

      let currentBundle = null;
      let decryptedPayload = null;

      function setBanner(kind, message) {
        if (!message) {
          bannerEl.className = 'inspect-banner';
          bannerEl.textContent = '';
          return;
        }

        bannerEl.className = 'inspect-banner show ' + kind;
        bannerEl.textContent = message;
      }

      function escapeHtml(str) {
        return String(str)
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#39;');
      }

      function renderAuth() {
        const returnTo = window.location.pathname + window.location.search;
        const signinHref = '/auth/github/login?return_to=' + encodeURIComponent(returnTo);
        const logoutHref = '/auth/logout?return_to=' + encodeURIComponent('/inspect' + (window.location.search || ''));

        if (authState && authState.authenticated) {
          const label = authState.login ? '@' + authState.login : 'authenticated user';
          authSubtitleEl.textContent = 'Signed in as ' + label + '.';
          authActionsEl.innerHTML = '<a class="inspect-btn" href="' + escapeHtml(logoutHref) + '">Sign out</a>';
          decryptBtn.disabled = false;
        } else {
          authSubtitleEl.textContent = 'Sign in required for plaintext decryption.';
          authActionsEl.innerHTML = '<a class="inspect-btn primary" id="github-signin" href="' + escapeHtml(signinHref) + '">Sign in with GitHub</a>';
          decryptBtn.disabled = true;
        }
      }

      function authStatusMessage(code) {
        if (!code) return null;
        const map = {
          ok: { kind: 'pass', message: 'GitHub sign-in successful.' },
          logged_out: { kind: 'warn', message: 'Signed out.' },
          access_denied: { kind: 'warn', message: 'GitHub sign-in was denied by user.' },
          oauth_state_mismatch: { kind: 'fail', message: 'OAuth state validation failed. Please retry sign-in.' },
          oauth_missing_code: { kind: 'fail', message: 'OAuth callback missing authorization code.' },
          oauth_not_configured: { kind: 'fail', message: 'Explorer OAuth is not configured.' },
          session_not_configured: { kind: 'fail', message: 'Explorer session secret is not configured.' },
          github_user_fetch_failed: { kind: 'fail', message: 'GitHub user lookup failed. Try again.' },
          oauth_network_error: { kind: 'fail', message: 'OAuth network failure. Retry in a moment.' },
          token_exchange_failed: { kind: 'fail', message: 'GitHub token exchange failed.' },
        };

        return map[code] || { kind: 'warn', message: 'OAuth status: ' + code };
      }

      function normalizeBundleShape(input) {
        if (!input || typeof input !== 'object' || Array.isArray(input)) {
          throw new Error('Bundle JSON must be an object');
        }
        return input;
      }

      function extractPublicLayer(bundle) {
        const payload = (bundle && typeof bundle.payload === 'object' && bundle.payload !== null)
          ? bundle.payload
          : bundle;

        const viewerKeys = Array.isArray(payload.viewer_keys) ? payload.viewer_keys : [];
        const viewerRoles = {};
        viewerKeys.forEach((entry) => {
          if (entry && typeof entry.viewer_did === 'string' && typeof entry.role === 'string') {
            viewerRoles[entry.viewer_did] = entry.role;
          }
        });

        return {
          bundle_version: String(payload.bundle_version ?? '1'),
          schema_version: typeof payload.schema_version === 'string' ? payload.schema_version : null,
          visibility: typeof payload.visibility === 'string' ? payload.visibility : null,
          agent_did: typeof payload.agent_did === 'string' ? payload.agent_did : null,
          signer_did: typeof bundle.signer_did === 'string' ? bundle.signer_did : null,
          bundle_id: typeof payload.bundle_id === 'string' ? payload.bundle_id : null,
          issued_at: typeof bundle.issued_at === 'string' ? bundle.issued_at : null,
          has_encrypted_payload: payload.encrypted_payload !== undefined,
          viewer_count: viewerKeys.length,
          viewer_dids: viewerKeys.map((entry) => entry.viewer_did).filter((did) => typeof did === 'string'),
          viewer_roles: viewerRoles,
        };
      }

      function setPublicLayer(bundle) {
        const summary = extractPublicLayer(bundle);
        const rows = [
          ['bundle_version', summary.bundle_version],
          ['schema_version', summary.schema_version || '(none)'],
          ['visibility', summary.visibility || '(none)'],
          ['agent_did', summary.agent_did || '(none)'],
          ['signer_did', summary.signer_did || '(none)'],
          ['bundle_id', summary.bundle_id || '(none)'],
          ['issued_at', summary.issued_at || '(none)'],
          ['encrypted_payload', summary.has_encrypted_payload ? 'yes' : 'no'],
          ['viewer_count', String(summary.viewer_count)],
          ['viewer_dids', summary.viewer_dids.length ? summary.viewer_dids.join(', ') : '(none)'],
        ];

        publicLayerEl.innerHTML = rows
          .map((row) => '<dt>' + escapeHtml(row[0]) + '</dt><dd>' + escapeHtml(row[1]) + '</dd>')
          .join('');
      }

      function setPublicJson(bundle) {
        const payload = (bundle && typeof bundle.payload === 'object' && bundle.payload !== null) ? bundle.payload : bundle;
        const preview = {
          bundle_version: payload.bundle_version,
          schema_version: payload.schema_version,
          visibility: payload.visibility,
          encrypted_payload: payload.encrypted_payload,
          viewer_keys: payload.viewer_keys,
          event_chain_count: Array.isArray(payload.event_chain) ? payload.event_chain.length : 0,
          receipts_count: Array.isArray(payload.receipts) ? payload.receipts.length : 0,
          tool_receipts_count: Array.isArray(payload.tool_receipts) ? payload.tool_receipts.length : 0,
          execution_receipts_count: Array.isArray(payload.execution_receipts) ? payload.execution_receipts.length : 0,
          side_effect_receipts_count: Array.isArray(payload.side_effect_receipts) ? payload.side_effect_receipts.length : 0,
          network_receipts_count: Array.isArray(payload.network_receipts) ? payload.network_receipts.length : 0,
        };
        publicJsonEl.textContent = JSON.stringify(preview, null, 2);
      }

      function uniqStrings(values) {
        return Array.from(new Set(values.filter((value) => typeof value === 'string' && value.trim().length > 0)));
      }

      function renderDecryptedHighlights(payload) {
        if (!payload || typeof payload !== 'object') {
          decryptedHighlightsEl.className = 'inspect-empty';
          decryptedHighlightsEl.textContent = 'No decrypted plaintext loaded.';
          decryptedJsonEl.style.display = 'none';
          decryptedJsonEl.textContent = '';
          return;
        }

        const toolNames = uniqStrings(
          (Array.isArray(payload.tool_receipts) ? payload.tool_receipts : [])
            .map((item) => item && typeof item === 'object' ? item.tool_name : null)
        );

        const commands = uniqStrings(
          (Array.isArray(payload.execution_receipts) ? payload.execution_receipts : [])
            .map((item) => item && typeof item === 'object' ? item.command : null)
        );

        const filePaths = uniqStrings(
          (Array.isArray(payload.side_effect_receipts) ? payload.side_effect_receipts : [])
            .flatMap((item) => {
              if (!item || typeof item !== 'object') return [];
              return [item.path, item.file_path, item.target_path, item.target];
            })
        );

        const networkHosts = uniqStrings(
          (Array.isArray(payload.network_receipts) ? payload.network_receipts : [])
            .flatMap((item) => {
              if (!item || typeof item !== 'object') return [];
              return [item.host, item.hostname, item.remote_address, item.remote_host];
            })
        );

        const chunks = [];
        if (toolNames.length) {
          chunks.push('<p class="dim" style="margin-bottom:0.25rem">Tool calls</p><ul class="inspect-list">' + toolNames.map((x) => '<li>' + escapeHtml(x) + '</li>').join('') + '</ul>');
        }
        if (commands.length) {
          chunks.push('<p class="dim" style="margin-top:0.55rem; margin-bottom:0.25rem">Commands</p><ul class="inspect-list">' + commands.map((x) => '<li>' + escapeHtml(x) + '</li>').join('') + '</ul>');
        }
        if (filePaths.length) {
          chunks.push('<p class="dim" style="margin-top:0.55rem; margin-bottom:0.25rem">File paths</p><ul class="inspect-list">' + filePaths.map((x) => '<li>' + escapeHtml(x) + '</li>').join('') + '</ul>');
        }
        if (networkHosts.length) {
          chunks.push('<p class="dim" style="margin-top:0.55rem; margin-bottom:0.25rem">Network hosts</p><ul class="inspect-list">' + networkHosts.map((x) => '<li>' + escapeHtml(x) + '</li>').join('') + '</ul>');
        }

        if (chunks.length === 0) {
          decryptedHighlightsEl.className = 'inspect-empty';
          decryptedHighlightsEl.textContent = 'Plaintext decrypted successfully. No known highlight fields were found; see full JSON below.';
        } else {
          decryptedHighlightsEl.className = '';
          decryptedHighlightsEl.innerHTML = chunks.join('');
        }

        decryptedJsonEl.style.display = 'block';
        decryptedJsonEl.textContent = JSON.stringify(payload, null, 2);
      }

      function applyBundle(bundle) {
        currentBundle = normalizeBundleShape(bundle);
        decryptedPayload = null;
        setPublicLayer(currentBundle);
        setPublicJson(currentBundle);
        renderDecryptedHighlights(null);
      }

      function parseAndApplyRawJson(raw) {
        const parsed = JSON.parse(raw);
        applyBundle(parsed);
      }

      async function loadBundleFromApi(urlValue) {
        const target = new URL('/api/inspect/load', window.location.origin);
        target.searchParams.set('bundle', urlValue);

        const resp = await fetch(target.toString(), {
          method: 'GET',
          credentials: 'same-origin',
          headers: {
            Accept: 'application/json',
          },
        });

        const body = await resp.json().catch(() => null);
        if (!resp.ok || !body || typeof body !== 'object') {
          throw new Error('Failed to load bundle URL');
        }
        if (!body.bundle || typeof body.bundle !== 'object') {
          const msg = typeof body.error === 'string' ? body.error : 'Bundle URL returned invalid JSON payload';
          throw new Error(msg);
        }

        applyBundle(body.bundle);
      }

      async function decryptBundle() {
        if (!currentBundle) {
          setBanner('warn', 'Load a bundle first.');
          return;
        }

        if (!authState || !authState.authenticated) {
          const returnTo = window.location.pathname + window.location.search;
          window.location.href = '/auth/github/login?return_to=' + encodeURIComponent(returnTo);
          return;
        }

        setBanner('warn', 'Decrypting...');

        let response;
        try {
          response = await fetch('/api/inspect/decrypt', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
              'Content-Type': 'application/json',
              Accept: 'application/json',
            },
            body: JSON.stringify({ bundle: currentBundle }),
          });
        } catch (error) {
          const msg = error instanceof Error ? error.message : String(error);
          setBanner('fail', 'Decryption request failed: ' + msg);
          return;
        }

        const body = await response.json().catch(() => null);
        if (!body || typeof body !== 'object') {
          setBanner('fail', 'Decryption endpoint returned invalid JSON');
          return;
        }

        const status = body.status;
        if (status === 'decrypted' && body.decrypted_payload && typeof body.decrypted_payload === 'object') {
          decryptedPayload = body.decrypted_payload;
          renderDecryptedHighlights(decryptedPayload);
          setBanner('pass', 'Decryption successful. Plaintext forensics loaded.');
          return;
        }

        if (status === 'unauthorized') {
          renderDecryptedHighlights(null);
          setBanner('warn', 'You are not authorized to view this bundle\'s plaintext');
          return;
        }

        if (status === 'unauthenticated') {
          renderDecryptedHighlights(null);
          setBanner('warn', 'Session expired. Sign in with GitHub to decrypt.');
          return;
        }

        if (status === 'not_encrypted') {
          renderDecryptedHighlights(null);
          setBanner('warn', 'Bundle has no encrypted payload to decrypt.');
          return;
        }

        const msg = typeof body.message === 'string' ? body.message : 'Decryption failed';
        setBanner('fail', msg);
      }

      async function maybeLoadFromQuery() {
        const params = new URLSearchParams(window.location.search);
        const bundleUrl = params.get('bundle');
        if (!bundleUrl) return;

        bundleUrlEl.value = bundleUrl;
        try {
          await loadBundleFromApi(bundleUrl);
          setBanner('pass', 'Loaded bundle from URL query parameter.');
        } catch (error) {
          const msg = error instanceof Error ? error.message : String(error);
          setBanner('fail', msg);
        }
      }

      loadUrlBtn.addEventListener('click', async () => {
        const value = bundleUrlEl.value.trim();
        if (!value) {
          setBanner('warn', 'Enter a bundle URL first.');
          return;
        }

        try {
          await loadBundleFromApi(value);
          setBanner('pass', 'Bundle loaded from URL.');
        } catch (error) {
          const msg = error instanceof Error ? error.message : String(error);
          setBanner('fail', msg);
        }
      });

      uploadBtn.addEventListener('click', () => {
        bundleFileEl.click();
      });

      bundleFileEl.addEventListener('change', async () => {
        const file = bundleFileEl.files && bundleFileEl.files[0];
        if (!file) return;

        try {
          const raw = await file.text();
          parseAndApplyRawJson(raw);
          setBanner('pass', 'Bundle loaded from uploaded file.');
        } catch (error) {
          const msg = error instanceof Error ? error.message : String(error);
          setBanner('fail', 'Invalid JSON file: ' + msg);
        }
      });

      parsePasteBtn.addEventListener('click', () => {
        const raw = bundlePasteEl.value.trim();
        if (!raw) {
          setBanner('warn', 'Paste bundle JSON first.');
          return;
        }

        try {
          parseAndApplyRawJson(raw);
          setBanner('pass', 'Bundle parsed from pasted JSON.');
        } catch (error) {
          const msg = error instanceof Error ? error.message : String(error);
          setBanner('fail', 'Invalid JSON: ' + msg);
        }
      });

      resetBtn.addEventListener('click', () => {
        currentBundle = null;
        decryptedPayload = null;
        bundleFileEl.value = '';
        bundlePasteEl.value = '';
        publicLayerEl.innerHTML = '';
        publicJsonEl.textContent = '{}';
        renderDecryptedHighlights(null);
        setBanner('warn', 'Inspector reset.');
      });

      decryptBtn.addEventListener('click', decryptBundle);

      renderAuth();
      const authInfo = authStatusMessage(authStatus);
      if (authInfo) {
        setBanner(authInfo.kind, authInfo.message);
      }

      publicJsonEl.textContent = '{}';
      maybeLoadFromQuery();
    })();
  </script>
</div>
`;

  return layout(meta, body);
}
