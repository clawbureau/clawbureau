/**
 * clawsig.com — Clawsig Protocol landing page
 *
 * Minimal, credible protocol site. No framework, no build step beyond TS.
 */

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // Redirect www → apex
    if (url.hostname.startsWith('www.')) {
      url.hostname = url.hostname.replace('www.', '');
      return Response.redirect(url.toString(), 301);
    }

    if (url.pathname === '/verify' && request.method === 'POST') {
      return handleVerify(request);
    }

    if (url.pathname === '/badge/conformance.svg') {
      return conformanceBadge();
    }

    return landing();
  },
};

// ── Inline verification endpoint ─────────────────────────────────
async function handleVerify(request: Request): Promise<Response> {
  try {
    const body = await request.text();
    const bundle = JSON.parse(body);

    // Basic structural verification (no crypto in Worker — just schema checks)
    const checks: Record<string, boolean | string> = {};

    checks.has_proof_bundle_version = typeof bundle.proof_bundle_version === 'string';
    checks.has_run_id = typeof bundle.run_id === 'string';
    checks.has_agent_did = typeof bundle.agent_did === 'string' && bundle.agent_did.startsWith('did:');
    checks.has_events = Array.isArray(bundle.events) && bundle.events.length > 0;
    checks.has_signature = typeof bundle.signature === 'string' && bundle.signature.length > 10;
    checks.event_count = String(bundle.events?.length ?? 0);
    checks.receipt_count = String(bundle.receipts?.length ?? 0);
    checks.tool_receipt_count = String(bundle.tool_receipts?.length ?? 0);
    checks.side_effect_receipt_count = String(bundle.side_effect_receipts?.length ?? 0);
    checks.human_approval_receipt_count = String(bundle.human_approval_receipts?.length ?? 0);

    const allPassed = checks.has_proof_bundle_version &&
      checks.has_run_id &&
      checks.has_agent_did &&
      checks.has_events &&
      checks.has_signature;

    return new Response(JSON.stringify({
      status: allPassed ? 'STRUCTURAL_PASS' : 'STRUCTURAL_FAIL',
      note: 'Structural check only. For full cryptographic verification, use: npx @clawbureau/clawverify-cli verify proof-bundle --input bundle.json',
      checks,
    }, null, 2), {
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    });
  } catch (e: any) {
    return new Response(JSON.stringify({
      status: 'ERROR',
      reason: e.message || 'Invalid JSON',
    }, null, 2), {
      status: 400,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    });
  }
}

// ── Conformance badge ────────────────────────────────────────────
function conformanceBadge(): Response {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="220" height="20" role="img" aria-label="conformance: 22/22 pass">
  <title>conformance: 22/22 pass</title>
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <clipPath id="r"><rect width="220" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="110" height="20" fill="#555"/>
    <rect x="110" width="110" height="20" fill="#4c1"/>
    <rect width="220" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">
    <text x="55" y="15" fill="#010101" fill-opacity=".3">conformance</text>
    <text x="55" y="14">conformance</text>
    <text x="165" y="15" fill="#010101" fill-opacity=".3">22/22 pass</text>
    <text x="165" y="14">22/22 pass</text>
  </g>
</svg>`;
  return new Response(svg, {
    headers: {
      'Content-Type': 'image/svg+xml',
      'Cache-Control': 'public, max-age=3600',
    },
  });
}

// ── Landing page ─────────────────────────────────────────────────
function landing(): Response {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Clawsig Protocol — Verifiable Agent Proof Bundles</title>
  <meta name="description" content="Clawsig Protocol: cryptographically signed proof bundles for AI agent actions. Offline verification, fail-closed design, Coverage MTS.">
  <style>
    :root {
      --bg: #0a0a0a;
      --fg: #e8e8e8;
      --dim: #888;
      --accent: #4ade80;
      --accent-dim: #16a34a;
      --code-bg: #1a1a1a;
      --border: #2a2a2a;
      --link: #60a5fa;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
      background: var(--bg);
      color: var(--fg);
      line-height: 1.6;
      min-height: 100vh;
    }
    .container { max-width: 720px; margin: 0 auto; padding: 3rem 1.5rem; }
    h1 { font-size: 2rem; font-weight: 700; margin-bottom: 0.25rem; }
    h1 span { color: var(--accent); }
    .version { color: var(--dim); font-size: 0.875rem; margin-bottom: 2rem; display: block; }
    .tagline { font-size: 1.125rem; color: var(--dim); margin-bottom: 2.5rem; max-width: 600px; }
    h2 { font-size: 1.125rem; font-weight: 600; margin: 2.5rem 0 1rem; color: var(--accent); text-transform: uppercase; letter-spacing: 0.05em; font-size: 0.75rem; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem; }
    @media (max-width: 600px) { .grid { grid-template-columns: 1fr; } }
    .card {
      background: var(--code-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 1rem;
    }
    .card-title { font-weight: 600; font-size: 0.875rem; margin-bottom: 0.25rem; }
    .card-desc { color: var(--dim); font-size: 0.8125rem; }
    a { color: var(--link); text-decoration: none; }
    a:hover { text-decoration: underline; }
    code {
      background: var(--code-bg);
      border: 1px solid var(--border);
      border-radius: 3px;
      padding: 0.125rem 0.375rem;
      font-size: 0.8125rem;
    }
    pre {
      background: var(--code-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 1rem;
      overflow-x: auto;
      font-size: 0.8125rem;
      line-height: 1.5;
      margin: 1rem 0;
    }
    pre code { background: none; border: none; padding: 0; }
    .badges { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 2rem; }
    .badges img { height: 20px; }
    .verify-section { margin: 2rem 0; }
    textarea {
      width: 100%;
      height: 120px;
      background: var(--code-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--fg);
      font-family: monospace;
      font-size: 0.8125rem;
      padding: 0.75rem;
      resize: vertical;
    }
    button {
      background: var(--accent-dim);
      color: white;
      border: none;
      border-radius: 4px;
      padding: 0.5rem 1.25rem;
      font-size: 0.875rem;
      cursor: pointer;
      margin-top: 0.5rem;
    }
    button:hover { background: var(--accent); color: var(--bg); }
    #result { margin-top: 0.75rem; font-size: 0.8125rem; }
    .pass { color: var(--accent); }
    .fail { color: #f87171; }
    .links { list-style: none; }
    .links li { margin-bottom: 0.5rem; font-size: 0.875rem; }
    .links li::before { content: '→ '; color: var(--dim); }
    footer { margin-top: 4rem; padding-top: 2rem; border-top: 1px solid var(--border); color: var(--dim); font-size: 0.75rem; }
    .coverage-table { width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 0.8125rem; }
    .coverage-table th, .coverage-table td { text-align: left; padding: 0.375rem 0.75rem; border-bottom: 1px solid var(--border); }
    .coverage-table th { color: var(--dim); font-weight: 600; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }
  </style>
</head>
<body>
  <div class="container">
    <h1><span>Clawsig</span> Protocol</h1>
    <span class="version">v0.1.0 · Coverage MTS · 22 conformance vectors</span>

    <p class="tagline">Cryptographically signed proof bundles for AI agent actions. Verify offline what any agent did, which tools it used, what side-effects it caused, and who approved it.</p>

    <div class="badges">
      <a href="https://github.com/clawbureau/clawbureau/actions"><img src="/badge/conformance.svg" alt="conformance: 22/22 pass"></a>
      <a href="https://www.npmjs.com/package/@clawbureau/clawsig-sdk"><img src="https://img.shields.io/npm/v/@clawbureau/clawsig-sdk?label=clawsig-sdk&color=4c1" alt="npm"></a>
      <a href="https://www.npmjs.com/package/@clawbureau/clawverify-cli"><img src="https://img.shields.io/npm/v/@clawbureau/clawverify-cli?label=clawverify-cli&color=4c1" alt="npm"></a>
    </div>

    <h2>Get started</h2>
    <pre><code><span style="color:#888"># Emit a proof bundle from any Node.js agent</span>
npm install @clawbureau/clawsig-sdk

<span style="color:#888"># Verify it offline</span>
npx @clawbureau/clawverify-cli verify proof-bundle --input bundle.json</code></pre>

    <pre><code><span style="color:#888">// 5 lines to verifiable proof</span>
import { createClawsigRun } from '@clawbureau/clawsig-sdk';

const run = await createClawsigRun({ agentDid, proxyUrl, keyFile });
const response = await run.callLLM({ model: 'claude-sonnet-4-20250514', messages });
const bundle = await run.finalize();</code></pre>

    <h2>Coverage levels</h2>
    <table class="coverage-table">
      <thead><tr><th>Level</th><th>What's proven</th><th>Methods</th></tr></thead>
      <tbody>
        <tr><td><strong>M</strong></td><td>Which model was called, when, by whom</td><td><code>callLLM</code></td></tr>
        <tr><td><strong>MT</strong></td><td>+ which tools were invoked</td><td>+ <code>recordToolCall</code></td></tr>
        <tr><td><strong>MTS</strong></td><td>+ side-effects + human approvals</td><td>+ <code>recordSideEffect</code> + <code>recordHumanApproval</code></td></tr>
      </tbody>
    </table>

    <h2>Verify a proof bundle</h2>
    <div class="verify-section">
      <textarea id="bundle-input" placeholder='Paste a proof bundle JSON here...'></textarea>
      <button onclick="verifyBundle()">Verify (structural)</button>
      <div id="result"></div>
    </div>

    <h2>Links</h2>
    <ul class="links">
      <li><a href="https://github.com/clawbureau/clawbureau/blob/main/docs/specs/clawsig-protocol/CLAWSIG_PROTOCOL_v0.1.md">Protocol spec (v0.1)</a></li>
      <li><a href="https://github.com/clawbureau/clawbureau/blob/main/docs/specs/clawsig-protocol/ADOPTION_GUIDE.md">Adoption guide</a></li>
      <li><a href="https://www.npmjs.com/package/@clawbureau/clawsig-sdk">@clawbureau/clawsig-sdk on npm</a></li>
      <li><a href="https://www.npmjs.com/package/@clawbureau/clawverify-cli">@clawbureau/clawverify-cli on npm</a></li>
      <li><a href="https://www.npmjs.com/package/@clawbureau/clawverify-core">@clawbureau/clawverify-core on npm</a></li>
      <li><a href="https://github.com/clawbureau/clawbureau/blob/main/docs/specs/clawsig-protocol/REASON_CODE_REGISTRY.md">Reason code registry</a></li>
      <li><a href="https://github.com/clawbureau/clawbureau/blob/main/packages/schema/fixtures/protocol-conformance/manifest.v1.json">Conformance suite (22 vectors)</a></li>
      <li><a href="https://github.com/clawbureau/clawbureau">GitHub repository</a></li>
    </ul>

    <h2>Enterprise deployment</h2>
    <p style="color:var(--dim);font-size:0.875rem;margin-bottom:1rem">Running agents in regulated environments? Claw EA wraps the Clawsig Protocol with enterprise controls.</p>
    <ul class="links">
      <li><a href="https://www.clawea.com/pricing/enterprise">Enterprise plans and pricing</a></li>
      <li><a href="https://www.clawea.com/guides/github-actions-proof-pipeline">GitHub Actions proof pipeline guide</a></li>
      <li><a href="https://www.clawea.com/trust/security-review">Security review pack</a></li>
      <li><a href="https://www.clawea.com/case-studies/dogfood-claw-bureau">Case study: 3 agents, 190+ PRs, 12 services</a></li>
      <li><a href="https://www.clawea.com/docs">Full documentation hub</a></li>
    </ul>

    <h2>Design principles</h2>
    <div class="grid">
      <div class="card">
        <div class="card-title">Offline by default</div>
        <div class="card-desc">Verification requires zero network access. Proof bundles are self-contained.</div>
      </div>
      <div class="card">
        <div class="card-title">Fail-closed</div>
        <div class="card-desc">Unknown versions, algorithms, or fields → FAIL. No silent pass-through.</div>
      </div>
      <div class="card">
        <div class="card-title">Hash-only privacy</div>
        <div class="card-desc">Tool args, results, and side-effect payloads are digested. Raw content never enters bundles.</div>
      </div>
      <div class="card">
        <div class="card-title">Additive coverage</div>
        <div class="card-desc">Start at M, add MT, then MTS. Each level is backward-compatible.</div>
      </div>
    </div>

    <footer>
      <p>Clawsig Protocol v0.1.0 · <a href="https://clawbureau.com">Clawbureau</a> · MIT License</p>
    </footer>
  </div>

  <script>
    async function verifyBundle() {
      const input = document.getElementById('bundle-input').value.trim();
      const el = document.getElementById('result');
      if (!input) { el.innerHTML = '<span class="fail">Paste a proof bundle JSON first.</span>'; return; }
      try {
        el.textContent = 'Verifying...';
        const res = await fetch('/verify', { method: 'POST', body: input });
        const data = await res.json();
        const cls = data.status === 'STRUCTURAL_PASS' ? 'pass' : 'fail';
        el.innerHTML = '<pre class="' + cls + '">' + JSON.stringify(data, null, 2) + '</pre>';
      } catch (e) {
        el.innerHTML = '<span class="fail">Error: ' + e.message + '</span>';
      }
    }
  </script>
</body>
</html>`;

  return new Response(html, {
    headers: {
      'Content-Type': 'text/html;charset=utf-8',
      'Cache-Control': 'public, max-age=300',
    },
  });
}
