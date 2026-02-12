/**
 * Shared layout, theme, and HTML primitives for the Clawsig Explorer.
 *
 * Design: dark theme, monospace hashes, green/red status indicators.
 * Inspired by GitHub dark mode. No frameworks, no JS routing.
 */

export interface PageMeta {
  title: string;
  description: string;
  path: string;
  ogType?: string;
}

function css(): string {
  return /* css */ `
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --pass: #00ff88;
      --fail: #ff4444;
      --warn: #ffaa00;
      --bg: #0a0a0a;
      --bg-card: #141414;
      --bg-card-hover: #1a1a1a;
      --border: #2a2a2a;
      --text: #e0e0e0;
      --text-dim: #888888;
      --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      --font-mono: "SF Mono", "Fira Code", "JetBrains Mono", Menlo, monospace;
    }

    body {
      font-family: var(--font-sans);
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      -webkit-font-smoothing: antialiased;
    }

    a { color: var(--pass); text-decoration: none; }
    a:hover { text-decoration: underline; }

    .mono { font-family: var(--font-mono); font-size: 0.875rem; }
    .dim { color: var(--text-dim); }
    .pass { color: var(--pass); }
    .fail { color: var(--fail); }
    .warn { color: var(--warn); }

    .container {
      max-width: 960px;
      margin: 0 auto;
      padding: 0 1.5rem;
      width: 100%;
    }

    header {
      border-bottom: 1px solid var(--border);
      padding: 1rem 0;
      position: sticky;
      top: 0;
      background: rgba(10, 10, 10, 0.95);
      backdrop-filter: blur(8px);
      z-index: 100;
    }

    header .container {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 2rem;
    }

    .logo {
      font-weight: 700;
      font-size: 1.125rem;
      color: var(--text);
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .logo-icon {
      width: 24px;
      height: 24px;
      background: var(--pass);
      border-radius: 4px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 14px;
      color: #000;
      font-weight: 900;
    }

    nav { display: flex; gap: 1.5rem; font-size: 0.875rem; }
    nav a { color: var(--text-dim); }
    nav a:hover, nav a.active { color: var(--text); text-decoration: none; }

    footer {
      border-top: 1px solid var(--border);
      padding: 2rem 0;
      margin-top: auto;
      font-size: 0.8125rem;
      color: var(--text-dim);
      text-align: center;
    }

    footer code {
      background: var(--bg-card);
      padding: 0.2em 0.5em;
      border-radius: 4px;
      font-family: var(--font-mono);
      font-size: 0.8125rem;
    }

    main { padding: 2rem 0; flex: 1; }

    .card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.5rem;
      margin-bottom: 1rem;
    }

    .card:hover { border-color: #3a3a3a; }

    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 0.375rem;
      padding: 0.25rem 0.75rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .status-badge.pass {
      background: rgba(0, 255, 136, 0.1);
      color: var(--pass);
      border: 1px solid rgba(0, 255, 136, 0.3);
    }

    .status-badge.fail {
      background: rgba(255, 68, 68, 0.1);
      color: var(--fail);
      border: 1px solid rgba(255, 68, 68, 0.3);
    }

    .status-badge.warn {
      background: rgba(255, 170, 0, 0.1);
      color: var(--warn);
      border: 1px solid rgba(255, 170, 0, 0.3);
    }

    .status-badge .dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: currentColor;
    }

    .hash {
      font-family: var(--font-mono);
      font-size: 0.8125rem;
      background: var(--bg-card);
      padding: 0.2em 0.5em;
      border-radius: 4px;
      word-break: break-all;
      border: 1px solid var(--border);
    }

    .did {
      font-family: var(--font-mono);
      font-size: 0.8125rem;
      color: var(--pass);
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.875rem;
    }

    th, td {
      text-align: left;
      padding: 0.75rem 1rem;
      border-bottom: 1px solid var(--border);
    }

    th {
      color: var(--text-dim);
      font-weight: 500;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    tr:hover td { background: rgba(255, 255, 255, 0.02); }

    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }

    .stat-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem;
      text-align: center;
    }

    .stat-card .value {
      font-size: 2rem;
      font-weight: 700;
      font-family: var(--font-mono);
      color: var(--pass);
    }

    .stat-card .label {
      font-size: 0.75rem;
      color: var(--text-dim);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-top: 0.25rem;
    }

    .verify-panel {
      border: 2px solid var(--border);
      border-radius: 8px;
      padding: 1.5rem;
      margin: 1.5rem 0;
    }

    .verify-panel.verified { border-color: var(--pass); }
    .verify-panel.failed { border-color: var(--fail); }
    .verify-panel.pending { border-color: var(--warn); }

    .verify-panel h3 {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      margin-bottom: 1rem;
      font-size: 0.9375rem;
    }

    .verify-checks {
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }

    .verify-check {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      font-size: 0.875rem;
    }

    .verify-check .icon { width: 18px; text-align: center; }

    .copy-btn {
      background: transparent;
      border: 1px solid var(--border);
      color: var(--text-dim);
      padding: 0.25rem 0.5rem;
      border-radius: 4px;
      cursor: pointer;
      font-size: 0.75rem;
      font-family: var(--font-sans);
    }

    .copy-btn:hover { border-color: var(--text-dim); color: var(--text); }

    .section-title {
      font-size: 0.75rem;
      color: var(--text-dim);
      text-transform: uppercase;
      letter-spacing: 0.1em;
      margin-bottom: 0.75rem;
      font-weight: 600;
    }

    .page-title {
      font-size: 1.75rem;
      font-weight: 700;
      margin-bottom: 0.5rem;
    }

    .page-subtitle {
      color: var(--text-dim);
      font-size: 0.9375rem;
      margin-bottom: 2rem;
    }

    .detail-grid {
      display: grid;
      grid-template-columns: auto 1fr;
      gap: 0.5rem 1.5rem;
      font-size: 0.875rem;
    }

    .detail-grid dt {
      color: var(--text-dim);
      font-weight: 500;
    }

    .detail-grid dd { word-break: break-all; }

    .hero {
      text-align: center;
      padding: 4rem 0 3rem;
    }

    .hero h1 {
      font-size: 2.5rem;
      font-weight: 800;
      margin-bottom: 0.75rem;
      background: linear-gradient(135deg, var(--text), var(--pass));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }

    .hero p {
      font-size: 1.125rem;
      color: var(--text-dim);
      max-width: 600px;
      margin: 0 auto 2rem;
    }

    .cta-box {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem 1.5rem;
      font-family: var(--font-mono);
      font-size: 0.9375rem;
      display: inline-block;
    }

    .cta-box .prompt { color: var(--text-dim); }
    .cta-box .cmd { color: var(--pass); }

    .run-item {
      display: flex;
      align-items: center;
      gap: 1rem;
      padding: 0.75rem 0;
      border-bottom: 1px solid var(--border);
      font-size: 0.875rem;
    }

    .run-item:last-child { border-bottom: none; }

    .run-item .run-id {
      font-family: var(--font-mono);
      font-size: 0.8125rem;
      color: var(--pass);
      min-width: 120px;
    }

    .run-item .run-meta {
      color: var(--text-dim);
      flex: 1;
    }

    .run-item .run-time {
      color: var(--text-dim);
      font-size: 0.75rem;
    }

    @media (max-width: 640px) {
      .hero h1 { font-size: 1.75rem; }
      .stats-grid { grid-template-columns: 1fr 1fr; }
      .detail-grid { grid-template-columns: 1fr; }
      nav { gap: 0.75rem; }
    }
  `;
}

export function layout(meta: PageMeta, body: string): string {
  const siteUrl = "https://explorer.clawsig.com";
  const fullUrl = `${siteUrl}${meta.path}`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${esc(meta.title)} | Clawsig Explorer</title>
  <meta name="description" content="${esc(meta.description)}">
  <meta name="robots" content="index, follow">
  <link rel="canonical" href="${fullUrl}">

  <meta property="og:type" content="${meta.ogType ?? "website"}">
  <meta property="og:title" content="${esc(meta.title)}">
  <meta property="og:description" content="${esc(meta.description)}">
  <meta property="og:url" content="${fullUrl}">
  <meta property="og:site_name" content="Clawsig Explorer">

  <meta name="twitter:card" content="summary">
  <meta name="twitter:title" content="${esc(meta.title)}">
  <meta name="twitter:description" content="${esc(meta.description)}">

  <style>${css()}</style>
</head>
<body>
  <header>
    <div class="container">
      <a href="/" class="logo">
        <span class="logo-icon">&#x2713;</span>
        Clawsig Explorer
      </a>
      <nav>
        <a href="/">Explorer</a>
        <a href="/agents">Agents</a>
        <a href="/stats">Stats</a>
        <a href="https://docs.clawsig.com" target="_blank" rel="noopener">Docs</a>
      </nav>
    </div>
  </header>

  <main>
    <div class="container">
      ${body}
    </div>
  </main>

  <footer>
    <div class="container">
      Powered by Clawsig Protocol &mdash; Verify on your own machine: <code>npx clawsig verify</code>
    </div>
  </footer>
</body>
</html>`;
}

/** HTML-escape */
export function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Truncate a DID for display with copy button */
export function didDisplay(did: string): string {
  if (did.length <= 24) return `<span class="did">${esc(did)}</span>`;
  const prefix = did.slice(0, 16);
  const suffix = did.slice(-8);
  return `<span class="did" title="${esc(did)}">${esc(prefix)}...${esc(suffix)}</span>
    <button class="copy-btn" onclick="navigator.clipboard.writeText('${esc(did)}')">Copy</button>`;
}

/** Format a status badge */
export function statusBadge(status: string): string {
  const cls = status === "PASS" ? "pass" : status === "POLICY_VIOLATION" ? "fail" : "warn";
  return `<span class="status-badge ${cls}"><span class="dot"></span>${esc(status)}</span>`;
}

/** Format a proof tier badge */
export function tierBadge(tier: string): string {
  const cls = tier === "gateway" || tier === "sandbox" ? "pass" : tier === "self" ? "warn" : "fail";
  return `<span class="status-badge ${cls}">${esc(tier.toUpperCase())} TIER</span>`;
}

/** Format a timestamp to relative time */
export function relativeTime(ts: string): string {
  try {
    const d = new Date(ts);
    const now = Date.now();
    const diff = now - d.getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return `${mins}m ago`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    if (days < 30) return `${days}d ago`;
    return d.toISOString().slice(0, 10);
  } catch {
    return ts;
  }
}

/** Format number with commas */
export function fmtNum(n: number): string {
  return n.toLocaleString("en-US");
}
