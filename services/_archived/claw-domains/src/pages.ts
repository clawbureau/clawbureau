/* ------------------------------------------------------------------ */
/*  HTML page generators                                               */
/* ------------------------------------------------------------------ */

import type { DomainConfig, EcosystemDomain } from "./types.js";

const CSS = /* css */ `
  *,*::before,*::after{box-sizing:border-box}
  :root{
    --bg:#070910;
    --surface:#0f1422;
    --surface-2:#131a2c;
    --border:rgba(148,163,184,.22);
    --text:#e5ecf8;
    --muted:#9fb2d1;
    --primary:#62a7ff;
    --primary-2:#8ed1ff;
    --green:#3ddc97;
    --amber:#ffbf5f;
    --rose:#ff6b8a;
    --shadow:0 25px 80px rgba(0,0,0,.38);
  }
  html,body{
    margin:0;
    padding:0;
    min-height:100%;
    background:
      radial-gradient(1200px 700px at -15% -15%, rgba(98,167,255,.25), transparent 65%),
      radial-gradient(900px 520px at 110% -10%, rgba(142,209,255,.18), transparent 60%),
      linear-gradient(180deg, #070910 0%, #070c16 100%);
    color:var(--text);
    font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    line-height:1.6;
  }
  a{color:var(--primary);text-decoration:none}
  a:hover{text-decoration:underline}

  .shell{max-width:1120px;margin:0 auto;padding:24px 18px 56px}
  .nav{
    display:flex;align-items:center;justify-content:space-between;
    gap:14px;padding:12px 14px;border:1px solid var(--border);
    border-radius:14px;background:rgba(12,17,29,.78);backdrop-filter:blur(8px);
  }
  .nav-brand{font-weight:700;letter-spacing:.02em;color:#f4f8ff}
  .nav-links{display:flex;flex-wrap:wrap;gap:10px 14px;font-size:.9rem}
  .nav-links a{color:var(--muted)}
  .nav-links a:hover{color:var(--text);text-decoration:none}

  .hero{
    margin-top:16px;
    background:linear-gradient(165deg, rgba(20,27,46,.84), rgba(10,14,24,.92));
    border:1px solid var(--border);
    border-radius:22px;
    box-shadow:var(--shadow);
    padding:28px;
    position:relative;overflow:hidden;
  }
  .hero::before{
    content:"";position:absolute;inset:-30% -10% auto auto;width:420px;height:420px;
    background:radial-gradient(circle, rgba(98,167,255,.26), transparent 72%);
    pointer-events:none;
  }

  .kicker{font-size:.75rem;text-transform:uppercase;letter-spacing:.12em;color:var(--primary-2);margin-bottom:10px}
  .domain{font-size:clamp(1.8rem,4vw,3rem);font-weight:780;line-height:1.1;letter-spacing:-.02em;margin:0 0 10px}
  .tagline{font-size:1.05rem;color:#c2d5f1;max-width:760px;margin:0}
  .purpose{margin-top:12px;color:var(--muted);max-width:820px}

  .meta{display:flex;flex-wrap:wrap;gap:10px;margin-top:16px}
  .chip{display:inline-flex;align-items:center;gap:6px;padding:6px 11px;border-radius:999px;border:1px solid var(--border);font-size:.78rem;color:#c5d7f5;background:rgba(12,18,32,.8)}
  .dot{width:8px;height:8px;border-radius:999px;display:inline-block}
  .dot-live{background:var(--green)}
  .dot-building{background:var(--amber)}
  .dot-planned{background:#8b9cb9}
  .dot-sale{background:var(--rose)}

  .grid{display:grid;grid-template-columns:1.1fr .9fr;gap:14px;margin-top:14px}
  @media (max-width:920px){.grid{grid-template-columns:1fr}}

  .panel{
    border:1px solid var(--border);border-radius:16px;background:rgba(10,14,24,.72);
    padding:18px;
  }
  .panel h2{margin:0 0 10px;font-size:1rem;letter-spacing:.01em}
  .panel p{margin:0;color:var(--muted)}

  .price-box{margin-top:12px;padding:14px;border-radius:14px;border:1px solid rgba(61,220,151,.28);background:rgba(22,56,42,.22)}
  .price{font-size:2rem;line-height:1.1;font-weight:760;color:#d7ffe8;margin:0 0 4px}
  .price-note{margin:0;color:#95c8ac;font-size:.86rem}

  .form{display:grid;gap:10px}
  .form-row{display:grid;gap:6px}
  .form-row label{font-size:.74rem;letter-spacing:.08em;text-transform:uppercase;color:#acc2e6}
  .form-row input,.form-row textarea{
    width:100%;border-radius:12px;border:1px solid var(--border);
    background:rgba(7,11,20,.8);color:var(--text);padding:11px 12px;
    font:inherit;font-size:.95rem;outline:none;
  }
  .form-row input:focus,.form-row textarea:focus{border-color:rgba(98,167,255,.7)}
  .form-row textarea{min-height:94px;resize:vertical}

  .btn{
    border:none;border-radius:12px;padding:11px 14px;cursor:pointer;font-weight:640;
    background:linear-gradient(90deg, #4e8fff, #7db3ff);color:#061225;
  }
  .btn:hover{filter:brightness(1.05)}
  .btn:disabled{opacity:.6;cursor:not-allowed}

  .status-ok,.status-err{display:none;font-size:.9rem;margin-top:6px}
  .status-ok{color:#73e2b0}
  .status-err{color:#ff8da5}

  .cards{display:grid;grid-template-columns:repeat(2, minmax(0,1fr));gap:10px;margin-top:10px}
  @media (max-width:760px){.cards{grid-template-columns:1fr}}
  .card{
    border:1px solid var(--border);border-radius:14px;background:rgba(12,18,30,.72);
    padding:12px;
  }
  .card .title{font-weight:640;color:#d8e6ff;margin-bottom:4px}
  .card .desc{font-size:.88rem;color:var(--muted)}
  .card .meta{margin-top:8px}

  .footer{margin-top:20px;text-align:center;color:var(--muted);font-size:.82rem}
  .footer a{color:#bfd3f5}

  .ecosystem-wrap{margin-top:16px;display:grid;gap:14px}
  .pillar{
    border:1px solid var(--border);border-radius:16px;background:rgba(10,14,24,.74);
    padding:14px;
  }
  .pillar h3{margin:0 0 10px;font-size:1.02rem}
  .pill-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
  @media (max-width:860px){.pill-grid{grid-template-columns:1fr}}

  .domain-link{display:inline-flex;align-items:center;gap:7px;font-weight:650}

  .tiny{font-size:.78rem;color:var(--muted)}
`;

function esc(v: string): string {
  return v
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function fmtUsd(n: number): string {
  return "$" + n.toLocaleString("en-US");
}

function statusDot(status: string): string {
  if (status === "live") return "dot-live";
  if (status === "building") return "dot-building";
  if (status === "for_sale") return "dot-sale";
  return "dot-planned";
}

function prettyStatus(status: string): string {
  if (status === "for_sale") return "For sale";
  if (status === "building") return "Building";
  if (status === "live") return "Live";
  return "Planned";
}

function statusHint(cfg: DomainConfig): string {
  return prettyStatus(cfg.status_hint ?? (cfg.mode === "for_sale" ? "for_sale" : "building"));
}

function nav(hostname: string): string {
  const e = encodeURIComponent(hostname);
  return `<header class="nav">
    <div class="nav-brand">Claw Bureau Ecosystem</div>
    <nav class="nav-links">
      <a href="https://clawbureau.com" data-track-action="nav_click" data-track-label="nav_bureau" data-track-target="https://clawbureau.com">clawbureau.com</a>
      <a href="https://clawbounties.com" data-track-action="nav_click" data-track-label="nav_bounties" data-track-target="https://clawbounties.com">clawbounties.com</a>
      <a href="https://clawproxy.com" data-track-action="nav_click" data-track-label="nav_proxy" data-track-target="https://clawproxy.com">clawproxy.com</a>
      <a href="https://clawverify.com" data-track-action="nav_click" data-track-label="nav_verify" data-track-target="https://clawverify.com">clawverify.com</a>
      <a href="/ecosystem" data-track-action="nav_click" data-track-label="nav_ecosystem" data-track-target="/ecosystem">ecosystem map</a>
      <a href="/api/domains?host=${e}" data-track-action="nav_click" data-track-label="nav_domains_api" data-track-target="/api/domains">domain API</a>
    </nav>
  </header>`;
}

function relatedCards(hostname: string, related: EcosystemDomain[]): string {
  if (related.length === 0) {
    return `<p class="tiny">No related links configured yet.</p>`;
  }

  return `<div class="cards">${related
    .map((d) => {
      const href = `https://${d.domain}`;
      return `<article class="card">
        <div class="title"><a class="domain-link" href="${href}" target="_blank" rel="noopener" data-track-action="related_click" data-track-label="${esc(hostname)}:related" data-track-target="${esc(href)}"><span class="dot ${statusDot(d.status)}"></span>${esc(d.domain)}</a></div>
        <div class="desc">${esc(d.purpose)}</div>
        <div class="meta"><span class="chip">${esc(d.pillar)}</span><span class="chip">${esc(prettyStatus(d.status))}</span></div>
      </article>`;
    })
    .join("")}</div>`;
}

function featuredCards(hostname: string, domains: EcosystemDomain[]): string {
  return `<div class="cards">${domains
    .map((d) => {
      const href = `https://${d.domain}`;
      return `<article class="card">
        <div class="title"><a class="domain-link" href="${href}" target="_blank" rel="noopener" data-track-action="outbound_click" data-track-label="${esc(hostname)}:featured" data-track-target="${esc(href)}"><span class="dot ${statusDot(d.status)}"></span>${esc(d.domain)}</a></div>
        <div class="desc">${esc(d.tagline)}</div>
        <div class="tiny">${esc(d.purpose)}</div>
      </article>`;
    })
    .join("")}</div>`;
}

function analyticsBeacon(token: string): string {
  if (!token) return "";
  return `<script defer src="https://static.cloudflareinsights.com/beacon.min.js" data-cf-beacon='{"token":"${token}"}'></script>`;
}

function trackingScript(): string {
  return `<script>
  (function(){
    const TRACK_ENDPOINT = '/api/track';
    function safeJson(data){ try { return JSON.stringify(data); } catch { return null; } }
    function send(payload){
      const body = safeJson(payload);
      if(!body) return;
      try {
        if (navigator.sendBeacon) {
          const blob = new Blob([body], { type: 'application/json' });
          navigator.sendBeacon(TRACK_ENDPOINT, blob);
          return;
        }
      } catch {}
      fetch(TRACK_ENDPOINT, {
        method:'POST',
        headers:{'content-type':'application/json'},
        body,
        keepalive:true,
      }).catch(()=>{});
    }

    window.__clawTrack = send;

    document.addEventListener('click', function(ev){
      const t = ev.target;
      if (!(t instanceof Element)) return;
      const el = t.closest('[data-track-action]');
      if (!el) return;
      const action = el.getAttribute('data-track-action');
      if (!action) return;
      send({
        action,
        label: el.getAttribute('data-track-label') || undefined,
        target: el.getAttribute('data-track-target') || (el instanceof HTMLAnchorElement ? el.href : undefined),
      });
    }, { passive: true });
  })();
  </script>`;
}

function layout(opts: {
  hostname: string;
  title: string;
  description: string;
  body: string;
  analyticsToken: string;
}): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1.0" />
  <title>${esc(opts.title)}</title>
  <meta name="description" content="${esc(opts.description)}" />
  <meta name="theme-color" content="#090f1b" />
  <style>${CSS}</style>
</head>
<body>
  <main class="shell">
    ${nav(opts.hostname)}
    ${opts.body}
    <footer class="footer">
      Part of the <a href="https://clawbureau.com" target="_blank" rel="noopener" data-track-action="nav_click" data-track-label="footer_bureau" data-track-target="https://clawbureau.com">Claw Bureau ecosystem</a> ·
      <a href="/ecosystem" data-track-action="nav_click" data-track-label="footer_ecosystem" data-track-target="/ecosystem">view ecosystem map</a>
    </footer>
  </main>
  ${trackingScript()}
  ${analyticsBeacon(opts.analyticsToken)}
</body>
</html>`;
}

export function forSalePage(
  hostname: string,
  cfg: DomainConfig,
  analyticsToken: string,
  contactEmail: string,
  related: EcosystemDomain[],
  featured: EcosystemDomain[],
): string {
  const formScript = `<script>
    (function(){
      const form = document.getElementById('offer-form');
      if (!form) return;
      const btn = form.querySelector('button');
      const ok = document.getElementById('status-ok');
      const err = document.getElementById('status-err');

      form.addEventListener('submit', async function(e){
        e.preventDefault();
        if (!(btn instanceof HTMLButtonElement)) return;
        btn.disabled = true;
        btn.textContent = 'Sending…';
        if (ok) ok.style.display = 'none';
        if (err) err.style.display = 'none';

        const payload = {
          name: form.name.value,
          email: form.email.value,
          offer_amount: form.offer_amount.value ? Number(form.offer_amount.value) : null,
          message: form.message.value,
        };

        try {
          const res = await fetch('/api/inquiries', {
            method: 'POST',
            headers: {'content-type': 'application/json'},
            body: JSON.stringify(payload),
          });

          if (!res.ok) throw new Error('submit_failed');

          if (window.__clawTrack) {
            window.__clawTrack({
              action: payload.offer_amount ? 'offer' : 'inquiry',
              label: '${esc(hostname)}:form_submit',
              target: '/api/inquiries',
              value: payload.offer_amount || 0,
            });
          }

          form.reset();
          if (ok) ok.style.display = 'block';
          btn.disabled = false;
          btn.textContent = 'Submit interest';
        } catch {
          if (err) err.style.display = 'block';
          btn.disabled = false;
          btn.textContent = 'Submit interest';
        }
      });
    })();
  </script>`;

  const body = `
  <section class="hero">
    <div class="kicker">Premium domain opportunity</div>
    <h1 class="domain">${esc(hostname)}</h1>
    <p class="tagline">${esc(cfg.tagline)}</p>
    <p class="purpose">${esc(cfg.purpose)}</p>
    <div class="meta">
      <span class="chip"><span class="dot ${statusDot(cfg.status_hint ?? "for_sale")}"></span>${esc(statusHint(cfg))}</span>
      <span class="chip">${esc(cfg.pillar)}</span>
      ${cfg.bin_price ? `<span class="chip">BIN ${fmtUsd(cfg.bin_price)}</span>` : ""}
    </div>
  </section>

  <section class="grid">
    <article class="panel">
      <h2>Why this domain matters</h2>
      <p>This domain aligns to the <strong>${esc(cfg.pillar)}</strong> pillar and can anchor a focused product narrative in the Claw ecosystem.</p>
      ${cfg.bin_price ? `<div class="price-box"><p class="price">${fmtUsd(cfg.bin_price)}</p><p class="price-note">Buy-it-now benchmark · open to strategic offers</p></div>` : ""}

      <h2 style="margin-top:14px">Related ecosystem services</h2>
      ${relatedCards(hostname, related)}
    </article>

    <article class="panel">
      <h2>Express interest</h2>
      <p class="tiny" style="margin-bottom:10px">We review strategic offers quickly. Tell us your intended use and timing.</p>
      <form id="offer-form" class="form" autocomplete="on">
        <div class="form-row">
          <label for="name">Name</label>
          <input id="name" name="name" required placeholder="Jane Smith" />
        </div>
        <div class="form-row">
          <label for="email">Email</label>
          <input id="email" type="email" name="email" required placeholder="jane@company.com" />
        </div>
        <div class="form-row">
          <label for="offer_amount">Offer amount (USD)</label>
          <input id="offer_amount" name="offer_amount" type="number" min="100" step="100" placeholder="${cfg.bin_price ? Math.round(cfg.bin_price * 0.65).toLocaleString("en-US") : "10000"}" />
        </div>
        <div class="form-row">
          <label for="message">Message</label>
          <textarea id="message" name="message" placeholder="Intended product, budget range, and timing"></textarea>
        </div>
        <button class="btn" type="submit">Submit interest</button>
        <div id="status-ok" class="status-ok">✓ Received. We will reply within 48 hours.</div>
        <div id="status-err" class="status-err">Could not submit. Please email ${esc(contactEmail)} directly.</div>
      </form>

      <p class="tiny" style="margin-top:10px">
        Or email
        <a href="mailto:${esc(contactEmail)}?subject=${encodeURIComponent(`Domain inquiry: ${hostname}`)}" data-track-action="cta_click" data-track-label="${esc(hostname)}:email_cta" data-track-target="mailto:${esc(contactEmail)}">${esc(contactEmail)}</a>
      </p>
    </article>
  </section>

  <section class="panel" style="margin-top:14px">
    <h2>Explore live ecosystem surfaces</h2>
    <p class="tiny">These services are already running and can inform acquisition strategy.</p>
    ${featuredCards(hostname, featured)}
  </section>

  ${formScript}
  `;

  return layout({
    hostname,
    title: `${hostname} — premium domain opportunity`,
    description: cfg.purpose,
    body,
    analyticsToken,
  });
}

export function comingSoonPage(
  hostname: string,
  cfg: DomainConfig,
  analyticsToken: string,
  related: EcosystemDomain[],
  featured: EcosystemDomain[],
): string {
  const body = `
  <section class="hero">
    <div class="kicker">Ecosystem build track</div>
    <h1 class="domain">${esc(hostname)}</h1>
    <p class="tagline">${esc(cfg.tagline)}</p>
    <p class="purpose">${esc(cfg.purpose)}</p>
    <div class="meta">
      <span class="chip"><span class="dot ${statusDot(cfg.status_hint ?? "building")}"></span>${esc(statusHint(cfg))}</span>
      <span class="chip">${esc(cfg.pillar)}</span>
    </div>
  </section>

  <section class="grid">
    <article class="panel">
      <h2>Current purpose</h2>
      <p>${esc(cfg.purpose)}</p>

      <h2 style="margin-top:14px">Related services</h2>
      ${relatedCards(hostname, related)}
    </article>

    <article class="panel">
      <h2>What to use now</h2>
      <p class="tiny" style="margin-bottom:10px">While this domain is in build/planning, use the live services below.</p>
      ${featuredCards(hostname, featured)}

      <p class="tiny" style="margin-top:10px">
        Want updates? Start at
        <a href="https://joinclaw.com" target="_blank" rel="noopener" data-track-action="cta_click" data-track-label="${esc(hostname)}:joinclaw" data-track-target="https://joinclaw.com">joinclaw.com</a>
        or browse
        <a href="https://clawbureau.com" target="_blank" rel="noopener" data-track-action="cta_click" data-track-label="${esc(hostname)}:bureau" data-track-target="https://clawbureau.com">clawbureau.com</a>.
      </p>
    </article>
  </section>

  <section class="panel" style="margin-top:14px">
    <h2>Ecosystem navigation</h2>
    <p class="tiny">See all domains, status, and purpose on the ecosystem map.</p>
    <p style="margin-top:10px">
      <a class="btn" style="display:inline-block;text-decoration:none" href="/ecosystem" data-track-action="ecosystem_click" data-track-label="${esc(hostname)}:ecosystem_cta" data-track-target="/ecosystem">Open ecosystem map</a>
    </p>
  </section>
  `;

  return layout({
    hostname,
    title: `${hostname} — ${cfg.tagline}`,
    description: cfg.purpose,
    body,
    analyticsToken,
  });
}

export function ecosystemPage(
  hostname: string,
  analyticsToken: string,
  domains: EcosystemDomain[],
): string {
  const grouped = new Map<string, EcosystemDomain[]>();
  for (const d of domains) {
    const key = d.pillar;
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key)!.push(d);
  }

  const sections = [...grouped.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([pillar, items]) => {
      const cards = items
        .sort((a, b) => a.domain.localeCompare(b.domain))
        .map((d) => {
          const href = `https://${d.domain}`;
          return `<article class="card">
            <div class="title"><a class="domain-link" href="${href}" target="_blank" rel="noopener" data-track-action="ecosystem_click" data-track-label="ecosystem:${esc(pillar)}" data-track-target="${esc(href)}"><span class="dot ${statusDot(d.status)}"></span>${esc(d.domain)}</a></div>
            <div class="desc">${esc(d.tagline)}</div>
            <div class="tiny">${esc(d.purpose)}</div>
            <div class="meta"><span class="chip">${esc(prettyStatus(d.status))}</span>${d.active_service ? '<span class="chip">active service</span>' : ''}</div>
          </article>`;
        })
        .join("");

      return `<section class="pillar"><h3>${esc(pillar)}</h3><div class="pill-grid">${cards}</div></section>`;
    })
    .join("");

  const body = `
    <section class="hero">
      <div class="kicker">Claw Bureau domain architecture</div>
      <h1 class="domain">Ecosystem map</h1>
      <p class="tagline">Clear status, purpose, and links across live, building, planned, and strategic domains.</p>
      <p class="purpose">Use this map to navigate logical service relationships, discover current entry points, and track where each domain fits in the ecosystem.</p>
      <div class="meta">
        <span class="chip"><span class="dot dot-live"></span>${domains.filter((d) => d.status === "live").length} live</span>
        <span class="chip"><span class="dot dot-building"></span>${domains.filter((d) => d.status === "building").length} building</span>
        <span class="chip"><span class="dot dot-planned"></span>${domains.filter((d) => d.status === "planned").length} planned</span>
        <span class="chip"><span class="dot dot-sale"></span>${domains.filter((d) => d.status === "for_sale").length} for sale</span>
      </div>
    </section>

    <section class="ecosystem-wrap">
      ${sections}
    </section>
  `;

  return layout({
    hostname,
    title: "Claw Bureau ecosystem map",
    description: "Status and purpose map for Claw Bureau domains.",
    body,
    analyticsToken,
  });
}
