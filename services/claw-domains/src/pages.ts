/* ------------------------------------------------------------------ */
/*  HTML page generators                                              */
/* ------------------------------------------------------------------ */

import type { DomainConfig } from "./types.js";

/* ── shared CSS ───────────────────────────────────────────────────── */

const CSS = /* css */ `
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  :root{
    --bg:#09090b;--surface:#18181b;--border:#27272a;
    --text:#fafafa;--muted:#a1a1aa;--accent:#3b82f6;
    --accent-hover:#2563eb;--green:#22c55e;--amber:#f59e0b;
  }
  html{font-family:system-ui,-apple-system,BlinkMacSystemFont,
    'Segoe UI',Roboto,sans-serif;color:var(--text);
    background:var(--bg);min-height:100vh}
  body{display:flex;flex-direction:column;align-items:center;
    justify-content:center;min-height:100vh;padding:2rem 1rem;
    line-height:1.6}

  /* layout */
  .card{background:var(--surface);border:1px solid var(--border);
    border-radius:1rem;padding:3rem 2.5rem;max-width:540px;
    width:100%;text-align:center;position:relative;overflow:hidden}
  .card::before{content:'';position:absolute;inset:0;
    background:radial-gradient(ellipse at 50% -20%,
      rgba(59,130,246,.08) 0%,transparent 70%);pointer-events:none}

  /* typography */
  .domain{font-size:clamp(1.6rem,5vw,2.4rem);font-weight:700;
    letter-spacing:-.02em;margin-bottom:.25rem}
  .tagline{color:var(--muted);font-size:.95rem;margin-bottom:1.5rem}
  .pillar{display:inline-block;font-size:.7rem;text-transform:uppercase;
    letter-spacing:.08em;color:var(--accent);background:rgba(59,130,246,.1);
    padding:.25rem .75rem;border-radius:9999px;margin-bottom:2rem}
  .badge{display:inline-block;font-size:.65rem;text-transform:uppercase;
    letter-spacing:.1em;padding:.2rem .6rem;border-radius:9999px;
    margin-bottom:1.5rem}
  .badge-sale{color:var(--green);background:rgba(34,197,94,.1);
    border:1px solid rgba(34,197,94,.2)}
  .badge-soon{color:var(--amber);background:rgba(245,158,11,.1);
    border:1px solid rgba(245,158,11,.2)}

  /* price */
  .price{font-size:2rem;font-weight:700;margin-bottom:.25rem}
  .price-note{color:var(--muted);font-size:.8rem;margin-bottom:2rem}

  /* form */
  .form-group{text-align:left;margin-bottom:1rem}
  label{display:block;font-size:.75rem;text-transform:uppercase;
    letter-spacing:.06em;color:var(--muted);margin-bottom:.35rem}
  input,textarea{width:100%;padding:.6rem .8rem;font-size:.9rem;
    color:var(--text);background:var(--bg);border:1px solid var(--border);
    border-radius:.5rem;outline:none;transition:border-color .15s}
  input:focus,textarea:focus{border-color:var(--accent)}
  textarea{resize:vertical;min-height:80px}

  button{width:100%;padding:.75rem;font-size:.95rem;font-weight:600;
    color:#fff;background:var(--accent);border:none;border-radius:.5rem;
    cursor:pointer;transition:background .15s;margin-top:.5rem}
  button:hover{background:var(--accent-hover)}
  button:disabled{opacity:.5;cursor:not-allowed}

  .divider{display:flex;align-items:center;gap:.75rem;
    margin:1.5rem 0;color:var(--muted);font-size:.8rem}
  .divider::before,.divider::after{content:'';flex:1;
    border-top:1px solid var(--border)}

  .or-email{color:var(--muted);font-size:.8rem}
  .or-email a{color:var(--accent);text-decoration:none}
  .or-email a:hover{text-decoration:underline}

  .success{color:var(--green);font-size:.9rem;margin-top:1rem;display:none}
  .error{color:#ef4444;font-size:.85rem;margin-top:.5rem;display:none}

  /* footer */
  footer{margin-top:2.5rem;text-align:center;color:var(--muted);
    font-size:.75rem}
  footer a{color:var(--muted);text-decoration:none}
  footer a:hover{color:var(--text)}
  .eco-link{display:inline-flex;align-items:center;gap:.35rem}
  .eco-link svg{width:14px;height:14px}

  /* coming-soon specifics */
  .cta-link{display:inline-block;margin-top:1.5rem;padding:.6rem 1.5rem;
    font-size:.9rem;font-weight:600;color:var(--accent);
    border:1px solid var(--accent);border-radius:.5rem;
    text-decoration:none;transition:all .15s}
  .cta-link:hover{background:var(--accent);color:#fff}
`;

/* ── JS for the offer form ────────────────────────────────────────── */

const FORM_JS = /* js */ `
(function(){
  var f=document.getElementById('offer-form');
  if(!f)return;
  var btn=f.querySelector('button');
  var ok=document.getElementById('success');
  var err=document.getElementById('error');
  f.addEventListener('submit',function(e){
    e.preventDefault();
    btn.disabled=true;btn.textContent='Sending…';
    err.style.display='none';
    var d={
      name:f.elements.name.value,
      email:f.elements.email.value,
      offer_amount:parseFloat(f.elements.offer_amount.value)||null,
      message:f.elements.message.value
    };
    fetch('/api/inquiries',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(d)
    }).then(function(r){
      if(!r.ok)throw new Error('Failed');
      f.style.display='none';ok.style.display='block';
    }).catch(function(){
      err.style.display='block';err.textContent='Something went wrong. Try emailing us directly.';
      btn.disabled=false;btn.textContent='Make an Offer';
    });
  });
})();
`;

/* ── helpers ──────────────────────────────────────────────────────── */

function fmt(n: number): string {
  return "$" + n.toLocaleString("en-US");
}

function footerHtml(): string {
  return `
  <footer>
    <a href="https://clawbureau.com" class="eco-link" target="_blank" rel="noopener">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
      </svg>
      Part of the Claw Bureau ecosystem
    </a>
  </footer>`;
}

function beacon(token: string): string {
  if (!token) return "";
  return `<script defer src="https://static.cloudflareinsights.com/beacon.min.js" data-cf-beacon='{"token":"${token}"}'></script>`;
}

/* ── for-sale page ────────────────────────────────────────────────── */

export function forSalePage(
  hostname: string,
  cfg: DomainConfig,
  analyticsToken: string,
  contactEmail: string,
): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>${hostname} — Premium Domain Available</title>
  <meta name="description" content="${hostname} is a premium domain in the Claw Bureau ecosystem. Make an offer.">
  <meta name="robots" content="noindex">
  <style>${CSS}</style>
</head>
<body>
  <div class="card">
    <span class="badge badge-sale">Available</span>
    <h1 class="domain">${hostname}</h1>
    <p class="tagline">${cfg.tagline}</p>
    <span class="pillar">${cfg.pillar}</span>

    ${cfg.bin_price ? `<div class="price">${fmt(cfg.bin_price)}</div><p class="price-note">Buy it now — or make an offer</p>` : ""}

    <form id="offer-form" autocomplete="on">
      <div class="form-group">
        <label for="name">Your name</label>
        <input id="name" name="name" type="text" required placeholder="Jane Smith">
      </div>
      <div class="form-group">
        <label for="email">Email</label>
        <input id="email" name="email" type="email" required placeholder="jane@company.com">
      </div>
      <div class="form-group">
        <label for="offer_amount">Your offer (USD)</label>
        <input id="offer_amount" name="offer_amount" type="number" min="100" step="100"
          placeholder="${cfg.bin_price ? Math.round(cfg.bin_price * 0.6).toLocaleString("en-US") : "10000"}">
      </div>
      <div class="form-group">
        <label for="message">Message (optional)</label>
        <textarea id="message" name="message" rows="3" placeholder="Tell us about your project…"></textarea>
      </div>
      <button type="submit">Make an Offer</button>
      <div id="error" class="error"></div>
    </form>
    <div id="success" class="success">
      ✓ Offer received — we'll be in touch within 48 hours.
    </div>

    <div class="divider">or</div>
    <p class="or-email">
      Email us at <a href="mailto:${contactEmail}?subject=Inquiry: ${hostname}">${contactEmail}</a>
    </p>
  </div>
  ${footerHtml()}
  ${beacon(analyticsToken)}
  <script>${FORM_JS}</script>
</body>
</html>`;
}

/* ── coming-soon page ─────────────────────────────────────────────── */

export function comingSoonPage(
  hostname: string,
  cfg: DomainConfig,
  analyticsToken: string,
): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>${hostname} — Coming Soon</title>
  <meta name="description" content="${hostname} — ${cfg.tagline}. Part of the Claw Bureau agent economy.">
  <style>${CSS}</style>
</head>
<body>
  <div class="card">
    <span class="badge badge-soon">Coming Soon</span>
    <h1 class="domain">${hostname}</h1>
    <p class="tagline">${cfg.tagline}</p>
    <span class="pillar">${cfg.pillar}</span>

    <p style="color:var(--muted);font-size:.9rem;margin-top:1rem">
      This service is under development as part of the
      <strong style="color:var(--text)">Claw Bureau</strong> ecosystem.
    </p>

    <a href="https://clawbureau.com" class="cta-link" target="_blank" rel="noopener">
      Explore the Ecosystem →
    </a>
  </div>
  ${footerHtml()}
  ${beacon(analyticsToken)}
</body>
</html>`;
}
