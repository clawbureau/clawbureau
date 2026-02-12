/**
 * Shared CSS design system for clawea.com marketing site.
 * Dark enterprise theme aligned with Claw Bureau brand.
 */

export const CSS = /* css */ `
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}

:root{
  --bg:#050508;
  --bg-alt:#0a0a0f;
  --surface:#111118;
  --surface-2:#1a1a24;
  --surface-3:#222230;
  --border:#2a2a3a;
  --border-light:#3a3a4e;
  --text:#f5f7ff;
  --text-secondary:#eef2ff;
  --text-muted:#dbe3ff;
  --accent:#78b7ff;
  --accent-hover:#9bc9ff;
  --accent-bg:rgba(59,130,246,.08);
  --accent-border:rgba(59,130,246,.2);
  --green:#22c55e;
  --green-bg:rgba(34,197,94,.08);
  --amber:#f59e0b;
  --red:#ef4444;
  --purple:#a855f7;
  --cyan:#06b6d4;
  --font:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,sans-serif;
  --font-mono:'SF Mono','Fira Code','Fira Mono',Menlo,Consolas,monospace;
  --max-w:1120px;
  --radius:.75rem;
}

html{
  font-family:var(--font);color:var(--text);background:var(--bg);
  line-height:1.7;font-size:16px;-webkit-font-smoothing:antialiased;
  scroll-behavior:smooth;
}

body{min-height:100vh;display:flex;flex-direction:column}

a{color:var(--accent);text-decoration:none;transition:color .15s}
a:hover{color:var(--accent-hover)}

.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;
  overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}

[hidden]{display:none!important}

/* ── Layout ────────────────────────────────────────────────────── */
.wrap{max-width:var(--max-w);margin:0 auto;padding:0 1.5rem;width:100%}
.section{padding:5rem 0}
.section-sm{padding:3rem 0}
.grid-2{display:grid;grid-template-columns:repeat(2,1fr);gap:2rem}
.grid-3{display:grid;grid-template-columns:repeat(3,1fr);gap:2rem}
.grid-4{display:grid;grid-template-columns:repeat(4,1fr);gap:1.5rem}

@media(max-width:768px){
  .grid-2,.grid-3,.grid-4{grid-template-columns:1fr}
  .section{padding:3rem 0}
}

/* ── Nav ───────────────────────────────────────────────────────── */
nav{position:sticky;top:0;z-index:100;background:rgba(5,5,8,.85);
  backdrop-filter:blur(12px);border-bottom:1px solid var(--border);
  padding:.75rem 0}
nav .wrap{display:flex;align-items:center;justify-content:space-between;gap:1rem}
nav .logo{font-weight:700;font-size:1.15rem;color:var(--text);display:flex;align-items:center;gap:.5rem;flex-shrink:0}
nav .logo span{color:var(--accent)}
nav .links{display:flex;gap:1.5rem;align-items:center;font-size:.875rem}
nav .links a{color:var(--text)}
nav .links a:hover{color:var(--text)}
.nav-cta-mobile{display:none!important}

.nav-search{display:flex;align-items:center;gap:.5rem;position:relative;
  border:1px solid var(--border);background:var(--surface);border-radius:999px;
  padding:.35rem .75rem;min-width:220px;max-width:320px;width:min(100%,300px);
  transition:border-color .15s,box-shadow .15s;overflow:visible}
.nav-search:focus-within{border-color:var(--accent);box-shadow:0 0 0 3px rgba(59,130,246,.18)}
.nav-search-icon{color:var(--text-muted);font-size:.8rem;line-height:1;flex-shrink:0}
.nav-search input{border:none;background:transparent;color:var(--text);width:100%;
  font-size:.85rem;line-height:1.3;outline:none;padding:0;min-width:0}
.nav-search input::placeholder{color:var(--text-secondary)}
.nav-search-clear{border:none;background:transparent;color:var(--text-muted);cursor:pointer;
  font-size:1rem;line-height:1;padding:0 .1rem}
.nav-search-clear:hover{color:var(--text)}
.nav-search-hint{display:inline-flex;align-items:center;justify-content:center;
  font-family:var(--font-mono);font-size:.68rem;color:var(--text-muted);
  border:1px solid var(--border-light);border-radius:.4rem;padding:.1rem .35rem;
  line-height:1;flex-shrink:0}

.nav-search-results{position:absolute;left:0;right:0;top:calc(100% + .45rem);
  background:var(--surface);border:1px solid var(--border);border-radius:.85rem;
  box-shadow:0 20px 40px rgba(0,0,0,.35);padding:.4rem;z-index:150;display:grid;gap:.2rem;
  max-height:340px;overflow:auto}
.nav-search-results[hidden]{display:none!important}
.nav-search-result{display:block;padding:.6rem .65rem;border-radius:.6rem;
  border:1px solid transparent;color:var(--text);text-decoration:none}
.nav-search-result:hover,.nav-search-result.active{background:var(--surface-2);border-color:var(--border-light)}
.nav-search-result-title{display:block;font-size:.82rem;font-weight:600;line-height:1.35;margin-bottom:.15rem}
.nav-search-result-meta{display:block;font-size:.72rem;color:var(--text-muted);line-height:1.35}
.nav-search-empty{padding:.55rem .65rem;font-size:.78rem;color:var(--text-secondary)}

.cta-btn{display:inline-flex;align-items:center;gap:.4rem;padding:.5rem 1.25rem;
  font-size:.875rem;font-weight:700;color:#ffffff;background:#2563eb;
  border:none;border-radius:var(--radius);cursor:pointer;transition:all .15s;text-decoration:none}
.cta-btn:hover{background:#1d4ed8;color:#ffffff;transform:translateY(-1px)}
.cta-btn-outline{background:rgba(148,163,184,.14);border:1px solid #95a4cc;color:#eef2ff}
.cta-btn-outline:hover{background:rgba(148,163,184,.26);color:#fff}
.cta-btn-lg{padding:.75rem 2rem;font-size:1rem}

@media(max-width:960px){
  .nav-search{min-width:180px;width:100%;max-width:240px}
}

@media(max-width:768px){
  nav .wrap{gap:.5rem;flex-wrap:wrap}
  nav .logo{font-size:1rem}
  .nav-search{order:3;min-width:0;max-width:none;flex:1 0 100%;width:100%;padding:.45rem .75rem;margin-top:.2rem}
  .nav-search-hint{display:none}
  nav .links{display:none}
  .nav-cta-mobile{display:inline-flex!important;padding:.45rem .8rem;font-size:.8rem}
}

/* ── Hero ──────────────────────────────────────────────────────── */
.hero{padding:6rem 0 5rem;text-align:center;position:relative;overflow:hidden}
.hero::before{content:'';position:absolute;inset:0;
  background:radial-gradient(ellipse 80% 50% at 50% -20%,rgba(59,130,246,.1) 0%,transparent 70%);
  pointer-events:none}
.hero h1{font-size:clamp(2rem,5vw,3.2rem);font-weight:800;
  letter-spacing:-.03em;line-height:1.15;margin-bottom:1rem;
  max-width:800px;margin-left:auto;margin-right:auto;text-wrap:balance}
.hero .sub{font-size:clamp(1rem,2.5vw,1.25rem);color:var(--text-secondary);
  max-width:640px;margin:0 auto 2.5rem;line-height:1.6}
.hero .actions{display:flex;gap:1rem;justify-content:center;flex-wrap:wrap}

/* ── Section headings ──────────────────────────────────────────── */
.sh{text-align:center;margin-bottom:3rem}
.sh .kicker{font-size:.75rem;text-transform:uppercase;letter-spacing:.1em;
  color:#ffffff;margin-bottom:.5rem;display:block}
.sh h2{font-size:clamp(1.5rem,4vw,2.2rem);font-weight:700;letter-spacing:-.02em;
  line-height:1.2;margin-bottom:.75rem}
.sh p{color:var(--text-secondary);max-width:600px;margin:0 auto;font-size:1rem}

/* ── Cards ─────────────────────────────────────────────────────── */
.card{background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);padding:2rem;transition:border-color .2s,transform .2s}
.card:hover{border-color:var(--border-light);transform:translateY(-2px)}
.card h3{font-size:1.1rem;font-weight:600;margin-bottom:.5rem}
.card p{color:#ffffff;font-size:.9rem;line-height:1.6}
.card .icon{width:48px;height:48px;border-radius:12px;display:flex;align-items:center;
  justify-content:center;margin-bottom:1rem;font-size:1.5rem;
  background:var(--accent-bg);border:1px solid var(--accent-border)}
.card .icon svg{width:22px;height:22px;display:block}
.card-link{text-decoration:none;color:inherit;display:block}
.card-link:hover{color:inherit}

/* ── Feature rows ──────────────────────────────────────────────── */
.feat-row{display:grid;grid-template-columns:1fr 1fr;gap:4rem;align-items:center;padding:3rem 0}
.feat-row.reverse{direction:rtl}.feat-row.reverse > *{direction:ltr}
.feat-row h3{font-size:1.4rem;font-weight:700;margin-bottom:.75rem}
.feat-row p{color:var(--text-secondary);margin-bottom:1.25rem}
.feat-row ul{list-style:none;padding:0}
.feat-row li{color:var(--text-secondary);font-size:.9rem;padding:.35rem 0;
  padding-left:1.5rem;position:relative}
.feat-row li::before{content:'';position:absolute;left:0;top:.65rem;width:8px;height:8px;
  border-radius:50%;background:var(--green)}
.feat-visual{background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);padding:2rem;min-height:280px;display:flex;
  align-items:center;justify-content:center;font-family:var(--font-mono);
  font-size:.85rem;color:var(--text-muted);white-space:pre;line-height:1.8;overflow-x:auto}

@media(max-width:768px){
  .feat-row{grid-template-columns:1fr;gap:2rem}
  .feat-row.reverse{direction:ltr}
}

/* ── Stats ─────────────────────────────────────────────────────── */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:2rem;padding:2.5rem 0}
.stat{text-align:center}
.stat .num{font-size:2.5rem;font-weight:800;color:var(--text);letter-spacing:-.03em}
.stat .label{font-size:.8rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-top:.25rem}
@media(max-width:768px){.stats{grid-template-columns:repeat(2,1fr)}}

/* ── Badges / Pills ────────────────────────────────────────────── */
.badge{display:inline-block;font-size:.7rem;text-transform:uppercase;
  letter-spacing:.08em;padding:.2rem .7rem;border-radius:9999px;font-weight:600}
.badge-blue{color:#dbeafe;background:rgba(59,130,246,.18);border:1px solid rgba(96,165,250,.55)}
.badge-green{color:#dcfce7;background:rgba(34,197,94,.18);border:1px solid rgba(74,222,128,.5)}
.badge-purple{color:#f3e8ff;background:rgba(168,85,247,.2);border:1px solid rgba(192,132,252,.55)}

/* ── Pricing ───────────────────────────────────────────────────── */
.price-card{background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);padding:2.5rem 2rem;position:relative;
  display:flex;flex-direction:column}
.price-card.featured{border-color:var(--accent);
  box-shadow:0 0 40px rgba(59,130,246,.1)}
.price-card .tier{font-size:.8rem;text-transform:uppercase;letter-spacing:.08em;
  color:var(--text-muted);margin-bottom:.5rem}
.price-card .amount{font-size:2.5rem;font-weight:800;margin-bottom:.25rem}
.price-card .period{font-size:.85rem;color:var(--text);margin-bottom:1.5rem}
.price-card ul{list-style:none;padding:0;margin-bottom:2rem}
.price-card li{padding:.4rem 0;font-size:.9rem;color:var(--text);
  padding-left:1.5rem;position:relative}
.price-card li::before{content:'\\2713';position:absolute;left:0;color:var(--green);font-weight:700}
.price-card .cta-btn{margin-top:auto;align-self:flex-start}

/* ── FAQ (legacy static list) ─────────────────────────────────── */
.faq-legacy{max-width:720px;margin:0 auto}
.faq-legacy-item{border-bottom:1px solid var(--border);padding:1.25rem 0}
.faq-legacy-item h3{font-size:1rem;font-weight:600;margin-bottom:.5rem;color:var(--text)}
.faq-legacy-item p{color:var(--text-secondary);font-size:.9rem;line-height:1.7}

/* ── Glossary ──────────────────────────────────────────────────── */
.glossary-def{background:var(--surface);border:1px solid var(--border);
  border-left:3px solid var(--accent);border-radius:0 var(--radius) var(--radius) 0;
  padding:1.5rem 2rem;margin:2rem 0;font-size:1.05rem;line-height:1.8}

.search-summary{display:flex;align-items:center;gap:.6rem;flex-wrap:wrap;
  color:var(--text-secondary);font-size:.92rem;margin-bottom:1.25rem}
.search-pill{display:inline-flex;align-items:center;gap:.3rem;
  font-family:var(--font-mono);font-size:.78rem;border:1px solid var(--border-light);
  border-radius:999px;padding:.2rem .55rem;color:var(--text-muted);background:var(--surface)}
.search-results{display:grid;gap:1rem;margin-top:1rem}
.search-result-card{display:block;padding:1.2rem 1.25rem;background:var(--surface);
  border:1px solid var(--border);border-radius:var(--radius);transition:border-color .15s,transform .15s}
.search-result-card:hover{border-color:var(--accent);transform:translateY(-1px)}
.search-result-title{font-size:1rem;font-weight:600;color:var(--text);line-height:1.4;margin-bottom:.35rem}
.search-result-meta{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap;margin-bottom:.35rem}
.search-result-desc{font-size:.88rem;color:var(--text-secondary);line-height:1.55}
.search-empty{padding:1.15rem 1.2rem;border:1px dashed var(--border-light);
  border-radius:var(--radius);color:var(--text-secondary);background:var(--surface)}

/* ── CTA Banner ────────────────────────────────────────────────── */
.cta-banner{background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);padding:3.5rem 2.5rem;text-align:center;
  margin:3rem 0;position:relative;overflow:hidden}
.cta-banner::before{content:'';position:absolute;inset:0;
  background:radial-gradient(ellipse at 50% 0%,rgba(59,130,246,.06) 0%,transparent 60%);pointer-events:none}
.cta-banner h2{font-size:1.6rem;font-weight:700;margin-bottom:.75rem}
.cta-banner p{color:var(--text-secondary);margin-bottom:2rem;max-width:500px;margin-left:auto;margin-right:auto}

/* ── Lead forms / assessment ───────────────────────────────────── */
.lead-form{padding:1.5rem 1.35rem}
.form-grid-2{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1rem 1.1rem}
.form-field{display:flex;flex-direction:column;gap:.4rem}
.form-field span{font-size:.8rem;text-transform:uppercase;letter-spacing:.06em;color:var(--text);font-weight:600}
.form-field input,.form-field select,.form-field textarea{
  width:100%;border:1px solid #5f6d90;background:var(--surface-2);
  color:var(--text);border-radius:.6rem;padding:.65rem .75rem;font-size:.9rem;
  line-height:1.4;outline:none;transition:border-color .15s,box-shadow .15s;
  font-family:var(--font)
}
.form-field input::placeholder,.form-field textarea::placeholder{color:#ffffff!important;opacity:1}
.form-field select option{background:#0f1017;color:var(--text)}
.form-field input[type='date'],.form-field input[type='time']{color-scheme:dark;min-height:42px}
.form-field input[type='date']::-webkit-calendar-picker-indicator,
.form-field input[type='time']::-webkit-calendar-picker-indicator{filter:invert(1) brightness(1.6);opacity:1}
.form-field input:focus,.form-field select:focus,.form-field textarea:focus{
  border-color:var(--accent);box-shadow:0 0 0 3px rgba(59,130,246,.2)
}
.form-field textarea{resize:vertical;min-height:90px}
.form-field-wide{grid-column:1/-1}
.form-actions{display:flex;align-items:center;gap:.75rem;flex-wrap:wrap;margin-top:1rem}
.form-status{font-size:.82rem;color:var(--text-secondary)}
.form-note{margin-top:.85rem;font-size:.8rem;color:var(--text-secondary);max-width:none!important}
.cf-turnstile{margin-top:1rem}
.turnstile-preview{margin-top:1rem;padding:.7rem .8rem;border:1px dashed var(--border-light);
  border-radius:.6rem;background:var(--surface);color:var(--text-secondary);font-size:.82rem}

.score-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:1rem;margin-top:1.25rem}
.score-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:1.1rem 1.15rem}
.score-card h3{margin:0 0 .45rem;font-size:.88rem;letter-spacing:.04em;text-transform:uppercase;color:var(--text-muted)}
.score-value{font-size:2rem;font-weight:800;letter-spacing:-.03em;margin-bottom:.35rem;color:var(--text)}
.score-value.score-good{color:#4ade80}
.score-value.score-warn{color:#fbbf24}
.score-value.score-bad{color:#f87171}
.score-card p{margin:0;max-width:100%;font-size:.84rem;line-height:1.5}

.proof-summary-block{background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--accent);border-radius:0 var(--radius) var(--radius) 0;padding:1.1rem 1.2rem;max-width:780px}
.proof-summary-block h3{margin:.1rem 0 .55rem;font-size:1rem}
.proof-summary-block ul{max-width:100%;margin-bottom:.55rem}
.proof-summary-links{display:flex;gap:.4rem;flex-wrap:wrap;font-size:.86rem;margin:0}
.proof-summary-sources{margin-top:.65rem}
.proof-summary-sources strong{font-size:.78rem;text-transform:uppercase;letter-spacing:.06em;color:var(--text-muted)}
.proof-summary-sources ul{margin-top:.45rem;max-width:100%}
.sources-hub-list{columns:2;column-gap:2rem}
.sources-hub-list li{break-inside:avoid;margin-bottom:.45rem;line-height:1.5}

.pill-link{display:block;padding:.65rem .75rem;border-radius:.7rem;
  border:1px solid var(--border-light);background:rgba(148,163,184,.12);
  color:var(--text);text-decoration:none}
.pill-link:hover{background:rgba(148,163,184,.18);color:#fff}

.trust-proof-list{display:flex;justify-content:center;gap:1rem;flex-wrap:wrap;list-style:none;
  margin:1rem 0 0;padding:0;color:var(--text);font-size:.88rem}
.trust-proof-list li{position:relative;padding-left:1.1rem}
.trust-proof-list li::before{content:'✓';position:absolute;left:0;color:#86efac;font-weight:700}

.trust-flow-desktop{display:flex}
.trust-flow-mobile{display:none;list-style:decimal;padding-left:1.2rem;margin-top:.75rem;color:var(--text)}
.trust-flow-mobile li{margin-bottom:.45rem;line-height:1.55}
.trust-flow-chart{display:grid;gap:.45rem;max-width:100%}
.trust-flow-step{padding:.55rem .7rem;border:1px solid #8ea2d8;
  background:rgba(120,183,255,.18);border-radius:.55rem;font-size:.82rem;
  line-height:1.4;color:var(--text);font-family:var(--font);
  white-space:normal;overflow:visible;word-break:break-word}
.trust-flow-arrow{justify-self:center;color:#dbe7ff;font-size:1rem;line-height:1}

@media(max-width:900px){
  .score-grid{grid-template-columns:1fr}
}

@media(max-width:768px){
  .form-grid-2{grid-template-columns:1fr}
  .form-actions .cta-btn{width:100%;justify-content:center}
  .form-actions .form-status{width:100%}
  .content-page .actions .cta-btn{width:100%;justify-content:center}
  .score-grid{grid-template-columns:1fr}
  .sources-hub-list{columns:1}
  .sources-next-card{order:0}
  .sources-family-card ul{max-height:none;overflow:visible;padding-right:0}
  .trust-proof-list{gap:.55rem;font-size:.82rem}
  .trust-flow-desktop{display:none}
  .trust-flow-mobile{display:block}
  .trust-flow-step{font-size:1rem;padding:.65rem .75rem;line-height:1.55}
}

/* ── Breadcrumb ────────────────────────────────────────────────── */
.breadcrumb{font-size:.8rem;color:var(--text-secondary);margin-bottom:1.5rem;padding-top:2rem}
.breadcrumb a{color:var(--text-secondary)}.breadcrumb a:hover{color:#fff}
.breadcrumb span{margin:0 .4rem}

/* ── Content page ──────────────────────────────────────────────── */
.content-page h1{font-size:clamp(1.8rem,4vw,2.6rem);font-weight:800;
  letter-spacing:-.02em;line-height:1.2;margin-bottom:1rem}
.content-page .lead{font-size:1.1rem;color:var(--text-secondary);
  line-height:1.7;margin-bottom:3rem;max-width:720px}
.content-page .article-meta{font-size:.85rem;color:var(--text-muted);margin-bottom:.85rem;max-width:720px}
.content-page .article-meta time{color:var(--text-secondary)}

.article-meta-strip{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem;
  margin-bottom:2rem;max-width:780px}
.meta-chip{display:inline-flex;align-items:center;gap:.35rem;
  font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;
  border:1px solid var(--border);background:var(--surface);color:var(--text-muted);
  border-radius:999px;padding:.3rem .65rem;line-height:1.2}
.meta-chip a{color:inherit;text-decoration:none}
.meta-chip-link{color:var(--text-secondary);border-color:var(--border-light)}
.meta-chip-link:hover{color:var(--text);border-color:var(--accent)}
.content-page h2{font-size:1.4rem;font-weight:700;margin-top:3rem;margin-bottom:1rem;
  padding-top:1rem;border-top:1px solid var(--border)}
.content-page h3{font-size:1.1rem;font-weight:600;margin-top:2rem;margin-bottom:.75rem}
.content-page p{color:var(--text-secondary);margin-bottom:1.25rem;max-width:720px}
.content-page ul,.content-page ol{color:var(--text-secondary);padding-left:1.5rem;margin-bottom:1.25rem;max-width:720px}
.content-page li{margin-bottom:.4rem;line-height:1.6}
.content-page table{width:100%;border-collapse:collapse;margin:2rem 0;font-size:.9rem}
.content-page th{text-align:left;padding:.75rem 1rem;background:var(--surface);
  border-bottom:2px solid var(--border);font-weight:600;font-size:.8rem;
  text-transform:uppercase;letter-spacing:.04em;color:var(--text-muted)}
.content-page td{padding:.75rem 1rem;border-bottom:1px solid var(--border);
  color:var(--text-secondary)}
.content-page tr:hover td{background:var(--surface)}

/* ── Footer ────────────────────────────────────────────────────── */
footer{margin-top:auto;border-top:1px solid var(--border);padding:3rem 0 2rem;
  background:var(--bg-alt)}
footer .wrap{display:grid;grid-template-columns:2fr 1fr 1fr 1fr;gap:2rem}
footer h4{font-size:.75rem;text-transform:uppercase;letter-spacing:.08em;
  color:var(--text);margin-bottom:1rem}
footer ul{list-style:none;padding:0}
footer li{margin-bottom:.5rem}
footer li a{color:var(--text);font-size:.875rem}
footer li a:hover{color:#ffffff}
footer .copyright{grid-column:1/-1;text-align:center;font-size:.75rem;
  color:var(--text);margin-top:2rem;padding-top:1.5rem;border-top:1px solid var(--border)}
footer .copyright a{color:var(--text)}
footer .copyright a:hover{color:#fff}
footer .copyright span{color:var(--text)}
@media(max-width:768px){
  footer .wrap{grid-template-columns:1fr}
  footer h4{margin-top:1rem}
  footer li{margin-bottom:.85rem}
  footer li a{display:inline-block;padding:.4rem 0}
}

/* ── Table ─────────────────────────────────────────────────────── */
.comp-table{width:100%;border-collapse:collapse;margin:2rem 0;font-size:.9rem}
.comp-table th{text-align:left;padding:.75rem 1rem;background:var(--surface);
  border-bottom:2px solid var(--border);font-weight:600;font-size:.8rem;
  text-transform:uppercase;letter-spacing:.04em;color:var(--text-muted)}
.comp-table td{padding:.75rem 1rem;border-bottom:1px solid var(--border);
  color:var(--text-secondary)}
.comp-table tr:hover td{background:var(--surface)}

/* ── Internal link blocks ──────────────────────────────────────── */
.related{margin-top:3rem;padding-top:2rem;border-top:1px solid var(--border)}
.related h3{font-size:1rem;font-weight:600;margin-bottom:1rem;color:var(--text-muted)}
.related-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1rem}
.related-grid a{display:block;padding:1rem;background:var(--surface);
  border:1px solid var(--border);border-radius:var(--radius);font-size:.875rem;
  font-weight:500;transition:border-color .15s}
.related-grid a:hover{border-color:var(--accent)}

/* ── Code block ────────────────────────────────────────────────── */
code{font-family:var(--font-mono);font-size:.85em;background:var(--surface-2);
  padding:.08em .33em;border-radius:4px;line-height:1.45}
pre{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:1.5rem;overflow-x:auto;margin:1.5rem 0;font-family:var(--font-mono);
  font-size:.85rem;line-height:1.7;color:var(--text-secondary)}

/* ── Skip to content ─────────────────────────────────────────── */
.skip-link{position:absolute;top:-100%;left:1rem;z-index:200;padding:.75rem 1.25rem;
  background:var(--accent);color:#fff;border-radius:var(--radius);font-weight:600;
  font-size:.875rem;transition:top .15s}
.skip-link:focus{top:1rem}

/* ── Focus-visible ───────────────────────────────────────────── */
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:2px}
a:focus:not(:focus-visible){outline:none}

/* ── Reading progress ────────────────────────────────────────── */
.progress-bar{position:fixed;top:0;left:0;height:3px;background:var(--accent);
  z-index:150;width:0;transition:width .1s linear;pointer-events:none}

/* ── Mobile nav toggle ───────────────────────────────────────── */
.nav-toggle{display:none;background:none;border:none;cursor:pointer;padding:.5rem;
  flex-direction:column;gap:4px;z-index:120}
.nav-toggle span{display:block;width:20px;height:2px;background:var(--text);
  border-radius:1px;transition:transform .2s,opacity .2s}
.nav-toggle[aria-expanded="true"] span:nth-child(1){transform:translateY(6px) rotate(45deg)}
.nav-toggle[aria-expanded="true"] span:nth-child(2){opacity:0}
.nav-toggle[aria-expanded="true"] span:nth-child(3){transform:translateY(-6px) rotate(-45deg)}

@media(max-width:768px){
  .nav-toggle{display:flex}
  nav .links{
    display:none;position:fixed;inset:0;top:0;background:rgba(5,5,8,.97);
    backdrop-filter:blur(16px);flex-direction:column;align-items:center;
    justify-content:center;gap:1.5rem;font-size:1.1rem;z-index:110;padding-top:4rem}
  nav .links.open{display:flex}
  nav .links a{color:var(--text-secondary);font-size:1.1rem}
}

/* ── Active nav link ─────────────────────────────────────────── */
nav .links a[aria-current="page"]{color:var(--text);position:relative}
nav .links a[aria-current="page"]::after{content:'';position:absolute;bottom:-.35rem;
  left:0;right:0;height:2px;background:var(--accent);border-radius:1px}
@media(max-width:768px){
  nav .links a[aria-current="page"]::after{display:none}
  nav .links a[aria-current="page"]{color:var(--accent)}
}

/* ── Article layout with TOC sidebar ─────────────────────────── */
.article-layout{display:grid;grid-template-columns:1fr 220px;gap:3rem;
  align-items:start;margin-top:2rem}
.article-main{min-width:0}

@media(max-width:960px){
  .article-layout{grid-template-columns:1fr;gap:0}
}

/* ── Table of contents ───────────────────────────────────────── */
.toc{position:sticky;top:5rem;font-size:.8rem;order:2}
.toc details{border:1px solid var(--border);border-radius:var(--radius);
  padding:1rem 1.25rem;background:var(--surface)}
.toc summary{font-weight:600;font-size:.75rem;text-transform:uppercase;
  letter-spacing:.08em;color:var(--text-muted);cursor:pointer;list-style:none;
  display:flex;align-items:center;justify-content:space-between}
.toc summary::after{content:'\\25B6';font-size:.55rem;transition:transform .2s}
.toc details[open] summary::after{transform:rotate(90deg)}
.toc summary::-webkit-details-marker{display:none}
.toc nav{margin-top:.75rem}
.toc ol{list-style:none;padding:0;margin:0}
.toc li{padding:.25rem 0;border-left:2px solid var(--border);padding-left:.75rem}
.toc li.depth-3{padding-left:1.5rem;font-size:.75rem}
.toc a{color:var(--text-muted);text-decoration:none;transition:color .15s;
  display:block;line-height:1.4}
.toc a:hover,.toc a.active{color:var(--accent)}

@media(max-width:960px){
  .toc{position:static;order:-1;margin-bottom:2rem}
}

/* ── Key takeaways ───────────────────────────────────────────── */
.takeaways{background:var(--accent-bg);border:1px solid var(--accent-border);
  border-radius:var(--radius);padding:1.25rem 1.5rem;margin-bottom:2.5rem;max-width:720px}
.takeaways-title{font-size:.7rem;text-transform:uppercase;letter-spacing:.1em;
  color:var(--accent);font-weight:700;margin-bottom:.5rem;display:flex;
  align-items:center;gap:.4rem}
.takeaways p{color:var(--text-secondary);font-size:.9rem;line-height:1.7;margin:0}

/* ── Callouts ────────────────────────────────────────────────── */
.callout{border-left:3px solid var(--border-light);background:var(--surface);
  border-radius:0 var(--radius) var(--radius) 0;padding:1rem 1.25rem;margin:1.5rem 0;
  max-width:720px}
.callout-title{font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;
  font-weight:700;margin-bottom:.35rem}
.callout p{margin:0;font-size:.9rem;color:var(--text-secondary);line-height:1.6}
.callout-note{border-left-color:var(--accent)}
.callout-note .callout-title{color:var(--accent)}
.callout-tip{border-left-color:var(--green)}
.callout-tip .callout-title{color:var(--green)}
.callout-warning{border-left-color:var(--amber)}
.callout-warning .callout-title{color:var(--amber)}
.callout-caution{border-left-color:var(--red)}
.callout-caution .callout-title{color:var(--red)}

/* ── FAQ accordion ───────────────────────────────────────────── */
.faq-accordion{max-width:780px;margin:2rem auto 0}
.faq-accordion .faq-item{border-bottom:1px solid var(--border)}
.faq-trigger{width:100%;text-align:left;background:none;border:none;cursor:pointer;
  color:var(--text);font-size:1rem;font-weight:600;padding:1rem 0;
  display:flex;align-items:center;justify-content:space-between;gap:1rem}
.faq-trigger::after{content:'\\002B';font-size:1.2rem;color:var(--text-muted);
  flex-shrink:0;transition:transform .2s}
.faq-trigger[aria-expanded='true']::after{content:'\\2212'}
.faq-panel{padding:0 0 1.2rem;color:var(--text-secondary);font-size:.92rem;line-height:1.7}
.faq-panel p{margin:0;max-width:100%}

/* ── Table responsive wrapper ────────────────────────────────── */
.table-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch;margin:2rem 0;
  border:1px solid var(--border);border-radius:var(--radius)}
.table-wrap table{margin:0;border:none;border-radius:0;width:100%}
.table-wrap th:first-child,.table-wrap td:first-child{position:sticky;left:0;
  background:var(--surface);z-index:1}

@media(max-width:768px){
  .table-wrap{font-size:.8rem}
  .table-wrap th,.table-wrap td{padding:.5rem .75rem;white-space:nowrap}
}

/* ── Back to top ─────────────────────────────────────────────── */
.back-to-top{position:fixed;bottom:2rem;right:2rem;width:40px;height:40px;
  border-radius:50%;background:var(--surface-2);border:1px solid var(--border);
  color:var(--text-muted);display:flex;align-items:center;justify-content:center;
  cursor:pointer;opacity:0;visibility:hidden;transition:opacity .2s,visibility .2s,
  background .15s;z-index:90;font-size:1rem;text-decoration:none}
.back-to-top.visible{opacity:1;visibility:visible}
.back-to-top:hover{background:var(--surface-3);color:var(--text)}

/* ── Improved related cards ──────────────────────────────────── */
.related-card{display:block;padding:1.25rem;background:var(--surface);
  border:1px solid var(--border);border-radius:var(--radius);
  text-decoration:none;transition:border-color .15s,transform .15s}
.related-card:hover{border-color:var(--accent);transform:translateY(-1px)}
.related-card .related-label{font-size:.875rem;font-weight:600;color:var(--text);
  margin-bottom:.25rem;display:block}

/* ── Content heading anchors ─────────────────────────────────── */
.content-page h2[id],.content-page h3[id]{scroll-margin-top:5rem}
.content-page h2[id]:hover .heading-anchor,
.content-page h3[id]:hover .heading-anchor{opacity:1}
.heading-anchor{color:var(--text-muted);text-decoration:none;margin-left:.4rem;
  opacity:0;transition:opacity .15s;font-weight:400}
.heading-anchor:hover{color:var(--accent)}

/* ── Reduced motion ──────────────────────────────────────────── */
@media(prefers-reduced-motion:reduce){
  *,*::before,*::after{animation-duration:.01ms!important;
    animation-iteration-count:1!important;transition-duration:.01ms!important;
    scroll-behavior:auto!important}
  .progress-bar{display:none}
}

/* ── Print ───────────────────────────────────────────────────── */
@media print{
  nav,.nav-toggle,.back-to-top,.progress-bar,.cta-btn,.cta-banner,footer,.toc{display:none!important}
  body{background:#fff;color:#000}
  .content-page h2{border-top:none}
  a{color:#000;text-decoration:underline}
  .card,.takeaways{border:1px solid #ccc;background:#f9f9f9}
}
`;
