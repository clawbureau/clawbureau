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
  --text:#eeeef2;
  --text-secondary:#a0a0b4;
  --text-muted:#6a6a80;
  --accent:#3b82f6;
  --accent-hover:#2563eb;
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
nav .wrap{display:flex;align-items:center;justify-content:space-between}
nav .logo{font-weight:700;font-size:1.15rem;color:var(--text);display:flex;align-items:center;gap:.5rem}
nav .logo span{color:var(--accent)}
nav .links{display:flex;gap:1.5rem;align-items:center;font-size:.875rem}
nav .links a{color:var(--text-secondary)}
nav .links a:hover{color:var(--text)}
.cta-btn{display:inline-flex;align-items:center;gap:.4rem;padding:.5rem 1.25rem;
  font-size:.875rem;font-weight:600;color:#fff;background:var(--accent);
  border:none;border-radius:var(--radius);cursor:pointer;transition:all .15s;text-decoration:none}
.cta-btn:hover{background:var(--accent-hover);color:#fff;transform:translateY(-1px)}
.cta-btn-outline{background:transparent;border:1px solid var(--accent);color:var(--accent)}
.cta-btn-outline:hover{background:var(--accent-bg);color:var(--accent)}
.cta-btn-lg{padding:.75rem 2rem;font-size:1rem}

@media(max-width:768px){
  nav .links{display:none}
}

/* ── Hero ──────────────────────────────────────────────────────── */
.hero{padding:6rem 0 5rem;text-align:center;position:relative;overflow:hidden}
.hero::before{content:'';position:absolute;inset:0;
  background:radial-gradient(ellipse 80% 50% at 50% -20%,rgba(59,130,246,.1) 0%,transparent 70%);
  pointer-events:none}
.hero h1{font-size:clamp(2rem,5vw,3.2rem);font-weight:800;
  letter-spacing:-.03em;line-height:1.15;margin-bottom:1rem;
  max-width:800px;margin-left:auto;margin-right:auto}
.hero .sub{font-size:clamp(1rem,2.5vw,1.25rem);color:var(--text-secondary);
  max-width:640px;margin:0 auto 2.5rem;line-height:1.6}
.hero .actions{display:flex;gap:1rem;justify-content:center;flex-wrap:wrap}

/* ── Section headings ──────────────────────────────────────────── */
.sh{text-align:center;margin-bottom:3rem}
.sh .kicker{font-size:.75rem;text-transform:uppercase;letter-spacing:.1em;
  color:var(--accent);margin-bottom:.5rem;display:block}
.sh h2{font-size:clamp(1.5rem,4vw,2.2rem);font-weight:700;letter-spacing:-.02em;
  line-height:1.2;margin-bottom:.75rem}
.sh p{color:var(--text-secondary);max-width:600px;margin:0 auto;font-size:1rem}

/* ── Cards ─────────────────────────────────────────────────────── */
.card{background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);padding:2rem;transition:border-color .2s,transform .2s}
.card:hover{border-color:var(--border-light);transform:translateY(-2px)}
.card h3{font-size:1.1rem;font-weight:600;margin-bottom:.5rem}
.card p{color:var(--text-secondary);font-size:.9rem;line-height:1.6}
.card .icon{width:48px;height:48px;border-radius:12px;display:flex;align-items:center;
  justify-content:center;margin-bottom:1rem;font-size:1.5rem;
  background:var(--accent-bg);border:1px solid var(--accent-border)}
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
.badge-blue{color:var(--accent);background:var(--accent-bg);border:1px solid var(--accent-border)}
.badge-green{color:var(--green);background:var(--green-bg);border:1px solid rgba(34,197,94,.2)}
.badge-purple{color:var(--purple);background:rgba(168,85,247,.08);border:1px solid rgba(168,85,247,.2)}

/* ── Pricing ───────────────────────────────────────────────────── */
.price-card{background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);padding:2.5rem 2rem;position:relative}
.price-card.featured{border-color:var(--accent);
  box-shadow:0 0 40px rgba(59,130,246,.1)}
.price-card .tier{font-size:.8rem;text-transform:uppercase;letter-spacing:.08em;
  color:var(--text-muted);margin-bottom:.5rem}
.price-card .amount{font-size:2.5rem;font-weight:800;margin-bottom:.25rem}
.price-card .period{font-size:.85rem;color:var(--text-muted);margin-bottom:1.5rem}
.price-card ul{list-style:none;padding:0;margin-bottom:2rem}
.price-card li{padding:.4rem 0;font-size:.9rem;color:var(--text-secondary);
  padding-left:1.5rem;position:relative}
.price-card li::before{content:'\\2713';position:absolute;left:0;color:var(--green);font-weight:700}

/* ── FAQ ───────────────────────────────────────────────────────── */
.faq{max-width:720px;margin:0 auto}
.faq-item{border-bottom:1px solid var(--border);padding:1.25rem 0}
.faq-item h3{font-size:1rem;font-weight:600;margin-bottom:.5rem;color:var(--text)}
.faq-item p{color:var(--text-secondary);font-size:.9rem;line-height:1.7}

/* ── Glossary ──────────────────────────────────────────────────── */
.glossary-def{background:var(--surface);border:1px solid var(--border);
  border-left:3px solid var(--accent);border-radius:0 var(--radius) var(--radius) 0;
  padding:1.5rem 2rem;margin:2rem 0;font-size:1.05rem;line-height:1.8}

/* ── CTA Banner ────────────────────────────────────────────────── */
.cta-banner{background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);padding:3.5rem 2.5rem;text-align:center;
  margin:3rem 0;position:relative;overflow:hidden}
.cta-banner::before{content:'';position:absolute;inset:0;
  background:radial-gradient(ellipse at 50% 0%,rgba(59,130,246,.06) 0%,transparent 60%);pointer-events:none}
.cta-banner h2{font-size:1.6rem;font-weight:700;margin-bottom:.75rem}
.cta-banner p{color:var(--text-secondary);margin-bottom:2rem;max-width:500px;margin-left:auto;margin-right:auto}

/* ── Breadcrumb ────────────────────────────────────────────────── */
.breadcrumb{font-size:.8rem;color:var(--text-muted);margin-bottom:1.5rem;padding-top:2rem}
.breadcrumb a{color:var(--text-muted)}.breadcrumb a:hover{color:var(--accent)}
.breadcrumb span{margin:0 .4rem}

/* ── Content page ──────────────────────────────────────────────── */
.content-page h1{font-size:clamp(1.8rem,4vw,2.6rem);font-weight:800;
  letter-spacing:-.02em;line-height:1.2;margin-bottom:1rem}
.content-page .lead{font-size:1.1rem;color:var(--text-secondary);
  line-height:1.7;margin-bottom:3rem;max-width:720px}
.content-page .article-meta{font-size:.85rem;color:var(--text-muted);margin-bottom:1.75rem;max-width:720px}
.content-page .article-meta time{color:var(--text-secondary)}
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
  color:var(--text-muted);margin-bottom:1rem}
footer ul{list-style:none;padding:0}
footer li{margin-bottom:.5rem}
footer li a{color:var(--text-secondary);font-size:.875rem}
footer li a:hover{color:var(--text)}
footer .copyright{grid-column:1/-1;text-align:center;font-size:.75rem;
  color:var(--text-muted);margin-top:2rem;padding-top:1.5rem;border-top:1px solid var(--border)}
@media(max-width:768px){footer .wrap{grid-template-columns:1fr 1fr}}

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
  padding:.15em .4em;border-radius:4px}
pre{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:1.5rem;overflow-x:auto;margin:1.5rem 0;font-family:var(--font-mono);
  font-size:.85rem;line-height:1.7;color:var(--text-secondary)}
`;
