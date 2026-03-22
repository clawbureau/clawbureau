import { layout, esc, type PageMeta } from '../layout.js';
import registry from '../generated/e2e-demo-registry.json';

interface WorkflowStat {
  label: string;
  value: string;
  note: string;
}

interface WorkflowCard {
  id: string;
  eyebrow: string;
  title: string;
  summary: string;
  evidence: string;
  metrics: WorkflowStat[];
  steps: string[];
}

const workflowCards = registry.workflows as WorkflowCard[];

const linksById: Record<string, Array<{ href: string; label: string }>> = {
  'pr-proof': [
    { href: 'https://www.clawea.com/guides/github-actions-proof-pipeline', label: 'Public implementation guide' },
    { href: 'https://www.clawea.com/case-studies/e2e-proof-workflows', label: 'Narrative case study' },
  ],
  'bundle-review': [
    { href: '/inspect#reviewer-workflow', label: 'Inspect drill-down' },
    { href: '/runs', label: 'Browse run surfaces' },
    { href: 'https://www.clawea.com/case-studies/e2e-proof-workflows', label: 'Public workflow explainer' },
  ],
  'arena-decision': [
    { href: '/arena/arena_bty_arena_001#workflow-drilldown', label: 'Arena drill-down' },
    { href: '/arena', label: 'Open arena views' },
    { href: 'https://www.clawea.com/case-studies/e2e-proof-workflows', label: 'Public workflow explainer' },
  ],
};

function workflowSection(card: WorkflowCard): string {
  const links = linksById[card.id] ?? [];

  return `
    <section class="card" id="${esc(card.id)}" style="padding:1.35rem 1.35rem 1.1rem; background:linear-gradient(180deg, rgba(255,255,255,0.03), rgba(255,255,255,0.01)); border-color:rgba(255,255,255,0.08)">
      <div style="display:flex; justify-content:space-between; gap:1rem; align-items:flex-start; flex-wrap:wrap; margin-bottom:1rem">
        <div style="max-width:700px">
          <p class="dim" style="text-transform:uppercase; letter-spacing:0.14em; font-size:0.72rem; margin-bottom:0.45rem">${esc(card.eyebrow)}</p>
          <h2 style="font-size:1.55rem; line-height:1.08; margin-bottom:0.55rem">${esc(card.title)}</h2>
          <p class="dim" style="max-width:62ch">${esc(card.summary)}</p>
        </div>
        <div class="status-badge pass">Live artifact-backed</div>
      </div>

      <div style="display:grid; grid-template-columns:1.15fr 0.85fr; gap:1rem; align-items:start">
        <div style="display:grid; gap:0.95rem">
          <div style="border-top:1px solid var(--border); padding-top:0.95rem">
            <p class="dim" style="text-transform:uppercase; letter-spacing:0.12em; font-size:0.7rem; margin-bottom:0.45rem">Evidence anchor</p>
            <p class="mono" style="font-size:0.8rem; line-height:1.6; color:var(--text)">${esc(card.evidence)}</p>
          </div>

          <div style="display:grid; gap:0.6rem">
            ${card.steps
              .map(
                (step, index) => `
              <div style="display:grid; grid-template-columns:32px 1fr; gap:0.85rem; align-items:start">
                <div style="width:32px; height:32px; border-radius:999px; border:1px solid rgba(0,255,136,0.25); display:flex; align-items:center; justify-content:center; color:var(--pass); font-weight:700">${index + 1}</div>
                <div>
                  <p class="dim" style="font-size:0.9rem">${esc(step)}</p>
                </div>
              </div>`,
              )
              .join('')}
          </div>
        </div>

        <div style="display:grid; gap:0.75rem">
          ${card.metrics
            .map(
              (stat) => `
            <div style="padding:0.85rem 0.9rem; border:1px solid rgba(255,255,255,0.08); border-radius:10px; background:rgba(255,255,255,0.02)">
              <p class="dim" style="text-transform:uppercase; letter-spacing:0.1em; font-size:0.68rem">${esc(stat.label)}</p>
              <p style="font-size:1.15rem; font-weight:700; margin:0.2rem 0 0.18rem">${esc(stat.value)}</p>
              <p class="dim" style="font-size:0.82rem">${esc(stat.note)}</p>
            </div>`,
            )
            .join('')}

          <div style="padding-top:0.1rem; display:flex; flex-wrap:wrap; gap:0.55rem">
            ${links
              .map(
                (link) => `<a href="${esc(link.href)}" style="font-size:0.82rem; border:1px solid rgba(255,255,255,0.1); padding:0.55rem 0.75rem; border-radius:999px; text-decoration:none">${esc(link.label)} &rarr;</a>`,
              )
              .join('')}
          </div>
        </div>
      </div>
    </section>
  `;
}

export function e2eShowcasePage(): string {
  const meta: PageMeta = {
    title: 'E2E workflow showcase',
    description: 'Artifact-backed operator view of PR proof, proof-bundle review, and arena decision workflows.',
    path: '/showcase/e2e',
  };

  const body = `
    <section style="margin-bottom:1.6rem; padding:1.65rem; border:1px solid rgba(255,255,255,0.08); border-radius:18px; background:radial-gradient(circle at top left, rgba(0,255,136,0.13), transparent 32%), linear-gradient(135deg, rgba(255,255,255,0.02), rgba(255,255,255,0)); overflow:hidden">
      <p class="dim" style="text-transform:uppercase; letter-spacing:0.18em; font-size:0.72rem; margin-bottom:0.55rem">E2E demo surfaces v1 · wave 2 registry-backed</p>
      <h1 class="page-title" style="font-size:clamp(2.1rem, 6vw, 4rem); line-height:0.92; margin-bottom:0.85rem; max-width:10ch">Real workflows, rendered for humans.</h1>
      <p class="page-subtitle" style="max-width:62ch; color:var(--text); font-size:1rem; margin-bottom:1.1rem">
        This page turns three existing proof workflows into one operator-facing surface: a PR proof chain, a bundle review path, and an arena decision lane. Every number below comes from a captured artifact, not placeholder product copy.
      </p>
      <div style="display:flex; gap:0.6rem; flex-wrap:wrap; margin-bottom:1.15rem">
        <a href="https://www.clawea.com/case-studies/e2e-proof-workflows" style="border:1px solid rgba(0,255,136,0.25); background:rgba(0,255,136,0.08); padding:0.7rem 0.95rem; border-radius:999px; text-decoration:none">Public case study &rarr;</a>
        <a href="/inspect" style="border:1px solid rgba(255,255,255,0.1); padding:0.7rem 0.95rem; border-radius:999px; text-decoration:none">Inspect bundles &rarr;</a>
        <a href="/arena" style="border:1px solid rgba(255,255,255,0.1); padding:0.7rem 0.95rem; border-radius:999px; text-decoration:none">Arena views &rarr;</a>
      </div>
      <div class="stats-grid" style="margin-bottom:0">
        <div class="stat-card" style="text-align:left">
          <div class="value" style="font-size:1.5rem">3</div>
          <div class="label">workflows surfaced</div>
        </div>
        <div class="stat-card" style="text-align:left">
          <div class="value" style="font-size:1.5rem">2</div>
          <div class="label">existing sites updated</div>
        </div>
        <div class="stat-card" style="text-align:left">
          <div class="value" style="font-size:1.5rem">100%</div>
          <div class="label">artifact-backed examples</div>
        </div>
      </div>
    </section>

    <div style="display:grid; gap:1rem">
      ${workflowCards.map(workflowSection).join('')}
    </div>

    <section class="card" style="margin-top:1rem">
      <p class="section-title">Generated registry</p>
      <p class="dim" style="font-size:0.84rem; margin-bottom:0.75rem">Refreshed from source artifacts at ${esc(registry.generated_at)}.</p>
      <div style="display:grid; gap:0.45rem">
        ${Object.values(registry.source_artifacts)
          .map((artifactPath) => `<div class="mono">${esc(String(artifactPath))}</div>`)
          .join('')}
      </div>
    </section>
  `;

  return layout(meta, body);
}
