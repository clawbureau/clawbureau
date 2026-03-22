import { layout } from '../layout';
import { serviceSchema } from '../seo';
import registry from '../generated/e2e-demo-registry.json';

interface DemoLane {
  id: string;
  eyebrow: string;
  title: string;
  summary: string;
  evidence: string;
  metrics: Array<{ label: string; value: string; note: string }>;
  steps: string[];
}

const ctaById: Record<string, { href: string; label: string }> = {
  'pr-proof': {
    href: '/guides/github-actions-proof-pipeline',
    label: 'See the implementation guide',
  },
  'bundle-review': {
    href: 'https://explorer.clawsig.com/showcase/e2e',
    label: 'Open the operator showcase',
  },
  'arena-decision': {
    href: 'https://explorer.clawsig.com/arena',
    label: 'Browse arena views',
  },
};

const demoLanes = registry.workflows as DemoLane[];

function metricStrip(metrics: DemoLane['metrics']): string {
  return `
    <div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:0.85rem; margin-top:1rem">
      ${metrics
        .map(
          (metric) => `
        <div style="padding:0.95rem 0; border-top:1px solid rgba(255,255,255,0.12)">
          <p style="font-size:0.78rem; letter-spacing:0.12em; text-transform:uppercase; color:rgba(255,255,255,0.58)">${metric.label}</p>
          <p style="font-size:1.25rem; font-weight:700; margin:0.2rem 0 0.15rem">${metric.value}</p>
          <p style="color:rgba(255,255,255,0.68); font-size:0.9rem">${metric.note}</p>
        </div>`,
        )
        .join('')}
    </div>
  `;
}

function laneSection(lane: DemoLane): string {
  const cta = ctaById[lane.id] ?? { href: '/case-studies', label: 'Open case studies' };

  return `
    <section class="section" style="padding-top:0">
      <div class="wrap" style="max-width:1180px">
        <div style="display:grid; grid-template-columns:minmax(0,1.15fr) minmax(280px,0.85fr); gap:2rem; align-items:start; padding:1.35rem 0; border-top:1px solid rgba(255,255,255,0.12)">
          <div>
            <p style="font-size:0.74rem; letter-spacing:0.18em; text-transform:uppercase; color:rgba(255,255,255,0.56); margin-bottom:0.55rem">${lane.eyebrow}</p>
            <h2 style="font-size:clamp(1.6rem,3vw,2.8rem); line-height:0.98; max-width:12ch; margin-bottom:0.75rem">${lane.title}</h2>
            <p style="font-size:1.02rem; max-width:56ch; color:rgba(255,255,255,0.82); margin-bottom:0.85rem">${lane.summary}</p>
            <p style="font-family:var(--mono); font-size:0.82rem; line-height:1.7; color:rgba(210,255,235,0.82); max-width:70ch">${lane.evidence}</p>
            ${metricStrip(lane.metrics)}
          </div>

          <div style="padding:1.15rem 1.1rem; border:1px solid rgba(255,255,255,0.1); border-radius:18px; background:rgba(255,255,255,0.03)">
            <p style="font-size:0.72rem; letter-spacing:0.14em; text-transform:uppercase; color:rgba(255,255,255,0.56); margin-bottom:0.7rem">What the UI has to do</p>
            <div style="display:grid; gap:0.7rem; margin-bottom:1rem">
              ${lane.steps
                .map(
                  (item, index) => `
                <div style="display:grid; grid-template-columns:28px 1fr; gap:0.75rem; align-items:start">
                  <div style="width:28px; height:28px; border-radius:999px; border:1px solid rgba(161,255,208,0.28); display:flex; align-items:center; justify-content:center; color:#9af5c0; font-weight:700">${index + 1}</div>
                  <p style="color:rgba(255,255,255,0.8)">${item}</p>
                </div>`,
                )
                .join('')}
            </div>
            <a href="${cta.href}" class="cta-btn cta-btn-outline" style="display:inline-flex">${cta.label}</a>
          </div>
        </div>
      </div>
    </section>
  `;
}

export function e2eProofWorkflowsPage(): string {
  return layout({
    meta: {
      title: 'E2E Proof Workflows | Claw EA',
      description:
        'Three real workflow demos rendered as product surfaces: PR proof, proof-bundle review, and arena decisioning using captured artifacts from live E2E flows.',
      path: '/case-studies/e2e-proof-workflows',
    },
    breadcrumbs: [
      { name: 'Home', path: '/' },
      { name: 'Case Studies', path: '/case-studies' },
      { name: 'E2E Proof Workflows', path: '/case-studies/e2e-proof-workflows' },
    ],
    schemas: [
      serviceSchema(
        'E2E Proof Workflows',
        'Artifact-backed workflow demonstrations for PR proof, proof bundle review, and arena decision surfaces.',
        'https://www.clawea.com/case-studies/e2e-proof-workflows',
      ),
    ],
    body: `
      <section style="position:relative; min-height:calc(100svh - 76px); display:flex; align-items:flex-end; background:
        radial-gradient(circle at 18% 18%, rgba(95, 244, 179, 0.2), transparent 32%),
        radial-gradient(circle at 82% 12%, rgba(102, 136, 255, 0.14), transparent 26%),
        linear-gradient(160deg, #050816 0%, #0c1020 36%, #090b11 100%); overflow:hidden">
        <div style="position:absolute; inset:0; background-image:linear-gradient(rgba(255,255,255,0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.04) 1px, transparent 1px); background-size:80px 80px; mask-image:linear-gradient(to bottom, rgba(0,0,0,0.75), transparent 82%)"></div>
        <div class="wrap" style="position:relative; width:100%; padding-top:4rem; padding-bottom:3rem">
          <div style="max-width:620px">
            <p style="font-size:0.78rem; letter-spacing:0.2em; text-transform:uppercase; color:rgba(255,255,255,0.62); margin-bottom:0.8rem">Case study · wave 1 shipped</p>
            <h1 style="font-size:clamp(3rem,9vw,6.8rem); line-height:0.9; letter-spacing:-0.05em; margin-bottom:1rem">Real workflow demos on the sites people already use.</h1>
            <p class="lead" style="max-width:18em; font-size:1.12rem; color:rgba(255,255,255,0.84); margin-bottom:1.3rem">
              We took actual proof artifacts from live flows and turned them into two kinds of UI: a public-facing narrative on Claw EA and an operator-facing showcase in Clawsig Explorer.
            </p>
            <div style="display:flex; flex-wrap:wrap; gap:0.75rem; margin-bottom:1.4rem">
              <a href="https://explorer.clawsig.com/showcase/e2e" class="cta-btn cta-btn-lg">Open the operator showcase</a>
              <a href="/guides/github-actions-proof-pipeline" class="cta-btn cta-btn-outline cta-btn-lg">See the setup guide</a>
            </div>
          </div>
          <div style="display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:1rem; margin-top:2rem; align-items:end">
            ${demoLanes.map((lane) => `
              <div style="padding:1rem 0; border-top:1px solid rgba(255,255,255,0.14)">
                <p style="font-size:0.78rem; letter-spacing:0.12em; text-transform:uppercase; color:rgba(255,255,255,0.58)">${lane.title}</p>
                <p style="font-size:1.7rem; font-weight:700">${lane.metrics[0]?.value ?? 'Live evidence'}</p>
                <p style="color:rgba(255,255,255,0.72)">${lane.metrics[0]?.note ?? lane.summary}</p>
              </div>
            `).join('')}
          </div>
        </div>
      </section>

      <section class="section" style="padding-bottom:0">
        <div class="wrap" style="max-width:1180px">
          <div style="display:grid; grid-template-columns:minmax(0,1.1fr) minmax(260px,0.9fr); gap:2rem; align-items:end">
            <div>
              <p style="font-size:0.76rem; letter-spacing:0.16em; text-transform:uppercase; color:var(--text-secondary); margin-bottom:0.5rem">Visual thesis</p>
              <h2 style="font-size:clamp(1.8rem,4vw,3.4rem); line-height:0.96; max-width:12ch">Poster-like narrative in public, utility-first detail in ops.</h2>
            </div>
            <div style="color:var(--text-secondary)">
              <p>This wave follows a simple split: Claw EA gets the polished story and explorer gets the dense operator truth. Same workflows, different jobs, no card soup.</p>
            </div>
          </div>
        </div>
      </section>

      ${demoLanes.map(laneSection).join('')}

      <section class="section" style="padding-top:0">
        <div class="wrap" style="max-width:1180px">
          <div style="padding-top:1.1rem; border-top:1px solid rgba(255,255,255,0.12)">
            <p style="font-size:0.76rem; letter-spacing:0.16em; text-transform:uppercase; color:var(--text-secondary); margin-bottom:0.7rem">Generated from source artifacts</p>
            <p style="font-family:var(--mono); color:var(--text-secondary); font-size:0.84rem; margin-bottom:0.85rem">Registry refreshed: ${registry.generated_at}</p>
            <div style="display:grid; gap:0.45rem; font-family:var(--mono); font-size:0.82rem; color:rgba(255,255,255,0.82)">
              ${Object.values(registry.source_artifacts).map((artifactPath) => `<div>${artifactPath}</div>`).join('')}
            </div>
          </div>
        </div>
      </section>

      <section class="section">
        <div class="wrap">
          <div class="cta-banner">
            <h2>Want this level of evidence on your own workflow?</h2>
            <p>Start with one route: pull requests, approvals, or marketplace execution. We will map the evidence path and turn it into a surface your reviewers can actually use.</p>
            <a href="/book" class="cta-btn cta-btn-lg" data-cta="e2e-proof-workflows-book">Book a rollout session</a>
            <a href="https://explorer.clawsig.com/showcase/e2e" class="cta-btn cta-btn-outline cta-btn-lg" style="margin-left:.75rem" data-cta="e2e-proof-workflows-showcase">Open the operator showcase</a>
          </div>
        </div>
      </section>
    `,
  });
}
