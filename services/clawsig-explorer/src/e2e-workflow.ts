import registry from './generated/e2e-demo-registry.json';
import { esc } from './layout.js';

export interface E2eWorkflowMetric {
  label: string;
  value: string;
  note: string;
}

export interface E2eWorkflow {
  id: string;
  eyebrow: string;
  title: string;
  summary: string;
  evidence: string;
  metrics: E2eWorkflowMetric[];
  steps: string[];
  references?: Record<string, string | null | undefined>;
}

interface DrilldownLink {
  href: string;
  label: string;
}

interface DrilldownOptions {
  anchorId?: string;
  kicker?: string;
  title?: string;
  subtitle?: string;
  primaryLink?: DrilldownLink;
  secondaryLinks?: DrilldownLink[];
}

const workflows = registry.workflows as E2eWorkflow[];

export function getE2eWorkflow(id: string): E2eWorkflow | null {
  return workflows.find((workflow) => workflow.id === id) ?? null;
}

export function renderE2eDrilldownCard(id: string, options: DrilldownOptions = {}): string {
  const workflow = getE2eWorkflow(id);
  if (!workflow) return '';

  const links = [options.primaryLink, ...(options.secondaryLinks ?? [])].filter(
    (value): value is DrilldownLink => Boolean(value),
  );

  return `
    <div class="card"${options.anchorId ? ` id="${esc(options.anchorId)}"` : ''} style="border-color:rgba(0,255,136,0.18); background:linear-gradient(180deg, rgba(0,255,136,0.07), rgba(255,255,255,0.015));">
      <div style="display:flex; justify-content:space-between; gap:1rem; align-items:flex-start; flex-wrap:wrap; margin-bottom:0.8rem">
        <div style="max-width:720px">
          <p class="dim" style="font-size:0.72rem; letter-spacing:0.16em; text-transform:uppercase; margin-bottom:0.4rem">${esc(options.kicker ?? workflow.eyebrow)}</p>
          <h2 style="font-size:1.25rem; line-height:1.05; margin-bottom:0.45rem">${esc(options.title ?? workflow.title)}</h2>
          <p class="dim" style="font-size:0.88rem; max-width:60ch">${esc(options.subtitle ?? workflow.summary)}</p>
        </div>
        <a href="/showcase/e2e#${encodeURIComponent(workflow.id)}" style="font-size:0.82rem; white-space:nowrap">Back to showcase &rarr;</a>
      </div>

      <div style="display:grid; grid-template-columns:minmax(0,1.15fr) minmax(240px,0.85fr); gap:1rem; align-items:start">
        <div style="display:grid; gap:0.75rem">
          <div style="border-top:1px solid var(--border); padding-top:0.75rem">
            <p class="dim" style="font-size:0.7rem; text-transform:uppercase; letter-spacing:0.12em; margin-bottom:0.35rem">Evidence anchor</p>
            <p class="mono" style="font-size:0.78rem; line-height:1.6; color:var(--text)">${esc(workflow.evidence)}</p>
          </div>
          <div style="display:grid; gap:0.45rem">
            ${workflow.steps
              .map(
                (step, index) => `
              <div style="display:grid; grid-template-columns:26px 1fr; gap:0.65rem; align-items:start">
                <div style="width:26px; height:26px; border-radius:999px; border:1px solid rgba(0,255,136,0.28); display:flex; align-items:center; justify-content:center; color:var(--pass); font-weight:700; font-size:0.8rem">${index + 1}</div>
                <p class="dim" style="font-size:0.84rem">${esc(step)}</p>
              </div>`,
              )
              .join('')}
          </div>
        </div>

        <div style="display:grid; gap:0.65rem">
          ${workflow.metrics
            .map(
              (metric) => `
            <div style="padding:0.7rem 0.8rem; border:1px solid rgba(255,255,255,0.08); border-radius:10px; background:rgba(255,255,255,0.02)">
              <p class="dim" style="font-size:0.67rem; text-transform:uppercase; letter-spacing:0.1em">${esc(metric.label)}</p>
              <p style="font-size:1rem; font-weight:700; margin:0.18rem 0">${esc(metric.value)}</p>
              <p class="dim" style="font-size:0.78rem">${esc(metric.note)}</p>
            </div>`,
            )
            .join('')}
          ${links.length > 0 ? `
            <div style="display:flex; flex-wrap:wrap; gap:0.55rem; padding-top:0.15rem">
              ${links
                .map(
                  (link) => `<a href="${esc(link.href)}" style="font-size:0.8rem; border:1px solid rgba(255,255,255,0.1); padding:0.5rem 0.72rem; border-radius:999px; text-decoration:none">${esc(link.label)} &rarr;</a>`,
                )
                .join('')}
            </div>
          ` : ''}
        </div>
      </div>
    </div>
  `;
}
