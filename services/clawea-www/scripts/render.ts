import type { ArticleDraft } from "./draft-schema";

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function renderDraftToHtml(d: ArticleDraft): string {
  const answerBlock = `
  <div class="glossary-def">
    <strong>Direct answer:</strong> ${esc(d.directAnswer)}
  </div>`;

  const howTo = `
  <section>
    <h2>${esc(d.howToTitle)}</h2>
    <ol>
      ${d.howToSteps
        .map((s) => `<li><strong>${esc(s.name)}:</strong> ${esc(s.text)}</li>`)
        .join("\n")}
    </ol>
  </section>`;

  const sections = d.sections
    .map((s) => {
      const bullets = s.bullets?.length
        ? `<ul>${s.bullets.map((b) => `<li>${esc(b)}</li>`).join("")}</ul>`
        : "";
      const paras = s.paragraphs.map((p) => `<p>${esc(p)}</p>`).join("\n");
      const impact = s.impact
        ? `<p class="impact"><strong>Why it matters:</strong> ${esc(s.impact)}</p>`
        : "";
      return `<section><h2>${esc(s.heading)}</h2>${paras}${bullets}${impact}</section>`;
    })
    .join("\n");

  const templates = d.templates
    ? `
  <section>
    <h2>Deployable templates</h2>
    ${d.templates.openclawConfigJson5 ? `<h3>OpenClaw config (json5)</h3><pre>${esc(d.templates.openclawConfigJson5)}</pre>` : ""}
    ${d.templates.envVars?.length ? `<h3>Environment variables</h3><pre>${esc(d.templates.envVars.join("\n"))}</pre>` : ""}
    ${d.templates.wpcExampleJson ? `<h3>Work Policy Contract example</h3><pre>${esc(d.templates.wpcExampleJson)}</pre>` : ""}
    ${d.templates.deployCurl ? `<h3>Deploy via API</h3><pre>${esc(d.templates.deployCurl)}</pre>` : ""}
  </section>`
    : "";

  const caveats = d.caveats?.length
    ? `
  <section>
    <h2>Common pitfalls</h2>
    <ul>${d.caveats.map((c) => `<li>${esc(c)}</li>`).join("")}</ul>
  </section>`
    : "";

  const faq = `
  <section class="faq">
    <h2>Frequently Asked Questions</h2>
    ${d.faqs
      .map((f) => `<div class="faq-item"><h3>${esc(f.q)}</h3><p>${esc(f.a)}</p></div>`)
      .join("\n")}
  </section>`;

  const citations = `
  <section>
    <h2>Sources</h2>
    <ul>
      ${d.citations
        .map((c) => `<li><a href="${esc(c.url)}" target="_blank" rel="noopener">${esc(c.title || c.url)}</a></li>`)
        .join("\n")}
    </ul>
  </section>`;

  return [
    `<p class="lead">${esc(d.intro)}</p>`,
    answerBlock,
    howTo,
    sections,
    templates,
    caveats,
    faq,
    citations,
  ]
    .filter(Boolean)
    .join("\n\n");
}
