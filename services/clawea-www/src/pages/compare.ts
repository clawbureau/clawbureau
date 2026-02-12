/**
 * Comparison pages: /compare/*
 * High-intent "vs" and landscape pages for enterprise buyers.
 */

import { layout } from "../layout";
import { faqSchema, serviceSchema } from "../seo";

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

interface CompareRow {
  dimension: string;
  claw: string;
  other: string;
}

function renderCompareTable(otherLabel: string, rows: CompareRow[]): string {
  return `<div class="compare-table-wrap"><table class="compare-table" role="table">
    <thead><tr><th>Dimension</th><th>Claw EA</th><th>${esc(otherLabel)}</th></tr></thead>
    <tbody>${rows
      .map(
        (r) =>
          `<tr><td>${esc(r.dimension)}</td><td>${esc(r.claw)}</td><td>${esc(r.other)}</td></tr>`,
      )
      .join("")}</tbody>
  </table></div>`;
}

function compareCtaBanner(): string {
  return `
    <section class="section">
      <div class="wrap">
        <div class="cta-banner">
          <h2>See how this maps to your environment</h2>
          <p>Take the two-minute assessment. We map controls, receipts, and proof requirements to your stack.</p>
          <a href="/assessment" class="cta-btn cta-btn-lg" data-cta="compare-assessment">Take the assessment</a>
          <a href="/trust/security-review" class="cta-btn cta-btn-outline cta-btn-lg" style="margin-left:.75rem" data-cta="compare-security-review">Security Review Pack</a>
        </div>
      </div>
    </section>`;
}

/* ── /compare/claw-vs-manual-audit ───────────────────────────── */

export function compareManualAuditPage(): string {
  const rows: CompareRow[] = [
    { dimension: "Evidence format", claw: "Signed JSON proof bundles (Ed25519)", other: "Spreadsheets, screenshots, email threads" },
    { dimension: "Tamper detection", claw: "SHA-256 hash chain + Merkle root", other: "None; files are mutable" },
    { dimension: "Verification", claw: "Offline deterministic (any party)", other: "Manual review by auditor" },
    { dimension: "Collection effort", claw: "Automatic per run (zero marginal cost)", other: "Hours of manual work per control" },
    { dimension: "Retention", claw: "Append-only transparency log", other: "Shared drive with version conflicts" },
    { dimension: "Third-party verifiable", claw: "Yes (public key + proof bundle)", other: "No (trust the sender)" },
    { dimension: "Coverage gap detection", claw: "Explicit coverage matrix (M/MT/MTS)", other: "Unknown until audit" },
  ];

  return layout({
    meta: {
      title: "Claw EA vs Manual Audit Evidence | Comparison",
      description: "Compare automated proof bundles with cryptographic receipts against manual evidence collection using spreadsheets and screenshots.",
      path: "/compare/claw-vs-manual-audit",
    },
    breadcrumbs: [
      { name: "Home", path: "/" },
      { name: "Compare", path: "/compare/claw-vs-manual-audit" },
      { name: "vs Manual Audit", path: "/compare/claw-vs-manual-audit" },
    ],
    schemas: [
      serviceSchema("Claw EA vs Manual Audit Evidence", "Comparison of automated proof bundles vs manual evidence collection for enterprise AI agent compliance.", "https://www.clawea.com/compare/claw-vs-manual-audit"),
    ],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:900px">
        <span class="badge badge-blue">Comparison</span>
        <h1>Automated Proof Bundles vs Manual Audit Evidence</h1>
        <p class="lead">Most enterprises collect AI compliance evidence the same way they collect SOX evidence: manually. Spreadsheets, screenshots, and "trust me" emails. Claw EA replaces that with cryptographic proof bundles generated automatically on every run.</p>

        <h2>Head-to-Head</h2>
        ${renderCompareTable("Manual audit evidence", rows)}

        <h2>The Core Problem</h2>
        <p>Manual evidence collection does not scale to autonomous agents. An agent that runs 50 workflows per day generates 50 evidence collection tasks. Each task requires a human to screenshot, export, annotate, and file the evidence. Within a month, the evidence backlog exceeds the team's capacity, and gaps appear.</p>
        <p>Proof bundles solve this by making evidence generation a side effect of execution. Every model call produces a gateway receipt. Every tool invocation produces a hashed event. The bundle is signed and sealed automatically. Zero marginal cost per run.</p>

        <h2>When Manual Evidence Still Makes Sense</h2>
        <p>Manual collection is appropriate for one-off assessments, governance reviews that require human judgment, and situations where agent tooling is not yet deployed. If you run fewer than 5 agent workflows per week, the overhead of proof infrastructure may not be justified yet.</p>
        <p>The transition path: start with one workflow on proof bundles (a <a href="/workflows/production-deploy-approval">production deploy approval</a> is the most common starting point), then expand as evidence volume grows.</p>

        <h2>Offline Verification</h2>
        <p>The key differentiator is third-party verifiability. A proof bundle can be verified by your auditor, your customer, or a regulator without calling any Claw API. They need only the agent's public key and the bundle JSON. Manual evidence requires trusting the person who collected it.</p>
        <p>See the full technical breakdown in the <a href="/trust/security-review">Security Review Pack</a>.</p>
      </div>
    </section>
    ${compareCtaBanner()}`,
  });
}

/* ── /compare/claw-vs-guardrails ──────────────────────────────── */

export function compareGuardrailsPage(): string {
  const rows: CompareRow[] = [
    { dimension: "Primary function", claw: "Proof of what happened (receipts + bundles)", other: "Prevent harmful outputs (inference-time filtering)" },
    { dimension: "Enforcement point", claw: "Gateway + tool boundary + policy engine", other: "Model input/output layer" },
    { dimension: "Evidence produced", claw: "Signed receipts, hash-linked event chain, proof bundle", other: "Block/allow decision logs" },
    { dimension: "Offline verifiable", claw: "Yes (Ed25519 + SHA-256)", other: "No (requires platform access)" },
    { dimension: "Policy model", claw: "Declarative WPC (signed, immutable, content-addressed)", other: "Rule sets and classifiers (mutable)" },
    { dimension: "Scope", claw: "Full execution lifecycle (model + tools + side effects)", other: "Model I/O only" },
    { dimension: "Tamper evidence", claw: "Merkle transparency log", other: "Application logs (mutable)" },
    { dimension: "Complementary", claw: "Yes: guardrails can run inside a Claw-receipted pipeline", other: "Yes: output filtering + proof are orthogonal" },
  ];

  return layout({
    meta: {
      title: "Claw EA vs Guardrails (NeMo, Guardrails AI) | Comparison",
      description: "Compare protocol-level proof of execution against inference-time guardrails. Different problems, complementary solutions.",
      path: "/compare/claw-vs-guardrails",
    },
    breadcrumbs: [
      { name: "Home", path: "/" },
      { name: "Compare", path: "/compare/claw-vs-guardrails" },
      { name: "vs Guardrails", path: "/compare/claw-vs-guardrails" },
    ],
    schemas: [
      serviceSchema("Claw EA vs Inference Guardrails", "Comparison of protocol-level proof bundles vs inference-time guardrails for enterprise AI governance.", "https://www.clawea.com/compare/claw-vs-guardrails"),
    ],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:900px">
        <span class="badge badge-blue">Comparison</span>
        <h1>Protocol-Level Proof vs Inference-Time Guardrails</h1>
        <p class="lead">Guardrails (NVIDIA NeMo Guardrails, Guardrails AI, custom wrappers) filter what models say. Claw EA proves what agents did. These solve different problems and work well together.</p>

        <h2>Head-to-Head</h2>
        ${renderCompareTable("Inference guardrails", rows)}

        <h2>Different Layers, Different Questions</h2>
        <p>Guardrails answer: "Did the model output something harmful?" They operate at the inference layer, filtering or blocking specific patterns in model input and output.</p>
        <p>Claw EA answers: "Can you prove what the agent did, where it ran, and under what policy?" It operates at the execution layer, producing cryptographic evidence of the full lifecycle.</p>
        <p>An enterprise that deploys guardrails still cannot answer an auditor who asks "prove this agent only accessed approved systems." An enterprise that deploys Claw EA can, because every boundary crossing produces a signed receipt.</p>

        <h2>Using Them Together</h2>
        <p>The strongest posture combines both. Run guardrails inside a Claw-receipted pipeline: the guardrail filters harmful outputs, and the receipt chain proves the guardrail was active. A gateway receipt from <a href="/proof/gateway-receipts">clawproxy</a> will capture that the model call was mediated, and the tool receipt will capture that the guardrail check ran.</p>
        <p><a href="/policy/work-policy-contract">Work Policy Contracts</a> can enforce that guardrail middleware is required for specific models or use cases.</p>
      </div>
    </section>
    ${compareCtaBanner()}`,
  });
}

/* ── /compare/claw-vs-langfuse ────────────────────────────────── */

export function compareLangfusePage(): string {
  const rows: CompareRow[] = [
    { dimension: "Primary function", claw: "Cryptographic proof of execution", other: "Observability and analytics" },
    { dimension: "Data model", claw: "Signed receipts + hash-linked events", other: "Traces, spans, and metrics" },
    { dimension: "Verification", claw: "Offline deterministic (Ed25519 + SHA-256)", other: "Dashboard inspection (online)" },
    { dimension: "Tamper evidence", claw: "Yes (Merkle log + signed bundles)", other: "No (mutable database)" },
    { dimension: "Third-party audit", claw: "Yes (give auditor the bundle)", other: "No (give auditor dashboard access)" },
    { dimension: "Policy enforcement", claw: "Built-in (WPC + approval gates)", other: "Alerting only" },
    { dimension: "Cost attribution", claw: "Per-receipt token counts, tied to run", other: "Per-trace token counts, aggregate" },
    { dimension: "Complementary", claw: "Yes: use Langfuse for dashboards, Claw for proof", other: "Yes: observability + proof are orthogonal" },
  ];

  return layout({
    meta: {
      title: "Claw EA vs Langfuse | Receipts vs Observability",
      description: "Compare cryptographic receipts with offline verification against observability dashboards. Proof and monitoring solve different compliance requirements.",
      path: "/compare/claw-vs-langfuse",
    },
    breadcrumbs: [
      { name: "Home", path: "/" },
      { name: "Compare", path: "/compare/claw-vs-langfuse" },
      { name: "vs Langfuse", path: "/compare/claw-vs-langfuse" },
    ],
    schemas: [
      serviceSchema("Claw EA vs Langfuse", "Comparison of cryptographic proof of execution vs LLM observability platforms.", "https://www.clawea.com/compare/claw-vs-langfuse"),
    ],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:900px">
        <span class="badge badge-blue">Comparison</span>
        <h1>Cryptographic Receipts vs Observability Dashboards</h1>
        <p class="lead">Langfuse, Helicone, and similar platforms show you what happened. Claw EA proves it. The difference matters when an auditor, regulator, or customer asks for evidence.</p>

        <h2>Head-to-Head</h2>
        ${renderCompareTable("Observability (Langfuse, Helicone, etc.)", rows)}

        <h2>Why Observability Is Not Proof</h2>
        <p>An observability dashboard is a view into a mutable database. The platform operator can edit records, the database can be modified, and there is no way for a third party to verify that the dashboard reflects what actually happened.</p>
        <p>A proof bundle is a self-contained, signed artifact. The agent's Ed25519 signature covers a hash of every event. The gateway's signature covers every model call. Modify any byte and the signatures fail. No platform access required to verify.</p>

        <h2>Using Them Together</h2>
        <p>Most enterprises will use both. Observability for day-to-day monitoring, debugging, and cost optimization. Proof bundles for audit, compliance, and third-party verification. The data can flow from the same execution; they just serve different stakeholders.</p>
        <p>Claw EA's <a href="/agent-audit-and-replay">audit and replay</a> capabilities complement observability by providing the evidence chain that dashboards alone cannot produce.</p>
      </div>
    </section>
    ${compareCtaBanner()}`,
  });
}

/* ── /compare/claw-vs-custom-wrappers ─────────────────────────── */

export function compareCustomWrappersPage(): string {
  const rows: CompareRow[] = [
    { dimension: "Evidence standard", claw: "Protocol-defined schemas (versioned, interoperable)", other: "Ad-hoc logging (custom per team)" },
    { dimension: "Signing", claw: "Ed25519 per receipt + per bundle", other: "None (log entries are unsigned)" },
    { dimension: "Verification", claw: "Deterministic offline verifier", other: "Grep through logs" },
    { dimension: "Receipt binding", claw: "Receipts bound to event chain via run_id + event_hash", other: "Log correlation by timestamp (approximate)" },
    { dimension: "Policy enforcement", claw: "Content-addressed WPC pinned in receipts", other: "Config file (version unknown at audit time)" },
    { dimension: "Maintenance cost", claw: "Protocol handles versioning and schema evolution", other: "Team maintains custom wrappers per model/tool" },
    { dimension: "Third-party trust", claw: "Verifiable by anyone with the public key", other: "Trust the team that wrote the wrapper" },
  ];

  return layout({
    meta: {
      title: "Claw EA vs Custom Wrappers | Protocol Receipts vs Ad-Hoc Logging",
      description: "Compare protocol-level cryptographic receipts against custom wrapper logging for enterprise AI agents. Standardized evidence vs team-maintained infrastructure.",
      path: "/compare/claw-vs-custom-wrappers",
    },
    breadcrumbs: [
      { name: "Home", path: "/" },
      { name: "Compare", path: "/compare/claw-vs-custom-wrappers" },
      { name: "vs Custom Wrappers", path: "/compare/claw-vs-custom-wrappers" },
    ],
    schemas: [
      serviceSchema("Claw EA vs Custom Wrappers", "Comparison of protocol-level receipts vs ad-hoc custom wrapper logging for enterprise AI agents.", "https://www.clawea.com/compare/claw-vs-custom-wrappers"),
    ],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:900px">
        <span class="badge badge-blue">Comparison</span>
        <h1>Protocol-Level Receipts vs Custom Wrapper Logging</h1>
        <p class="lead">Most teams start with custom wrappers: intercept the API call, log the request and response, store it somewhere. This works until an auditor asks "prove this log was not modified." Protocol-level receipts answer that question by design.</p>

        <h2>Head-to-Head</h2>
        ${renderCompareTable("Custom wrappers / ad-hoc logging", rows)}

        <h2>The Wrapper Tax</h2>
        <p>Every custom wrapper is a maintenance liability. When the model provider changes their API, the wrapper breaks. When you add a new model, you write a new wrapper. When you need to prove what happened six months ago, you hope the log schema has not changed.</p>
        <p>Protocol-level receipts are versioned, schema-defined, and interoperable. A receipt from today and a receipt from six months ago both verify against the same algorithm. The <a href="/proof/proof-bundles">proof bundle</a> schema evolves additively, and unknown versions fail closed in the <a href="/proof/gateway-receipts">verifier</a>.</p>

        <h2>Migration Path</h2>
        <p>You do not need to rip out custom wrappers overnight. Route model calls through <a href="/proof/gateway-receipts">clawproxy</a> to start generating gateway receipts alongside your existing logging. The receipts add a signed evidence layer on top of whatever you already have.</p>
      </div>
    </section>
    ${compareCtaBanner()}`,
  });
}

/* ── /compare/agent-governance-platforms ──────────────────────── */

export function compareGovernanceLandscapePage(): string {
  return layout({
    meta: {
      title: "Agent Governance Platforms | Landscape Comparison | Claw EA",
      description: "How Claw EA compares to agent governance approaches: guardrails, observability, custom wrappers, and manual audit. Protocol-first architecture for verifiable execution.",
      path: "/compare/agent-governance-platforms",
    },
    breadcrumbs: [
      { name: "Home", path: "/" },
      { name: "Compare", path: "/compare/agent-governance-platforms" },
      { name: "Governance Platforms", path: "/compare/agent-governance-platforms" },
    ],
    schemas: [
      serviceSchema("Agent Governance Platform Landscape", "Comparison of approaches to enterprise AI agent governance: protocol-first proof, guardrails, observability, custom wrappers, and manual audit.", "https://www.clawea.com/compare/agent-governance-platforms"),
      faqSchema([
        { q: "What makes Claw EA different from other agent governance platforms?", a: "Claw EA is protocol-first: it defines cryptographic primitives (receipts, bundles, verifier) rather than building another dashboard or rule engine. The result is evidence that any third party can verify offline, without trusting the platform operator." },
        { q: "Can I use Claw EA with existing observability tools?", a: "Yes. Claw EA is complementary to observability (Langfuse, Helicone, Datadog). Use observability for monitoring and debugging; use proof bundles for audit, compliance, and third-party verification." },
        { q: "Does Claw EA replace guardrails?", a: "No. Guardrails filter model I/O. Claw EA proves what happened. The strongest posture uses both: guardrails for prevention, proof bundles for accountability." },
      ]),
    ],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:900px">
        <span class="badge badge-blue">Landscape</span>
        <h1>Agent Governance: Approaches Compared</h1>
        <p class="lead">Enterprises governing AI agents face a choice between prevention (guardrails), visibility (observability), evidence (proof), and process (manual audit). These are not mutually exclusive. Here is how they compare and where each fits.</p>

        <h2>The Four Approaches</h2>
        <div class="grid-2">
          <div class="card">
            <h3>1. Inference Guardrails</h3>
            <p><strong>What:</strong> Filter model input/output to prevent harmful content.</p>
            <p><strong>Strengths:</strong> Prevent specific failure modes in real time.</p>
            <p><strong>Gaps:</strong> No evidence of what actually happened. No tool/side-effect coverage. Mutable rules.</p>
            <p><a href="/compare/claw-vs-guardrails">Detailed comparison &rarr;</a></p>
          </div>
          <div class="card">
            <h3>2. Observability Platforms</h3>
            <p><strong>What:</strong> Trace, monitor, and visualize LLM calls and agent behavior.</p>
            <p><strong>Strengths:</strong> Debugging, cost tracking, performance optimization.</p>
            <p><strong>Gaps:</strong> Mutable data. Not third-party verifiable. Dashboard is not evidence.</p>
            <p><a href="/compare/claw-vs-langfuse">Detailed comparison &rarr;</a></p>
          </div>
          <div class="card">
            <h3>3. Custom Wrappers</h3>
            <p><strong>What:</strong> Team-built interceptors that log API calls and tool invocations.</p>
            <p><strong>Strengths:</strong> Flexible. Low initial cost. Team-controlled.</p>
            <p><strong>Gaps:</strong> No standard schema. No signing. High maintenance. Auditors cannot verify independently.</p>
            <p><a href="/compare/claw-vs-custom-wrappers">Detailed comparison &rarr;</a></p>
          </div>
          <div class="card">
            <h3>4. Protocol-First Proof (Claw EA)</h3>
            <p><strong>What:</strong> Cryptographic receipts at every enforcement boundary, compiled into signed proof bundles.</p>
            <p><strong>Strengths:</strong> Offline verification. Tamper-evident. Third-party auditable. Explicit coverage claims.</p>
            <p><strong>Gaps:</strong> Does not prevent harmful outputs (use guardrails). Does not replace monitoring dashboards (use observability).</p>
            <p><a href="/trust/security-review">Security Review Pack &rarr;</a></p>
          </div>
        </div>

        <h2>When to Use What</h2>
        <div class="compare-table-wrap"><table class="compare-table" role="table">
          <thead><tr><th>Requirement</th><th>Best approach</th></tr></thead>
          <tbody>
            <tr><td>Prevent harmful model outputs</td><td>Inference guardrails</td></tr>
            <tr><td>Debug agent behavior in real time</td><td>Observability</td></tr>
            <tr><td>Prove to an auditor what happened</td><td>Proof bundles (Claw EA)</td></tr>
            <tr><td>Enforce policy before execution</td><td>Policy-as-code (Claw EA WPC)</td></tr>
            <tr><td>Track cost and token usage</td><td>Observability or receipts</td></tr>
            <tr><td>Third-party verification</td><td>Proof bundles (Claw EA)</td></tr>
            <tr><td>Quick prototype logging</td><td>Custom wrappers</td></tr>
            <tr><td>Compliance evidence (SOC 2, SOX)</td><td>Proof bundles + <a href="/compare/claw-vs-manual-audit">automated collection</a></td></tr>
          </tbody>
        </table></div>

        <h2>The Protocol Advantage</h2>
        <p>Most governance tools are products: closed platforms with proprietary formats. Claw EA is built on a protocol: five open primitives (WPC, CST, Receipt, Bundle, Verifier) with published schemas and a reference verifier. This means your evidence is not locked to a vendor. If you stop using Claw EA tomorrow, your proof bundles still verify.</p>
      </div>
    </section>
    ${compareCtaBanner()}`,
  });
}
