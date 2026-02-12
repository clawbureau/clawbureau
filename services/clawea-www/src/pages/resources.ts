/**
 * Gated resource pages: /resources/*
 * Email capture → redirect to resource. Lead stored via /api/leads/submit.
 *
 * Turnstile HTML is injected by the caller (index.ts) since turnstile
 * state is resolved in the fetch handler.
 */

import { layout } from "../layout";
import { serviceSchema } from "../seo";

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

interface ResourceGateOpts {
  slug: string;
  formFields: "email-only" | "email-industry";
  resourcePath: string;
  turnstileHtml: string;
}

function resourceGateForm(opts: ResourceGateOpts): string {
  const industryField = opts.formFields === "email-industry"
    ? `
      <label for="industry" class="form-label">Industry</label>
      <select name="industry" id="industry" class="form-select" required>
        <option value="">Select your industry</option>
        <option value="financial-services">Financial Services</option>
        <option value="healthcare">Healthcare</option>
        <option value="government">Government / Public Sector</option>
        <option value="insurance">Insurance</option>
        <option value="legal">Legal</option>
        <option value="technology">Technology</option>
        <option value="other">Other</option>
      </select>`
    : "";

  return `
    <form class="resource-gate-form" id="resource-form" data-resource-path="${esc(opts.resourcePath)}" data-slug="${esc(opts.slug)}">
      <label for="email" class="form-label">Work email</label>
      <input type="email" name="email" id="email" class="form-input" placeholder="you@company.com" required autocomplete="email" />
      ${industryField}
      ${opts.turnstileHtml}
      <button type="submit" class="cta-btn cta-btn-lg" style="width:100%;margin-top:.75rem" data-cta="resource-${esc(opts.slug)}-download">Get the resource</button>
      <p class="form-disclaimer" style="font-size:.8rem;color:var(--text-muted);margin-top:.5rem">We will email you the resource and add you to our monthly insights. Unsubscribe anytime.</p>
      <div id="resource-form-error" class="form-error" style="display:none"></div>
    </form>`;
}

function resourceFormScript(): string {
  return `
<script>
(function() {
  var form = document.getElementById("resource-form");
  if (!form) return;
  form.addEventListener("submit", function(e) {
    e.preventDefault();
    var btn = form.querySelector("button[type=submit]");
    var errEl = document.getElementById("resource-form-error");
    btn.disabled = true;
    btn.textContent = "Submitting...";
    errEl.style.display = "none";

    var email = form.querySelector("[name=email]").value;
    var industry = form.querySelector("[name=industry]");
    var turnstileInput = form.querySelector("[name=cf-turnstile-response]");
    var slug = form.dataset.slug;
    var resourcePath = form.dataset.resourcePath;

    var payload = {
      email: email,
      page: window.location.pathname,
      pageFamily: "resource",
      resourceSlug: slug,
      turnstileToken: turnstileInput ? turnstileInput.value : "",
      attribution: {
        source: document.referrer || "direct",
        utm_campaign: new URLSearchParams(window.location.search).get("utm_campaign") || "",
        utm_source: new URLSearchParams(window.location.search).get("utm_source") || "",
        utm_medium: new URLSearchParams(window.location.search).get("utm_medium") || "",
      },
    };
    if (industry) payload.industry = industry.value;

    fetch("/api/leads/submit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.ok || data.leadId) {
        window.location.href = resourcePath;
      } else {
        errEl.textContent = data.error || "Something went wrong. Please try again.";
        errEl.style.display = "block";
        btn.disabled = false;
        btn.textContent = "Get the resource";
      }
    })
    .catch(function() {
      errEl.textContent = "Network error. Please try again.";
      errEl.style.display = "block";
      btn.disabled = false;
      btn.textContent = "Get the resource";
    });
  });
})();
</script>`;
}

/* ── /resources/protocol-whitepaper ──────────────────────────── */

export function resourceProtocolWhitepaperPage(turnstileHtml: string): string {
  return layout({
    meta: {
      title: "Download: Clawsig Protocol v0.1 Specification | Claw EA",
      description: "Download the Clawsig Protocol v0.1 specification. Five cryptographic primitives for verifiable AI agent execution: WPC, CST, Receipt, Bundle, Verifier.",
      path: "/resources/protocol-whitepaper",
    },
    breadcrumbs: [
      { name: "Home", path: "/" },
      { name: "Resources", path: "/resources/protocol-whitepaper" },
      { name: "Protocol Whitepaper", path: "/resources/protocol-whitepaper" },
    ],
    schemas: [
      serviceSchema("Clawsig Protocol v0.1 Specification", "Downloadable specification for the Clawsig Protocol: five cryptographic primitives for verifiable AI agent execution.", "https://www.clawea.com/resources/protocol-whitepaper"),
    ],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:700px">
        <span class="badge badge-blue">Resource</span>
        <h1>Clawsig Protocol v0.1 Specification</h1>
        <p class="lead">The complete protocol spec in one document. Five primitives, schema definitions, verification algorithm, and coverage semantics.</p>

        <h2>What You Get</h2>
        <ul>
          <li><strong>Work Policy Contract (WPC):</strong> Declarative, content-addressed policy documents</li>
          <li><strong>Capability Scoped Token (CST):</strong> Identity-bound permission tokens with policy pins</li>
          <li><strong>Receipt:</strong> Signed evidence of execution at gateway, tool, and approval boundaries</li>
          <li><strong>Proof Bundle:</strong> Hash-linked event chain with Ed25519 signature over the full run</li>
          <li><strong>Verifier:</strong> Deterministic offline verification algorithm</li>
        </ul>
        <p>The spec includes JSON schema references, reason code taxonomy, and the fail-closed verification algorithm.</p>

        ${resourceGateForm({ slug: "protocol-whitepaper", formFields: "email-only", resourcePath: "/llms-full.txt", turnstileHtml })}
        ${resourceFormScript()}
      </div>
    </section>`,
  });
}

/* ── /resources/security-checklist ───────────────────────────── */

export function resourceSecurityChecklistPage(turnstileHtml: string): string {
  return layout({
    meta: {
      title: "Download: Agent Security Checklist — 15 Controls | Claw EA",
      description: "15 controls every enterprise needs before deploying AI agents. Covers policy enforcement, identity, data protection, monitoring, and incident response.",
      path: "/resources/security-checklist",
    },
    breadcrumbs: [
      { name: "Home", path: "/" },
      { name: "Resources", path: "/resources/security-checklist" },
      { name: "Security Checklist", path: "/resources/security-checklist" },
    ],
    schemas: [
      serviceSchema("Agent Security Checklist: 15 Controls", "Downloadable checklist of 15 controls every enterprise needs before deploying AI agents.", "https://www.clawea.com/resources/security-checklist"),
    ],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:700px">
        <span class="badge badge-blue">Resource</span>
        <h1>Agent Security Checklist: 15 Controls Every Enterprise Needs</h1>
        <p class="lead">A practical checklist for security teams evaluating AI agent deployments. Each control includes what it does, why it matters, and how to verify it is working.</p>

        <h2>What the Checklist Covers</h2>
        <div class="grid-2">
          <div class="card">
            <h3>Policy Enforcement (4 controls)</h3>
            <p>Work Policy Contracts, approval gates, budget limits, forced dry-run</p>
          </div>
          <div class="card">
            <h3>Identity and Access (3 controls)</h3>
            <p>Scoped tokens, two-person rule, credential rotation</p>
          </div>
          <div class="card">
            <h3>Data Protection (4 controls)</h3>
            <p>DLP redaction, secret boundary, egress allowlist, encryption in transit</p>
          </div>
          <div class="card">
            <h3>Monitoring and Response (4 controls)</h3>
            <p>Tamper-evident logs, proof bundles, kill switch, SIEM export</p>
          </div>
        </div>

        ${resourceGateForm({ slug: "security-checklist", formFields: "email-only", resourcePath: "/trust/security-review", turnstileHtml })}
        ${resourceFormScript()}
      </div>
    </section>`,
  });
}

/* ── /resources/compliance-mapping ───────────────────────────── */

export function resourceComplianceMappingPage(turnstileHtml: string): string {
  return layout({
    meta: {
      title: "Download: Regulatory Mapping — SOX, HIPAA, FedRAMP → Agent Controls | Claw EA",
      description: "Map SOX, HIPAA, and FedRAMP requirements to specific AI agent controls. Each regulation paired with the control that satisfies it and the evidence it produces.",
      path: "/resources/compliance-mapping",
    },
    breadcrumbs: [
      { name: "Home", path: "/" },
      { name: "Resources", path: "/resources/compliance-mapping" },
      { name: "Compliance Mapping", path: "/resources/compliance-mapping" },
    ],
    schemas: [
      serviceSchema("Regulatory Compliance Mapping for AI Agents", "SOX, HIPAA, and FedRAMP requirements mapped to AI agent controls.", "https://www.clawea.com/resources/compliance-mapping"),
    ],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:700px">
        <span class="badge badge-blue">Resource</span>
        <h1>Regulatory Mapping: SOX, HIPAA, FedRAMP → Agent Controls</h1>
        <p class="lead">A reference document that maps specific regulatory requirements to the controls that satisfy them and the evidence those controls produce. Built for compliance teams evaluating AI agent governance.</p>

        <h2>Regulations Covered</h2>
        <div class="compare-table-wrap"><table class="compare-table" role="table">
          <thead><tr><th>Regulation</th><th>Key Requirements Mapped</th></tr></thead>
          <tbody>
            <tr><td>SOX (IT General Controls)</td><td>Access controls, change management, monitoring, evidence retention</td></tr>
            <tr><td>HIPAA Security Rule</td><td>Access controls, audit controls, transmission security, PHI handling</td></tr>
            <tr><td>FedRAMP / NIST 800-53</td><td>AC-* (access), AU-* (audit), CA-7 (continuous monitoring), SC-* (system comms)</td></tr>
            <tr><td>SOC 2 (TSC)</td><td>CC6.1 (logical access), CC7.2 (monitoring), CC8.1 (change management)</td></tr>
            <tr><td>EU AI Act (high-risk)</td><td>Transparency, human oversight, logging, risk management</td></tr>
          </tbody>
        </table></div>
        <p>Each mapping includes: the specific requirement, the Claw EA control that addresses it, and the proof artifact that serves as evidence.</p>

        ${resourceGateForm({ slug: "compliance-mapping", formFields: "email-industry", resourcePath: "/trust/security-review", turnstileHtml })}
        ${resourceFormScript()}
      </div>
    </section>`,
  });
}
