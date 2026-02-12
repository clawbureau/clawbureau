/**
 * Industry vertical pages: /industries/*
 * Regulated-industry pages targeting "[industry] + AI agent governance" searches.
 */

import { layout } from "../layout";
import { faqSchema, serviceSchema } from "../seo";

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function industryCtaBanner(slug: string): string {
  return `
    <section class="section">
      <div class="wrap">
        <div class="cta-banner">
          <h2>Map your controls to your stack</h2>
          <p>The two-minute assessment scores your readiness and maps controls to your environment.</p>
          <a href="/assessment" class="cta-btn cta-btn-lg" data-cta="industry-${esc(slug)}-assessment">Take the assessment</a>
          <a href="/trust/security-review" class="cta-btn cta-btn-outline cta-btn-lg" style="margin-left:.75rem" data-cta="industry-${esc(slug)}-security-review">Security Review Pack</a>
          <a href="/book" class="cta-btn cta-btn-outline cta-btn-lg" style="margin-left:.75rem" data-cta="industry-${esc(slug)}-book">Book a session</a>
        </div>
      </div>
    </section>`;
}

function controlCard(title: string, path: string, desc: string): string {
  return `<div class="card"><h4><a href="${esc(path)}">${esc(title)}</a></h4><p>${esc(desc)}</p></div>`;
}

function workflowLink(title: string, path: string): string {
  return `<li><a href="${esc(path)}">${esc(title)}</a></li>`;
}

/* ── /industries/financial-services ──────────────────────────── */

export function industryFinancialServicesPage(): string {
  return layout({
    meta: {
      title: "AI Agent Compliance for Financial Services | Claw EA",
      description: "How banks, asset managers, and fintechs deploy AI agents with SOX-grade evidence, budget controls, approval gates, and tamper-evident audit logs.",
      path: "/industries/financial-services",
    },
    breadcrumbs: [
      { name: "Home", path: "/" },
      { name: "Industries", path: "/industries/financial-services" },
      { name: "Financial Services", path: "/industries/financial-services" },
    ],
    schemas: [
      serviceSchema("AI Agent Compliance for Financial Services", "Enterprise AI agent governance for banking, asset management, and fintech with SOX-grade evidence.", "https://www.clawea.com/industries/financial-services"),
      faqSchema([
        { q: "How does Claw EA help with SOX compliance for AI agents?", a: "Every agent action produces a signed proof bundle with gateway receipts and event hashes. These proof bundles map directly to SOX IT general controls for access management, change management, and monitoring. Auditors can verify evidence offline without platform access." },
        { q: "Can AI agents be given spending authority with proper controls?", a: "Yes. Budget controls enforce per-run and per-day spending limits at the policy layer. Approval gates require human sign-off before high-value actions execute. Both controls produce receipts that prove enforcement occurred." },
        { q: "What audit log retention does Claw EA offer for financial services?", a: "Enterprise tier includes 7-year audit log retention with tamper-evident storage. Proof bundles are append-only and hash-linked, making post-hoc modification detectable." },
      ]),
    ],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:900px">
        <span class="badge badge-blue">Financial Services</span>
        <h1>AI Agent Governance for Banks, Asset Managers, and Fintechs</h1>
        <p class="lead">Financial services firms operate under overlapping regulations (SOX, OCC guidance, FFIEC, MAS TRM, PRA) that require provable controls on any system that touches financial data or executes transactions. AI agents are no exception.</p>

        <h2>What Goes Wrong Without Controls</h2>
        <p>A mid-size bank deploys 12 agents to automate trade reconciliation, compliance reporting, and customer onboarding. Within three months:</p>
        <ul>
          <li>An agent processes a batch of 400 reconciliation entries without approval — one entry contains a $2.3M discrepancy that propagates to downstream reports</li>
          <li>An auditor asks for evidence that agents only accessed approved data sources during Q3 — the team has application logs but nothing the auditor can independently verify</li>
          <li>A model provider outage causes an agent to retry with a different model that has not been approved for production use — no policy prevented the fallback</li>
        </ul>
        <p>Each of these is a control failure that produces a finding. Proof-first architecture prevents all three.</p>

        <h2>Regulatory Mapping</h2>
        <div class="compare-table-wrap"><table class="compare-table" role="table">
          <thead><tr><th>Regulation / Standard</th><th>Requirement</th><th>Claw EA Control</th></tr></thead>
          <tbody>
            <tr><td>SOX (ITGC)</td><td>Access controls, change management, monitoring</td><td><a href="/policy/scoped-tokens">Scoped tokens</a>, <a href="/controls/approval-gates">approval gates</a>, <a href="/proof/proof-bundles">proof bundles</a></td></tr>
            <tr><td>OCC Bulletin 2023-35</td><td>Third-party risk management for AI/ML</td><td><a href="/proof/gateway-receipts">Gateway receipts</a> prove which models were called and under what policy</td></tr>
            <tr><td>FFIEC Handbook</td><td>IT audit, business continuity, operations</td><td><a href="/audit/tamper-evident-logs">Tamper-evident logs</a>, <a href="/controls/kill-switch">kill switch</a></td></tr>
            <tr><td>MAS TRM</td><td>Technology risk management (Singapore)</td><td><a href="/controls/egress-allowlist">Egress allowlist</a>, <a href="/controls/two-person-rule">two-person rule</a></td></tr>
          </tbody>
        </table></div>

        <h2>Recommended Control Stack</h2>
        <div class="grid-2">
          ${controlCard("Budget Controls", "/controls/budget-controls", "Per-run and per-day spending limits enforced at the policy layer. Prevents runaway costs and unauthorized financial exposure.")}
          ${controlCard("Approval Gates", "/controls/approval-gates", "Human-in-the-loop sign-off before high-value actions execute. Receipt proves the approval occurred and who approved.")}
          ${controlCard("Tamper-Evident Logs", "/audit/tamper-evident-logs", "Append-only, hash-linked audit trail. Modification of any entry invalidates the chain. Auditor-verifiable offline.")}
          ${controlCard("Scoped Tokens", "/policy/scoped-tokens", "Capability tokens bound to identity groups. Agents can only access systems their token permits.")}
        </div>

        <h2>Relevant Workflows</h2>
        <ul>
          ${workflowLink("SOX Control Testing", "/workflows/sox-control-testing")}
          ${workflowLink("Production Deploy Approval", "/workflows/production-deploy-approval")}
          ${workflowLink("SIEM Evidence Collection", "/workflows/siem-evidence-collection")}
          ${workflowLink("Contract Review Approval", "/workflows/contract-review-approval")}
        </ul>
      </div>
    </section>
    ${industryCtaBanner("financial-services")}`,
  });
}

/* ── /industries/healthcare ──────────────────────────────────── */

export function industryHealthcarePage(): string {
  return layout({
    meta: {
      title: "AI Agent HIPAA Compliance | Healthcare | Claw EA",
      description: "Deploy AI agents in healthcare with HIPAA-aligned controls: DLP redaction, secret boundaries, egress allowlists, and tamper-evident audit retention.",
      path: "/industries/healthcare",
    },
    breadcrumbs: [
      { name: "Home", path: "/" },
      { name: "Industries", path: "/industries/healthcare" },
      { name: "Healthcare", path: "/industries/healthcare" },
    ],
    schemas: [
      serviceSchema("AI Agent HIPAA Compliance for Healthcare", "Enterprise AI agent governance for healthcare with HIPAA-aligned controls.", "https://www.clawea.com/industries/healthcare"),
      faqSchema([
        { q: "How does Claw EA prevent PHI exposure by AI agents?", a: "DLP redaction strips protected health information before it reaches model providers. Egress allowlists restrict which external endpoints agents can contact. Secret boundaries prevent credential leakage. All three controls produce signed receipts proving enforcement." },
        { q: "Can Claw EA support a BAA for HIPAA compliance?", a: "Enterprise tier includes BAA/DPA availability. The architecture is designed so that PHI never leaves your approved boundary — DLP redaction runs before model calls, not after." },
        { q: "How long are audit logs retained for healthcare compliance?", a: "HIPAA requires 6-year retention for security-relevant records. Enterprise tier provides 7-year tamper-evident retention with hash-linked proof chains." },
      ]),
    ],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:900px">
        <span class="badge badge-blue">Healthcare</span>
        <h1>AI Agent Governance for Healthcare and Life Sciences</h1>
        <p class="lead">Healthcare organizations deploying AI agents face HIPAA, HITECH, and 21 CFR Part 11 requirements that demand provable data handling controls. An agent that touches patient data, clinical notes, or billing records must operate within a verifiable boundary.</p>

        <h2>What Goes Wrong Without Controls</h2>
        <p>A regional health system deploys agents to automate clinical documentation, insurance pre-authorization, and patient scheduling. Within weeks:</p>
        <ul>
          <li>An agent summarizing clinical notes sends a prompt containing a patient's name, DOB, and diagnosis to a third-party model API — a HIPAA breach reportable to HHS</li>
          <li>A scheduling agent accesses the EHR API to check availability but also pulls patient records it does not need — excessive access with no boundary enforcement</li>
          <li>An auditor asks for evidence that PHI was redacted before every model call during Q2 — the team has no receipts, only application logs that show the call was made</li>
        </ul>
        <p>DLP redaction, egress allowlists, and proof bundles prevent all three scenarios and produce the evidence to prove it.</p>

        <h2>Regulatory Mapping</h2>
        <div class="compare-table-wrap"><table class="compare-table" role="table">
          <thead><tr><th>Regulation</th><th>Requirement</th><th>Claw EA Control</th></tr></thead>
          <tbody>
            <tr><td>HIPAA Security Rule</td><td>Access controls, audit controls, transmission security</td><td><a href="/controls/dlp-redaction">DLP redaction</a>, <a href="/controls/egress-allowlist">egress allowlist</a>, <a href="/proof/proof-bundles">proof bundles</a></td></tr>
            <tr><td>HITECH Act</td><td>Breach notification, increased penalties</td><td><a href="/controls/secret-boundary">Secret boundary</a> prevents credential/PHI leakage; receipts prove containment</td></tr>
            <tr><td>21 CFR Part 11</td><td>Electronic records, electronic signatures</td><td>Ed25519 signatures on every receipt and bundle satisfy electronic signature requirements</td></tr>
            <tr><td>State privacy (CCPA, etc.)</td><td>Data minimization, access logging</td><td><a href="/policy/scoped-tokens">Scoped tokens</a> enforce data minimization; <a href="/audit/tamper-evident-logs">tamper-evident logs</a> provide access records</td></tr>
          </tbody>
        </table></div>

        <h2>Recommended Control Stack</h2>
        <div class="grid-2">
          ${controlCard("DLP Redaction", "/controls/dlp-redaction", "Strip PHI (names, DOB, MRN, diagnoses) from prompts before they reach any model provider. Receipt proves redaction occurred.")}
          ${controlCard("Secret Boundary", "/controls/secret-boundary", "Prevent credentials and sensitive tokens from appearing in model context. Enforced at the gateway layer.")}
          ${controlCard("Egress Allowlist", "/controls/egress-allowlist", "Restrict which external APIs and endpoints agents can contact. Unauthorized destinations are blocked and logged.")}
          ${controlCard("Audit Log Retention", "/audit/tamper-evident-logs", "7-year tamper-evident retention with hash-linked proof chains. Meets HIPAA 6-year minimum with margin.")}
        </div>

        <h2>Relevant Workflows</h2>
        <ul>
          ${workflowLink("SIEM Evidence Collection", "/workflows/siem-evidence-collection")}
          ${workflowLink("Access Request Automation", "/workflows/access-request-automation")}
          ${workflowLink("Contract Review Approval", "/workflows/contract-review-approval")}
        </ul>
      </div>
    </section>
    ${industryCtaBanner("healthcare")}`,
  });
}

/* ── /industries/government ──────────────────────────────────── */

export function industryGovernmentPage(): string {
  return layout({
    meta: {
      title: "AI Agent FedRAMP & Government Compliance | Claw EA",
      description: "Deploy AI agents in government environments with FedRAMP-aligned controls: two-person rule, kill switch, forced dry-run, and tamper-evident transparency logs.",
      path: "/industries/government",
    },
    breadcrumbs: [
      { name: "Home", path: "/" },
      { name: "Industries", path: "/industries/government" },
      { name: "Government", path: "/industries/government" },
    ],
    schemas: [
      serviceSchema("AI Agent Governance for Government", "Enterprise AI agent governance for federal, state, and local government with FedRAMP-aligned controls.", "https://www.clawea.com/industries/government"),
      faqSchema([
        { q: "How does Claw EA align with FedRAMP requirements?", a: "Claw EA enforces access controls via scoped capability tokens, continuous monitoring via signed proof bundles, and incident response via kill switch and forced dry-run modes. All evidence is cryptographically signed and offline-verifiable, satisfying FedRAMP continuous monitoring requirements." },
        { q: "Does Claw EA support two-person rule for sensitive government workflows?", a: "Yes. The two-person rule control requires two distinct human approvals before high-impact actions execute. Each approval produces a signed receipt with the approver identity and timestamp." },
        { q: "Can agents be tested without side effects in government environments?", a: "Forced dry-run mode executes the full agent workflow without committing side effects. The proof bundle records the entire execution so reviewers can inspect agent behavior before granting live permissions." },
      ]),
    ],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:900px">
        <span class="badge badge-blue">Government</span>
        <h1>AI Agent Governance for Federal, State, and Local Government</h1>
        <p class="lead">Government agencies operate under Executive Order 14110 (Safe AI), OMB M-24-10, FedRAMP, and NIST 800-53 controls. AI agents that process government data or execute government functions must demonstrate compliance through verifiable evidence, not self-attestation.</p>

        <h2>What Goes Wrong Without Controls</h2>
        <p>A federal agency deploys agents to automate FOIA request processing, IT ticket triage, and procurement document review. Within the first quarter:</p>
        <ul>
          <li>An agent processing FOIA requests sends document contents to an unapproved commercial model API — data leaves the authorized boundary without detection</li>
          <li>A procurement agent approves a contract modification autonomously because no two-person rule was enforced — the modification exceeds the agent's delegated authority</li>
          <li>An IG investigation asks for evidence of agent behavior during a specific incident — the team has CloudWatch logs but nothing cryptographically signed or independently verifiable</li>
        </ul>

        <h2>Regulatory Mapping</h2>
        <div class="compare-table-wrap"><table class="compare-table" role="table">
          <thead><tr><th>Requirement</th><th>Source</th><th>Claw EA Control</th></tr></thead>
          <tbody>
            <tr><td>AI risk management</td><td>EO 14110, OMB M-24-10</td><td><a href="/policy/work-policy-contract">Work Policy Contracts</a> declare permitted actions; <a href="/controls/kill-switch">kill switch</a> halts execution</td></tr>
            <tr><td>Continuous monitoring</td><td>FedRAMP, NIST 800-53 CA-7</td><td><a href="/proof/proof-bundles">Proof bundles</a> per run; <a href="/audit/tamper-evident-logs">Merkle transparency log</a></td></tr>
            <tr><td>Access control</td><td>NIST 800-53 AC-*</td><td><a href="/policy/scoped-tokens">Capability scoped tokens</a> with group-based permissions</td></tr>
            <tr><td>Separation of duties</td><td>NIST 800-53 AC-5</td><td><a href="/controls/two-person-rule">Two-person rule</a> with signed approval receipts</td></tr>
            <tr><td>Audit and accountability</td><td>NIST 800-53 AU-*</td><td><a href="/audit/tamper-evident-logs">Tamper-evident logs</a> with 7-year retention</td></tr>
          </tbody>
        </table></div>

        <h2>Recommended Control Stack</h2>
        <div class="grid-2">
          ${controlCard("Two-Person Rule", "/controls/two-person-rule", "Require two distinct approvals before high-impact actions. Each approval is a signed receipt with identity and timestamp.")}
          ${controlCard("Kill Switch", "/controls/kill-switch", "Immediately halt all agent execution across the fleet. Single command, takes effect within seconds, produces a shutdown receipt.")}
          ${controlCard("Forced Dry-Run", "/controls/forced-dry-run", "Execute the full workflow without committing side effects. Proof bundle captures behavior for review before granting live access.")}
          ${controlCard("Tamper-Evident Logs", "/audit/tamper-evident-logs", "Hash-linked, append-only transparency log. Any modification to historical entries is detectable by any party.")}
        </div>

        <h2>Relevant Workflows</h2>
        <ul>
          ${workflowLink("Production Deploy Approval", "/workflows/production-deploy-approval")}
          ${workflowLink("Access Request Automation", "/workflows/access-request-automation")}
          ${workflowLink("SOX Control Testing", "/workflows/sox-control-testing")}
        </ul>
      </div>
    </section>
    ${industryCtaBanner("government")}`,
  });
}

/* ── /industries/insurance ───────────────────────────────────── */

export function industryInsurancePage(): string {
  return layout({
    meta: {
      title: "AI Agent Insurance Underwriting Automation | Claw EA",
      description: "Deploy AI agents for insurance underwriting, claims processing, and compliance with approval gates, proof bundles, reconciliation controls, and dispute handling evidence.",
      path: "/industries/insurance",
    },
    breadcrumbs: [
      { name: "Home", path: "/" },
      { name: "Industries", path: "/industries/insurance" },
      { name: "Insurance", path: "/industries/insurance" },
    ],
    schemas: [
      serviceSchema("AI Agent Governance for Insurance", "Enterprise AI agent governance for insurance underwriting, claims, and compliance.", "https://www.clawea.com/industries/insurance"),
      faqSchema([
        { q: "How does Claw EA support underwriting automation with proper controls?", a: "Approval gates require human sign-off before binding decisions. Proof bundles capture the full decision chain: what data the agent accessed, what model produced the recommendation, and who approved the final decision. This creates an auditable trail for regulators and dispute resolution." },
        { q: "Can proof bundles be used in insurance dispute resolution?", a: "Yes. A proof bundle is a self-contained, cryptographically signed record of an agent's execution. In a disputed claim, the bundle proves exactly what the agent did, what data it used, and under what policy it operated. Third parties can verify the bundle offline." },
      ]),
    ],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:900px">
        <span class="badge badge-blue">Insurance</span>
        <h1>AI Agent Governance for Insurance Underwriting and Claims</h1>
        <p class="lead">Insurance carriers deploying AI agents for underwriting, claims adjudication, and policy administration face regulatory scrutiny from state insurance departments, NAIC model laws, and emerging AI-specific regulations (Colorado SB 21-169, EU AI Act). Every automated decision must be explainable and provable.</p>

        <h2>What Goes Wrong Without Controls</h2>
        <p>A mid-market carrier deploys agents to automate small-commercial underwriting, first-notice-of-loss triage, and renewal pricing. Within two quarters:</p>
        <ul>
          <li>An underwriting agent binds a $5M policy without the required second-level approval — the binding authority exceeded the agent's delegation, and no gate prevented it</li>
          <li>A claims agent denies a homeowner claim using data from an unapproved third-party risk model — the state insurance department asks for evidence of the data source and decision logic</li>
          <li>A policyholder disputes a renewal price increase — the carrier cannot prove what factors the pricing agent considered because the execution trace was not signed</li>
        </ul>

        <h2>Regulatory Mapping</h2>
        <div class="compare-table-wrap"><table class="compare-table" role="table">
          <thead><tr><th>Regulation</th><th>Requirement</th><th>Claw EA Control</th></tr></thead>
          <tbody>
            <tr><td>NAIC Model Laws</td><td>Unfair claims practices, rate justification</td><td><a href="/proof/proof-bundles">Proof bundles</a> capture decision chain; <a href="/controls/approval-gates">approval gates</a> enforce authority limits</td></tr>
            <tr><td>Colorado SB 21-169</td><td>AI governance for insurance decisions</td><td><a href="/policy/work-policy-contract">Work Policy Contracts</a> declare permitted decision criteria; receipts prove compliance</td></tr>
            <tr><td>EU AI Act (high-risk)</td><td>Transparency, human oversight, logging</td><td><a href="/controls/two-person-rule">Two-person rule</a>, <a href="/audit/tamper-evident-logs">tamper-evident logs</a>, offline-verifiable proof</td></tr>
            <tr><td>State rate filings</td><td>Actuarial justification for pricing</td><td>Proof bundles include model inputs and outputs — auditors can verify what data informed the price</td></tr>
          </tbody>
        </table></div>

        <h2>Recommended Control Stack</h2>
        <div class="grid-2">
          ${controlCard("Approval Gates", "/controls/approval-gates", "Enforce binding authority limits. Underwriting decisions above threshold require human sign-off with signed receipt.")}
          ${controlCard("Proof Bundles", "/proof/proof-bundles", "Self-contained evidence of the full decision chain. What data was accessed, what model produced the output, who approved.")}
          ${controlCard("Budget Controls", "/controls/budget-controls", "Cap exposure per agent, per policy, per day. Prevents runaway automated binding without financial guardrails.")}
          ${controlCard("Egress Allowlist", "/controls/egress-allowlist", "Restrict which data sources and APIs agents can access. Unapproved third-party risk models are blocked.")}
        </div>

        <h2>Relevant Workflows</h2>
        <ul>
          ${workflowLink("Contract Review Approval", "/workflows/contract-review-approval")}
          ${workflowLink("Production Deploy Approval", "/workflows/production-deploy-approval")}
          ${workflowLink("SOX Control Testing", "/workflows/sox-control-testing")}
        </ul>
      </div>
    </section>
    ${industryCtaBanner("insurance")}`,
  });
}

/* ── /industries/legal ───────────────────────────────────────── */

export function industryLegalPage(): string {
  return layout({
    meta: {
      title: "AI Agent Legal Document Review Governance | Claw EA",
      description: "Deploy AI agents for legal document review, contract analysis, and due diligence with file path scopes, DLP controls, two-person rule, and audit replay.",
      path: "/industries/legal",
    },
    breadcrumbs: [
      { name: "Home", path: "/" },
      { name: "Industries", path: "/industries/legal" },
      { name: "Legal", path: "/industries/legal" },
    ],
    schemas: [
      serviceSchema("AI Agent Governance for Legal", "Enterprise AI agent governance for law firms and legal departments with privilege-aware controls.", "https://www.clawea.com/industries/legal"),
      faqSchema([
        { q: "How does Claw EA protect attorney-client privilege in AI workflows?", a: "File path scopes restrict which documents an agent can access. DLP redaction strips privileged content before it reaches external model providers. The proof bundle proves the agent never accessed out-of-scope documents, which is critical if privilege is later challenged." },
        { q: "Can legal teams replay an agent's document review for quality assurance?", a: "Yes. Audit replay re-executes the agent workflow using the original proof bundle as input. Reviewers can see every document the agent read, every extraction it made, and every decision point. The replay is deterministic because the proof bundle captures the full execution state." },
      ]),
    ],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:900px">
        <span class="badge badge-blue">Legal</span>
        <h1>AI Agent Governance for Law Firms and Legal Departments</h1>
        <p class="lead">Legal organizations face unique constraints: attorney-client privilege, ethical walls, conflict screening, and bar association opinions on AI use. An agent that reviews documents, drafts contracts, or assists with due diligence must operate within strict, provable boundaries.</p>

        <h2>What Goes Wrong Without Controls</h2>
        <p>A large law firm deploys agents to accelerate M&amp;A due diligence, contract extraction, and regulatory filing review. Within one engagement:</p>
        <ul>
          <li>A due diligence agent processing target company documents accidentally accesses a privileged memo from a concurrent matter — the ethical wall was not enforced at the agent layer</li>
          <li>A contract extraction agent sends full agreement text to a model API, including counterparty trade secrets covered by NDA — no DLP redaction was in place</li>
          <li>Opposing counsel challenges the accuracy of an AI-assisted document review — the firm cannot prove which documents the agent reviewed or what extraction logic it applied</li>
        </ul>

        <h2>Regulatory and Ethical Mapping</h2>
        <div class="compare-table-wrap"><table class="compare-table" role="table">
          <thead><tr><th>Requirement</th><th>Source</th><th>Claw EA Control</th></tr></thead>
          <tbody>
            <tr><td>Attorney-client privilege</td><td>ABA Model Rules, state bar rules</td><td>File path scopes restrict document access; <a href="/controls/dlp-redaction">DLP redaction</a> strips privilege markers</td></tr>
            <tr><td>Ethical walls / conflict screening</td><td>ABA Model Rule 1.6, 1.10</td><td><a href="/policy/scoped-tokens">Scoped tokens</a> enforce matter-level boundaries; agents cannot cross walls</td></tr>
            <tr><td>Supervisory responsibility</td><td>ABA Model Rule 5.3</td><td><a href="/controls/two-person-rule">Two-person rule</a> ensures human review before deliverables; proof bundle enables <a href="/agent-audit-and-replay">audit replay</a></td></tr>
            <tr><td>Data security</td><td>ABA Formal Opinion 477R</td><td><a href="/controls/egress-allowlist">Egress allowlist</a>, <a href="/controls/secret-boundary">secret boundary</a>, encrypted transit</td></tr>
          </tbody>
        </table></div>

        <h2>Recommended Control Stack</h2>
        <div class="grid-2">
          ${controlCard("DLP Redaction", "/controls/dlp-redaction", "Strip privileged content, PII, and counterparty trade secrets before prompts reach any model provider.")}
          ${controlCard("Two-Person Rule", "/controls/two-person-rule", "Require attorney review before AI-assisted work products are delivered. Signed receipt proves review occurred.")}
          ${controlCard("Scoped Tokens", "/policy/scoped-tokens", "Matter-level access boundaries. Each agent token restricts access to documents within its authorized matter.")}
          ${controlCard("Audit Replay", "/agent-audit-and-replay", "Replay the agent's document review step-by-step. Proves what was reviewed, what was extracted, and what was missed.")}
        </div>

        <h2>Relevant Workflows</h2>
        <ul>
          ${workflowLink("Contract Review Approval", "/workflows/contract-review-approval")}
          ${workflowLink("Access Request Automation", "/workflows/access-request-automation")}
        </ul>
      </div>
    </section>
    ${industryCtaBanner("legal")}`,
  });
}

/* ── /industries/technology ──────────────────────────────────── */

export function industryTechnologyPage(): string {
  return layout({
    meta: {
      title: "AI Agent DevOps Governance | Technology | Claw EA",
      description: "Deploy AI agents for DevOps, SRE, and platform engineering with deploy approvals, GitHub Actions integration, credential rotation controls, and rate limits.",
      path: "/industries/technology",
    },
    breadcrumbs: [
      { name: "Home", path: "/" },
      { name: "Industries", path: "/industries/technology" },
      { name: "Technology", path: "/industries/technology" },
    ],
    schemas: [
      serviceSchema("AI Agent Governance for Technology Companies", "Enterprise AI agent governance for DevOps, SRE, and platform engineering teams.", "https://www.clawea.com/industries/technology"),
      faqSchema([
        { q: "How does Claw EA integrate with existing CI/CD pipelines?", a: "The GitHub Actions proof pipeline adds a verification check to every PR. Agent-generated code carries a signed commit proof (commit.sig.json) that the CI check validates. The pipeline runs alongside your existing CI without replacing it." },
        { q: "Can AI agents deploy to production with proper controls?", a: "Yes, with the approval gate control. A production deploy workflow requires human approval before the deploy action executes. The approval produces a signed receipt. The full pipeline — from code generation to deploy — is captured in a proof bundle." },
        { q: "How are API credentials protected when agents access infrastructure?", a: "Scoped tokens restrict which credentials an agent can access. The secret boundary control prevents credentials from appearing in model context. Credential rotation events are logged with signed receipts." },
      ]),
    ],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:900px">
        <span class="badge badge-blue">Technology</span>
        <h1>AI Agent Governance for DevOps, SRE, and Platform Engineering</h1>
        <p class="lead">Technology companies are the earliest adopters of AI agents for code generation, infrastructure automation, incident response, and deployment pipelines. Speed matters, but so does proving that agents operated within authorized boundaries — especially when SOC 2, ISO 27001, or customer security reviews are on the line.</p>

        <h2>What Goes Wrong Without Controls</h2>
        <p>A SaaS company deploys agents across its platform engineering team: code review bots, automated deploy pipelines, incident triage agents, and infrastructure-as-code generators. Within two sprints:</p>
        <ul>
          <li>A deploy agent pushes a configuration change to production without the required approval — the change causes a 45-minute outage, and the incident review finds no record of who authorized the deploy</li>
          <li>A code review agent has access to all repositories, including the secrets management repo — no scope boundary restricts which repos the agent can read</li>
          <li>A customer's security team requests evidence that AI agents cannot exfiltrate data from their tenant — the engineering team cannot produce verifiable evidence because agent actions are only logged in application logs</li>
        </ul>

        <h2>Control Mapping</h2>
        <div class="compare-table-wrap"><table class="compare-table" role="table">
          <thead><tr><th>Concern</th><th>Without Controls</th><th>With Claw EA</th></tr></thead>
          <tbody>
            <tr><td>Production deploys</td><td>Agent deploys autonomously; no approval trail</td><td><a href="/controls/approval-gates">Approval gate</a> + signed receipt before deploy executes</td></tr>
            <tr><td>Repository access</td><td>Agent has org-wide read access</td><td><a href="/policy/scoped-tokens">Scoped tokens</a> restrict access to specific repos</td></tr>
            <tr><td>Credential handling</td><td>Credentials in environment variables, accessible to model context</td><td><a href="/controls/secret-boundary">Secret boundary</a> + <a href="/controls/credential-rotation">credential rotation</a></td></tr>
            <tr><td>Customer audit requests</td><td>Application logs (mutable, not verifiable)</td><td><a href="/proof/proof-bundles">Proof bundles</a> (signed, offline-verifiable)</td></tr>
            <tr><td>Rate limiting</td><td>No cap on agent API calls</td><td><a href="/controls/rate-limits">Rate limits</a> per agent, per endpoint, per time window</td></tr>
          </tbody>
        </table></div>

        <h2>Recommended Control Stack</h2>
        <div class="grid-2">
          ${controlCard("Deploy Approvals", "/controls/approval-gates", "Human sign-off before production deploys. Receipt captures approver, timestamp, and the exact artifact being deployed.")}
          ${controlCard("GitHub Actions Pipeline", "/guides/github-actions-proof-pipeline", "Claw Verified PR check validates signed commit proofs on every agent-generated PR.")}
          ${controlCard("Credential Rotation", "/controls/credential-rotation", "Rotate agent credentials on schedule. Rotation events produce signed receipts. Old credentials are revoked immediately.")}
          ${controlCard("Rate Limits", "/controls/rate-limits", "Cap API calls per agent, per endpoint, per time window. Prevents runaway agents from overwhelming upstream services.")}
        </div>

        <h2>Relevant Workflows</h2>
        <ul>
          ${workflowLink("Production Deploy Approval", "/workflows/production-deploy-approval")}
          ${workflowLink("Access Request Automation", "/workflows/access-request-automation")}
          ${workflowLink("SIEM Evidence Collection", "/workflows/siem-evidence-collection")}
        </ul>
      </div>
    </section>
    ${industryCtaBanner("technology")}`,
  });
}
