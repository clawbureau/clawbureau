/**
 * Pricing tier detail pages: /pricing/starter, /pricing/team, /pricing/enterprise
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

function featureRow(feature: string, included: boolean, detail?: string): string {
  const icon = included ? "&#10003;" : "&#8212;";
  const cls = included ? "feat-yes" : "feat-no";
  return `<tr><td>${esc(feature)}</td><td class="${cls}">${icon}</td>${detail ? `<td>${esc(detail)}</td>` : ""}</tr>`;
}

function tierCtaBanner(tier: string): string {
  return `
    <section class="section">
      <div class="wrap">
        <div class="cta-banner">
          <h2>Not sure which tier fits?</h2>
          <p>The assessment scores your readiness and recommends the right starting point.</p>
          <a href="/assessment" class="cta-btn cta-btn-lg" data-cta="pricing-${esc(tier)}-assessment">Take the assessment</a>
          <a href="/pricing" class="cta-btn cta-btn-outline cta-btn-lg" style="margin-left:.75rem" data-cta="pricing-${esc(tier)}-compare">Compare all tiers</a>
        </div>
      </div>
    </section>`;
}

/* ── /pricing/starter ────────────────────────────────────────── */

export function pricingStarterPage(): string {
  return layout({
    meta: {
      title: "Starter Plan | $49/mo | Claw EA Pricing",
      description: "Claw EA Starter: 1 AI agent, 5 skills, all channels, execution attestation, and 90-day audit log retention. Start with proof-first agent governance for $49/month.",
      path: "/pricing/starter",
    },
    breadcrumbs: [
      { name: "Home", path: "/" },
      { name: "Pricing", path: "/pricing" },
      { name: "Starter", path: "/pricing/starter" },
    ],
    schemas: [
      serviceSchema("Claw EA Starter Plan", "1 AI agent with execution attestation and 90-day audit log retention for $49/month.", "https://www.clawea.com/pricing/starter"),
      faqSchema([
        { q: "What is included in the Starter plan?", a: "1 AI agent, 5 skills per agent, all channels (Slack, Teams, email, etc.), all models via BYOK (bring your own key), execution attestation on every run, and 90-day audit log retention." },
        { q: "Can I upgrade from Starter to Team later?", a: "Yes. Upgrades are instant with no downtime. Your existing agent configuration, proof bundles, and audit logs carry over." },
        { q: "Does the Starter plan include proof bundles?", a: "Starter includes execution attestation (signed receipts per run). Full proof bundles with hash-linked event chains are available on Team tier and above." },
      ]),
    ],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:900px">
        <span class="badge badge-green">Starter</span>
        <h1>Starter: Proof-First Agent Governance</h1>
        <div style="display:flex;align-items:baseline;gap:.5rem;margin-bottom:1.5rem">
          <span style="font-size:2.5rem;font-weight:700;color:var(--accent)">$49</span>
          <span style="color:var(--text-muted)">/month</span>
        </div>
        <p class="lead">One agent. Full execution attestation. The fastest way to start generating cryptographic evidence from your AI workflows.</p>

        <h2>What You Get</h2>
        <div class="compare-table-wrap"><table class="compare-table" role="table">
          <thead><tr><th>Feature</th><th>Included</th></tr></thead>
          <tbody>
            ${featureRow("AI agents", true)}
            ${featureRow("Skills per agent", true)}
            ${featureRow("All channels (Slack, Teams, email, web)", true)}
            ${featureRow("All models via BYOK", true)}
            ${featureRow("Execution attestation (signed receipts)", true)}
            ${featureRow("90-day audit log retention", true)}
            ${featureRow("Work Policy Contracts", false)}
            ${featureRow("Budget controls", false)}
            ${featureRow("Multi-agent orchestration", false)}
            ${featureRow("SIEM integration", false)}
          </tbody>
        </table></div>

        <h2>Who This Is For</h2>
        <ul>
          <li>Solo developers and small teams running a single agent workflow</li>
          <li>Teams evaluating proof-first governance before committing to a larger deployment</li>
          <li>Startups that need signed execution evidence for customer security reviews</li>
        </ul>

        <h2>Limits</h2>
        <ul>
          <li><strong>1 agent</strong> — additional agents require Team tier</li>
          <li><strong>5 skills per agent</strong> — covers most single-workflow use cases</li>
          <li><strong>90-day retention</strong> — sufficient for evaluation, not for compliance (Team tier: 1 year, Enterprise: 7 years)</li>
        </ul>

        <h2>Upgrade Path</h2>
        <p>When you need more agents, Work Policy Contracts, or budget controls, upgrade to <a href="/pricing/team">Team</a>. Your existing agent, proof bundles, and audit history carry over with zero downtime.</p>

        <a href="/contact" class="cta-btn cta-btn-lg" data-cta="pricing-starter-get-started">Get Started</a>
      </div>
    </section>
    ${tierCtaBanner("starter")}`,
  });
}

/* ── /pricing/team ───────────────────────────────────────────── */

export function pricingTeamPage(): string {
  return layout({
    meta: {
      title: "Team Plan | $249/mo | Claw EA Pricing",
      description: "Claw EA Team: 5 AI agents, Work Policy Contracts, budget controls, model routing, 1-year audit retention. Built for teams that need policy enforcement.",
      path: "/pricing/team",
    },
    breadcrumbs: [
      { name: "Home", path: "/" },
      { name: "Pricing", path: "/pricing" },
      { name: "Team", path: "/pricing/team" },
    ],
    schemas: [
      serviceSchema("Claw EA Team Plan", "5 AI agents with Work Policy Contracts, budget controls, and 1-year audit retention for $249/month.", "https://www.clawea.com/pricing/team"),
      faqSchema([
        { q: "What does the Team plan add over Starter?", a: "5 agents (vs 1), 15 skills per agent (vs 5), Work Policy Contracts for declarative policy enforcement, budget controls for spending limits, model routing with failover, and 1-year audit log retention." },
        { q: "Can the Team plan support multiple departments?", a: "Yes. Each of the 5 agents can serve a different department or workflow. Scoped tokens and Work Policy Contracts ensure each agent operates within its authorized boundary." },
        { q: "Is there a per-seat charge?", a: "No. Team pricing is per-deployment, not per-seat. Your entire team can interact with agents through any supported channel." },
      ]),
    ],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:900px">
        <span class="badge badge-green">Team</span>
        <h1>Team: Policy-Enforced Agent Governance</h1>
        <div style="display:flex;align-items:baseline;gap:.5rem;margin-bottom:1.5rem">
          <span style="font-size:2.5rem;font-weight:700;color:var(--accent)">$249</span>
          <span style="color:var(--text-muted)">/month</span>
        </div>
        <p class="lead">Five agents. Full policy enforcement. The tier where governance moves from attestation to active control.</p>

        <h2>What You Get</h2>
        <div class="compare-table-wrap"><table class="compare-table" role="table">
          <thead><tr><th>Feature</th><th>Included</th></tr></thead>
          <tbody>
            ${featureRow("5 AI agents", true)}
            ${featureRow("15 skills per agent", true)}
            ${featureRow("All channels (Slack, Teams, email, web)", true)}
            ${featureRow("Model routing + failover", true)}
            ${featureRow("Work Policy Contracts", true)}
            ${featureRow("Budget controls (per-run, per-day)", true)}
            ${featureRow("Execution attestation + proof bundles", true)}
            ${featureRow("1-year audit log retention", true)}
            ${featureRow("Fleet management dashboard", false)}
            ${featureRow("Multi-agent orchestration", false)}
            ${featureRow("SIEM integration", false)}
            ${featureRow("Custom compliance mapping", false)}
          </tbody>
        </table></div>

        <h2>Who This Is For</h2>
        <ul>
          <li>Teams deploying 2-5 agents across different workflows or departments</li>
          <li>Organizations that need policy enforcement (not just attestation)</li>
          <li>Companies preparing for SOC 2 or similar audits that require control evidence</li>
        </ul>

        <h2>Key Capabilities</h2>
        <div class="grid-2">
          <div class="card">
            <h3>Work Policy Contracts</h3>
            <p>Declare what each agent is allowed to do. Immutable, content-addressed policies pinned to agent tokens. <a href="/policy/work-policy-contract">Learn more</a></p>
          </div>
          <div class="card">
            <h3>Budget Controls</h3>
            <p>Set per-run and per-day spending limits. Agents that exceed budgets are blocked, not warned. <a href="/controls/budget-controls">Learn more</a></p>
          </div>
          <div class="card">
            <h3>Model Routing</h3>
            <p>Route model calls through approved providers with automatic failover. Gateway receipts prove which model was used.</p>
          </div>
          <div class="card">
            <h3>1-Year Retention</h3>
            <p>Proof bundles and audit logs retained for 12 months. Sufficient for most annual audit cycles.</p>
          </div>
        </div>

        <h2>Upgrade Path</h2>
        <p>When you need more than 5 agents, SIEM integration, or fleet management, upgrade to Business ($999/mo) or <a href="/pricing/enterprise">Enterprise</a>. All configurations and audit history carry over.</p>

        <a href="/contact" class="cta-btn cta-btn-lg" data-cta="pricing-team-get-started">Get Started</a>
      </div>
    </section>
    ${tierCtaBanner("team")}`,
  });
}

/* ── /pricing/enterprise ─────────────────────────────────────── */

export function pricingEnterprisePage(): string {
  return layout({
    meta: {
      title: "Enterprise Plan | Custom Pricing | Claw EA",
      description: "Claw EA Enterprise: unlimited agents, custom compliance mapping, dedicated support, 7-year retention, BAA/DPA, on-prem option. Built for regulated enterprises.",
      path: "/pricing/enterprise",
    },
    breadcrumbs: [
      { name: "Home", path: "/" },
      { name: "Pricing", path: "/pricing" },
      { name: "Enterprise", path: "/pricing/enterprise" },
    ],
    schemas: [
      serviceSchema("Claw EA Enterprise Plan", "Unlimited AI agents with custom compliance mapping, 7-year retention, and dedicated support.", "https://www.clawea.com/pricing/enterprise"),
      faqSchema([
        { q: "What does the Enterprise plan include beyond Business?", a: "Unlimited agents, unlimited skills, custom container limits, custom compliance mapping (SOX, HIPAA, FedRAMP, etc.), dedicated support engineer, 7-year audit log retention, BAA/DPA availability, and an on-premises deployment option." },
        { q: "How does custom compliance mapping work?", a: "We map your specific regulatory requirements to Claw EA controls and proof artifacts. For example, SOX ITGC controls map to approval gates + proof bundles, HIPAA Security Rule maps to DLP + egress allowlist + retention. The mapping is documented and maintained as your requirements evolve." },
        { q: "Is there an on-premises deployment option?", a: "Yes. Enterprise tier includes the option to deploy Claw EA infrastructure within your own environment. Proof bundles and verification work identically in on-prem mode." },
        { q: "What SLA does the Enterprise plan offer?", a: "Enterprise includes a custom SLA with dedicated support engineer, priority incident response, and guaranteed response times. Specific terms are defined during contract negotiation." },
      ]),
    ],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:900px">
        <span class="badge badge-green">Enterprise</span>
        <h1>Enterprise: Unlimited Agents, Full Compliance</h1>
        <div style="display:flex;align-items:baseline;gap:.5rem;margin-bottom:1.5rem">
          <span style="font-size:2.5rem;font-weight:700;color:var(--accent)">Custom</span>
          <span style="color:var(--text-muted)">pricing</span>
        </div>
        <p class="lead">Unlimited agents. Custom compliance mapping. Dedicated support. The tier for regulated enterprises that need verifiable governance at scale.</p>

        <h2>Everything in Business, Plus</h2>
        <div class="compare-table-wrap"><table class="compare-table" role="table">
          <thead><tr><th>Feature</th><th>Included</th></tr></thead>
          <tbody>
            ${featureRow("Unlimited AI agents", true)}
            ${featureRow("Unlimited skills per agent", true)}
            ${featureRow("Custom container limits", true)}
            ${featureRow("Custom compliance mapping (SOX, HIPAA, FedRAMP)", true)}
            ${featureRow("Dedicated support engineer", true)}
            ${featureRow("7-year audit log retention", true)}
            ${featureRow("BAA / DPA available", true)}
            ${featureRow("On-premises deployment option", true)}
            ${featureRow("Custom SLA with priority incident response", true)}
            ${featureRow("SSO / SCIM integration", true)}
          </tbody>
        </table></div>

        <h2>Who This Is For</h2>
        <ul>
          <li>Regulated enterprises (banking, healthcare, government, insurance) deploying agent fleets</li>
          <li>Organizations with specific compliance requirements that need mapped controls</li>
          <li>Companies that require on-premises deployment or data residency guarantees</li>
          <li>Teams deploying 25+ agents with cross-department orchestration</li>
        </ul>

        <h2>Enterprise Capabilities</h2>
        <div class="grid-2">
          <div class="card">
            <h3>Custom Compliance Mapping</h3>
            <p>We map your regulations to controls: SOX ITGC → approval gates + proof bundles, HIPAA → DLP + egress + retention, FedRAMP → two-person rule + Merkle logs.</p>
          </div>
          <div class="card">
            <h3>7-Year Retention</h3>
            <p>Tamper-evident proof bundles and audit logs retained for 7 years. Meets the strictest regulatory retention requirements (SOX, HIPAA, government records).</p>
          </div>
          <div class="card">
            <h3>Dedicated Support</h3>
            <p>Named support engineer who knows your deployment. Priority incident response. Quarterly architecture reviews.</p>
          </div>
          <div class="card">
            <h3>On-Premises Option</h3>
            <p>Deploy within your own infrastructure. Same protocol, same proof bundles, same offline verification. No data leaves your boundary.</p>
          </div>
        </div>

        <h2>Security Review</h2>
        <p>Enterprise evaluation starts with the <a href="/trust/security-review">Security Review Pack</a>: architecture overview, threat model, proof artifacts, and deployment integrity documentation. Your security team can review before committing.</p>

        <h2>Start the Conversation</h2>
        <p>Enterprise pricing is based on deployment size, compliance requirements, and support needs. The fastest path is a 30-minute planning session.</p>
        <div style="display:flex;gap:.75rem;flex-wrap:wrap">
          <a href="/book" class="cta-btn cta-btn-lg" data-cta="pricing-enterprise-book">Book a session</a>
          <a href="/trust/security-review" class="cta-btn cta-btn-outline cta-btn-lg" data-cta="pricing-enterprise-security-review">Security Review Pack</a>
        </div>
      </div>
    </section>
    ${tierCtaBanner("enterprise")}`,
  });
}
