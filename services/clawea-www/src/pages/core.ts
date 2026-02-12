/**
 * Core pages: home, pricing, assessment, contact, book, sources, 404, articles.
 */

import { layout } from "../layout";
import {
  faqSchema, serviceSchema, canonical, breadcrumbSchema,
  definedTermSchema, techArticleSchema, productSchema,
  softwareApplicationSchema, offerCatalogSchema,
} from "../seo";
import type {
  Env, Article, ManifestEntry, TurnstilePosture, SearchResult,
} from "../index";
import { clipString, shouldRenderTurnstileWidget } from "../leads";
import { breadcrumbsFromSlug } from "../index";
import { howToSchema } from "../seo";

export function homePage(): string {
  return layout({
    meta: {
      title: "Claw EA | Enterprise AI Agents, Deployed and Verified",
      description: "Deploy managed AI agents for your enterprise. Every action cryptographically attested. Every model call receipted. Every output verifiable. Reliable, performant, scalable, flexible, secure.",
      path: "/",
    },
    body: `
    <section class="hero">
      <div class="wrap">
        <span class="badge badge-blue">Proof-First Agent Pilots</span>
        <h1>Ship Irreversible Agent Workflows With Proof</h1>
        <p class="sub">Policy-as-code controls. Cryptographic receipts. Offline verification. Start with one production deploy approval workflow and expand from evidence, not assumptions. Two-week pilot.</p>
        <div class="actions">
          <a href="/assessment" class="cta-btn cta-btn-lg" data-cta="home-assessment">Take the assessment</a>
          <a href="/trust/security-review" class="cta-btn cta-btn-outline cta-btn-lg" data-cta="home-security-review">See the Security Review Pack</a>
        </div>
        <ul class="trust-proof-list" aria-label="What your security team gets">
          <li>Every model call receipted (Ed25519)</li>
          <li>Tamper-evident audit logs (Merkle)</li>
          <li>Offline-verifiable proof bundles</li>
        </ul>
      </div>
    </section>

    <section class="section-sm" style="border-bottom:1px solid var(--border)">
      <div class="wrap stats">
        <div class="stat"><div class="num">20+</div><div class="label">Channel Integrations</div></div>
        <div class="stat"><div class="num">12+</div><div class="label">AI Models Supported</div></div>
        <div class="stat"><div class="num">100%</div><div class="label">Action Attestation</div></div>
        <div class="stat"><div class="num">&lt;200ms</div><div class="label">Receipt Overhead</div></div>
      </div>
    </section>

    <section class="section">
      <div class="wrap">
        <div class="sh">
          <span class="kicker">Why Claw EA</span>
          <h2>Six Pillars of Enterprise AI Done Right</h2>
          <p>Built on OpenClaw, hardened for enterprise. Every design decision optimizes for these six properties.</p>
        </div>
        <div class="grid-3">
          <div class="card">
            <div class="icon">🛡️</div>
            <h3>Secure by Architecture</h3>
            <p>Hardware-isolated Cloudflare Sandboxes. Per-agent DID identities. Work Policy Contracts enforce egress, DLP, and approval gates before any agent runs.</p>
          </div>
          <div class="card">
            <div class="icon">⚡</div>
            <h3>Performant at the Edge</h3>
            <p>Cloudflare's global edge network. Smart model routing. Sleep/wake cycles that cut costs without sacrificing response time. Sub-200ms receipt overhead.</p>
          </div>
          <div class="card">
            <div class="icon">📈</div>
            <h3>Scales to Thousands</h3>
            <p>Up to 9,999 agents per tenant. Multi-tenant isolation at the infrastructure level. Budget controls per agent, team, or org. Fleet management dashboard.</p>
          </div>
          <div class="card">
            <div class="icon">🔄</div>
            <h3>No Model Lock-in</h3>
            <p>Claude, GPT, Gemini, Llama, Mistral, DeepSeek, Qwen. Any model, any provider. BYOK (Bring Your Own Key) or managed. Switch models without code changes.</p>
          </div>
          <div class="card">
            <div class="icon">✅</div>
            <h3>Reliable Operations</h3>
            <p>Auto-restart on failure. Health checks every 5 minutes. Persistent R2 state survives sleep/wake. Cron-based monitoring with configurable retry limits.</p>
          </div>
          <div class="card">
            <div class="icon">📋</div>
            <h3>Audit-Ready by Default</h3>
            <p>Cryptographic proof bundles for every run. Tamper-evident audit logs. SOC 2, HIPAA, GDPR, FedRAMP compatible. Export to any SIEM.</p>
          </div>
        </div>
      </div>
    </section>

    <section class="section" style="background:var(--bg-alt)">
      <div class="wrap">
        <div class="sh">
          <span class="kicker">Permissioned Execution</span>
          <h2>Controls That Make Agents Safe to Run</h2>
          <p>Agents get cheap. Risk gets expensive. Claw EA is built around enforceable policy-as-code controls that prevent exfiltration and force approvals for irreversible actions.</p>
        </div>
        <div class="grid-4">
          ${[
            ["Egress Allowlist", "/controls/egress-allowlist", "Only approved domains and IPs."],
            ["DLP Redaction", "/controls/dlp-redaction", "Redact before data leaves the boundary."],
            ["Approval Gates", "/controls/approval-gates", "Step-up approvals for high-risk steps."],
            ["Two-person Rule", "/controls/two-person-rule", "Require two humans for irreversible actions."],
            ["Budgets", "/controls/budgets", "Token and cost budgets per workflow."],
            ["File Path Scopes", "/controls/file-path-scopes", "Restrict what can be read or written."],
            ["Kill Switch", "/controls/kill-switch", "Stop execution when policy is violated."],
            ["MCP Security", "/mcp/security-best-practices", "Use MCP without turning tools into exfiltration."],
          ]
            .map(([name, href, desc]) => `<a href="${href}" class="card card-link"><h3>${name}</h3><p>${desc}</p></a>`)
            .join("")}
        </div>
      </div>
    </section>

    <section class="section">
      <div class="wrap">
        <div class="sh">
          <span class="kicker">Channels + Tools</span>
          <h2>Chat Control Plane Plus Enterprise Systems</h2>
          <p>Run agents where your team already works, and connect them to enterprise tools under strict policy and proof.</p>
        </div>
        <div class="grid-4">
          ${[
            ["Microsoft Teams", "/channels/microsoft-teams", "Approvals and control sessions."],
            ["Slack", "/channels/slack", "Fast control plane for teams."],
            ["Email", "/channels/email", "High-risk outbound, policy-first."],
            ["Google Chat", "/channels/google-chat", "Workspace-native control plane."],
            ["Entra ID", "/tools/entra-id", "Identity and step-up approvals."],
            ["SharePoint", "/tools/sharepoint", "Scoped document access."],
            ["GitHub", "/tools/github", "Code changes with policy and proof."],
            ["Jira", "/tools/jira", "Change control and ticket workflows."],
          ]
            .map(([name, href, desc]) => `<a href="${href}" class="card card-link"><h3>${name}</h3><p>${desc}</p></a>`)
            .join("")}
        </div>
        <div class="actions" style="justify-content:center;margin-top:2rem">
          <a href="/channels" class="cta-btn cta-btn-outline" data-cta="home-browse-channels">Browse all channels</a>
          <a href="/tools" class="cta-btn cta-btn-outline" data-cta="home-browse-tools">Browse all tools</a>
        </div>
      </div>
    </section>

    <section class="section" style="background:var(--bg-alt)">
      <div class="wrap">
        <div class="sh">
          <span class="kicker">Pillars</span>
          <h2>Policy, Proof, and Supply Chain</h2>
          <p>Claw EA is built for permissioned execution you can audit, not generic "AI agents".</p>
        </div>
        <div class="grid-2">
          ${[
            ["Policy-as-Code", "/policy-as-code-for-agents", "Define what agents may do before they run."],
            ["Secure Execution", "/secure-agent-execution", "Sandboxing, tool policy, and secrets boundaries."],
            ["Proof and Attestation", "/agent-proof-and-attestation", "Receipts and proof bundles you can verify."],
            ["Audit and Replay", "/agent-audit-and-replay", "Evidence retention and replay posture."],
            ["Supply Chain Security", "/agent-supply-chain-security", "Signed skills and governance for extensions."],
            ["Event-native Agents", "/event-native-agents", "Webhooks and changefeeds, paired with policy."],
          ]
            .map(([name, href, desc]) => `<a href="${href}" class="card card-link"><h3>${name}</h3><p>${desc}</p></a>`)
            .join("")}
        </div>
      </div>
    </section>

    <section class="section">
      <div class="wrap">
        <div class="cta-banner">
          <h2>Start With a Two-Week Proof-First Pilot</h2>
          <p>Pick one irreversible workflow. We deploy controls, receipts, and proof bundles. Your security team verifies independently. You decide whether to expand.</p>
          <a href="/assessment" class="cta-btn cta-btn-lg" data-cta="home-bottom-assessment">Take the assessment</a>
          <a href="/trust/security-review" class="cta-btn cta-btn-outline cta-btn-lg" style="margin-left:.75rem" data-cta="home-bottom-security-review">Security Review Pack</a>
        </div>
      </div>
    </section>`,
    schemas: [
      serviceSchema(
        "Claw EA - Enterprise AI Agent Platform",
        "Deploy managed, verified AI agents for enterprise. Cryptographic attestation, multi-model support, 20+ channel integrations.",
        "https://www.clawea.com",
      ),
      softwareApplicationSchema({
        name: "Claw EA",
        description: "Enterprise AI agent platform with cryptographic proof of every action. Policy-as-code controls, gateway receipts, offline-verifiable proof bundles.",
        url: "https://www.clawea.com",
        applicationCategory: "SecurityApplication",
        operatingSystem: "Cloud",
        offersUrl: "https://www.clawea.com/pricing",
      }),
    ],
  });
}

export function pricingPage(): string {
  return layout({
    meta: {
      title: "Pricing | Claw EA Enterprise AI Agents",
      description: "Transparent pricing for enterprise AI agent infrastructure. Start free, scale to thousands. Starter, Team, Business, and Enterprise tiers.",
      path: "/pricing",
    },
    breadcrumbs: [{ name: "Home", path: "/" }, { name: "Pricing", path: "/pricing" }],
    body: `
    <section class="section content-page">
      <div class="wrap">
        <div class="sh">
          <span class="kicker">Pricing</span>
          <h1 class="h2">Start Small, Scale Without Limits</h1>
          <p>Every tier includes full execution attestation, proof bundles, and audit logs.</p>
        </div>
        <ul class="trust-proof-list" style="margin:-.5rem 0 1.5rem" aria-label="Compliance highlights">
          <li>SOC 2 aligned controls</li>
          <li>HIPAA and GDPR mapping</li>
          <li>SIEM export ready</li>
        </ul>
        <div class="grid-4 pricing-grid">
          <div class="price-card">
            <div class="tier">Starter</div>
            <div class="amount">$49</div>
            <div class="period">per month</div>
            <ul>
              <li>1 AI agent</li>
              <li>5 skills per agent</li>
              <li>All channels supported</li>
              <li>All models (BYOK)</li>
              <li>Execution attestation</li>
              <li>90-day audit log retention</li>
            </ul>
            <a href="/pricing/starter" class="cta-btn cta-btn-outline">See details</a>
          </div>
          <div class="price-card">
            <div class="tier">Team</div>
            <div class="amount">$249</div>
            <div class="period">per month</div>
            <ul>
              <li>5 AI agents</li>
              <li>15 skills per agent</li>
              <li>All channels supported</li>
              <li>Model routing + failover</li>
              <li>Work Policy Contracts</li>
              <li>1-year audit log retention</li>
              <li>Budget controls</li>
            </ul>
            <a href="/pricing/team" class="cta-btn cta-btn-outline">See details</a>
          </div>
          <div class="price-card featured">
            <div class="tier" style="color:var(--accent)">Business</div>
            <div class="amount">$999</div>
            <div class="period">per month</div>
            <ul>
              <li>25 AI agents</li>
              <li>50 skills per agent</li>
              <li>Fleet management dashboard</li>
              <li>Multi-agent orchestration</li>
              <li>Custom agent templates</li>
              <li>3-year audit log retention</li>
              <li>SIEM integration</li>
              <li>Priority support</li>
            </ul>
            <a href="/contact" class="cta-btn">Get Started</a>
          </div>
          <div class="price-card">
            <div class="tier">Enterprise</div>
            <div class="amount">Custom</div>
            <div class="period">Contact sales</div>
            <ul>
              <li><strong>Everything in Business, plus:</strong></li>
              <li>Unlimited agents</li>
              <li>Unlimited skills</li>
              <li>Custom container limits</li>
              <li>Custom compliance mapping</li>
              <li>Dedicated support engineer</li>
              <li>7-year audit log retention</li>
              <li>BAA / DPA available</li>
              <li>On-prem option</li>
            </ul>
            <a href="/pricing/enterprise" class="cta-btn cta-btn-outline">See details</a>
          </div>
        </div>
      </div>
    </section>`,
    schemas: [
      productSchema("Claw EA", "Enterprise AI Agent Platform", "https://www.clawea.com/pricing", [
        { price: "49", priceCurrency: "USD" },
        { price: "249", priceCurrency: "USD" },
        { price: "999", priceCurrency: "USD" },
      ]),
      offerCatalogSchema([
        { name: "Starter", price: "49", description: "1 AI agent, 5 skills, all channels, basic attestation." },
        { name: "Team", price: "199", description: "5 agents, 15 skills each, approval gates, DLP, priority support." },
        { name: "Business", price: "499", description: "25 agents, unlimited skills, full WPC enforcement, SLA guarantees." },
        { name: "Enterprise", price: "0", description: "Custom agent fleet, dedicated sandbox, SSO/SCIM, compliance mapping." },
      ]),
    ],
  });
}

type AssessmentResult = {
  readinessScore: number;
  roiScore: number;
  riskScore: number;
  confidenceLabel: string;
  recommendedTrack: "guided-pilot" | "self-serve-pilot" | "architecture-review";
  timeline?: string;
  previewMode: boolean;
};

export function parseAssessmentResult(url: URL): AssessmentResult {
  const hasExplicitScores = ["readiness", "roi", "risk"].some((k) => url.searchParams.has(k));

  let readinessScore = Math.min(100, Math.max(0, Number(url.searchParams.get("readiness") ?? "0") || 0));
  let roiScore = Math.min(100, Math.max(0, Number(url.searchParams.get("roi") ?? "0") || 0));
  let riskScore = Math.min(100, Math.max(0, Number(url.searchParams.get("risk") ?? "0") || 0));

  const previewMode = !hasExplicitScores || (readinessScore === 0 && roiScore === 0 && riskScore === 0);
  if (previewMode) {
    readinessScore = 67;
    roiScore = 63;
    riskScore = 38;
  }

  const blended = Math.round((readinessScore * 0.4) + (roiScore * 0.35) + ((100 - riskScore) * 0.25));
  const confidenceLabel = blended >= 78 ? "high-intent" : blended >= 55 ? "medium-intent" : "early-intent";

  const recommendedTrack: AssessmentResult["recommendedTrack"] = blended >= 78
    ? "guided-pilot"
    : blended >= 55
      ? "architecture-review"
      : "self-serve-pilot";

  return {
    readinessScore,
    roiScore,
    riskScore,
    confidenceLabel,
    recommendedTrack,
    timeline: clipString(url.searchParams.get("timeline"), 80) ?? "",
    previewMode,
  };
}

function formGuardAttrs(posture: TurnstilePosture): string {
  if (posture.formEnabled) return "";
  return ` data-form-blocked="1" data-form-block-message="${esc(posture.message)}" data-form-block-code="${esc(posture.code)}"`;
}

function submitGuardAttrs(posture: TurnstilePosture): string {
  if (posture.formEnabled) return "";
  return " disabled aria-disabled=\"true\"";
}

export function renderTurnstileBlock(posture: TurnstilePosture, opts?: { widgetEnabled?: boolean }): string {
  const widgetEnabled = opts?.widgetEnabled ?? true;
  const widget = widgetEnabled && shouldRenderTurnstileWidget(posture) && posture.siteKey
    ? `<div class="cf-turnstile" data-sitekey="${esc(posture.siteKey)}"></div>`
    : "";

  const statusClass = posture.formEnabled
    ? "form-security-note"
    : "form-security-note form-security-note-critical";

  const statusText = posture.formEnabled
    ? posture.required
      ? "Bot protection enabled via Cloudflare Turnstile."
      : "Bot protection optional in this environment."
    : posture.message;

  return `${widget}<p class="${statusClass}" data-form-security-note>${esc(statusText)}</p>`;
}

function renderLeadIntakeTrustRail(posture: TurnstilePosture): string {
  const postureLine = posture.formEnabled
    ? "Turnstile challenge required before lead or booking submission."
    : posture.message;

  return `<aside class="trust-rail" aria-label="Lead intake safeguards">
    <span class="badge ${posture.formEnabled ? "badge-green" : "badge-purple"}">${posture.formEnabled ? "Protection active" : "Protection paused"}</span>
    <h3>Submission safeguards</h3>
    <ul>
      <li>${esc(postureLine)}</li>
      <li>Duplicate suppression enforced by Durable Object lead locks.</li>
      <li>Lead and booking transitions are captured in immutable audit rows.</li>
    </ul>
  </aside>`;
}

export function assessmentPage(turnstile: TurnstilePosture): string {
  return layout({
    meta: {
      title: "AI Readiness Assessment | Claw EA",
      description: "Score your enterprise readiness, expected ROI, and operational risk in 2 minutes.",
      path: "/assessment",
      canonicalPath: "/assessment",
    },
    breadcrumbs: [{ name: "Home", path: "/" }, { name: "Assessment", path: "/assessment" }],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:760px">
        <span class="badge badge-purple">Demand capture</span>
        <h1 data-hero-copy>Enterprise Agent Readiness Assessment</h1>
        <p class="lead">Answer five short questions. We return a readiness score, ROI estimate, and risk posture with a clear next step.</p>

        <form class="card lead-form" data-assessment-form style="margin-top:1.5rem">
          <div class="form-grid-2">
            <label class="form-field">
              <span>Team size *</span>
              <select name="teamSize" required>
                <option value="">Select…</option>
                <option value="1-20">1-20</option>
                <option value="21-100">21-100</option>
                <option value="101-500">101-500</option>
                <option value="500+">500+</option>
              </select>
            </label>

            <label class="form-field">
              <span>Current stage *</span>
              <select name="maturity" required>
                <option value="">Select…</option>
                <option value="exploration">Exploration</option>
                <option value="pilot">Pilot running</option>
                <option value="production">Production with guardrails</option>
              </select>
            </label>

            <label class="form-field">
              <span>Primary objective *</span>
              <select name="objective" required>
                <option value="">Select…</option>
                <option value="cost">Reduce manual process cost</option>
                <option value="speed">Faster approvals and delivery</option>
                <option value="compliance">Audit and compliance confidence</option>
              </select>
            </label>

            <label class="form-field">
              <span>Risk tolerance *</span>
              <select name="riskTolerance" required>
                <option value="">Select…</option>
                <option value="low">Low (strict approvals)</option>
                <option value="moderate">Moderate</option>
                <option value="high">High (speed first)</option>
              </select>
            </label>

            <label class="form-field form-field-wide">
              <span>Timeline to launch *</span>
              <select name="timeline" required>
                <option value="">Select…</option>
                <option value="2-weeks">Within 2 weeks</option>
                <option value="30-days">Within 30 days</option>
                <option value="quarter">This quarter</option>
                <option value="later">Later planning</option>
              </select>
            </label>
          </div>

          <div class="form-actions" style="margin-top:1.25rem">
            <button type="submit" class="cta-btn cta-btn-lg" data-cta="assessment-calculate" data-cta-copy>Calculate my score</button>
            <a href="/contact" style="font-size:.9rem;color:var(--text);text-decoration:underline" data-cta="assessment-contact">Need a custom plan? Talk to sales.</a>
          </div>

          <p class="form-note">No signup required for scoring. You can submit your details on the result page if you want a tailored plan.</p>
        </form>

        <div style="margin-top:1.25rem">${renderLeadIntakeTrustRail(turnstile)}</div>
      </div>
    </section>
    <script>
    (function(){
      var form=document.querySelector('[data-assessment-form]');
      if(!form)return;

      function pick(value,map,fallback){return (map&&map[value])||fallback;}

      form.addEventListener('submit',function(e){
        e.preventDefault();

        var fd=new FormData(form);
        var team=String(fd.get('teamSize')||'');
        var maturity=String(fd.get('maturity')||'');
        var objective=String(fd.get('objective')||'');
        var riskTolerance=String(fd.get('riskTolerance')||'');
        var timeline=String(fd.get('timeline')||'');

        var readiness=Math.round(
          pick(team,{'1-20':40,'21-100':55,'101-500':70,'500+':78},42)
          + pick(maturity,{'exploration':8,'pilot':18,'production':25},10)
          + pick(timeline,{'2-weeks':15,'30-days':10,'quarter':6,'later':3},5)
        );

        var roi=Math.round(
          pick(objective,{'cost':72,'speed':68,'compliance':64},60)
          + pick(team,{'1-20':5,'21-100':8,'101-500':12,'500+':15},6)
        );

        var risk=Math.round(
          pick(riskTolerance,{'low':30,'moderate':48,'high':66},48)
          - pick(maturity,{'exploration':0,'pilot':5,'production':10},0)
        );

        readiness=Math.max(0,Math.min(100,readiness));
        roi=Math.max(0,Math.min(100,roi));
        risk=Math.max(0,Math.min(100,risk));

        var out='/assessment/result?readiness='+encodeURIComponent(String(readiness))
          +'&roi='+encodeURIComponent(String(roi))
          +'&risk='+encodeURIComponent(String(risk))
          +'&team='+encodeURIComponent(team)
          +'&objective='+encodeURIComponent(objective)
          +'&timeline='+encodeURIComponent(timeline);

        if(window.__claweaTrack){
          window.__claweaTrack('cta_click',{
            ctaId:'assessment-calculate',
            ctaVariant:'calculator',
            actionOutcome:'calculated',
            targetPath:'/assessment/result'
          });
        }

        window.location.href=out;
      });
    })();
    </script>`,
    schemas: [
      faqSchema([
        { q: "How long does this take?", a: "Around two minutes. You only answer five questions." },
        { q: "Do I need to sign up?", a: "No. You can calculate your score without entering contact details." },
        { q: "Can I share this with my team?", a: "Yes. Copy the result URL and share it internally." },
      ]),
    ],
  });
}

export function assessmentResultPage(result: AssessmentResult, turnstile: TurnstilePosture, opts?: { widgetEnabled?: boolean }): string {
  const trackLabel = result.recommendedTrack === "guided-pilot"
    ? "Guided pilot"
    : result.recommendedTrack === "architecture-review"
      ? "Architecture review"
      : "Self-serve pilot";

  const readinessClass = result.readinessScore >= 70 ? "score-good" : result.readinessScore >= 50 ? "score-warn" : "score-bad";
  const roiClass = result.roiScore >= 70 ? "score-good" : result.roiScore >= 50 ? "score-warn" : "score-bad";
  const riskClass = result.riskScore <= 40 ? "score-good" : result.riskScore <= 65 ? "score-warn" : "score-bad";

  return layout({
    meta: {
      title: `Assessment Result (${result.confidenceLabel}) | Claw EA`,
      description: "Review your readiness, ROI, and risk score. Get the fastest next step for enterprise agent rollout.",
      path: "/assessment/result",
      canonicalPath: "/assessment/result",
      noindex: true,
    },
    breadcrumbs: [
      { name: "Home", path: "/" },
      { name: "Assessment", path: "/assessment" },
      { name: "Result", path: "/assessment/result" },
    ],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:820px">
        <span class="badge badge-green">Assessment result</span>
        <h1>Your recommended track: ${esc(trackLabel)}</h1>
        <p class="lead">We scored your current operating posture across readiness, ROI potential, and risk control fit.</p>

        <div class="score-grid">
          <article class="score-card">
            <h3>Readiness</h3>
            <div class="score-value ${readinessClass}">${result.readinessScore}</div>
            <p>How prepared your team is to launch a controlled pilot quickly.</p>
          </article>
          <article class="score-card">
            <h3>ROI signal</h3>
            <div class="score-value ${roiClass}">${result.roiScore}</div>
            <p>Estimated value potential from throughput and approval cycle improvements.</p>
          </article>
          <article class="score-card">
            <h3>Risk posture</h3>
            <div class="score-value ${riskClass}">${result.riskScore}</div>
            <p>Lower is safer. Higher scores indicate higher risk exposure without strict execution controls.</p>
          </article>
        </div>

        <div class="proof-summary-block" style="margin-top:1.5rem">
          <h3>Proof-first rollout checklist</h3>
          <ul>
            <li>Start with one irreversible workflow and enforce approval gates.</li>
            <li>Require receipts and proof bundles for every model call and side effect.</li>
            <li>Track lead-to-launch metrics weekly and keep an explicit rollback path.</li>
          </ul>
        </div>

        <div class="card" style="margin-top:1.5rem;border-left:3px solid var(--accent)">
          <h3 style="margin-bottom:.5rem">Recommended controls for your profile</h3>
          <p style="font-size:.9rem;color:var(--text-secondary);margin-bottom:.75rem">Based on your assessment scores, these are the controls that matter most for your rollout.</p>
          <div class="grid-2">
            ${result.riskScore >= 50 ? `
            <a href="/controls/approval-gates" class="card card-link" data-cta="result-control-approval-gates"><h4>Approval Gates</h4><p>Step-up human approvals for irreversible actions.</p></a>
            <a href="/controls/two-person-rule" class="card card-link" data-cta="result-control-two-person"><h4>Two-Person Rule</h4><p>Require two humans for high-risk steps.</p></a>
            ` : ""}
            <a href="/controls/egress-allowlist" class="card card-link" data-cta="result-control-egress"><h4>Egress Allowlist</h4><p>Lock down what agents can reach.</p></a>
            <a href="/controls/dlp-redaction" class="card card-link" data-cta="result-control-dlp"><h4>DLP Redaction</h4><p>Strip sensitive data before it leaves the boundary.</p></a>
            ${result.readinessScore < 60 ? `
            <a href="/controls/budgets" class="card card-link" data-cta="result-control-budgets"><h4>Budget Controls</h4><p>Set token and cost limits per workflow.</p></a>
            ` : ""}
            <a href="/controls/kill-switch" class="card card-link" data-cta="result-control-kill-switch"><h4>Kill Switch</h4><p>Stop execution instantly when policy is violated.</p></a>
          </div>
          <p style="margin-top:.75rem;font-size:.9rem"><a href="/trust/security-review" data-cta="result-security-review-pack">See the full Security Review Pack &rarr;</a></p>
        </div>

        <form class="card lead-form" data-lead-form data-cta="assessment-result-form" style="margin-top:2rem"${formGuardAttrs(turnstile)}>
          <h3 style="margin-bottom:.5rem">Get your tailored rollout plan</h3>
          <p class="form-note" style="margin-bottom:1rem">This takes less than 45 seconds.</p>

          <div class="form-grid-2">
            <label class="form-field">
              <span>Work email *</span>
              <input type="email" name="email" required placeholder="you@company.com" autocomplete="email">
            </label>
            <label class="form-field">
              <span>Company *</span>
              <input type="text" name="company" required placeholder="Company name" autocomplete="organization">
            </label>
            <label class="form-field">
              <span>Your role</span>
              <input type="text" name="role" placeholder="Security lead, platform lead, CTO..." autocomplete="organization-title">
            </label>
          </div>

          <input type="hidden" name="primaryUseCase" value="assessment-result-followup">
          <input type="hidden" name="assessment.readinessScore" value="${result.readinessScore}">
          <input type="hidden" name="assessment.roiScore" value="${result.roiScore}">
          <input type="hidden" name="assessment.riskScore" value="${result.riskScore}">
          <input type="hidden" name="assessment.confidenceLabel" value="${esc(result.confidenceLabel)}">
          <input type="hidden" name="timeline" value="${esc(result.timeline ?? "")}">

          ${renderTurnstileBlock(turnstile, { widgetEnabled: opts?.widgetEnabled })}

          <div class="form-actions">
            <button type="submit" class="cta-btn" data-cta="assessment-result-submit"${submitGuardAttrs(turnstile)}>Email me the tailored plan</button>
            <span class="form-status" data-lead-form-status aria-live="polite"></span>
          </div>
        </form>

        <div class="cta-banner" style="margin-top:1.5rem">
          <h2>Want to skip forms and talk now?</h2>
          <p>Book a rollout session directly or review trust controls before you proceed.</p>
          <a href="/book?from=assessment-result&confidence=${encodeURIComponent(result.confidenceLabel)}" class="cta-btn cta-btn-lg" data-cta="assessment-result-book">Book rollout session</a>
          <a href="/contact?from=assessment-result&confidence=${encodeURIComponent(result.confidenceLabel)}" class="cta-btn cta-btn-outline cta-btn-lg" style="margin-left:.75rem" data-cta="assessment-result-contact" data-cta-copy>Talk to Sales</a>
          <p style="margin-top:.9rem;font-size:.9rem"><a href="/trust/security-review" style="color:var(--text);text-decoration:underline" data-cta="assessment-result-security-review">Review the Security Review Pack first</a></p>
        </div>

        <div class="card" style="margin-top:1.5rem">
          <h3 style="margin-bottom:.5rem">Implementation guides for your profile</h3>
          <p style="font-size:.9rem;color:var(--text-secondary);margin-bottom:.75rem">Start with the guide that matches your highest-priority control.</p>
          <div class="grid-2">
            ${result.riskScore >= 50 ? `
            <a href="/guides/github-actions-proof-pipeline" class="card card-link" data-cta="result-guide-github"><h4>GitHub Actions Proof Pipeline</h4><p>Set up verified PR checks in 30 minutes.</p></a>
            ` : ""}
            <a href="/guides/okta-scoped-tokens" class="card card-link" data-cta="result-guide-okta"><h4>Okta Scoped Tokens</h4><p>Map identity groups to agent permissions.</p></a>
            <a href="/guides/compliance-evidence-export" class="card card-link" data-cta="result-guide-compliance"><h4>Compliance Evidence Export</h4><p>Generate audit-ready proof bundles.</p></a>
            ${result.riskScore >= 50 ? `
            <a href="/industries/${result.roiScore >= 60 ? "financial-services" : "technology"}" class="card card-link" data-cta="result-industry"><h4>Industry Guide</h4><p>See controls mapped to your regulatory requirements.</p></a>
            ` : ""}
          </div>
        </div>

        <div style="margin-top:1.5rem;display:flex;gap:.75rem;flex-wrap:wrap">
          <button onclick="window.print()" class="cta-btn cta-btn-outline" data-cta="result-print">
            Download as PDF
          </button>
          <button id="share-results-btn" class="cta-btn cta-btn-outline" data-cta="result-share">
            Share results
          </button>
        </div>
        <div id="share-url-box" style="display:none;margin-top:.75rem;padding:1rem;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius)">
          <label style="font-size:.85rem;font-weight:600;display:block;margin-bottom:.25rem">Share this link with your team:</label>
          <input id="share-url-input" type="text" readonly style="width:100%;padding:.5rem;font-family:var(--font-mono);font-size:.8rem;background:var(--bg);border:1px solid var(--border);border-radius:4px;color:var(--text)" value="">
          <button id="copy-share-url" style="margin-top:.5rem;cursor:pointer;background:var(--accent);color:#fff;border:none;padding:.4rem 1rem;border-radius:4px;font-size:.85rem">Copy link</button>
        </div>
        <script>
        (function(){
          var btn=document.getElementById("share-results-btn");
          var box=document.getElementById("share-url-box");
          var inp=document.getElementById("share-url-input");
          var copyBtn=document.getElementById("copy-share-url");
          if(!btn||!box||!inp)return;
          btn.addEventListener("click",function(){
            inp.value=window.location.href;
            box.style.display="block";
            inp.select();
          });
          if(copyBtn){copyBtn.addEventListener("click",function(){
            inp.select();
            navigator.clipboard.writeText(inp.value).then(function(){copyBtn.textContent="Copied!";setTimeout(function(){copyBtn.textContent="Copy link"},2000)});
          });}
        })();
        </script>

        <div style="margin-top:1.25rem">${renderLeadIntakeTrustRail(turnstile)}</div>
      </div>
    </section>`,
    schemas: [
      serviceSchema(
        "Claw EA Readiness Assessment",
        "Assessment route for enterprise AI agent rollout readiness and risk-to-proof conversion planning.",
        "https://www.clawea.com/assessment",
      ),
    ],
  });
}

export function contactPage(turnstile: TurnstilePosture, opts?: { widgetEnabled?: boolean }): string {
  return layout({
    meta: {
      title: "Contact Sales | Claw EA Enterprise AI Agents",
      description: "Talk to our enterprise sales team about deploying verified AI agents for your organization.",
      path: "/contact",
    },
    breadcrumbs: [{ name: "Home", path: "/" }, { name: "Contact", path: "/contact" }],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:760px">
        <h1>Talk to Sales</h1>
        <p class="lead">Short path: share your contact details and use case. We reply with a scoped recommendation and next steps.</p>

        <form class="card lead-form" data-lead-form data-cta="contact-lead-form"${formGuardAttrs(turnstile)}>
          <div class="form-grid-2">
            <label class="form-field">
              <span>Work email *</span>
              <input type="email" name="email" required placeholder="you@company.com" autocomplete="email">
            </label>
            <label class="form-field">
              <span>Company *</span>
              <input type="text" name="company" required placeholder="Company name" autocomplete="organization">
            </label>
            <label class="form-field">
              <span>Full name *</span>
              <input type="text" name="fullName" required placeholder="Your name" autocomplete="name">
            </label>
            <label class="form-field">
              <span>Role (optional)</span>
              <input type="text" name="role" placeholder="Security lead, platform lead, CTO..." autocomplete="organization-title">
            </label>
            <label class="form-field form-field-wide">
              <span>Primary use case (optional)</span>
              <textarea name="primaryUseCase" rows="3" placeholder="Example: production deploy approvals, SIEM evidence collection, identity lifecycle approvals"></textarea>
            </label>
          </div>

          ${renderTurnstileBlock(turnstile, { widgetEnabled: opts?.widgetEnabled })}

          <p class="form-note" style="margin:.75rem 0 0">By submitting, you agree to follow-up from Claw EA and our <a href="/policy" aria-label="Read privacy policy">privacy policy</a>.</p>

          <div class="form-actions">
            <button type="submit" class="cta-btn cta-btn-lg" data-cta="contact-fast-submit" data-cta-copy${submitGuardAttrs(turnstile)}>Request tailored plan</button>
            <a href="/assessment" class="cta-btn cta-btn-outline cta-btn-lg" data-cta="contact-assessment">Run readiness assessment</a>
            <span class="form-status" data-lead-form-status aria-live="polite"></span>
          </div>

          <p class="form-note">Prefer email? Write to <a href="mailto:enterprise@clawbureau.com">enterprise@clawbureau.com</a>. Include company, role, and target use case.</p>
        </form>

        <div style="margin-top:1.25rem">${renderLeadIntakeTrustRail(turnstile)}</div>
      </div>
    </section>`,
    schemas: [
      faqSchema([
        { q: "How fast do you reply?", a: "Typically within four business hours." },
        { q: "Do you support pilots before contract?", a: "Yes. We can run a guided pilot with strict scope and measurable success criteria." },
        { q: "Can we bring our own model keys?", a: "Yes. BYOK is supported, and we keep proof and policy controls in place." },
      ]),
    ],
  });
}

export function bookPage(requestUrl: URL, turnstile: TurnstilePosture, opts?: { widgetEnabled?: boolean }): string {
  const leadId = clipString(requestUrl.searchParams.get("lead"), 80) ?? "";
  const email = clipString(requestUrl.searchParams.get("email"), 220) ?? "";
  const company = clipString(requestUrl.searchParams.get("company"), 160) ?? "";

  return layout({
    meta: {
      title: "Book a Rollout Session | Claw EA",
      description: "Book a deployment planning session for your enterprise AI agent rollout.",
      path: "/book",
    },
    breadcrumbs: [{ name: "Home", path: "/" }, { name: "Book", path: "/book" }],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:760px">
        <span class="badge badge-blue">Deployment planning</span>
        <h1>Book your deployment planning session</h1>
        <p class="lead">Share minimal details and reserve a rollout session. We prefill context from your assessment/contact path when available.</p>

        <form class="card lead-form" data-book-form data-cta="book-submit-form"${formGuardAttrs(turnstile)}>
          <input type="hidden" name="leadId" value="${esc(leadId)}">

          <div class="form-grid-2">
            <label class="form-field">
              <span>Work email</span>
              <input type="email" name="email" value="${esc(email)}" placeholder="you@company.com" autocomplete="email">
            </label>
            <label class="form-field">
              <span>Company</span>
              <input type="text" name="company" value="${esc(company)}" placeholder="Company name" autocomplete="organization">
            </label>
            <label class="form-field">
              <span>Preferred date</span>
              <input type="date" name="slotDate">
            </label>
            <label class="form-field">
              <span>Preferred time</span>
              <input type="time" name="slotTime" step="900">
            </label>
            <label class="form-field form-field-wide">
              <span>Timezone</span>
              <select name="timezone">
                <option value="">Auto-detect / Not sure</option>
                <option value="UTC">UTC</option>
                <option value="Europe/Berlin">Europe/Berlin</option>
                <option value="Europe/London">Europe/London</option>
                <option value="America/New_York">America/New_York</option>
                <option value="America/Chicago">America/Chicago</option>
                <option value="America/Los_Angeles">America/Los_Angeles</option>
                <option value="Asia/Singapore">Asia/Singapore</option>
                <option value="Asia/Tokyo">Asia/Tokyo</option>
              </select>
            </label>
            <label class="form-field form-field-wide">
              <span>Context for the session</span>
              <textarea name="notes" rows="4" placeholder="Scope, teams involved, compliance constraints, deadlines"></textarea>
            </label>
          </div>

          ${renderTurnstileBlock(turnstile, { widgetEnabled: opts?.widgetEnabled })}

          <div class="form-actions">
            <button type="submit" class="cta-btn cta-btn-lg" data-cta="book-submit-primary"${submitGuardAttrs(turnstile)}>Confirm booking request</button>
            <a href="/assessment" class="cta-btn cta-btn-outline cta-btn-lg" data-cta="book-assessment">Run assessment first</a>
            <span class="form-status" data-book-form-status aria-live="polite"></span>
          </div>

          <p class="form-note">Ops will confirm by email with exact session time and preparation checklist.</p>
        </form>

        <div style="margin-top:1.25rem">${renderLeadIntakeTrustRail(turnstile)}</div>
      </div>
    </section>`,
    schemas: [
      serviceSchema(
        "Claw EA Rollout Planning Session",
        "Book an enterprise rollout planning and qualification session for verified AI agents.",
        "https://www.clawea.com/book",
      ),
    ],
  });
}

export function sourcesHubPage(manifest: Record<string, ManifestEntry>): string {
  const rows = Object.entries(manifest)
    .map(([slug, meta]) => ({ slug, meta }))
    .filter((row) => row.meta.indexable !== false)
    .slice(0, 80);

  const familyCounts = new Map<string, number>();
  for (const row of rows) {
    const family = row.slug.split("/")[0] || "root";
    familyCounts.set(family, (familyCounts.get(family) ?? 0) + 1);
  }

  const familySummary = [...familyCounts.entries()]
    .sort((a, b) => (b[1] - a[1]) || a[0].localeCompare(b[0], "en"))
    .map(([family, count]) => `<li><a href="/${family}" class="pill-link">${esc(family)} · ${count} pages</a></li>`)
    .join("");

  const defaultFamilySummary = [
    ["tools", "Connector security and operations guides"],
    ["workflows", "Approval and evidence playbooks"],
    ["controls", "Policy controls and guardrails"],
    ["channels", "Team-facing control plane entries"],
  ]
    .map(([slug, label]) => `<li><a href="/${slug}" class="pill-link">${esc(slug)} · ${esc(label)}</a></li>`)
    .join("");

  const topIndexable = rows
    .slice(0, 24)
    .map((row) => `<li><a href="/${row.slug}">${esc(row.meta.title.replace(/ \| Claw EA$/, ""))}</a></li>`)
    .join("");

  const defaultTopIndexable = [
    ["/trust", "Trust Layer"],
    ["/agent-proof-and-attestation", "Proof and Attestation"],
    ["/secure-agent-execution", "Secure Agent Execution"],
    ["/policy-as-code-for-agents", "Policy as Code for Agents"],
    ["/controls", "Controls Hub"],
    ["/workflows", "Workflow Playbooks"],
    ["/tools", "Tools Hub"],
    ["/channels", "Channels Hub"],
  ]
    .map(([path, label]) => `<li><a href="${path}">${label}</a></li>`)
    .join("");

  return layout({
    meta: {
      title: "Citation Source Hub | Claw EA",
      description: "Source-first routing hub for citation-ready Claw EA pages and proof-linked implementation guides.",
      path: "/sources",
      canonicalPath: "/sources",
    },
    breadcrumbs: [{ name: "Home", path: "/" }, { name: "Sources", path: "/sources" }],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:900px">
        <span class="badge badge-blue">Citation hub</span>
        <h1>Source hub for AI discovery and enterprise buyers</h1>
        <p class="lead">Use this page to route to citation-ready articles, workflow runbooks, and proof-first pages with explicit references.</p>

        <div class="proof-summary-block">
          <h3>How to cite Claw EA pages</h3>
          <ul>
            <li>Prefer direct article URLs under <code>/tools</code>, <code>/workflows</code>, and <code>/controls</code>.</li>
            <li>Use pages that include explicit Sources sections and proof summaries.</li>
            <li>For platform trust claims, cite <a href="/trust">/trust</a> and <a href="/agent-proof-and-attestation">/agent-proof-and-attestation</a>.</li>
          </ul>
        </div>

        <div class="grid-2" style="margin-top:1.5rem">
          <article class="card sources-family-card">
            <h3>Core resource categories</h3>
            <ul>${familySummary || defaultFamilySummary}</ul>
          </article>
          <article class="card sources-next-card">
            <h3>Next steps</h3>
            <div class="actions" style="justify-content:flex-start;gap:.5rem;margin-top:.25rem">
              <a href="/assessment" class="cta-btn cta-btn-outline">Run assessment</a>
              <a href="/contact" class="cta-btn cta-btn-outline">Submit project brief</a>
              <a href="/book" class="cta-btn cta-btn-outline">Book rollout session</a>
            </div>
            <ul style="margin-top:.85rem">
              <li><a href="/trust">Review trust controls</a></li>
              <li><a href="/pricing">Review pricing and rollout tiers</a></li>
            </ul>
          </article>
        </div>

        <article class="card" style="margin-top:1.5rem">
          <h3>Frequently cited pages</h3>
          <ul class="sources-hub-list">${topIndexable || defaultTopIndexable}</ul>
        </article>
      </div>
    </section>`,
  });
}

export function notFoundPage(): string {
  return layout({
    meta: { title: "Page Not Found | Claw EA", description: "The page you're looking for doesn't exist.", path: "/404", noindex: true },
    body: `
    <section class="section content-page" style="text-align:center">
      <div class="wrap">
        <h1>404 - Page Not Found</h1>
        <p class="lead">The page you're looking for doesn't exist or has been moved.</p>
        <div class="actions" style="margin-top:2rem;justify-content:center">
          <a href="/" class="cta-btn cta-btn-lg">Back to Home</a>
          <a href="/assessment" class="cta-btn cta-btn-outline cta-btn-lg">Run assessment</a>
          <a href="/book" class="cta-btn cta-btn-outline cta-btn-lg">Book session</a>
          <a href="/contact" class="cta-btn cta-btn-outline cta-btn-lg">Talk to sales</a>
        </div>
      </div>
    </section>`,
  });
}

// ── Article Page Renderer ─────────────────────────────────────────

export function formatDateYmd(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().slice(0, 10);
}

export function estimateReadMinutes(rawHtml: string, wordsPerMinute = 220): number {
  const words = rawHtml
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .split(" ")
    .filter(Boolean).length;

  if (words <= 0) return 1;
  return Math.max(1, Math.round(words / wordsPerMinute));
}

function toTitle(s: string): string {
  return s
    .split("-")
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

function uniqueLinks(items: Array<{ name: string; path: string }>): Array<{ name: string; path: string }> {
  const out: Array<{ name: string; path: string }> = [];
  const seen = new Set<string>();
  for (const i of items) {
    if (!i?.path || seen.has(i.path)) continue;
    seen.add(i.path);
    out.push(i);
  }
  return out;
}

export function relatedLinksForArticle(article: Article): Array<{ name: string; path: string }> {
  const slugParts = article.slug.split("/").filter(Boolean);
  const family = slugParts[0] ?? "";

  const links: Array<{ name: string; path: string }> = [
    { name: "Run assessment", path: "/assessment" },
    { name: "Talk to sales", path: "/contact" },
    { name: "Policy-as-Code", path: "/policy-as-code-for-agents" },
    { name: "Secure Execution", path: "/secure-agent-execution" },
    { name: "Proof and Attestation", path: "/agent-proof-and-attestation" },
  ];

  if (family) {
    links.push({ name: `${toTitle(family)} hub`, path: `/${family}` });
  }

  // Family-specific helpers
  if (family === "workflows") {
    const toolSlug = slugParts[2];
    const channelSlug = slugParts[3];
    if (toolSlug) links.push({ name: `${toTitle(toolSlug)} tool page`, path: `/tools/${toolSlug}` });
    if (channelSlug) links.push({ name: `${toTitle(channelSlug)} channel page`, path: `/channels/${channelSlug}` });

    links.push({ name: "Approval gates", path: "/controls/approval-gates" });
    links.push({ name: "Two-person rule", path: "/controls/two-person-rule" });
    links.push({ name: "Budgets", path: "/controls/budgets" });
  }

  if (family === "tools") {
    const toolSlug = slugParts[1];
    if (toolSlug) links.push({ name: `${toTitle(toolSlug)} overview`, path: `/tools/${toolSlug}` });

    links.push({ name: "Egress allowlist", path: "/controls/egress-allowlist" });
    links.push({ name: "DLP and redaction", path: "/controls/dlp-redaction" });
    links.push({ name: "Secrets boundary", path: "/controls/secret-boundary" });
  }

  if (family === "channels") {
    const channelSlug = slugParts[1];
    if (channelSlug) links.push({ name: `${toTitle(channelSlug)} overview`, path: `/channels/${channelSlug}` });

    links.push({ name: "Tool allow/deny", path: "/controls/tool-allow-deny" });
    links.push({ name: "Approval gates", path: "/controls/approval-gates" });
    links.push({ name: "Kill switch", path: "/controls/kill-switch" });
  }

  if (family === "controls") {
    links.push({ name: "Controls hub", path: "/controls" });
    links.push({ name: "Policy artifacts", path: "/policy" });
  }

  // Cluster-aware cross-linking
  for (const cluster of MONEY_CLUSTERS) {
    const isHub = article.slug === cluster.hub;
    const isChild = cluster.children.includes(article.slug);
    if (isHub) {
      for (const child of cluster.children) {
        const label = child.split("/").pop() ?? child;
        links.push({ name: toTitle(label.replace(/-/g, " ")), path: `/${child}` });
      }
      links.push({ name: "Security Review Pack", path: "/trust/security-review" });
    } else if (isChild) {
      links.push({ name: cluster.hubTitle, path: `/${cluster.hub}` });
      links.push({ name: "Security Review Pack", path: "/trust/security-review" });
    }
  }

  // Remove self-link and dedupe
  const self = `/${article.slug}`;
  const isClusterHub = MONEY_CLUSTERS.some((c) => article.slug === c.hub);
  const maxLinks = isClusterHub ? 14 : 8;
  return uniqueLinks(links.filter((l) => l.path !== self)).slice(0, maxLinks);
}

// ── Article Processing Helpers ────────────────────────────────────

function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/<[^>]+>/g, "")
    .replace(/&[^;]+;/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}

interface TocEntry {
  id: string;
  text: string;
  depth: number;
}

/** Inject `id` attributes + anchor links into h2/h3 elements, extract TOC. */
function extractAndInjectHeadings(rawHtml: string): { html: string; toc: TocEntry[] } {
  const toc: TocEntry[] = [];
  const seen = new Set<string>();
  const processed = rawHtml.replace(
    /<(h[23])([^>]*)>([\s\S]*?)<\/\1>/gi,
    (_match, tag: string, attrs: string, content: string) => {
      if (attrs.includes(" id=")) return _match; // already has id
      const text = content.replace(/<[^>]+>/g, "").trim();
      let id = slugify(text);
      if (!id) return _match;
      if (seen.has(id)) id += "-" + seen.size;
      seen.add(id);
      const depth = tag.toLowerCase() === "h2" ? 2 : 3;
      toc.push({ id, text, depth });
      return `<${tag}${attrs} id="${id}">${content}<a href="#${id}" class="heading-anchor" aria-hidden="true">#</a></${tag}>`;
    },
  );
  return { html: processed, toc };
}

/** Render a sticky sidebar Table of Contents from extracted headings. */
function renderToc(toc: TocEntry[]): string {
  if (toc.length < 3) return "";
  const items = toc
    .map((e) => `<li class="depth-${e.depth}"><a href="#${e.id}">${esc(e.text)}</a></li>`)
    .join("");
  return `
  <aside class="toc" aria-label="Table of contents">
    <details open>
      <summary>On this page</summary>
      <nav><ol>${items}</ol></nav>
    </details>
  </aside>`;
}

/** Wrap bare <table> elements in a responsive scroll container. */
function wrapTables(rawHtml: string): string {
  return rawHtml
    .replace(/<table\b/g, '<div class="table-wrap" role="region" tabindex="0"><table')
    .replace(/<\/table>/g, "</table></div>");
}

function isBofuArticle(article: Article): boolean {
  return (
    article.slug.startsWith("tools/")
    || article.slug.startsWith("workflows/")
    || article.slug.startsWith("channels/")
    || article.slug.startsWith("compliance/")
    || article.slug.startsWith("compare/")
    || article.slug.startsWith("for/")
  );
}

function renderProofSummaryBlock(article: Article): string {
  if (!isBofuArticle(article)) return "";

  const sourceList = (article.sources ?? [])
    .slice(0, 3)
    .map((s) => `<li><a href="${esc(s.uri)}" rel="noopener" target="_blank">${esc(s.title || s.uri)}</a></li>`)
    .join("");

  return `
  <section class="proof-summary-block" aria-label="Proof-first summary">
    <h3>Proof-first summary</h3>
    <ul>
      <li>Execution policy is explicit before an agent can run irreversible actions.</li>
      <li>Every model call and tool action can be tied to receipts and audit evidence.</li>
      <li>Rollback posture is documented with deterministic failure handling paths.</li>
    </ul>
    <p class="proof-summary-links">
      <a href="/assessment" data-cta="proof-summary-assessment">Run assessment</a>
      <span>·</span>
      <a href="/contact" data-cta="proof-summary-contact">Request tailored rollout plan</a>
    </p>
    ${sourceList ? `<div class="proof-summary-sources"><strong>Top references</strong><ul>${sourceList}</ul></div>` : ""}
  </section>`;
}

export function articlePage(article: Article): string {
  const breadcrumbs = breadcrumbsFromSlug(article.slug);
  const schemas: string[] = [];

  const url = canonical(`/${article.slug}`);
  const headline = article.title.replace(/ \| Claw EA$/, "");

  if (article.faqs.length > 0) {
    schemas.push(faqSchema(article.faqs));
  }

  if (article.howToSteps && article.howToSteps.length > 0) {
    schemas.push(
      howToSchema(
        { title: article.howToTitle ?? headline, steps: article.howToSteps },
        url,
      ),
    );
  }

  if (article.category === "glossary") {
    schemas.push(definedTermSchema(headline, article.description, url));
  } else {
    schemas.push(
      techArticleSchema({
        headline,
        description: article.description,
        url,
        datePublished: article.generatedAt,
        dateModified: article.generatedAt,
        section: article.category,
      }),
    );
  }

  const updated = formatDateYmd(article.generatedAt);
  const readMinutes = estimateReadMinutes(article.html);
  const slugParts = article.slug.split("/").filter(Boolean);

  // Process article body: inject heading IDs, extract TOC, wrap tables
  const { html: processedHtml, toc } = extractAndInjectHeadings(article.html);
  const bodyHtml = wrapTables(processedHtml);
  const tocHtml = renderToc(toc);

  // Key takeaways module (uses article description as summary)
  const takeawaysHtml = article.description
    ? `<div class="takeaways"><div class="takeaways-title">&#9672; Key takeaway</div><p>${esc(article.description)}</p></div>`
    : "";

  const proofSummaryHtml = renderProofSummaryBlock(article);

  // Related content with card styling
  const related = relatedLinksForArticle(article);
  const relatedHtml = related.length
    ? `<div class="related"><h3>Related</h3><div class="related-grid">${related
        .map((l) => `<a href="${l.path}" class="related-card"><span class="related-label">${esc(l.name)}</span></a>`)
        .join("")}</div></div>`
    : "";

  const categoryLabel = article.category
    .replace(/-/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());

  const familySlug = slugParts.length > 1 ? slugParts[0] : null;
  const familyLinkHtml = familySlug
    ? `<a href="/${familySlug}" class="meta-chip meta-chip-link" role="listitem">${esc(toTitle(familySlug))} hub</a>`
    : "";

  return layout({
    meta: {
      title: article.title,
      description: article.description,
      path: `/${article.slug}`,
      ogType: "article",
      ogImageAlt: `${headline} | Claw EA`,
      articleSection: categoryLabel,
      publishedTime: article.generatedAt,
      modifiedTime: article.generatedAt,
      // Plan A: fail-closed. Only explicitly indexable pages should be indexed.
      noindex: article.indexable !== true,
    },
    breadcrumbs,
    schemas,
    body: `
    <section class="section content-page">
      <div class="wrap">
        <span class="badge badge-blue">${categoryLabel}</span>
        <h1>${esc(headline)}</h1>
        <p class="article-meta">Evidence is linked in Sources when available.</p>
        <div class="article-meta-strip" role="list" aria-label="Article metadata">
          <span class="meta-chip" role="listitem">Updated <time datetime="${esc(article.generatedAt)}">${updated}</time></span>
          <span class="meta-chip" role="listitem">${readMinutes} min read</span>
          <span class="meta-chip" role="listitem">${esc(categoryLabel)}</span>
          ${familyLinkHtml}
        </div>
        ${takeawaysHtml}
        ${proofSummaryHtml}
        <div class="article-layout">
          ${tocHtml}
          <div class="article-main">
            <div class="article-body">${bodyHtml}</div>
            ${clusterCtaForArticle(article.slug)}
            ${relatedHtml}
          </div>
        </div>
      </div>
    </section>`,
  });
}

export function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/* ── Money Cluster CTAs ────────────────────────────────────────── */

interface ClusterDef {
  label: string;
  hub: string;
  hubTitle: string;
  children: string[];
  angle: string;
}

const MONEY_CLUSTERS: ClusterDef[] = [
  {
    label: "Production Deploy Approvals",
    hub: "workflows/production-deploy-approval",
    hubTitle: "Production Deploy Approval Workflow",
    children: [
      "tools/github", "tools/github-actions", "tools/argo-cd", "tools/terraform-cloud",
      "controls/two-person-rule", "controls/approval-gates",
      "workflows/cicd-policy-enforcement",
    ],
    angle: "We run this on our own repo. Every agent PR carries a verifiable evidence pack.",
  },
  {
    label: "Identity / Access Request Automation",
    hub: "workflows/access-request-automation",
    hubTitle: "Access Request Automation Workflow",
    children: [
      "tools/okta", "tools/entra-id", "tools/google-admin",
      "policy/scoped-tokens", "controls/approval-gates",
    ],
    angle: "Scoped tokens bind agent identity to permissions to audit trail.",
  },
  {
    label: "Compliance Evidence Collection",
    hub: "workflows/siem-evidence-collection",
    hubTitle: "SIEM Evidence Collection Workflow",
    children: [
      "workflows/sox-control-testing", "audit/tamper-evident-logs",
      "proof/proof-bundles", "compliance",
    ],
    angle: "Proof bundles are offline-verifiable evidence artifacts. No vendor lock-in.",
  },
];

export function clusterCtaForArticle(slug: string): string {
  for (const cluster of MONEY_CLUSTERS) {
    const isHub = slug === cluster.hub;
    const isChild = cluster.children.includes(slug);
    if (!isHub && !isChild) continue;

    const hubLink = isHub
      ? ""
      : `<p style="margin-bottom:.5rem"><a href="/${cluster.hub}">&larr; ${esc(cluster.hubTitle)}</a></p>`;

    return `
    <div class="cta-banner" style="margin-top:2rem">
      ${hubLink}
      <h2>See how this works for your stack</h2>
      <p>${esc(cluster.angle)}</p>
      <a href="/assessment" class="cta-btn cta-btn-lg" data-cta="cluster-assessment-${esc(cluster.hub.split("/").pop() ?? "")}">Take the assessment</a>
      <a href="/trust/security-review" class="cta-btn cta-btn-outline cta-btn-lg" style="margin-left:.75rem" data-cta="cluster-security-review">Security Review Pack</a>
    </div>`;
  }

  // Default CTA for non-cluster pages
  return `
    <div class="cta-banner" style="margin-top:2rem">
      <h2>See how this applies to your environment</h2>
      <p>Take the two-minute assessment. We map controls to your stack and risk profile.</p>
      <a href="/assessment" class="cta-btn cta-btn-lg" data-cta="article-assessment">Take the assessment</a>
    </div>`;
}

// ── Router ────────────────────────────────────────────────────────

