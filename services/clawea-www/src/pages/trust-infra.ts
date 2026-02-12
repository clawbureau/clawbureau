/**
 * Trust infrastructure pages: /security, /privacy, /terms, /status, /docs, /changelog
 * Pages enterprise buyers check before procurement.
 */

import { layout } from "../layout";
import { faqSchema, serviceSchema } from "../seo";

/* ── /security ───────────────────────────────────────────────── */

export function securityPage(): string {
  return layout({
    meta: {
      title: "Security | Claw EA",
      description: "How Claw EA handles data, encryption, access controls, and infrastructure security. Protocol is hash-only by design — no customer data stored in proof artifacts.",
      path: "/security",
    },
    breadcrumbs: [
      { name: "Home", path: "/" },
      { name: "Security", path: "/security" },
    ],
    schemas: [
      serviceSchema("Claw EA Security Posture", "Data handling, encryption, access controls, and infrastructure security for enterprise AI agent governance.", "https://www.clawea.com/security"),
      faqSchema([
        { q: "Does Claw EA store customer data?", a: "No. Proof bundles contain cryptographic hashes of inputs and outputs, not the actual content. Gateway receipts record request_hash and response_hash (SHA-256), not the request or response text. No customer PII, PHI, or proprietary content is stored in proof artifacts." },
        { q: "What encryption does Claw EA use?", a: "Ed25519 for all signatures (receipts, bundles, commit proofs). SHA-256 for content hashing and event chain integrity. TLS 1.3 for all data in transit. AES-256 for data at rest where applicable." },
        { q: "How is identity managed?", a: "DID-based identity (did:key with Ed25519 key pairs). No passwords or bearer tokens to leak. Each agent has its own DID. Key rotation is supported with continuity proofs." },
      ]),
    ],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:900px">
        <h1>Security</h1>
        <p class="lead">Claw EA is designed so that the protocol itself minimizes the attack surface. Proof artifacts contain hashes, not content. Identity is DID-based, not password-based. Verification is offline, not API-dependent.</p>

        <h2>Data Handling</h2>
        <div class="grid-2">
          <div class="card">
            <h3>Hash-Only by Design</h3>
            <p>Gateway receipts contain <code>request_hash</code> and <code>response_hash</code> (SHA-256), not the actual model inputs or outputs. Proof bundles contain event hashes, not event content. This means proof artifacts are safe to store, transmit, and share with auditors without exposing proprietary data.</p>
          </div>
          <div class="card">
            <h3>No PII in Receipts</h3>
            <p>Receipts record: model name, provider, token counts, latency, and hash bindings. They do not record: prompt text, response text, user names, email addresses, or any personally identifiable information.</p>
          </div>
        </div>

        <h2>Encryption</h2>
        <div class="compare-table-wrap"><table class="compare-table" role="table">
          <thead><tr><th>Layer</th><th>Algorithm</th><th>Purpose</th></tr></thead>
          <tbody>
            <tr><td>Signatures</td><td>Ed25519</td><td>Receipt signing, bundle signing, commit proofs</td></tr>
            <tr><td>Hashing</td><td>SHA-256</td><td>Content hashing, event chain integrity, Merkle roots</td></tr>
            <tr><td>Transit</td><td>TLS 1.3</td><td>All API communication, worker-to-worker, client-to-edge</td></tr>
            <tr><td>At rest</td><td>AES-256</td><td>D1 databases, R2 object storage (Cloudflare-managed keys)</td></tr>
          </tbody>
        </table></div>

        <h2>Identity and Access</h2>
        <ul>
          <li><strong>DID-based identity:</strong> Agents are identified by <code>did:key</code> with Ed25519 key pairs. No passwords, no bearer tokens, no shared secrets.</li>
          <li><strong>Capability scoped tokens (CST):</strong> Short-lived, scope-hashed, job-bound. Expired tokens are rejected. Revocation is immediate.</li>
          <li><strong>Key rotation:</strong> Agent DIDs can be rotated with continuity proofs that link the old key to the new key.</li>
          <li><strong>No admin passwords:</strong> Infrastructure access is via Cloudflare Access (SSO-gated) and Wrangler CLI (API token with scoped permissions).</li>
        </ul>

        <h2>Infrastructure</h2>
        <ul>
          <li><strong>Cloudflare Workers:</strong> Every request runs in a hardware-isolated V8 isolate. No shared memory, no shared filesystem, no container escape surface.</li>
          <li><strong>300+ global PoPs:</strong> Requests are routed to the nearest Cloudflare edge. Sub-300ms TTFB globally.</li>
          <li><strong>No long-lived servers:</strong> Workers are ephemeral. No SSH access, no persistent processes, no attack surface from long-running daemons.</li>
          <li><strong>DDoS protection:</strong> Cloudflare's network-layer DDoS mitigation is always on. No additional configuration required.</li>
        </ul>

        <h2>Verification Independence</h2>
        <p>The most important security property: <strong>you do not need to trust the platform to verify proof artifacts.</strong> The clawverify reference verifier runs offline with only the bundle JSON and the signer's public key. If Claw EA were compromised, your existing proof bundles would still verify independently.</p>

        <h2>Deep Dive</h2>
        <p>The <a href="/trust/security-review">Security Review Pack</a> contains the full architecture diagram, threat model (replay, exfiltration, prompt injection, nondeterminism), Merkle transparency logging details, and deployment integrity documentation.</p>
      </div>
    </section>`,
  });
}

/* ── /privacy ────────────────────────────────────────────────── */

export function privacyPage(): string {
  return layout({
    meta: {
      title: "Privacy Policy | Claw EA",
      description: "How Claw EA handles personal data. Proof bundles contain hashes, not content. No PII in receipts by design. GDPR-compatible architecture.",
      path: "/privacy",
    },
    breadcrumbs: [
      { name: "Home", path: "/" },
      { name: "Privacy Policy", path: "/privacy" },
    ],
    schemas: [],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:900px">
        <h1>Privacy Policy</h1>
        <p><strong>Effective date:</strong> February 12, 2026</p>
        <p><strong>Last updated:</strong> February 12, 2026</p>
        <p>Claw Bureau ("we," "us," "our") operates the Claw EA platform and the clawea.com website. This policy describes how we collect, use, and protect personal data.</p>

        <h2>1. Data We Collect</h2>
        <h3>Website visitors</h3>
        <ul>
          <li><strong>Contact forms:</strong> Name, email, company, team size (when you submit the contact, book, or assessment forms)</li>
          <li><strong>Resource downloads:</strong> Email address and optionally industry (when you access gated resources)</li>
          <li><strong>Analytics:</strong> Page views, referral source, UTM parameters. We do not use third-party tracking cookies. Analytics are first-party and aggregated.</li>
          <li><strong>Turnstile:</strong> Cloudflare Turnstile challenge tokens for bot protection. No CAPTCHAs, no fingerprinting.</li>
        </ul>

        <h3>Platform users (Claw EA product)</h3>
        <ul>
          <li><strong>Account identity:</strong> DID (Decentralized Identifier) key pairs. No passwords, no email-based accounts.</li>
          <li><strong>Proof artifacts:</strong> Receipts and proof bundles contain <strong>cryptographic hashes only</strong>, not content. Gateway receipts record request_hash and response_hash (SHA-256), not the actual text of model inputs or outputs.</li>
          <li><strong>Metadata:</strong> Model name, provider, token counts, latency, timestamps. No PII is included in receipt metadata.</li>
        </ul>

        <h2>2. How We Use Data</h2>
        <ul>
          <li><strong>Contact information:</strong> To respond to inquiries, schedule sessions, and send product updates (with opt-out)</li>
          <li><strong>Analytics:</strong> To understand which pages are useful and improve the site</li>
          <li><strong>Proof artifacts:</strong> Stored for audit and verification purposes. We do not mine, analyze, or sell proof artifact data.</li>
        </ul>

        <h2>3. Data We Do Not Collect</h2>
        <ul>
          <li>Model prompt text or response text (hashes only)</li>
          <li>Customer proprietary data or trade secrets</li>
          <li>Third-party tracking cookies or cross-site identifiers</li>
          <li>Biometric data, location data, or device fingerprints</li>
        </ul>

        <h2>4. Data Sharing</h2>
        <p>We do not sell personal data. We share data only with:</p>
        <ul>
          <li><strong>Cloudflare:</strong> Infrastructure provider (Workers, D1, R2). Subject to Cloudflare's privacy policy and DPA.</li>
          <li><strong>Service providers:</strong> Email delivery (for form responses and product updates). No data broker relationships.</li>
        </ul>

        <h2>5. GDPR and International Data</h2>
        <ul>
          <li><strong>Legal basis:</strong> Legitimate interest (website analytics), consent (form submissions), contract performance (platform usage)</li>
          <li><strong>Data residency:</strong> Data is processed at Cloudflare edge locations globally. Enterprise tier supports data residency restrictions.</li>
          <li><strong>Rights:</strong> You may request access, correction, deletion, or portability of your personal data by contacting us at privacy@clawbureau.com</li>
          <li><strong>DPA:</strong> Available on Enterprise tier for customers requiring a Data Processing Agreement</li>
        </ul>

        <h2>6. Data Retention</h2>
        <ul>
          <li><strong>Contact form submissions:</strong> Retained for 24 months or until you request deletion</li>
          <li><strong>Proof artifacts:</strong> Retained per your tier (90 days to 7 years). Deleted on account termination unless regulatory retention applies.</li>
          <li><strong>Analytics:</strong> Aggregated data retained indefinitely. Individual-level data rotated every 90 days.</li>
        </ul>

        <h2>7. Security</h2>
        <p>See our <a href="/security">Security page</a> for details on encryption, access controls, and infrastructure. The protocol's hash-only design means that even in the event of a data breach, proof artifacts do not contain exploitable content.</p>

        <h2>8. Changes</h2>
        <p>We will update this policy as our practices evolve. Material changes will be noted with an updated effective date. Continued use of the site after changes constitutes acceptance.</p>

        <h2>9. Contact</h2>
        <p>For privacy questions or data requests: <strong>privacy@clawbureau.com</strong></p>
        <p>Claw Bureau<br>Privacy inquiries</p>
      </div>
    </section>`,
  });
}

/* ── /terms ──────────────────────────────────────────────────── */

export function termsPage(): string {
  return layout({
    meta: {
      title: "Terms of Service | Claw EA",
      description: "Terms of service for the Claw EA platform and website. Standard SaaS terms with pilot engagement scope and liability limits.",
      path: "/terms",
    },
    breadcrumbs: [
      { name: "Home", path: "/" },
      { name: "Terms of Service", path: "/terms" },
    ],
    schemas: [],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:900px">
        <h1>Terms of Service</h1>
        <p><strong>Effective date:</strong> February 12, 2026</p>
        <p><strong>Last updated:</strong> February 12, 2026</p>
        <p>These terms govern your use of the Claw EA platform and clawea.com website operated by Claw Bureau ("we," "us," "our").</p>

        <h2>1. Service Description</h2>
        <p>Claw EA provides enterprise AI agent governance infrastructure including: policy enforcement, cryptographic receipts, proof bundles, verification, and related tools. The platform runs on Cloudflare Workers infrastructure.</p>

        <h2>2. Account and Access</h2>
        <ul>
          <li>Platform access requires a Claw EA subscription or pilot agreement</li>
          <li>Identity is DID-based. You are responsible for securing your private keys.</li>
          <li>You may not share access credentials or use the platform for unauthorized purposes</li>
          <li>We may suspend access for violation of these terms or for security reasons</li>
        </ul>

        <h2>3. Pilot Engagements</h2>
        <p>Two-week pilot engagements are subject to a separate pilot agreement that specifies scope, success criteria, and conversion terms. Pilot pricing and terms are agreed in writing before the pilot begins.</p>

        <h2>4. Subscriptions and Payment</h2>
        <ul>
          <li>Subscription tiers (Starter, Team, Business, Enterprise) are billed monthly or annually as agreed</li>
          <li>Prices may change with 30 days notice. Existing subscriptions are honored until renewal.</li>
          <li>Enterprise pricing is custom and defined in your order form</li>
          <li>Refunds are handled on a case-by-case basis for annual subscriptions</li>
        </ul>

        <h2>5. Your Data</h2>
        <ul>
          <li>You retain ownership of all data you provide to the platform</li>
          <li>Proof artifacts (receipts, bundles) contain hashes of your data, not the data itself</li>
          <li>We do not access, analyze, or sell your data</li>
          <li>On account termination, your data is deleted per our <a href="/privacy">Privacy Policy</a> retention schedule</li>
        </ul>

        <h2>6. Proof Artifacts and Verification</h2>
        <ul>
          <li>Proof bundles are cryptographic evidence, not legal guarantees</li>
          <li>Verification results (PASS/FAIL) are deterministic given the same inputs</li>
          <li>We do not warrant that proof artifacts will satisfy any specific regulatory requirement — compliance mapping is advisory</li>
          <li>The offline verifier is provided as-is for independent verification</li>
        </ul>

        <h2>7. Availability</h2>
        <ul>
          <li>We target 99.9% uptime for platform services</li>
          <li>Enterprise tier includes a custom SLA with defined guarantees</li>
          <li>Scheduled maintenance will be announced 48 hours in advance when possible</li>
          <li>Current service status is available at <a href="/status">/status</a></li>
        </ul>

        <h2>8. Limitation of Liability</h2>
        <p>To the maximum extent permitted by law, our total liability for any claims arising from use of the platform is limited to the fees you paid in the 12 months preceding the claim. We are not liable for indirect, consequential, or punitive damages.</p>

        <h2>9. Intellectual Property</h2>
        <ul>
          <li>The Clawsig Protocol specification is published openly. You may implement it.</li>
          <li>The Claw EA platform, branding, and proprietary tooling remain our intellectual property</li>
          <li>"Claw EA," "Claw Bureau," "Claw Verified," and related marks are our trademarks</li>
        </ul>

        <h2>10. Termination</h2>
        <p>Either party may terminate with 30 days written notice. On termination, we will provide a data export (proof bundles, configuration) within 30 days of request. After the export period, data is deleted per retention policy.</p>

        <h2>11. Governing Law</h2>
        <p>These terms are governed by the laws of the jurisdiction specified in your order form (or Delaware, USA if no order form exists). Disputes will be resolved by binding arbitration unless both parties agree to litigation.</p>

        <h2>12. Changes</h2>
        <p>We may update these terms with 30 days notice. Material changes will be communicated by email to active subscribers. Continued use after the notice period constitutes acceptance.</p>

        <h2>13. Contact</h2>
        <p>For questions about these terms: <strong>legal@clawbureau.com</strong></p>
      </div>
    </section>`,
  });
}

/* ── /docs ───────────────────────────────────────────────────── */

export function docsPage(): string {
  return layout({
    meta: {
      title: "Documentation | Claw EA",
      description: "Developer, security team, and compliance team documentation for Claw EA. Protocol spec, SDK, CLI, API references, and adoption guides.",
      path: "/docs",
    },
    breadcrumbs: [
      { name: "Home", path: "/" },
      { name: "Documentation", path: "/docs" },
    ],
    schemas: [
      serviceSchema("Claw EA Documentation", "Developer, security team, and compliance team documentation for enterprise AI agent governance.", "https://www.clawea.com/docs"),
    ],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:960px">
        <h1>Documentation</h1>
        <p class="lead">Everything you need to evaluate, implement, and operate Claw EA.</p>

        <div class="docs-tabs" role="tablist" aria-label="Documentation sections">
          <button class="docs-tab active" role="tab" aria-selected="true" aria-controls="tab-quickstart" data-tab="quickstart">Quick Start</button>
          <button class="docs-tab" role="tab" aria-selected="false" aria-controls="tab-sdk" data-tab="sdk">SDK Reference</button>
          <button class="docs-tab" role="tab" aria-selected="false" aria-controls="tab-api" data-tab="api">API Reference</button>
          <button class="docs-tab" role="tab" aria-selected="false" aria-controls="tab-protocol" data-tab="protocol">Protocol Spec</button>
          <button class="docs-tab" role="tab" aria-selected="false" aria-controls="tab-security" data-tab="security">Security &amp; Compliance</button>
        </div>

        <!-- Quick Start -->
        <div class="docs-panel active" id="tab-quickstart" role="tabpanel">
          <h2>Get started in 5 minutes</h2>
          <p>Install the SDK, generate a DID keypair, emit a proof bundle, and verify it.</p>

          <h3>1. Install the SDK</h3>
          <pre><code>npm install @clawbureau/clawsig-sdk</code></pre>

          <h3>2. Generate a DID keypair</h3>
          <pre><code>npx clawsig keygen --out ./agent-key.json
# Output: did:key:z6Mkf...xy3m (your agent DID)</code></pre>

          <h3>3. Sign a commit</h3>
          <pre><code>COMMIT_SHA=$(git rev-parse HEAD)
npx clawsig sign "commit:$COMMIT_SHA" --key ./agent-key.json
# Output: commit.sig.json</code></pre>

          <h3>4. Verify the signature</h3>
          <pre><code>npx clawsig verify ./commit.sig.json
# Output: PASS — signature valid for did:key:z6Mkf...xy3m</code></pre>

          <h3>5. Add to your CI pipeline</h3>
          <p>See the <a href="/guides/github-actions-proof-pipeline">GitHub Actions proof pipeline guide</a> for a complete workflow file.</p>

          <h3>Next steps</h3>
          <ul>
            <li><a href="/guides/okta-scoped-tokens">Connect Okta for identity-scoped tokens</a></li>
            <li><a href="/guides/compliance-evidence-export">Export compliance evidence bundles</a></li>
            <li><a href="/resources/protocol-whitepaper">Read the full protocol spec</a></li>
          </ul>
        </div>

        <!-- SDK Reference -->
        <div class="docs-panel" id="tab-sdk" role="tabpanel" hidden>
          <h2>SDK Reference</h2>
          <p>The <code>@clawbureau/clawsig-sdk</code> package provides TypeScript types and utilities for the Clawsig Protocol.</p>

          <h3>Core types</h3>
          <div class="compare-table-wrap"><table class="compare-table" role="table">
            <thead><tr><th>Type</th><th>Description</th><th>Schema</th></tr></thead>
            <tbody>
              <tr><td><code>WorkPolicyContract</code></td><td>Signed, content-addressed policy document</td><td>work_policy_contract.v1.json</td></tr>
              <tr><td><code>ScopedTokenClaims</code></td><td>CST claim set with scopes and policy pin</td><td>scoped_token_claims.v1.json</td></tr>
              <tr><td><code>GatewayReceipt</code></td><td>Signed model gateway attestation</td><td>gateway_receipt.v1.json</td></tr>
              <tr><td><code>ToolReceipt</code></td><td>Signed tool invocation attestation</td><td>tool_receipt.v1.json</td></tr>
              <tr><td><code>ProofBundle</code></td><td>Hash-linked event chain with receipts</td><td>proof_bundle.v1.json</td></tr>
              <tr><td><code>ReceiptBinding</code></td><td>Ties a receipt to a run_id + event_hash</td><td>receipt_binding.v1.json</td></tr>
              <tr><td><code>CommitSignature</code></td><td>Ed25519 signature over a git commit SHA</td><td>message_signature.m1.json</td></tr>
            </tbody>
          </table></div>

          <h3>Key functions</h3>
          <div class="compare-table-wrap"><table class="compare-table" role="table">
            <thead><tr><th>Function</th><th>Description</th></tr></thead>
            <tbody>
              <tr><td><code>keygen()</code></td><td>Generate an Ed25519 keypair and DID</td></tr>
              <tr><td><code>sign(message, privateKey)</code></td><td>Sign a message (commit SHA, bundle hash) with Ed25519</td></tr>
              <tr><td><code>verify(signature, publicKey)</code></td><td>Verify an Ed25519 signature — returns PASS/FAIL with reason code</td></tr>
              <tr><td><code>hashBundle(bundle)</code></td><td>Compute canonical SHA-256 hash of a proof bundle</td></tr>
              <tr><td><code>verifyBundle(bundle, config)</code></td><td>Full bundle verification: signatures, bindings, event chain integrity</td></tr>
              <tr><td><code>resolveDidKey(did)</code></td><td>Resolve a did:key to an Ed25519 public key</td></tr>
            </tbody>
          </table></div>

          <h3>Installation</h3>
          <pre><code>npm install @clawbureau/clawsig-sdk
# TypeScript types included. No runtime dependencies.</code></pre>
        </div>

        <!-- API Reference -->
        <div class="docs-panel" id="tab-api" role="tabpanel" hidden>
          <h2>API Reference</h2>
          <p>Public-facing endpoints for each service. All services run on Cloudflare Workers with CORS enabled.</p>

          <h3>clawverify (verification)</h3>
          <div class="compare-table-wrap"><table class="compare-table" role="table">
            <thead><tr><th>Endpoint</th><th>Method</th><th>Description</th></tr></thead>
            <tbody>
              <tr><td><code>/health</code></td><td>GET</td><td>Service health check</td></tr>
              <tr><td><code>/v1/verify</code></td><td>POST</td><td>Verify a proof bundle or receipt</td></tr>
              <tr><td><code>/v1/verify/commit</code></td><td>POST</td><td>Verify a commit signature</td></tr>
              <tr><td><code>/v1/conformance</code></td><td>GET</td><td>List conformance test vectors</td></tr>
            </tbody>
          </table></div>
          <p>Base URL: <code>https://clawverify.com</code></p>

          <h3>clawproxy (model gateway)</h3>
          <div class="compare-table-wrap"><table class="compare-table" role="table">
            <thead><tr><th>Endpoint</th><th>Method</th><th>Description</th></tr></thead>
            <tbody>
              <tr><td><code>/health</code></td><td>GET</td><td>Service health check</td></tr>
              <tr><td><code>/v1/chat/completions</code></td><td>POST</td><td>Proxied model call with receipt generation</td></tr>
              <tr><td><code>/v1/receipts</code></td><td>GET</td><td>List receipts for a run</td></tr>
            </tbody>
          </table></div>
          <p>Base URL: <code>https://clawproxy.com</code></p>

          <h3>clawbounties (marketplace)</h3>
          <div class="compare-table-wrap"><table class="compare-table" role="table">
            <thead><tr><th>Endpoint</th><th>Method</th><th>Description</th></tr></thead>
            <tbody>
              <tr><td><code>/health</code></td><td>GET</td><td>Service health check</td></tr>
              <tr><td><code>/v1/bounties</code></td><td>GET/POST</td><td>List or create bounties</td></tr>
              <tr><td><code>/v1/bounties/:id/accept</code></td><td>POST</td><td>Accept a bounty assignment</td></tr>
              <tr><td><code>/v1/submissions</code></td><td>POST</td><td>Submit completed work with proof</td></tr>
            </tbody>
          </table></div>
          <p>Base URL: <code>https://clawbounties.com</code></p>

          <h3>clawescrow (payment escrow)</h3>
          <div class="compare-table-wrap"><table class="compare-table" role="table">
            <thead><tr><th>Endpoint</th><th>Method</th><th>Description</th></tr></thead>
            <tbody>
              <tr><td><code>/health</code></td><td>GET</td><td>Service health check</td></tr>
              <tr><td><code>/v1/escrows</code></td><td>POST</td><td>Create an escrow hold</td></tr>
              <tr><td><code>/v1/escrows/:id/release</code></td><td>POST</td><td>Release escrowed funds</td></tr>
              <tr><td><code>/v1/escrows/:id/refund</code></td><td>POST</td><td>Refund escrowed funds</td></tr>
            </tbody>
          </table></div>
          <p>Base URL: <code>https://clawescrow.com</code></p>
        </div>

        <!-- Protocol Spec -->
        <div class="docs-panel" id="tab-protocol" role="tabpanel" hidden>
          <h2>Clawsig Protocol v0.1</h2>
          <p>Five composable primitives. Everything else is built on these.</p>

          <div class="grid-2">
            <div class="card">
              <h3>1. Work Policy Contract (WPC)</h3>
              <p>Signed, immutable, content-addressed policy document. Defines what an agent may do before it runs.</p>
              <p><a href="/policy/work-policy-contract">Full spec &rarr;</a></p>
            </div>
            <div class="card">
              <h3>2. Capability Scoped Token (CST)</h3>
              <p>Short-lived, scope-hashed, job-bound permission token. Optionally pinned to a policy hash.</p>
              <p><a href="/policy/scoped-tokens">Full spec &rarr;</a></p>
            </div>
            <div class="card">
              <h3>3. Receipt</h3>
              <p>Signed attestation at an enforcement boundary (gateway, tool, approval). Not a log entry.</p>
              <p><a href="/proof/gateway-receipts">Gateway receipts &rarr;</a></p>
            </div>
            <div class="card">
              <h3>4. Proof Bundle</h3>
              <p>Hash-linked event chain + receipts + Ed25519 signature. Offline-verifiable, portable.</p>
              <p><a href="/proof/proof-bundles">Full spec &rarr;</a></p>
            </div>
          </div>
          <div class="card" style="margin-top:1rem">
            <h3>5. Verifier</h3>
            <p>Deterministic PASS/FAIL engine. Unknown schema/version/algorithm fails closed. Machine-readable reason codes.</p>
            <p>Reference implementation: <a href="https://clawverify.com" rel="noopener">clawverify</a></p>
          </div>
          <p style="margin-top:1rem"><a href="/resources/protocol-whitepaper" class="cta-btn cta-btn-outline">Download full protocol spec</a></p>
        </div>

        <!-- Security & Compliance -->
        <div class="docs-panel" id="tab-security" role="tabpanel" hidden>
          <h2>Security and Compliance</h2>
          <div class="grid-2">
            <div class="card">
              <h3>Security Review</h3>
              <ul>
                <li><a href="/trust/security-review">Security Review Pack</a></li>
                <li><a href="/security">Security posture</a></li>
                <li><a href="/resources/security-checklist">15-control checklist</a></li>
              </ul>
            </div>
            <div class="card">
              <h3>Controls</h3>
              <ul>
                <li><a href="/controls/approval-gates">Approval gates</a></li>
                <li><a href="/controls/dlp-redaction">DLP redaction</a></li>
                <li><a href="/controls/egress-allowlist">Egress allowlist</a></li>
                <li><a href="/controls/kill-switch">Kill switch</a></li>
                <li><a href="/controls/two-person-rule">Two-person rule</a></li>
                <li><a href="/controls">All controls &rarr;</a></li>
              </ul>
            </div>
            <div class="card">
              <h3>Regulatory Mapping</h3>
              <ul>
                <li><a href="/resources/compliance-mapping">SOX, HIPAA, FedRAMP mapping</a></li>
                <li><a href="/industries/financial-services">Financial services</a></li>
                <li><a href="/industries/healthcare">Healthcare</a></li>
                <li><a href="/industries/government">Government</a></li>
              </ul>
            </div>
            <div class="card">
              <h3>Audit and Evidence</h3>
              <ul>
                <li><a href="/agent-audit-and-replay">Audit and replay</a></li>
                <li><a href="/audit/tamper-evident-logs">Tamper-evident logs</a></li>
                <li><a href="/workflows/sox-control-testing">SOX control testing</a></li>
                <li><a href="/workflows/siem-evidence-collection">SIEM evidence collection</a></li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </section>

    <style>
      .docs-tabs{display:flex;gap:0;border-bottom:2px solid var(--border);margin-bottom:2rem;overflow-x:auto}
      .docs-tab{background:none;border:none;padding:.75rem 1.25rem;font-size:.9rem;font-weight:500;color:var(--text-muted);cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-2px;white-space:nowrap;transition:color .15s,border-color .15s}
      .docs-tab:hover{color:var(--text)}
      .docs-tab.active{color:var(--accent);border-bottom-color:var(--accent)}
      .docs-panel{display:none}
      .docs-panel.active{display:block}
    </style>
    <script>
    (function(){
      var tabs=document.querySelectorAll(".docs-tab");
      var panels=document.querySelectorAll(".docs-panel");
      tabs.forEach(function(tab){
        tab.addEventListener("click",function(){
          tabs.forEach(function(t){t.classList.remove("active");t.setAttribute("aria-selected","false")});
          panels.forEach(function(p){p.classList.remove("active");p.hidden=true});
          tab.classList.add("active");
          tab.setAttribute("aria-selected","true");
          var panel=document.getElementById("tab-"+tab.dataset.tab);
          if(panel){panel.classList.add("active");panel.hidden=false}
          // Update URL hash for direct linking
          history.replaceState(null,"","#"+tab.dataset.tab);
        });
      });
      // Restore tab from URL hash
      var hash=window.location.hash.slice(1);
      if(hash){
        var target=document.querySelector('[data-tab="'+hash+'"]');
        if(target)target.click();
      }
    })();
    </script>`,
  });
}

/* ── /changelog ──────────────────────────────────────────────── */

interface ChangelogPr {
  number: number;
  title: string;
  mergedAt: string;
  url: string;
}

function renderLivePrs(prs: ChangelogPr[]): string {
  if (!prs.length) return "";
  // Group by week
  const weeks: Record<string, ChangelogPr[]> = {};
  for (const pr of prs) {
    const d = new Date(pr.mergedAt);
    const weekStart = new Date(d);
    weekStart.setDate(d.getDate() - d.getDay());
    const key = weekStart.toISOString().slice(0, 10);
    if (!weeks[key]) weeks[key] = [];
    weeks[key].push(pr);
  }

  const sortedWeeks = Object.keys(weeks).sort().reverse();
  let html = `<h2 style="margin-top:2.5rem;border-top:1px solid var(--border);padding-top:1.5rem">Recent merged PRs (live from GitHub)</h2>`;
  html += `<p style="font-size:.85rem;color:var(--text-muted);margin-bottom:1.5rem">Auto-updated. Filtered to user-facing changes.</p>`;

  for (const week of sortedWeeks) {
    const weekDate = new Date(week);
    const label = `Week of ${weekDate.toLocaleDateString("en-US", { month: "long", day: "numeric", year: "numeric" })}`;
    html += `<article class="changelog-entry"><h3>${label}</h3><ul>`;
    for (const pr of weeks[week]) {
      const safeTitle = pr.title.replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
      html += `<li><a href="${pr.url}" rel="noopener">#${pr.number}</a> — ${safeTitle}</li>`;
    }
    html += `</ul></article>`;
  }
  return html;
}

export function changelogPage(livePrs: ChangelogPr[] = []): string {
  return layout({
    meta: {
      title: "Changelog | Claw EA",
      description: "Product changelog for Claw EA. Shipped features, dates, and PR numbers. Updated weekly.",
      path: "/changelog",
    },
    breadcrumbs: [
      { name: "Home", path: "/" },
      { name: "Changelog", path: "/changelog" },
    ],
    schemas: [],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:900px">
        <h1>Changelog</h1>
        <p class="lead">What shipped, when it shipped, and where to find the details. Updated weekly.</p>

        <article class="changelog-entry">
          <h2>February 12, 2026</h2>
          <h3>AEO-MKT-004: Trust infrastructure and protocol rename</h3>
          <ul>
            <li>Renamed "Claw Protocol" to "Clawsig Protocol" across all marketing content</li>
            <li>Added /security, /privacy, /terms, /docs, /changelog, /status pages</li>
            <li>Added /case-studies with dogfooding case study</li>
            <li>Footer and nav restructured for 160+ page site</li>
          </ul>

          <h3>AEO-MKT-003: Vertical depth and programmatic authority (<a href="https://github.com/clawbureau/clawbureau/pull/185">#185</a>)</h3>
          <ul>
            <li>Six industry vertical pages: financial services, healthcare, government, insurance, legal, technology</li>
            <li>Three pricing tier detail pages: starter, team, enterprise</li>
            <li>/proof-points credibility page with protocol adoption metrics</li>
            <li>Three resource gate pages with email capture (protocol whitepaper, security checklist, compliance mapping)</li>
            <li>Footer expanded with Industries, Resources, Get Started columns</li>
          </ul>

          <h3>AEO-MKT-002: Canonical source for enterprise agent security (<a href="https://github.com/clawbureau/clawbureau/pull/181">#181</a>)</h3>
          <ul>
            <li>/llms-full.txt — 33KB knowledge document for LLM retrieval</li>
            <li>SoftwareApplication + OfferCatalog structured data on homepage and pricing</li>
            <li>Five comparison pages (vs manual audit, guardrails, Langfuse, custom wrappers, governance landscape)</li>
            <li>Three implementation guides (GitHub Actions, Okta tokens, compliance export)</li>
          </ul>
        </article>

        <article class="changelog-entry">
          <h2>February 11, 2026</h2>
          <h3>AEO-MKT-001: Conversion hardening (<a href="https://github.com/clawbureau/clawbureau/pull/177">#177</a>)</h3>
          <ul>
            <li>Security Review Pack at /trust/security-review (architecture, threat model, proof artifacts)</li>
            <li>Money cluster CTA system on article pages (3 clusters: deploy approvals, identity/access, compliance)</li>
            <li>Homepage hero compressed to single message: "Ship Irreversible Agent Workflows With Proof"</li>
            <li>Assessment result page: conditional control recommendations based on risk/readiness scores</li>
          </ul>

          <h3>AEO-UX-001: Visual quality gate (<a href="https://github.com/clawbureau/clawbureau/pull/172">#172</a>)</h3>
          <ul>
            <li>Playwright screenshot capture + Gemini visual critique pipeline</li>
            <li>P0=0, P1=0 gate passed (29 P2 issues accepted)</li>
            <li>Turnstile integration with real staging/production keys</li>
            <li>Mobile nav, skip links, aria-labels, form accessibility improvements</li>
          </ul>
        </article>

        <article class="changelog-entry">
          <h2>February 10, 2026</h2>
          <h3>AEO-REV-007: Revenue execution loop (<a href="https://github.com/clawbureau/clawbureau/pull/159">#159</a>)</h3>
          <ul>
            <li>Lead alert control plane with SLA health monitoring</li>
            <li>Routing health dashboard and replay capability</li>
            <li>Experiment recommendation engine (Wilson confidence + holdout-aware rules)</li>
            <li>Attribution revenue summary endpoint</li>
          </ul>

          <h3>AEO-REV-006: Intent-to-pipeline OS (<a href="https://github.com/clawbureau/clawbureau/pull/156">#156</a>)</h3>
          <ul>
            <li>Source intent classification (sourceIntent + scoreReasons)</li>
            <li>Lead scoring with multi-signal model</li>
            <li>Routing queue with segment-based dispatch</li>
            <li>D1 migrations for intent pipeline tables</li>
          </ul>
        </article>

        <article class="changelog-entry">
          <h2>February 9, 2026</h2>
          <h3>AEO-CONTENT-004: Content factory (<a href="https://github.com/clawbureau/clawbureau/pull/150">#150</a>)</h3>
          <ul>
            <li>Model writeoff pipeline: multi-candidate generation + council review</li>
            <li>Human tone lint for production quality gate</li>
            <li>117 articles published across 10 categories</li>
            <li>Batch upload to R2 with manifest sync</li>
          </ul>

          <h3>AEO-PIPE-003: Indexing automation (<a href="https://github.com/clawbureau/clawbureau/pull/146">#146</a>)</h3>
          <ul>
            <li>IndexNow integration (worker + direct CLI)</li>
            <li>Google Indexing API via service account</li>
            <li>Unified /api/index-queue/enqueue endpoint</li>
          </ul>
        </article>

        <article class="changelog-entry">
          <h2>Earlier</h2>
          <h3>Protocol and economy services</h3>
          <ul>
            <li>Clawsig Protocol v0.1 with 22 conformance test vectors</li>
            <li>Economy services: clawbounties, clawescrow, clawcuts, clawsettle, clawledger</li>
            <li>clawverify verification service and clawproxy model gateway</li>
            <li>190+ PRs merged with DID-signed commit proofs</li>
          </ul>
        </article>

        ${renderLivePrs(livePrs)}
      </div>
    </section>`,
  });
}

/* ── /status (live health dashboard) ─────────────────────────── */

export function statusPage(): string {
  return layout({
    meta: {
      title: "System Status | Claw EA",
      description: "Live service health for Claw EA infrastructure. Real-time status of clawverify, clawproxy, clawbounties, clawescrow, clawcuts, and related services.",
      path: "/status",
    },
    breadcrumbs: [
      { name: "Home", path: "/" },
      { name: "Status", path: "/status" },
    ],
    schemas: [],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:900px">
        <h1>System Status</h1>
        <div id="status-banner" class="status-banner status-loading">
          <span id="status-icon">&#9679;</span>
          <span id="status-text">Checking services...</span>
        </div>
        <p style="font-size:.85rem;color:var(--text-muted);margin-bottom:2rem">Auto-refreshes every 60 seconds. Last checked: <span id="status-time">—</span></p>

        <div id="status-grid" class="status-grid"></div>
      </div>
    </section>

    <style>
      .status-banner{padding:1rem 1.5rem;border-radius:var(--radius);font-weight:600;font-size:1.1rem;margin-bottom:1.5rem;display:flex;align-items:center;gap:.75rem}
      .status-banner.status-loading{background:var(--surface);color:var(--text-muted)}
      .status-banner.status-ok{background:#0a2e1a;color:#4ade80;border:1px solid #166534}
      .status-banner.status-partial{background:#2e1a00;color:#fb923c;border:1px solid #9a3412}
      .status-banner.status-down{background:#2e0a0a;color:#f87171;border:1px solid #991b1b}
      .status-grid{display:grid;gap:1rem}
      .status-row{display:flex;justify-content:space-between;align-items:center;padding:1rem 1.25rem;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius)}
      .status-row .svc-name{font-weight:600;font-size:.95rem}
      .status-row .svc-url{font-size:.8rem;color:var(--text-muted)}
      .status-row .svc-status{display:flex;align-items:center;gap:.5rem;font-size:.9rem;font-weight:500}
      .status-row .svc-status .dot{width:10px;height:10px;border-radius:50%;display:inline-block}
      .dot-ok{background:#4ade80}
      .dot-degraded{background:#fb923c}
      .dot-down{background:#f87171}
      .dot-checking{background:var(--text-muted);animation:pulse 1s infinite}
      @keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
      .svc-latency{font-size:.8rem;color:var(--text-muted);margin-left:.5rem}
    </style>

    <script>
    (function() {
      var services = [
        { name: "clawverify", url: "https://clawverify.com", label: "Clawverify (Verification)" },
        { name: "clawproxy", url: "https://clawproxy.com", label: "Clawproxy (Model Gateway)" },
        { name: "clawbounties", url: "https://clawbounties.com", label: "Clawbounties (Marketplace)" },
        { name: "clawescrow", url: "https://clawescrow.com", label: "Clawescrow (Payment Escrow)" },
        { name: "clawcuts", url: "https://clawcuts.com", label: "Clawcuts (Revenue Distribution)" },
        { name: "clawscope", url: "https://clawscope.com", label: "Clawscope (Token Issuer)" },
        { name: "clawea-www", url: "https://www.clawea.com", label: "Claw EA (Marketing Site)" },
      ];

      var grid = document.getElementById("status-grid");
      var banner = document.getElementById("status-banner");
      var statusText = document.getElementById("status-text");
      var statusIcon = document.getElementById("status-icon");
      var statusTime = document.getElementById("status-time");

      function renderGrid() {
        grid.innerHTML = services.map(function(s) {
          return '<div class="status-row" id="row-' + s.name + '">' +
            '<div><div class="svc-name">' + s.label + '</div><div class="svc-url">' + s.url + '/health</div></div>' +
            '<div class="svc-status"><span class="dot dot-checking"></span><span>Checking...</span></div>' +
            '</div>';
        }).join("");
      }

      function checkAll() {
        var results = [];
        var done = 0;

        services.forEach(function(s) {
          var row = document.getElementById("row-" + s.name);
          var statusEl = row.querySelector(".svc-status");
          var start = Date.now();

          fetch(s.url + "/health", { mode: "cors", cache: "no-store" })
            .then(function(r) {
              var latency = Date.now() - start;
              var ok = r.ok;
              results.push({ name: s.name, ok: ok, latency: latency });
              statusEl.innerHTML = '<span class="dot ' + (ok ? "dot-ok" : "dot-degraded") + '"></span>' +
                '<span>' + (ok ? "Operational" : "Degraded") + '</span>' +
                '<span class="svc-latency">' + latency + 'ms</span>';
            })
            .catch(function() {
              var latency = Date.now() - start;
              results.push({ name: s.name, ok: false, latency: latency });
              statusEl.innerHTML = '<span class="dot dot-down"></span><span>Unreachable</span>' +
                '<span class="svc-latency">' + latency + 'ms</span>';
            })
            .finally(function() {
              done++;
              if (done === services.length) updateBanner(results);
            });
        });
      }

      function updateBanner(results) {
        var allOk = results.every(function(r) { return r.ok; });
        var anyDown = results.some(function(r) { return !r.ok; });
        banner.className = "status-banner " + (allOk ? "status-ok" : anyDown ? "status-partial" : "status-ok");
        statusIcon.textContent = allOk ? "\\u2713" : "\\u26A0";
        statusText.textContent = allOk ? "All systems operational" : "Partial service disruption";
        statusTime.textContent = new Date().toLocaleTimeString();
      }

      renderGrid();
      checkAll();
      setInterval(checkAll, 60000);
    })();
    </script>`,
  });
}
