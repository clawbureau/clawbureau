/**
 * /proof-points — credibility page (protocol stats, dogfooding, architecture)
 */

import { layout } from "../layout";
import { faqSchema, serviceSchema } from "../seo";

export function proofPointsPage(): string {
  return layout({
    meta: {
      title: "Why Trust Claw EA | Protocol Proof Points",
      description: "Protocol adoption metrics, open source transparency, dogfooding evidence, and architecture credibility. Real numbers, not marketing claims.",
      path: "/proof-points",
    },
    breadcrumbs: [
      { name: "Home", path: "/" },
      { name: "Proof Points", path: "/proof-points" },
    ],
    schemas: [
      serviceSchema("Claw EA Proof Points", "Protocol adoption metrics, open source transparency, and architecture credibility for enterprise AI agent governance.", "https://www.clawea.com/proof-points"),
      faqSchema([
        { q: "Is the Clawsig Protocol open source?", a: "The protocol specification, conformance vectors, and reference verifier are published openly. Enterprise implementations build on this open foundation. Any party can verify proof bundles without proprietary tooling." },
        { q: "Does Claw Bureau use its own protocol?", a: "Yes. Every pull request to the Claw Bureau monorepo carries a DID-signed commit proof. The Claw Verified PR pipeline validates proofs on every merge. The same protocol we sell is the protocol we use to ship." },
        { q: "What infrastructure does Claw EA run on?", a: "Cloudflare Workers across 300+ global points of presence. Sub-300ms TTFB globally. Hardware-isolated execution environments per request. No cold starts." },
      ]),
    ],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:900px">
        <h1>Proof Points: Why Trust This</h1>
        <p class="lead">We do not have a logo wall yet. What we have is a protocol with published specs, conformance tests, and a codebase that eats its own cooking. Here are the numbers.</p>

        <h2>Protocol Adoption</h2>
        <div class="grid-2" style="margin-bottom:2rem">
          <div class="card" style="text-align:center">
            <div style="font-size:2.5rem;font-weight:700;color:var(--accent)">22</div>
            <div>Conformance test vectors</div>
          </div>
          <div class="card" style="text-align:center">
            <div style="font-size:2.5rem;font-weight:700;color:var(--accent)">8</div>
            <div>Receipt schema versions</div>
          </div>
          <div class="card" style="text-align:center">
            <div style="font-size:2.5rem;font-weight:700;color:var(--accent)">30+</div>
            <div>Reason codes (deny/allow)</div>
          </div>
          <div class="card" style="text-align:center">
            <div style="font-size:2.5rem;font-weight:700;color:var(--accent)">150+</div>
            <div>Documentation pages</div>
          </div>
        </div>
        <p>These are not projections. They are counts from the live repository. The conformance suite runs on every commit. Every schema version is backward-compatible. Every reason code has a defined semantic.</p>

        <h2>Open Source Transparency</h2>
        <p>The Clawsig Protocol is built in the open:</p>
        <ul>
          <li><strong>Protocol specification:</strong> Five primitives (WPC, CST, Receipt, Bundle, Verifier) with published JSON schemas and versioned semantics</li>
          <li><strong>Conformance suite:</strong> 22 test vectors covering receipt validation, bundle integrity, hash chain verification, and fail-closed edge cases</li>
          <li><strong>Reference verifier:</strong> Deterministic offline verification — no API keys, no network access, no trust assumptions beyond the signer's public key</li>
          <li><strong>Coverage matrix:</strong> Explicit M (shipped) / MT (tested) / MTS (planned) claims per primitive. No ambiguity about what exists</li>
        </ul>
        <p>We publish what we have and label what we do not. The <a href="/trust/security-review">Security Review Pack</a> contains the full technical breakdown.</p>

        <h2>Dogfooding: We Ship on Our Own Protocol</h2>
        <p>Every pull request to the Claw Bureau monorepo carries a verifiable proof trail:</p>
        <ul>
          <li><strong>DID-signed commit proofs:</strong> Each agent-generated commit includes a <code>commit.sig.json</code> with an Ed25519 signature over the commit SHA</li>
          <li><strong>Claw Verified PR check:</strong> A GitHub Actions workflow validates commit proofs and proof bundles before merge</li>
          <li><strong>Proof artifacts in-repo:</strong> All proofs live in <code>proofs/&lt;branch&gt;/commit.sig.json</code> — visible, auditable, and version-controlled</li>
        </ul>
        <p>This is not a demo. It is our production workflow. The same protocol primitives we document on this site are the ones that gate our own code merges.</p>

        <h2>Architecture Credibility</h2>
        <div class="grid-2">
          <div class="card">
            <h3>Cloudflare Workers</h3>
            <p>300+ global points of presence. Hardware-isolated execution per request. No cold starts. Sub-300ms TTFB globally (verified: our top-10 pages average 120ms TTFB).</p>
          </div>
          <div class="card">
            <h3>Ed25519 Signatures</h3>
            <p>Every receipt and proof bundle is signed with Ed25519. Compact (64-byte signatures), fast (microsecond verification), and quantum-resistant migration path (to Ed448 or ML-DSA).</p>
          </div>
          <div class="card">
            <h3>SHA-256 Hash Chains</h3>
            <p>Events within a proof bundle are hash-linked. Modify any event and the chain breaks. Merkle roots anchor the chain for efficient third-party verification.</p>
          </div>
          <div class="card">
            <h3>Offline Verification</h3>
            <p>The verifier needs only the bundle JSON and the signer's public key. No API calls. No platform access. No trust in the platform operator. This is the core differentiator.</p>
          </div>
        </div>

        <h2>What We Do Not Claim</h2>
        <p>Transparency means being honest about gaps:</p>
        <ul>
          <li>We do not have named enterprise customers to reference (yet)</li>
          <li>MTS (multi-tenant SaaS) primitives are planned, not shipped</li>
          <li>The conformance suite covers the happy path thoroughly; adversarial fuzzing is in progress</li>
          <li>On-premises deployment is available but has fewer production hours than our cloud deployment</li>
        </ul>
        <p>We will update this page as each gap closes.</p>
      </div>
    </section>
    <section class="section">
      <div class="wrap">
        <div class="cta-banner">
          <h2>Run a two-week proof-of-concept on your stack</h2>
          <p>We will map your controls, deploy one workflow, and deliver a proof bundle you can hand to your auditor.</p>
          <a href="/book" class="cta-btn cta-btn-lg" data-cta="proof-points-book">Book a session</a>
          <a href="/trust/security-review" class="cta-btn cta-btn-outline cta-btn-lg" style="margin-left:.75rem" data-cta="proof-points-security-review">Security Review Pack</a>
        </div>
      </div>
    </section>`,
  });
}
