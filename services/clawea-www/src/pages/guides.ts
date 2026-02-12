/**
 * Implementation guides: /guides/*
 * Deep how-to pages that bridge "interested" to "implementing".
 */

import { layout } from "../layout";
import { howToSchema, serviceSchema } from "../seo";

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function guideCtaBanner(guideSlug: string): string {
  return `
    <section class="section">
      <div class="wrap">
        <div class="cta-banner">
          <h2>Ready to implement this?</h2>
          <p>Take the assessment to map your stack, or review the Security Review Pack to prepare your security team.</p>
          <a href="/assessment" class="cta-btn cta-btn-lg" data-cta="guide-${esc(guideSlug)}-assessment">Take the assessment</a>
          <a href="/trust/security-review" class="cta-btn cta-btn-outline cta-btn-lg" style="margin-left:.75rem" data-cta="guide-${esc(guideSlug)}-security-review">Security Review Pack</a>
        </div>
      </div>
    </section>`;
}

/* ── /guides/github-actions-proof-pipeline ────────────────────── */

export function guideGithubActionsProofPage(): string {
  return layout({
    meta: {
      title: "GitHub Actions Proof Pipeline Guide | Claw EA",
      description: "Step-by-step guide to setting up a Claw Verified PR pipeline with GitHub Actions: install clawproof-wrap, configure clawverify, add the workflow, verify your first PR.",
      path: "/guides/github-actions-proof-pipeline",
    },
    breadcrumbs: [
      { name: "Home", path: "/" },
      { name: "Guides", path: "/guides" },
      { name: "GitHub Actions Proof Pipeline", path: "/guides/github-actions-proof-pipeline" },
    ],
    schemas: [
      serviceSchema("GitHub Actions Proof Pipeline Setup Guide", "Implementation guide for Claw Verified PR pipeline with GitHub Actions.", "https://www.clawea.com/guides/github-actions-proof-pipeline"),
      howToSchema(
        {
          title: "Set up a Claw Verified PR pipeline with GitHub Actions",
          steps: [
            { name: "Install clawproof-wrap", text: "Add the clawproof SDK to your project as a dev dependency." },
            { name: "Configure the clawverify allowlist", text: "Create a clawverify config JSON with your receipt signer DIDs and allowed algorithms." },
            { name: "Generate your first commit proof", text: "Run the sign-message script to create a commit.sig.json for your latest commit." },
            { name: "Add the GitHub Actions workflow", text: "Copy the claw-verified-pr.yml workflow into .github/workflows/." },
            { name: "Push and verify", text: "Push a PR with proof artifacts and confirm the check passes." },
          ],
        },
        "https://www.clawea.com/guides/github-actions-proof-pipeline",
      ),
    ],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:900px">
        <span class="badge badge-green">Implementation Guide</span>
        <h1>GitHub Actions Proof Pipeline</h1>
        <p class="lead">This guide walks you through setting up a Claw Verified PR pipeline on your own repository. Every agent-generated PR will carry a verifiable evidence pack, and a GitHub Actions check will validate it before merge.</p>
        <p><strong>Working example:</strong> The Claw Bureau monorepo uses this exact pipeline. The workflow file and verification runner are live in our repository.</p>

        <h2 id="step-1">Step 1: Install clawproof-wrap</h2>
        <p>The <code>clawproof-wrap</code> CLI generates proof artifacts (commit signatures and proof bundles) for your agent runs.</p>
        <pre><code>npm install --save-dev @clawbureau/clawproof-sdk</code></pre>
        <p>This gives you access to <code>ClawproofRun</code> for recording tool calls and generating proof bundles, and the <code>sign-message</code> utility for commit proofs.</p>

        <h2 id="step-2">Step 2: Configure the clawverify allowlist</h2>
        <p>Create a configuration file that tells the verifier which DID keys are trusted receipt signers.</p>
        <pre><code>{
  "version": "1",
  "allowlists": {
    "receipt_signers": [
      "did:key:z6Mkf...xy3m"
    ],
    "bundle_signers": [
      "did:key:z6Mkn...E7c7"
    ]
  },
  "algorithms": ["Ed25519"],
  "fail_on_unknown_version": true,
  "fail_on_unknown_algorithm": true
}</code></pre>
        <p>Save this as <code>packages/schema/fixtures/clawverify.config.json</code> (or wherever your project keeps verification config). The <code>receipt_signers</code> should include your clawproxy gateway DID. The <code>bundle_signers</code> should include your agent DIDs.</p>

        <h2 id="step-3">Step 3: Generate your first commit proof</h2>
        <p>After making a commit, sign it with the agent's DID key:</p>
        <pre><code># Get the latest commit SHA
COMMIT_SHA=$(git rev-parse HEAD)

# Sign it
node scripts/did-work/sign-message.mjs "commit:$COMMIT_SHA"</code></pre>
        <p>This outputs a <code>commit.sig.json</code> envelope:</p>
        <pre><code>{
  "version": "m1",
  "type": "message_signature",
  "algo": "ed25519",
  "did": "did:key:z6Mkt...m8XW",
  "message": "commit:abc123...",
  "createdAt": "2026-02-12T12:21:40.739Z",
  "signature": "base64-encoded-ed25519-signature"
}</code></pre>
        <p>Save it to <code>proofs/&lt;branch-name&gt;/commit.sig.json</code> and commit it to the PR.</p>

        <h2 id="step-4">Step 4: Add the GitHub Actions workflow</h2>
        <p>Create <code>.github/workflows/claw-verified-pr.yml</code>:</p>
        <pre><code>name: Claw Verified PR
on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-node@v4
        with:
          node-version: '22'

      - run: npm ci

      - name: Run Claw Verified PR check
        run: node scripts/protocol/run-claw-verified-pr.mjs
        env:
          GITHUB_TOKEN: \${{ secrets.GITHUB_TOKEN }}
          CLAWPROOF_VERIFY: "1"</code></pre>
        <p>The runner script validates commit proof signatures against declared DIDs and checks any proof bundle artifacts present in the PR.</p>

        <h2 id="step-5">Step 5: Push and verify</h2>
        <p>Push your branch with the proof artifacts. The GitHub Actions check will:</p>
        <ul>
          <li>Find <code>proofs/**/commit.sig.json</code> files in the PR diff</li>
          <li>Verify each signature against the declared DID</li>
          <li>If proof bundles exist, verify receipt signatures and event chain integrity</li>
          <li>Report PASS/FAIL with machine-readable reason codes</li>
        </ul>
        <p>By default the check is observational (does not block merge). Add the <code>claw-verified</code> label to a PR to enforce it.</p>

        <h2>What you get</h2>
        <ul>
          <li>Every agent PR carries offline-verifiable authorship proof</li>
          <li>Proof bundles (if present) are validated against your allowlist</li>
          <li>GitHub check status visible to reviewers before merge</li>
          <li>Evidence artifacts stored in the repository itself (not a third-party service)</li>
        </ul>
        <p>For the full technical architecture behind these proofs, see the <a href="/trust/security-review">Security Review Pack</a>.</p>
      </div>
    </section>
    ${guideCtaBanner("github-actions")}`,
  });
}

/* ── /guides/okta-scoped-tokens ──────────────────────────────── */

export function guideOktaScopedTokensPage(): string {
  return layout({
    meta: {
      title: "Okta Scoped Tokens Guide | Claw EA",
      description: "How to map Okta groups to CST scopes for policy-gated agent execution. Bind identity, permissions, and audit trail through scoped capability tokens.",
      path: "/guides/okta-scoped-tokens",
    },
    breadcrumbs: [
      { name: "Home", path: "/" },
      { name: "Guides", path: "/guides" },
      { name: "Okta Scoped Tokens", path: "/guides/okta-scoped-tokens" },
    ],
    schemas: [
      serviceSchema("Okta Scoped Tokens Implementation Guide", "Guide for mapping Okta groups to CST scopes for policy-gated AI agent execution.", "https://www.clawea.com/guides/okta-scoped-tokens"),
      howToSchema(
        {
          title: "Map Okta groups to CST scopes for agent execution",
          steps: [
            { name: "Define scope mapping", text: "Map each Okta group to a set of CST claims (allowed tools, models, egress endpoints)." },
            { name: "Configure the token issuer", text: "Set up clawscope to accept Okta OIDC tokens and mint CSTs with mapped scopes." },
            { name: "Pin policy to token", text: "Bind a Work Policy Contract hash to the CST so the agent can only operate under declared policy." },
            { name: "Test the flow", text: "Authenticate as an Okta user, receive a scoped CST, and execute an agent workflow." },
            { name: "Verify the audit trail", text: "Check that receipts carry the token_scope_hash and that the agent DID matches expectations." },
          ],
        },
        "https://www.clawea.com/guides/okta-scoped-tokens",
      ),
    ],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:900px">
        <span class="badge badge-green">Implementation Guide</span>
        <h1>Okta to Scoped Agent Tokens</h1>
        <p class="lead">This guide shows how to connect your Okta identity provider to the Claw EA capability token system. The result: an agent's permissions are derived from the requesting user's Okta group membership, and every action carries a token scope hash that ties it to the exact permission set.</p>

        <h2 id="overview">How It Works</h2>
        <p>The flow is: <strong>Okta OIDC token → clawscope (token issuer) → CST (Capability Scoped Token) → agent execution → receipts with token_scope_hash</strong></p>
        <ol>
          <li>User authenticates via Okta and receives an OIDC token with group claims</li>
          <li>clawscope validates the OIDC token and maps groups to CST scopes</li>
          <li>CST is issued with: allowed tools, allowed models, egress endpoints, and optional policy pin</li>
          <li>Agent receives the CST and operates within its scope</li>
          <li>Every receipt includes the <code>token_scope_hash</code> — auditors can verify scope was enforced</li>
        </ol>

        <h2 id="scope-mapping">Step 1: Define the scope mapping</h2>
        <p>Map Okta groups to CST claim sets. Example:</p>
        <pre><code>{
  "scope_mappings": [
    {
      "okta_group": "platform-engineers",
      "cst_claims": {
        "allowed_tools": ["github", "argo-cd", "terraform"],
        "allowed_models": ["claude-sonnet-4-20250514", "gpt-4o"],
        "egress_allowlist": ["api.github.com", "*.atlassian.net"],
        "max_ttl_seconds": 3600
      }
    },
    {
      "okta_group": "security-analysts",
      "cst_claims": {
        "allowed_tools": ["splunk", "jira", "servicenow"],
        "allowed_models": ["claude-sonnet-4-20250514"],
        "egress_allowlist": ["*.splunkcloud.com"],
        "max_ttl_seconds": 1800
      }
    }
  ]
}</code></pre>
        <p>The scope mapping is the policy bridge between your identity provider and agent execution. It answers: "What can agents do on behalf of users in this group?"</p>

        <h2 id="policy-pin">Step 2: Pin policy to tokens</h2>
        <p>Optionally, bind a <a href="/policy/work-policy-contract">Work Policy Contract</a> hash to the CST. This ensures the agent operates under a specific, immutable policy document.</p>
        <pre><code>{
  "policy_pin": {
    "policy_hash_b64u": "sha256-hash-of-wpc-json",
    "policy_version": "deploy-approval-v3"
  }
}</code></pre>
        <p>When the agent presents this CST to clawproxy, the gateway verifies the policy pin matches the active policy. If it does not match, the request is denied. Fail-closed.</p>

        <h2 id="verification">Step 3: Verify the audit trail</h2>
        <p>After execution, every gateway receipt will carry:</p>
        <ul>
          <li><code>token_scope_hash_b64u</code> — deterministic hash of the CST claims</li>
          <li><code>binding.run_id</code> — ties the receipt to a specific run</li>
          <li><code>binding.event_hash_b64u</code> — ties the receipt to a specific event in the proof bundle</li>
        </ul>
        <p>An auditor can verify: the user was in the expected Okta group, the CST had the correct scope, and the receipts prove the agent operated within that scope.</p>

        <h2>Related</h2>
        <ul>
          <li><a href="/tools/okta">Okta integration overview</a></li>
          <li><a href="/tools/entra-id">Entra ID integration (similar flow with Azure AD groups)</a></li>
          <li><a href="/policy/scoped-tokens">CST specification</a></li>
          <li><a href="/workflows/access-request-automation">Access request automation workflow</a></li>
          <li><a href="/trust/security-review">Security Review Pack</a></li>
        </ul>
      </div>
    </section>
    ${guideCtaBanner("okta-scoped-tokens")}`,
  });
}

/* ── /guides/compliance-evidence-export ───────────────────────── */

export function guideComplianceExportPage(): string {
  return layout({
    meta: {
      title: "Compliance Evidence Export Guide | Claw EA",
      description: "How to generate an export bundle, verify it offline, and attach it to a SOX or SOC 2 evidence request. Step-by-step with real CLI commands.",
      path: "/guides/compliance-evidence-export",
    },
    breadcrumbs: [
      { name: "Home", path: "/" },
      { name: "Guides", path: "/guides" },
      { name: "Compliance Evidence Export", path: "/guides/compliance-evidence-export" },
    ],
    schemas: [
      serviceSchema("Compliance Evidence Export Guide", "Implementation guide for generating and verifying offline compliance evidence from AI agent runs.", "https://www.clawea.com/guides/compliance-evidence-export"),
      howToSchema(
        {
          title: "Export and verify compliance evidence from agent runs",
          steps: [
            { name: "Select the runs to export", text: "Query the agent run history for the audit period (date range, agent, workflow type)." },
            { name: "Generate the export bundle", text: "Use the export endpoint or CLI to produce a self-contained bundle with all receipts and manifests." },
            { name: "Verify the bundle offline", text: "Run the clawverify CLI against the bundle to get a deterministic PASS/FAIL result." },
            { name: "Attach to evidence request", text: "Upload the verified bundle and verification report to your GRC platform or evidence folder." },
          ],
        },
        "https://www.clawea.com/guides/compliance-evidence-export",
      ),
    ],
    body: `
    <section class="section content-page">
      <div class="wrap" style="max-width:900px">
        <span class="badge badge-green">Implementation Guide</span>
        <h1>Compliance Evidence Export</h1>
        <p class="lead">When your auditor asks "prove that Agent X only accessed approved systems between January 1 and March 31," you need to produce verifiable evidence. This guide shows how to generate an export bundle, verify it offline, and deliver it as SOX/SOC 2 evidence.</p>

        <h2 id="export">Step 1: Generate the export bundle</h2>
        <p>An export bundle is a self-contained package of proof bundles, receipts, and a content-addressed manifest. It covers a specific audit window.</p>
        <pre><code># Export all runs for a specific agent in a date range
clawproof export \\
  --agent-did "did:key:z6Mkn...E7c7" \\
  --from "2026-01-01" \\
  --to "2026-03-31" \\
  --output ./evidence/q1-2026-export.json</code></pre>
        <p>The export bundle includes:</p>
        <ul>
          <li>Every proof bundle for runs in the window</li>
          <li>All gateway and tool receipts referenced by those bundles</li>
          <li>A manifest with SHA-256 hashes for every included file</li>
          <li>A top-level Ed25519 signature over the manifest</li>
        </ul>

        <h2 id="verify">Step 2: Verify offline</h2>
        <p>Run the verifier against the export bundle. This requires no network access and no API keys.</p>
        <pre><code># Verify the export bundle
clawverify verify \\
  --bundle ./evidence/q1-2026-export.json \\
  --config ./clawverify.config.json \\
  --output ./evidence/q1-2026-verify-report.json</code></pre>
        <p>The verification report contains:</p>
        <ul>
          <li><strong>PASS/FAIL</strong> verdict for each proof bundle</li>
          <li>Machine-readable reason codes for any failures</li>
          <li>Receipt count, event count, and coverage summary</li>
          <li>Timestamp range and agent DID for each run</li>
        </ul>
        <p>If any proof bundle fails verification, the export is flagged. Unknown schema versions or algorithms fail closed.</p>

        <h2 id="deliver">Step 3: Deliver to your auditor</h2>
        <p>Provide your auditor with:</p>
        <ol>
          <li>The export bundle JSON (<code>q1-2026-export.json</code>)</li>
          <li>The verification report (<code>q1-2026-verify-report.json</code>)</li>
          <li>The clawverify config (<code>clawverify.config.json</code>) — this is public, it just contains allowed DIDs</li>
          <li>Instructions to re-run verification independently (the auditor does not need platform access)</li>
        </ol>
        <p>The auditor can re-run <code>clawverify verify</code> themselves using the same inputs. If the result matches, they have independent confirmation that the evidence is authentic and untampered.</p>

        <h2 id="mapping">Mapping to compliance frameworks</h2>
        <div class="grid-2">
          <div class="card">
            <h3>SOC 2 (Trust Services Criteria)</h3>
            <ul>
              <li><strong>CC6.1</strong> (logical access): CST scopes + token_scope_hash in receipts</li>
              <li><strong>CC7.2</strong> (system monitoring): gateway receipts as monitoring evidence</li>
              <li><strong>CC8.1</strong> (change management): commit.sig.json proofs on every PR</li>
            </ul>
          </div>
          <div class="card">
            <h3>SOX (IT General Controls)</h3>
            <ul>
              <li><strong>Access controls</strong>: Okta group → CST scope mapping</li>
              <li><strong>Change management</strong>: signed commits + Claw Verified PR pipeline</li>
              <li><strong>Monitoring</strong>: proof bundles as continuous control evidence</li>
            </ul>
          </div>
        </div>

        <h2>Related</h2>
        <ul>
          <li><a href="/workflows/siem-evidence-collection">SIEM evidence collection workflow</a></li>
          <li><a href="/workflows/sox-control-testing">SOX control testing workflow</a></li>
          <li><a href="/audit/tamper-evident-logs">Tamper-evident logging</a></li>
          <li><a href="/proof/proof-bundles">Proof bundle specification</a></li>
          <li><a href="/trust/security-review">Security Review Pack</a></li>
        </ul>
      </div>
    </section>
    ${guideCtaBanner("compliance-export")}`,
  });
}
