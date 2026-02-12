# Claw Verified GitHub App

Cryptographic verification for AI-generated pull requests.

When an AI agent opens a PR, Claw Verified checks for Clawsig proof bundles and validates that the agent followed your repo's Work Policy Contract (WPC). The result is posted as a GitHub Check Run.

## How It Works

1. Agent opens a PR containing `proofs/**/proof_bundle.v1.json`
2. The GitHub App receives a `pull_request` webhook
3. It downloads and verifies each proof bundle using `@clawbureau/clawverify-core`
4. It checks the bundle against your repo's `.clawsig/policy.json` (WPC)
5. A Check Run is posted with the result:
   - **Success** — all bundles pass verification and policy compliance
   - **Failure** — one or more bundles fail, with detailed reason codes
   - **Neutral** — no proof bundles found in the PR

## Check Run Output

The check run includes:

- Bundle count and pass/fail breakdown
- Per-bundle: agent DID, proof tier, model identity tier
- Receipt counts (gateway, tool, side-effect, human approval)
- Policy compliance status with violation details
- Reason codes from the Clawsig verification engine

## Trust Model

**Repo-Anchored TOFU (Trust On First Use):**

- Policy trust is anchored to the repo's default branch (protected by GitHub branch protection)
- The `.clawsig/policy.json` WPC is unsigned in v1 — GitHub's Web2 trust is the anchor
- Gateway receipts are only accepted from hardcoded trusted Gateway DIDs
- Agent identity (DID) is informational only — we verify what the agent did, not who it claims to be

**Fabrication Prevention:**

- PR diff file hashes are compared against tool_receipt content hashes
- If an agent claims to have written code that doesn't match the actual PR diff, verification fails

## Setup

### 1. Register the GitHub App

Use `app-manifest.json` to register via GitHub's [manifest flow](https://docs.github.com/en/apps/creating-github-apps/setting-up-a-github-app/creating-a-github-app-from-a-manifest):

```bash
# Or manually create at https://github.com/settings/apps/new
```

### 2. Configure Secrets

```bash
cd services/claw-verified-app

# GitHub App ID (from app settings page)
wrangler secret put GITHUB_APP_ID

# Private key (PEM format, from app settings)
wrangler secret put GITHUB_PRIVATE_KEY

# Webhook secret (configured during app setup)
wrangler secret put GITHUB_WEBHOOK_SECRET
```

### 3. Deploy

```bash
wrangler deploy          # production
wrangler deploy --env staging  # staging
```

### 4. Configure Webhook URL

Set the webhook URL in your GitHub App settings:

```
https://claw-verified-app.clawbureau.workers.dev/webhook
```

## Repo Configuration

Initialize your repo for Claw Verified:

```bash
npx @clawbureau/clawverify-cli init
```

This creates:

- `.clawsig/policy.json` — Work Policy Contract
- `.clawsig/README.md` — documentation

### Policy Options

Edit `.clawsig/policy.json` to configure:

```json
{
  "policy_version": "1",
  "policy_id": "my-repo-policy",
  "issuer_did": "did:web:myorg.example.com",
  "allowed_agents": ["did:key:*"],
  "minimum_proof_tier": "gateway",
  "required_receipt_types": ["gateway", "tool"],
  "egress_allowlist": ["api.github.com", "registry.npmjs.org"]
}
```

| Field | Description |
|-------|-------------|
| `allowed_agents` | Agent DIDs permitted to contribute (wildcards supported) |
| `minimum_proof_tier` | Minimum required: `self`, `gateway`, or `sandbox` |
| `required_receipt_types` | Receipt types that must be present in bundles |
| `egress_allowlist` | Allowed network egress targets |

## Development

```bash
npm install
npm run typecheck

# Local dev (requires secrets in .dev.vars)
npm run dev
```

## Architecture

```
src/
  index.ts    — Worker entry + webhook router + signature verification
  github.ts   — GitHub API client (JWT auth, check runs, file fetching)
  verify.ts   — Bundle verification orchestrator
  policy.ts   — WPC loader + policy compliance checker
  trust.ts    — Trusted gateway DID allowlist
  types.ts    — Type definitions
```

## Proof Bundle Paths

The app looks for bundles matching these patterns:

- `proofs/**/proof_bundle.v1.json`
- `proofs/**/proof_bundle.json`
- `.clawsig/bundle.json`
- `.clawsig/proof_bundle.v1.json`
- `artifacts/poh/**-bundle.json`

## API

### POST /webhook

GitHub webhook endpoint. Requires valid `x-hub-signature-256` header.

### GET /health

Health check. Returns `{"status":"ok","service":"claw-verified-app"}`.
