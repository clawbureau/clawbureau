# Claw Verified GitHub App

Cryptographic verification for AI-generated pull requests. Posts "Claw Verified" check runs on PRs containing Clawsig proof bundles.

## How It Works

1. Agent generates code and attaches a `proof_bundle.json` to the PR
2. This app receives the webhook, discovers proof bundles in the PR diff
3. Runs offline verification: structural integrity, gateway trust, policy compliance
4. Posts a GitHub Check Run: PASS / FAIL / Neutral (no bundles)

## Trust Model

- **Policy:** Loaded from `.clawsig/policy.json` on the repo's default branch (unsigned v1 — Web2 trust via branch protection)
- **Gateway:** Hardcoded allowlist of trusted gateway DIDs in `src/trust.ts`
- **Agent Identity:** Informational only — the DID links the event chain but is not an identity claim
- **Fabrication Prevention:** Bundle receipts are cross-referenced against PR diff

## Setup

### 1. Create GitHub App

Use the manifest at `app-manifest.json` or create manually:
- **Permissions:** `checks: write`, `contents: read`, `pull_requests: read`
- **Events:** `pull_request`, `check_suite`
- **Webhook URL:** `https://claw-verified-app.clawbureau.workers.dev/webhook`

### 2. Configure Secrets

```bash
cd services/claw-verified-app
wrangler secret put GITHUB_APP_ID
wrangler secret put GITHUB_PRIVATE_KEY
wrangler secret put GITHUB_WEBHOOK_SECRET
```

### 3. Deploy

```bash
npm run deploy           # production
npm run deploy:staging   # staging
```

### 4. Add Policy to Your Repo

```bash
npx @clawbureau/clawverify-cli init
# Creates .clawsig/policy.json + .clawsig/README.md
```

## Policy (`.clawsig/policy.json`)

```json
{
  "version": "1",
  "allowed_agent_dids": ["*"],
  "minimum_proof_tier": "gateway",
  "required_receipt_types": ["gateway_receipt"],
  "allowed_providers": ["anthropic", "openai"]
}
```

## Check Run Output

```
Claw Verified: PASS (1 bundle)
- Bundles: 1
- Receipts: 7 (3 gateway, 4 tool)
- Policy: .clawsig/policy.json
- Agent(s): did:key:z6Mk...
```
