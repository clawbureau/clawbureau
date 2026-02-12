> **Type:** Spec
> **Status:** CANONICAL
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-12
> **Source of truth:** `.github/workflows/claw-verified-pr.yml` + `packages/clawproof-adapters/` + `packages/clawverify-cli/`
>
> **Scope:**
> - Repo-level convention for agent PR evidence packs (PoH bundles + offline verification output)
> - Offline verification (no hosted services required)
> - GitHub check behavior (observe vs enforce)

# Claw Verified PR Pipeline (CPL-US-010)

## 1) Canonical PR evidence pack layout

**All PoH evidence for PRs MUST live under:**

```
artifacts/poh/<branch>/
```

Where `<branch>` is the git branch name (slashes are allowed).

For each run (`run_id`), store:

- `artifacts/poh/<branch>/<run_id>-bundle.json`
- `artifacts/poh/<branch>/<run_id>-urm.json`
- `artifacts/poh/<branch>/<run_id>-trust-pulse.json`
- `artifacts/poh/<branch>/<run_id>-verify.json` (offline verifier output)

Notes:
- `proofs/**/commit.sig.json` remains the **DID commit proof lane**.
- The evidence pack is additive: do not rewrite older runs; add new runs.

## 2) Offline verifier config (Claw Bureau allowlists)

Use the committed config:

- `packages/schema/fixtures/clawverify.config.clawbureau.v1.json`

This includes the allowlisted **gateway receipt signer DIDs** for both prod + staging `clawproxy`.

## 3) How to generate evidence (clawproof-wrap)

From repo root:

```bash
# Required: point the harness at clawproxy.
export CLAWPROOF_PROXY_URL=https://clawproxy.com

# Optional: auth token (CST) if you want real receipts for protected proxy routes.
# export CLAWPROOF_PROXY_TOKEN=...

# Run the harness through the wrapper.
# The wrapper defaults to writing evidence into artifacts/poh/<branch>/.
CLAWPROOF_VERIFY=1 \
clawproof-wrap pi -- pi "run the tests"
```

This will write:

```bash
artifacts/poh/<branch>/<run_id>-bundle.json
artifacts/poh/<branch>/<run_id>-urm.json
artifacts/poh/<branch>/<run_id>-trust-pulse.json
artifacts/poh/<branch>/<run_id>-verify.json
```

## 4) How to verify offline (manual)

```bash
# Build verifier core + CLI
cd packages/clawverify-core && npm ci && npm run build
cd ../clawverify-cli && npm ci && npm run build
cd ../../

# Verify a proof bundle
node packages/clawverify-cli/dist/cli.js verify proof-bundle \
  --input artifacts/poh/<branch>/<run_id>-bundle.json \
  --config packages/schema/fixtures/clawverify.config.clawbureau.v1.json
```

## 5) GitHub check: claw-verified-pr

Workflow:
- `.github/workflows/claw-verified-pr.yml`

Behavior:
- **Observe mode (default):** if PR evidence exists, verify it and post a summary; do not fail the PR.
- **Enforce mode:** fail the check if either:
  - PR label `claw-verified` is present, OR
  - PR adds `proofs/**/commit.sig.json` (strong signal it is agent-generated)

In enforce mode, the PR must include:
- at least one `artifacts/poh/**-bundle.json`
- at least one valid `proofs/**/commit.sig.json`

## 6) Commit proof (agent work)

After your feature commit, add a DID commit proof:

```bash
mkdir -p proofs/<your-branch>

DID_WORK_SKILL_SIGNING_PATH=/Users/gfw/clawd/02-Projects/clawbureau/skill-did-work/dist/signing.js \
node scripts/did-work/sign-message.mjs "commit:<sha>" \
  > proofs/<your-branch>/commit.sig.json
```

Commit the proof in a follow-up commit.

## 7) Branch protection recommendation

For repositories that adopt the Claw Verified PR pipeline, consider adding `verify` as a **required status check** on the default branch.

This makes enforce mode mandatory for all PRs and ensures:
- every merge includes a verified PoH evidence pack or is explicitly observed
- DID commit proofs are cryptographically checked before merge

To enable: Settings → Branches → Branch protection rules → Require status checks → add `verify`.

> **Note:** Do not enable this until the team is comfortable with the pipeline. Start with observe mode (no label, no commit proofs) and promote to enforce once agents routinely produce evidence packs.

## 8) CI caching + artifact persistence

The `claw-verified-pr` workflow uses `actions/setup-node` with `cache: npm` to avoid cold `npm ci` on every push.

Verify summaries are uploaded as GitHub artifacts (`claw-verified-pr-summary`) with 90-day retention, so evidence persists beyond ephemeral job logs.
