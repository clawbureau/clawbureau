# Agent A+D Dispatch: Phase 5 — Claw Verified GitHub App

## Context

Read these files first:
- `docs/strategy/GEMINI_DEEP_THINK_REVIEW_2026-02-12.md` — strategic mandate
- `.github/workflows/claw-verified-pr.yml` — existing CI workflow (internal dogfood)
- `scripts/protocol/run-clawsig-verified-pr.mjs` — existing verification runner
- `packages/clawverify-cli/` — offline CLI verifier
- `packages/clawverify-core/` — core verification library

## Background

You already have a working "Claw Verified" PR pipeline (CPL-US-010) that dogfoods on your own PRs. The GitHub Action checks for `proofs/**/commit.sig.json` and `artifacts/poh/**-bundle.json`, runs verification, and blocks merge on failure.

The pivot: **turn this into a public GitHub App that any repo can install.**

## Your Mission

### Deliverable 1: GitHub App
Build a GitHub App (not just an Action — an App with its own identity and check runs).

**Architecture:**
- GitHub App hosted on Cloudflare Worker (new service: `services/clawverify-github/`)
- Receives PR webhook events
- Checks for `proof_bundle.json` or `.clawsig/bundle.json` in PR diff
- Downloads bundle, runs `@clawbureau/clawverify-core` verification
- If repo has `.clawsig/policy.json` (WPC), validates bundle against it
- Posts Check Run with PASS/FAIL + detailed reason codes
- If no bundle found in PR: posts informational check (not blocking)

**Configuration (`.clawsig/config.json` in user's repo):**
```json
{
  "version": "1",
  "enforce": true,
  "policy": ".clawsig/policy.json",
  "require_human_approval_receipt": false,
  "allowed_agents": ["did:key:*"],
  "badge": true
}
```

### Deliverable 2: `clawsig init` Enhancement
Enhance the existing `clawsig init` command to scaffold a repo for the GitHub App:
```bash
npx @clawbureau/clawverify-cli init
```
Creates:
- `.clawsig/config.json` — default configuration
- `.clawsig/policy.json` — starter WPC (allow all providers, no egress restrictions)
- `.clawsig/README.md` — explains what these files do
- `.github/workflows/clawsig-verify.yml` — fallback Action for repos that prefer Actions over the App

### Deliverable 3: Landing Page
On the protocol site (to be `clawprotocol.org`, currently `clawsig.com`):
- `/github` — landing page for the GitHub App
- "Install in 60 seconds" flow
- Live demo showing a PR with the Claw Verified checkmark
- Link to GitHub Marketplace listing

### Deliverable 4: Developer Guide
`docs/guides/GITHUB_APP_QUICKSTART.md`:
1. Install the Claw Verified GitHub App
2. Run `npx @clawbureau/clawverify-cli init` in your repo
3. Configure your policy (WPC)
4. Have an AI agent open a PR with a proof bundle
5. See the green checkmark

### Implementation Notes
- The GitHub App Worker needs a GitHub App private key (secret)
- Use Cloudflare KV or D1 for tracking installations
- Check runs use GitHub Checks API (not commit statuses)
- App should be open-source (builds trust, matches protocol positioning)
- Rate limiting: max 100 verifications per repo per hour

### Constraints
- The App must work with the existing `proof_bundle.v1.json` schema
- Verification must be deterministic (same bundle = same result, always)
- No external API calls during verification (offline-capable logic)
- Must handle repos with no `.clawsig/` config gracefully (informational only)
- Must work with GitHub Enterprise (not just github.com)
