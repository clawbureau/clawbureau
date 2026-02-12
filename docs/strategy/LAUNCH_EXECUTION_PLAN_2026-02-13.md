# Launch Execution Plan (2026-02-13)

## Dependency Graph

```
WAVE 1 (parallel, no deps)
  |
  +-- AGENT-SDK -----> fix preload.mjs (undici) + wrap.ts (polyglot + VaaS upload)
  |                    FILES: packages/clawsig-sdk/src/preload.mjs
  |                           packages/clawsig-sdk/src/local-proxy.ts
  |                           packages/clawverify-cli/src/wrap.ts
  |
  +-- AGENT-APP -----> diff-to-receipt reconciliation + observe mode + deploy
  |                    FILES: services/claw-verified-app/src/reconcile.ts (NEW)
  |                           services/claw-verified-app/src/verify.ts
  |                           services/claw-verified-app/src/policy.ts
  |                           services/claw-verified-app/src/index.ts
  |
  +-- AGENT-SPEC ----> fix 4 spec ambiguities in protocol doc
  |                    FILES: docs/strategy/GEMINI_DEEP_THINK_ROUND6_SPEC_AND_LAUNCH_2026-02-12.md
  |                           (or new: docs/specs/clawsig-protocol/CLAWSIG_PROTOCOL_v1.0.md)
  |
  +-- BROWSER -------> register GitHub App on github.com/organizations/clawbureau
                       OUTPUT: app_id, private_key.pem, webhook_secret, client_id

WAVE 2 (after Wave 1 merges + browser completes)
  |
  +-- AGENT-DEPLOY --> wrangler secret put for GitHub App + deploy claw-verified-app
  |                    wrangler deploy services/claw-verified-app
  |
  +-- AGENT-NPM ----> npm publish all 4 packages with --provenance
                       @clawbureau/clawsig-sdk
                       @clawbureau/clawverify-cli
                       @clawbureau/clawverify-core
                       @clawbureau/clawsig-conformance

WAVE 3 (after Wave 2 completes)
  |
  +-- E2E-TEST -----> npx clawsig wrap -- "echo hello" (smoke test)
  |                    verify proof bundle generated, VaaS accepts it
  |
  +-- AGENT-DEMO ---> create github.com/clawbureau/express-demo
                       fork express, add .clawsig/policy.json, add CI workflow
                       create issue with prompt injection payload
```

## Wave 1: Fix the 3 P0 Bugs + Register GitHub App

### AGENT-SDK: Fix preload.mjs + wrap.ts
**Lane:** `packages/clawsig-sdk/`, `packages/clawverify-cli/`
**Branch:** `fix/sdk/launch-p0-dx-fixes`
**Tasks:**
1. Rewrite `preload.mjs` to intercept `undici` global fetch via `setGlobalDispatcher(new EnvHttpProxyAgent(...))`
2. Keep existing `node:https` monkey-patching as fallback for older Node
3. Add `HTTP_PROXY` and `HTTPS_PROXY` env vars in `wrap.ts` for polyglot (Python/Go) support
4. Change `wrap.ts` to upload bundle to VaaS API on exit instead of writing to `.clawsig/`
5. If `gh` CLI is available, append badge markdown to PR description
6. Add `CLAWSIG_PROXY_URL` env var (full URL including port) for undici dispatcher
7. Run typecheck

### AGENT-APP: Diff-to-Receipt Reconciliation + Observe Mode
**Lane:** `services/claw-verified-app/`
**Branch:** `fix/claw-verified-app/diff-reconciliation`
**Tasks:**
1. Create `src/reconcile.ts` -- parse PR diff files, compare against side_effect_receipts
2. Add `UNATTESTED_FILE_MUTATION` reason code to verification output
3. Update `src/verify.ts` to call reconciliation BEFORE WPC evaluation
4. Update `src/verify.ts` to support VaaS bundle lookup (extract run_id from PR body)
5. Implement "Observe Mode" in `src/policy.ts` -- if no policy on default branch, post NEUTRAL check run
6. Run typecheck

### AGENT-SPEC: Fix Protocol Spec Ambiguities
**Lane:** `docs/`
**Branch:** `fix/docs/spec-v1-ambiguities`
**Tasks:**
1. Section 8: Change RT Log L2 anchoring from MUST to SHOULD
2. Section 4.3: Add TrustedLogDirectory to WPC spec
3. Section 5: Add fail-closed rule for unresolvable Context Keys
4. Section 7: Add lexicographic sorting requirement for receipt arrays
5. Move protocol spec from strategy doc to canonical location: `docs/specs/clawsig-protocol/CLAWSIG_PROTOCOL_v1.0.md`

### BROWSER: Register GitHub App
**Interactive browser session with user's profile.**
**Steps:**
1. Navigate to github.com/organizations/clawbureau/settings/apps/new
2. Fill in:
   - App name: "Claw Verified"
   - Homepage: https://clawsig.com
   - Webhook URL: https://claw-verified-app.generaite.workers.dev/webhook
   - Webhook secret: (generate random 32-byte hex)
3. Permissions:
   - Repository: Contents (read), Pull requests (read), Checks (write), Metadata (read)
4. Subscribe to events: Pull request, Check suite
5. Generate private key (downloads .pem file)
6. Save: app_id, client_id, webhook_secret, private_key path
7. Install app on clawbureau org (all repos)

## Wave 2: Deploy + Publish

### AGENT-DEPLOY: Wire Secrets + Deploy GitHub App
**Depends on:** Wave 1 AGENT-APP merge + BROWSER completion
**Tasks:**
1. `wrangler secret put GITHUB_APP_ID`
2. `wrangler secret put GITHUB_PRIVATE_KEY` (PEM contents)
3. `wrangler secret put GITHUB_WEBHOOK_SECRET`
4. `wrangler deploy` for claw-verified-app (prod)
5. Smoke test: curl webhook endpoint with test payload

### AGENT-NPM: Publish Packages
**Depends on:** Wave 1 AGENT-SDK merge
**Tasks:**
1. Verify npm login / token
2. `cd packages/clawverify-core && npm publish --provenance --access public`
3. `cd packages/clawsig-sdk && npm publish --provenance --access public`
4. `cd packages/clawverify-cli && npm publish --provenance --access public`
5. `cd packages/clawsig-conformance && npm publish --provenance --access public`
6. Verify: `npm info @clawbureau/clawsig-sdk`

## Wave 3: E2E Test + Demo Repo

### E2E-TEST: Smoke test the full flow
**Depends on:** Wave 2
**Tasks:**
1. `npx @clawbureau/clawverify-cli wrap -- "echo hello world"`
2. Verify: proof bundle generated with ephemeral DID
3. Verify: VaaS API accepts the bundle
4. Verify: badge URL returned and accessible

### AGENT-DEMO: Create express-demo repo
**Depends on:** Wave 2
**Tasks:**
1. Fork expressjs/express to clawbureau/express-demo
2. Add `.clawsig/policy.json` (WPC v2 from Round 6 launch kit)
3. Add `.github/workflows/clawsig-verify.yml`
4. Create issue with prompt injection in HTML comment
5. Verify GitHub App is active on the repo

## Risk Register

| Risk | Mitigation |
|------|-----------|
| npm publish fails (auth/provenance) | Test with --dry-run first. Ensure NPM_TOKEN is set. |
| GitHub App webhook URL wrong | Use workers.dev URL initially, switch to custom domain later. |
| undici import fails on older Node | Keep node:https patching as fallback. Document Node >= 18.19 requirement. |
| VaaS API not accepting bundles | The ledger was just deployed. May need to debug D1 schema. Test with curl first. |
| Browser session times out | Save credentials incrementally. App registration is idempotent. |
