## Brutal priority ordering (tomorrow public > next-week elegance)

**P0 Launch blockers (must be green to be public tomorrow):**
1) **clawverify**: commit proof verification + token introspection + one-call agent verification (**CVF-US-011..013**)  
2) **clawledger**: reserve asset registry + compute reserves surfaced in reserve attestation (**CLD-US-010..011**)  
3) **clawproxy**: receipts must bind to token+policy (fail-closed) + platform-paid mode that fails closed without ledger approval (**CPX-US-012..013**)  
4) **clawbounties**: trust-tier proof classification + commit proofs + tier gating + owner-verified voting **only to the minimum needed to prevent “fake trust” in public** (**CBT-US-009..014**)  
5) **cross-domain**: real domains have non-embarrassing landings + docs + /skill.md + robots/sitemap + Cloudflare bindings and secrets present.

Hard constraints explicitly honored:
- **Fail-closed** everywhere (unknown schema/version/algo/token/policy = deny).  
- **Confidential mode** never stores raw prompts/keys/tokens; store hashes or encrypted blobs only.  
- **Token service is `clawscope.com`** (do not assume clawauth.com).  
- Compatible with **Pi coding agent 0.51.0** “one story per iteration” loop + **DID commit proof** requirement (`scripts/ralph/PI.md`).  
- Domain inventory is from `../cf-domains.md`.  

---

# 1) Dependency-aware, interleaved task plan (next 200 iterations)

### Service dependency graph (tomorrow-critical path)
- **clawverify** is the trust root for: commit proofs, owner attestations, token introspection, one-call verification.
- **clawledger** is the payment-reserve root for: platform-paid inference and reserve attestations.
- **clawproxy** depends on **clawverify** (receipt verifiability + policy binding semantics) and **clawledger** (platform-paid authorization).
- **clawbounties** depends on **clawverify** (proof bundle tier, commit proof, owner attestation), and indirectly **clawproxy** (gateway receipts) and **clawledger/clawescrow** for holds/stakes.

### Interleaving strategy for 200 iterations
You only have **13 failing story IDs** listed, so the remaining iterations must “count” by converting into: smaller sub-stories, contract tests, public-domain docs, deploy wiring, and merge hardening—without violating “one story per iteration”.

I’m treating each “iteration” as a Pi/Ralph unit-of-work that ends in a signed commit + DID commit proof bundle (per `scripts/ralph/PI.md`).

---

## Iterations 1–40 (P0): clawverify becomes authoritative trust API
**Goal:** unblock proxy+bounties immediately.

1–12. **CVF-US-011** (commit proof verification) — slice into 4 micro-iterations:
- (a) endpoint + strict schema validation (fail-closed)
- (b) signer binding rule (`signer_did === payload.agent_did`)
- (c) repo-claim lookup stub (fail-closed if unavailable unless claim provided)
- (d) tests + fixtures

13–25. **CVF-US-013** (scoped token introspection) — slice into 4 micro-iterations:
- (a) endpoint skeleton + response shape stable
- (b) signature + exp/iat validation
- (c) audience + scope checks
- (d) audit log: log **token hash only** (never raw token)

26–40. **CVF-US-012** (one-call agent verification) — slice into 4 micro-iterations:
- (a) aggregator endpoint skeleton + deterministic overall logic
- (b) integrate owner attestation verification result (existing CVF-US-010 assumed done elsewhere; if not, stub fail-closed)
- (c) integrate proof-bundle verifier result (existing CVF-US-007)
- (d) tests for PASS/FAIL matrices

**Proof of “done”:** contract tests that bounties/proxy can run locally with mocked fetch.

(Alignment source: `docs/oracle/roadmaps/clawverify-remaining-stories.gpt-5.2-pro.md`.)

---

## Iterations 41–80 (P0): clawledger reserves become real (and usable by proxy)
**Goal:** platform-paid cannot ship without reserve semantics.

41–60. **CLD-US-010** (reserve asset registry + snapshots + attestation breakdown)
- add D1 tables + migrations
- add admin-gated CRUD endpoints (fail-closed if ADMIN_TOKEN missing)
- update reserve attestation response to include reserve breakdown, stale/missing handling

61–70. **CLD-US-011** (compute reserve assets Gemini/FAL)
- create “compute_credit” reserve assets definitions
- normalize snapshot ingestion to “credit units”
- haircuts + max_age_seconds defaults
- fixtures + tests

71–80. **Missing launch blocker (ledger ↔ proxy)**: reserve authorization endpoints
- **CLD-LB-001** `POST /v1/reserve/authorize` (fail-closed)
- **CLD-LB-002** `POST /v1/reserve/settle` (best-effort settle; authorization is the hard gate)

(Implementation shape guidance: `docs/oracle/roadmaps/clawledger-reserve-assets.gpt-5.2-pro.md` and the proxy roadmap’s expected interface.)

---

## Iterations 81–120 (P0): clawproxy receipts bind to token+policy; platform-paid works or fails closed
81–95. **CPX-US-012** (token/policy binding in receipts + fail-closed)
- receipt binding fields expanded: `tokenHash`, `tokenScopeHashB64u`, `ownerRef`, `payment` section
- enforce token-policy binding especially in confidential mode (deny if mismatch or missing)
- tests: mismatch denies; confidential mode never logs secrets

96–120. **CPX-US-013** (platform-paid inference)
- routing rule: BYOK if provider key present else platform-paid if scope allows
- call ledger `/v1/reserve/authorize` **before** calling provider
- receipt includes `payment.mode=platform`, `ledgerRef`, `paid=true`
- fail-closed: if ledger unavailable or denies → **provider must not be called**

(Alignment source: `docs/oracle/roadmaps/clawproxy-remaining-stories.gpt-5.2-pro.md`.)

---

## Iterations 121–175 (P0/P1): clawbounties trust minimum for public
You can’t launch “trust marketplace” publicly if proof tier, commit proofs, and gating are fake.

121–135. **CBT-US-012** (commit proofs required for code bounties) — do early because it depends on CVF-US-011
136–148. **CBT-US-009** (proof tier classification from clawverify result)
149–157. **CBT-US-013** (min PoH tier gating at accept)
158–175. **CBT-US-014** (owner-verified voting + higher-stake fallback)

Then finish the remaining bounties UX correctness:
176–185. **CBT-US-011** (difficulty scalar K, immutable)
186–195. **CBT-US-010** (fee disclosure; store policy+quote; can be “read-only simulate”)
196–200. **CBT-US-… hardening passes**: contract tests + docs endpoints + public landing sanity

(Alignment source: `docs/oracle/roadmaps/clawbounties-remaining-stories.gpt-5.2-pro.md`.)

---

# 2) Improved, smaller acceptance criteria per remaining story (with exact endpoints)

Below are “agent-resistant” acceptance criteria: small, testable, and hard to stall on.

## clawverify

### CVF-US-011 — Verify commit proofs (fail-closed, repo-claim required)
**Endpoint:** `POST https://clawverify.com/v1/verify/commit-proof`

**Request**
```json
{
  "envelope": { "... SignedEnvelope ...": "..." },
  "repo_claim": {
    "claim_id": "claim_123",
    "repo_url": "https://github.com/org/repo",
    "agent_did": "did:key:z...",
    "status": "active"
  }
}
```

**Response (200 VALID)**
```json
{
  "result": { "status": "VALID", "verified_at": "2026-02-02T00:00:00Z" },
  "commit": {
    "repo_url": "https://github.com/org/repo",
    "commit_sha": "40hex...",
    "agent_did": "did:key:z...",
    "proof_bundle_hash_b64u": "optional..."
  },
  "repo_claim": { "lookup": "PROVIDED", "status": "FOUND", "claim_id": "claim_123" }
}
```

**Response (422 INVALID)**
```json
{
  "result": { "status": "INVALID" },
  "error": { "code": "REPO_CLAIM_NOT_FOUND", "message": "Repo claim missing or mismatch" }
}
```

**Acceptance criteria**
- [ ] Rejects if envelope schema id/version not allowlisted (fail-closed).
- [ ] Rejects if `payload.commit_sha` not `^[0-9a-f]{40}$`.
- [ ] Rejects if `envelope.signer_did !== payload.agent_did` (no delegation).
- [ ] Rejects if `repo_claim` missing **and** `env.CLAWCLAIM_BASE_URL` not set (fail-closed).
- [ ] Unit tests cover: valid, bad sig, subject mismatch, missing claim, mismatch claim.

(See schema references in `docs/oracle/roadmaps/clawbounties-remaining-stories.gpt-5.2-pro.md`.)

---

### CVF-US-012 — One-call agent verification (deterministic aggregator)
**Endpoint:** `POST https://clawverify.com/v1/verify/agent`

**Request**
```json
{
  "agent_did": "did:key:z...",
  "scoped_token": { "token": { "... SignedEnvelope scoped_token ...": "..." } },
  "expected_audience": "https://clawbounties.com",
  "required_scopes": ["cbt:accept"]
}
```

**Response (always 200, fail-closed inside payload)**
```json
{
  "agent_did": "did:key:z...",
  "verified_at": "2026-02-02T00:00:00Z",
  "policy": { "present": true, "token_active": false, "audience_ok": false, "scope_ok": false, "policy_ok": true },
  "owner": { "present": false, "owner_status": "UNKNOWN", "result": { "status": "INVALID" } },
  "poh": { "present": false, "trust_tier": "unknown", "bundle_result": { "status": "INVALID" } },
  "overall": { "status": "FAIL", "fail_reasons": ["TOKEN_EXPIRED"], "risk_flags": ["OWNER_MISSING","NO_POH"] }
}
```

**Acceptance criteria**
- [ ] Never returns PASS unless all required provided components validate.
- [ ] Missing optional components produce explicit `present:false` + risk flags.
- [ ] No secrets/tokens echoed back in errors or logs.

---

### CVF-US-013 — Scoped token introspection
**Endpoint:** `POST https://clawverify.com/v1/token/introspect`

**Request**
```json
{
  "token": { "... SignedEnvelope scoped_token ...": "..." },
  "expected_audience": "https://clawproxy.com",
  "required_scopes": ["cpx:proxy:invoke"]
}
```

**Response (200)**
```json
{
  "active": true,
  "sub": "did:key:z...",
  "aud": ["https://clawproxy.com"],
  "scope": ["cpx:proxy:invoke"],
  "exp": 1760003600,
  "iat": 1760000000,
  "policy_hash_b64u": "optional",
  "token_scope_hash_b64u": "optional",
  "error": null
}
```

**Acceptance criteria**
- [ ] `active=false` for invalid signature, expired token, audience mismatch, insufficient scope (still HTTP 200).
- [ ] Logs only a **token hash** (never the raw token).
- [ ] Unit tests cover all inactive cases deterministically.

---

## clawproxy

### CPX-US-012 — Receipts bind to token+policy; confidential mode fail-closed
**Endpoint:** `POST https://clawproxy.com/v1/proxy/:provider`

**Required headers**
- `Authorization: Bearer <CST>` (CST minted by `clawscope.com`, per your constraint)
- `X-Policy-Hash: <hash>` required when `X-Confidential-Mode: true`
- Optional BYOK:
  - `X-Provider-Api-Key: ...`

**Receipt shape (embedded in response as `_receipt`)**
```json
{
  "_receipt": {
    "receipt_version": "1",
    "binding": {
      "policyHash": "…",
      "tokenHash": "sha256hex…",
      "tokenScopeHashB64u": "…",
      "ownerRef": "optional"
    },
    "privacyMode": "hash-only|encrypted",
    "signature": "base64…"
  }
}
```

**Acceptance criteria**
- [ ] If confidential mode and token lacks/mismatches `policy_hash_b64u` → deny with 403 (fail-closed).
- [ ] Receipt includes `binding.tokenHash` and **never** includes token plaintext.
- [ ] Tests assert logs do not include `Authorization` or provider keys.

(Implementation plan: `docs/oracle/roadmaps/clawproxy-remaining-stories.gpt-5.2-pro.md`.)

---

### CPX-US-013 — Platform-paid inference mode (reserve-backed)
**Behavior rule**
- If no BYOK header present: platform-paid allowed **only** with scope `cpx:pay:platform`, and only if ledger approves first.

**Receipt addition**
```json
{
  "_receipt": {
    "payment": { "mode": "platform", "paid": true, "ledgerRef": "ldg_123" }
  }
}
```

**Acceptance criteria**
- [ ] When platform-paid, must call `clawledger` authorize endpoint first; if authorize fails → do not call provider.
- [ ] If ledger unavailable → return 503 `LEDGER_UNAVAILABLE` (fail-closed).
- [ ] Receipt marks payment mode and ledgerRef.

---

## clawledger

### CLD-US-010 — Reserve assets registry + snapshots + reserve attestation breakdown
**Endpoints (admin-gated, fail-closed if no ADMIN_TOKEN configured)**
- `POST /v1/reserve/assets`
- `PATCH /v1/reserve/assets/:id`
- `POST /v1/reserve/assets/:id/snapshots`
- `GET /v1/reserve/assets/:id/snapshots/latest`

**Public attestation endpoint**
- `GET /v1/attestation/reserve` (also keep existing `GET /attestation/reserve` as alias if already shipped)

**Attestation response must include**
```json
{
  "reserveBreakdown": [
    {
      "reserveAssetId": "ras_compute_gemini_k",
      "assetType": "compute_credit",
      "provider": "gemini",
      "rawAmount": "12000",
      "haircutBps": 5000,
      "isStale": false,
      "eligibleAmount": "6000"
    }
  ],
  "eligibleReservesTotal": "6000",
  "rawReservesTotal": "12000"
}
```

**Acceptance criteria**
- [ ] Missing snapshot => eligibleAmount = 0 and flagged (fail-closed).
- [ ] Stale snapshot => eligibleAmount = 0 and flagged (fail-closed).
- [ ] Admin endpoints 403 if ADMIN_TOKEN missing.

(Design basis: `docs/oracle/roadmaps/clawledger-reserve-assets.gpt-5.2-pro.md`.)

---

### CLD-US-011 — Compute reserve assets (Gemini k, FAL .5k)
**Acceptance criteria**
- [ ] Two reserve assets exist in fixtures/tests: Gemini + FAL with haircuts and max age.
- [ ] Snapshot ingestion normalizes to “credit units” (integers as strings).
- [ ] Reserve attestation shows both assets and totals.

---

## clawbounties

### CBT-US-009 — Proof tier classification
**Endpoint:** `POST /v1/bounties/:bountyId/submissions` and `GET /v1/submissions/:id`

**Acceptance criteria**
- [ ] On submission creation, verification is attempted; if verifier unavailable or invalid → `proof.verify_status="invalid|pending"` and `tier=null` (fail-closed).
- [ ] When valid: tier is `gateway` iff at least one valid clawproxy receipt is present; else `self`. `sandbox` reserved.
- [ ] Response exposes:
```json
{ "proof": { "verify_status": "valid", "tier": "gateway", "verified_at": "…" } }
```

---

### CBT-US-010 — Fee disclosure (small, auditable)
**Acceptance criteria**
- [ ] `POST /v1/bounties` response includes stored fee quote + policy `{id, version, hash}`.
- [ ] `POST /v1/bounties/:id/accept` response includes worker net + same policy ref.
- [ ] If clawcuts unavailable: bounty creation fails (fail-closed) **or** returns fees with `status:"unavailable"` and does not allow posting—pick one and test it. For tomorrow public, I recommend **deny posting** if fees can’t be disclosed.

---

### CBT-US-011 — Difficulty scalar K (immutable)
**Acceptance criteria**
- [ ] `difficulty_k` required on creation; 400 if missing/out of range.
- [ ] Any update endpoint cannot change it (400/409).
- [ ] `GET /v1/bounties/:id` always returns it.

---

### CBT-US-012 — Code bounty commit proofs
**Acceptance criteria**
- [ ] For `bounties.kind="code"`, submission must include `commit_proof_envelope`; else 400.
- [ ] Bounties calls `clawverify /v1/verify/commit-proof`; invalid => submission rejected/pending-verification (fail-closed).
- [ ] If commit proof includes `proof_bundle_hash_b64u`, must match submission’s bundle hash.

---

### CBT-US-013 — PoH tier gating at accept
**Acceptance criteria**
- [ ] `min_poh_tier` is settable at bounty creation.
- [ ] `POST /v1/bounties/:id/accept` fetches agent tier (via `clawrep` or `clawverify /v1/verify/agent`) and denies if insufficient.
- [ ] If tier lookup fails and `min_poh_tier >= 2` => deny (fail-closed).

---

### CBT-US-014 — Owner-verified voting with stake fallback
**Acceptance criteria**
- [ ] If `require_owner_verified_votes=true`, votes without owner attestation envelope => 400.
- [ ] Owner attestation verified via clawverify; expired => treated as unverified.
- [ ] Unverified votes require stake `base * multiplier` and are recorded as such.

---

# 3) Launch / SEO / skills / domain plan (what must exist tomorrow) + Workers checklist

Domains you actually control are enumerated in `../cf-domains.md`. For tomorrow, focus on these **7**:
- `joinclaw.com` (public hub)
- `clawscope.com` (token issuer surface)
- `clawproxy.com` (gateway)
- `clawverify.com` (verifier + schema registry)
- `clawbounties.com` (marketplace)
- `clawescrow.com` (escrow)
- `clawledger.com` (ledger + attestation)

Everything else can be a **single-page placeholder + canonical link** to `joinclaw.com` to avoid SEO garbage.

---

## What must exist on each domain tomorrow (minimum public-acceptable)

### Common on all 7 domains
- `GET /` landing page:
  - product name, one-line purpose, status (“Public beta”), and links to docs + status + security contact
  - `<link rel="canonical" href="https://joinclaw.com/...">` where appropriate
- `GET /robots.txt` (allow indexing only for joinclaw + docs; disallow API paths)
- `GET /sitemap.xml` (just `/`, `/docs`, `/skill.md`, `/status`)
- `GET /.well-known/security.txt` (contact + disclosure policy)
- `GET /status` (simple uptime text + build SHA, no secrets)
- `GET /skill.md` (see below)
- CORS policy: **deny by default**, allow only necessary origins for docs/dev console.

### joinclaw.com (hub)
- `/did-work` landing that matches plugin metadata from `../openclaw-did-work/openclaw.plugin.json`
- `/skills/did-work/skill.md` serving the contents/essentials from `../skill-did-work/SKILL.md`
- `/docs` with:
  - “Quick start: get a token from clawscope, call clawproxy, verify via clawverify”
  - “Trust tiers” overview (mirror SKILL.md)
- SEO: basic OpenGraph + schema.org SoftwareApplication.

### clawverify.com
- `/docs` describing:
  - `/v1/verify/commit-proof`
  - `/v1/token/introspect`
  - `/v1/verify/agent`
- **Schema registry exposure** (public, read-only):
  - `GET /v1/schemas/allowlist`
  - `GET /v1/schemas/validate` (or `POST`, depending on existing implementation)
  - Ensure schema `$id` values match the referenced schemas in `packages/schema/**` (per interconnection rules in `docs/INTERCONNECTION.md`)

### clawproxy.com
- `/docs` describing headers + privacy modes + fail-closed behavior
- Make sure confidential mode is explained without leaking “prompt/receipt” internals.

### clawledger.com
- `/docs` with reserve attestation explanation (what reserves mean, haircuts, staleness)
- `GET /v1/attestation/reserve` publicly accessible
- Admin endpoints not documented publicly (or documented with big warnings), and **hard-403 when ADMIN_TOKEN missing**.

### clawbounties.com
- `/docs` minimal: post/accept/submit flows + trust requirements + proof expectations
- If the UI isn’t ready, the API docs must be.

### clawescrow.com
- `/docs` minimal: create/release/dispute endpoints + security model (holds, disputes)

### clawscope.com (token service)
- `/docs` minimal: “Mint scoped token (CST)”, audience, expiry, scopes
- Strongly recommend `/v1/jwks.json` for proxy/verifier key discovery **(read-only)**

---

## /skill.md contract (tomorrow minimum)
Each service domain should serve `GET /skill.md` describing:
- purpose
- base URL
- auth header format
- 3 example curl calls
- which endpoints are stable “v1”

For `did-work` specifically, ensure it aligns with:
- plugin config in `../openclaw-did-work/openclaw.plugin.json`
- signing behavior in `../openclaw-did-work/src/sign-tool.ts` (DID identity + `.sig.json` output)

---

## Cloudflare Workers deployment checklist (routes, wrangler, secrets, bindings)

### Routes (Cloudflare dashboard)
Bind each Worker to:
- `clawproxy.com/*`
- `clawverify.com/*`
- `clawledger.com/*`
- `clawbounties.com/*`
- `clawescrow.com/*`
- `clawscope.com/*`
- `joinclaw.com/*` (static Worker or Pages)

### `wrangler.toml` (minimum per service)
- `name = "clawproxy-prod"` etc
- `compatibility_date = "2025-xx-xx"`
- `main = "src/index.ts"`
- `routes = [{ pattern = "clawproxy.com/*", zone_name = "clawproxy.com" }]`
- `vars` only for non-secrets
- `observability` on (if you have it)

### Required bindings (typical)
- **D1**:
  - clawledger: `LEDGER_DB`
  - clawverify: `VERIFY_DB` (audit log)
  - clawbounties: `BOUNTIES_DB`
  - clawescrow: `ESCROW_DB`
- **KV**:
  - clawproxy: `POLICY_KV` (WPC/policy hash allowlist/cache), optionally `RATE_KV`
  - joinclaw: `SITE_KV` (if serving static content from KV)
- **R2 (optional tomorrow)**:
  - for proof bundles or docs artifacts; otherwise skip.

### Secrets (set via `wrangler secret put …`)
**clawproxy**
- token verification:
  - `CST_JWKS_URL=https://clawscope.com/v1/jwks.json` (recommended)
  - or `CST_PUBLIC_KEY_B64U` (fallback)
- platform provider keys (if enabling platform-paid):
  - `PLATFORM_OPENAI_API_KEY` / `PLATFORM_ANTHROPIC_API_KEY` / …
- `CLAWLEDGER_URL=https://clawledger.com`
- `PROXY_SIGNING_KEY` (receipt signing)
- `PROXY_ENCRYPTION_KEY` (for encrypted receipts)
- `PROXY_ALLOW_LEGACY_AUTH="false"` (tomorrow: default deny)

**clawverify**
- if needed for clawclaim stub:
  - `CLAWCLAIM_BASE_URL` (if you actually have it; otherwise commit-proof requires provided claim)
- any signing/verifier keys required by your existing implementation

**clawledger**
- `ADMIN_TOKEN` (or leave unset to hard-disable admin endpoints; but then you can’t ingest snapshots—so for tomorrow, set it)
- attestation signing key material (if you implement real signatures)

**clawbounties / clawescrow**
- service-to-service secrets (only if already implemented); otherwise hard-disable privileged flows.

### “Fail-closed sanity checks” (must run before calling it public)
- unset each secret one-by-one and confirm endpoints return **403/401/503** (not permissive defaults).
- confirm confidential mode never echoes headers/body in error responses.

---

# 4) Repo / PR merge plan (phase1-trust → main safely with proof bundles + signed commits)

Your repo rules are explicit in:
- `docs/GIT_STRATEGY.md` (PR requirements, proof bundles)
- `docs/INTERCONNECTION.md` (no schema forks, additive changes)
- `docs/PARALLEL_EXECUTION.md` (Pi vs Ralph responsibilities)
- `scripts/ralph/PI.md` (DID commit proof generation)

### Merge order (min conflicts + respects dependencies)
1) **Core/shared** (only if shared files overlap): schema registry, signing helpers, ignores
2) **clawledger** (so proxy can depend on ledger endpoints)
3) **clawverify** (so bounties/proxy can depend on verification endpoints)
4) **clawproxy**
5) **clawescrow**
6) **clawbounties**
7) **joinclaw/docs** (can land anytime, but avoid conflicts by keeping separate)

### Non-negotiables (because of DID commit proof requirement)
- **No rebase** of published branches (rebasing breaks commit SHAs and commit proofs).
- **No squash merge** for the same reason.
- Use merge commits, git-signed.

### Proof bundle checklist per PR
Add:
```
/proofs/<pr-id>/
  commit.sig.json
  receipt.json            (if any gateway receipts exist; otherwise omit)
  artifact.sig.json       (if signing a bundle artifact; optional)
  manifest.json           (list what stories closed, endpoints added, env vars)
```
Generate commit proof exactly as required by `scripts/ralph/PI.md`:
```bash
BRANCH=$(git branch --show-current)
PROOF_DIR="proofs/${BRANCH}"
mkdir -p "$PROOF_DIR"
node ./scripts/did-work/sign-message.mjs "commit:$(git rev-parse HEAD)" > "$PROOF_DIR/commit.sig.json"
```

### Conflict minimization tactics
- If multiple branches touched `/packages/schema/**`, resolve by **adding new versioned schema files** rather than editing in place (per `docs/INTERCONNECTION.md`).
- Treat `scripts/did-work/sign-message.mjs` as “core-owned”; merge it once, then freeze.

(If you want a ready-to-run merge playbook, the structure in `docs/oracle/roadmaps/phase1-trust-merge-plan.gpt-5.2-pro.md` already matches this approach.)

---

# 5) FAST PATH (by tomorrow) vs BEST PATH (next week)

## FAST PATH (tomorrow public, minimal but real)
**Objective:** Public can hit domains, read docs, mint/verify trust artifacts, and nothing insecure is accidentally enabled.

Must ship:
- CVF-US-011/012/013 fully passing with tests.
- CLD-US-010/011 minimally passing + reserve attestation shows breakdown; snapshot ingestion works behind ADMIN_TOKEN.
- CPX-US-012/013 passing: receipts bind token+policy; platform-paid is either:
  - enabled with ledger authorize gate, or
  - returns deterministic “not enabled” **fail-closed** when env keys missing.
- CBT-US-009/012/013/014 passing **at minimum** (trust tier, commit proofs, tier gating, owner-verified voting).  
  If time compresses: ship the endpoints with strict validation first, then fee disclosure and K next.
- Domains: `/`, `/docs`, `/skill.md`, `robots.txt`, `sitemap.xml`, `security.txt`.

## BEST PATH (next week, “it’s solid”)
- Add golden-vector crypto parity tests (see reuse guidance in `docs/oracle/roadmaps/moltbook-reuse-plan.gpt-5.2-pro.md`) so DID/JCS/signatures are provably interoperable.
- Replace any stubbed repo-claim validation with real `clawclaim` service (still fail-closed).
- Add end-to-end contract tests across:
  - token minted by clawscope → proxy receipt issued → clawverify verifies receipt → bounties ingests proof tier
- Add a minimal status page + uptime checks + incident doc.
- Expand schema registry UX and versioning docs (tie into `docs/PRD_INDEX.md` inventory).

---

## Final “tomorrow morning go/no-go” checklist
- [ ] All listed story IDs are green: **CVF-US-011..013, CPX-US-012..013, CLD-US-010..011, CBT-US-009..014**
- [ ] Proxy confidential mode verified: no plaintext prompts/tokens/keys in logs or receipts
- [ ] Token service references are **only `clawscope.com`**, not clawauth
- [ ] Each public domain serves: `/`, `/docs`, `/skill.md`, `/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt`
- [ ] Wrangler configs: routes correct; D1/KV bindings present; secrets set; removing secrets causes fail-closed responses
- [ ] Every PR has git-signed commits + `/proofs/<pr>/commit.sig.json` (per `scripts/ralph/PI.md`)

If you paste the current `prd.json` “fails” lists for each service worktree (or confirm they exactly match the ranges you gave), I can convert the iteration plan into an exact per-worktree “next story to run” queue that your overnight fleet can execute without human routing.
