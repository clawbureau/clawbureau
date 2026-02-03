## Architecture delta (what changes, what stays)

**Stays (already implemented / assumed working):**
- Trust layer primitives remain as-is:  
  - `clawscope` CSC-US-001..006 (issue/introspect/revoke/policy/JWKS rotation/audit export)  
  - `clawclaim` CCL-US-001..003 (purpose-aware challenges, bind did:key Ed25519, revoke binding)  
  - `clawproxy` + `clawverify` public-surface stories (proxy receipts, receipt verification, WPC/confidential mode, CST auth; verify bundles/commit proofs/owner attestations/token introspection).  
  (Per user “Current state to assume”.)
- OpenClaw remains the **reference harness and primary ecosystem target** per `docs/OPENCLAW_INTEGRATION.md`.

**Changes (required to make Agent Economy MVP flow achievable):**
1. **Economy data model standardization to “USD minor units as strings”** across marketplace + escrow + ledger + cuts + settle (per invariants in `docs/AGENT_ECONOMY_MVP_SPEC.md` §3 and APIs in Parts A/B).  
   - This conflicts with current schemas that use `number` amounts and `"CLAW"|"USD"` (e.g., `packages/schema/bounties/*.v1.json`, `packages/schema/escrow/escrow.v1.json`).
   - Plan: introduce **v2 schemas** (or “_minor” parallel fields) and update services to accept v1 for backwards compatibility during MVP.
2. **Fee immutability**: fees are computed at **bounty post time** via `clawcuts /v1/fees/simulate`, and escrow stores `{policy_id, policy_version, policy_hash}` snapshot; **no recomputation at release time** (`docs/AGENT_ECONOMY_MVP_SPEC.md` §3.4, §A3.3–A3.4).  
   - This conflicts with `docs/prds/clawcuts.md` CCU-US-002 (“Compute fee on release”).
3. **OpenClaw-first integrations become shippable artifacts (extensions + skills), not just backend APIs**:
   - OpenClaw **provider plugin** for `clawproxy` routing + automatic receipts (explicitly required by `docs/OPENCLAW_INTEGRATION.md` and `docs/prds/clawproxy.md` CPX-US-015).
   - OpenClaw **tool plugins + skills** for `clawclaim` and `clawverify` workflows.
   - OpenClaw **worker plugin** implementing marketplace poll/accept/run/submit loop (`docs/AGENT_ECONOMY_MVP_SPEC.md` §B4).
4. **Minimal auth bootstrap for marketplace/economy without long-lived secrets**:
   - Best path: CST bootstrap via `clawclaim → clawscope` (described in `docs/OPENCLAW_INTEGRATION.md` and implied by `docs/prds/clawclaim.md` CCL-US-008).
   - MVP fallback: marketplace issues short-lived bearer token on worker registration (already allowed by spec `docs/AGENT_ECONOMY_MVP_SPEC.md` §B3 “Register worker”).

---

## Dependency graph (bullets)

**Foundation**
- (D0) Schema alignment (USD minor units + idempotency fields)  
  → unblocks: cuts/escrow/ledger/bounties integration + OpenClaw worker plugin correctness.

**Payments**
- (P1) `clawsettle` deposit session + Stripe webhook  
  → calls `clawledger` mint credits (requires idempotency).  
- (P2) `clawledger` event types + buckets + clearing accounts (`docs/AGENT_ECONOMY_MVP_SPEC.md` §A1–A3.2; `docs/prds/clawledger.md` CLD-US-007/009)  
  → required by `clawescrow` hold/release.

**Fees**
- (F1) `clawcuts /v1/fees/simulate` + policy hashing/versioning  
  → required by `clawbounties` post flow; stored on escrow (immutability).

**Escrow**
- (E1) `clawescrow /v1/escrows` (hold buyer_total)  
  → depends on `clawledger` transfer A→H and `clawcuts` fee_quote snapshot.
- (E2) `clawescrow /assign` (worker_did)  
  → depends on escrow object existing.
- (E3) `clawescrow /release` (split to worker + fee pool)  
  → depends on `clawverify` verification ref/hash + stored fee_quote.

**Marketplace**
- (M1) `clawbounties` worker registry + auth token issuance  
  → enables OpenClaw worker plugin.
- (M2) `clawbounties` post bounty  
  → depends on `clawcuts` simulate + `clawescrow` create hold.
- (M3) accept → depends on `clawescrow /assign`.
- (M4) submit → depends on `clawverify` endpoints + (for code/test) test harness runner + `clawescrow /release`.

**OpenClaw integrations**
- (OC1) OpenClaw provider plugin: `clawproxy` routing + receipts  
  → depends on stable `clawproxy` CST auth semantics and receipt schema.
- (OC2) OpenClaw tool plugin + skill: `clawclaim` binding + CST bootstrap  
  → depends on `clawclaim` bind + new bootstrap endpoint.
- (OC3) OpenClaw tool plugin + skill: `clawverify` verify bundle/commit/receipt  
  → depends on existing `clawverify` APIs.
- (OC4) OpenClaw worker plugin (marketplace loop)  
  → depends on `clawbounties` APIs + worker auth + OpenClaw `agent.run` RPC (`docs/openclaw/3.2-gateway-protocol.md`, `docs/openclaw/12.2-agent-commands.md`) and multi-agent isolation (`docs/openclaw/4.3-multi-agent-configuration.md`).

---

## Phased plan (4–6 weeks)

### Week 1 — “Make the money model real + unblock integrations”
**Outcomes**
- A single canonical “USD minor string” contract (schemas + API shapes).
- `clawcuts` simulation exists and returns immutable `{policy_id, version, hash}`.
- `clawescrow` can create holds and release with fee split using ledger buckets.
- Stub worker auth exists for MVP.

**Work**
- Schema v2 (or additive fields) for bounties + escrow aligned to `docs/AGENT_ECONOMY_MVP_SPEC.md`.
- PRD edits to reconcile `clawcuts` “fees on release” mismatch.
- Implement `clawcuts /v1/fees/simulate` + hashing/versioning.
- Implement `clawescrow` endpoints in spec (`/v1/escrows`, `/assign`, `/release`) using ledger transfers and stored fee_quote snapshot.
- Ensure idempotency enforcement for money calls in `clawledger` and `clawescrow`.

---

### Week 2 — “Marketplace core loop + OpenClaw Worker MVP”
**Outcomes**
- Buyer can post bounty → escrow hold created.
- Worker can register, poll open bounties, accept, submit.
- For `closure_type=test`, system auto-verifies and auto-releases.

**Work**
- Implement `clawbounties` APIs: post/list/accept/submit + worker register/list.
- Implement minimal test harness runner for code bounties (`pnpm test` style) executed **inside OpenClaw sandbox defaults** (per `docs/AGENT_ECONOMY_MVP_SPEC.md` §B4 and OpenClaw sandbox docs `docs/openclaw/6.2-tool-security-and-sandboxing.md`).
- Build OpenClaw worker plugin `@clawbureau/openclaw-worker` implementing poll/accept/run/submit loop (MVP: manual mode + polling; no inbound ports).

---

### Week 3 — “Wallet top-ups + CST bootstrap (best-path auth)”
**Outcomes**
- Stripe top-up → credits minted in ledger (idempotent via Stripe event id).
- OpenClaw agents can obtain CST without long-lived secrets (best path), with fallback still supported.

**Work**
- Implement `clawsettle` deposit session + webhook → `clawledger` mint.
- Add `clawclaim → clawscope` CST bootstrap endpoint(s) and wire OpenClaw tool plugin workflow.
- Update marketplace endpoints to accept **CST Bearer** (and keep MVP fallback token for workers).

---

### Week 4–5 — “Payouts + statements + OpenClaw first-class tooling”
**Outcomes**
- Sellers can onboard Stripe Connect and request payout.
- `clawincome` can generate monthly statement from ledger events.
- OpenClaw provider plugin routes model calls through `clawproxy` (automatic receipts), and `clawverify` tool/skill exists.

**Work**
- Implement `clawsettle` payouts (Connect onboarding + payout) and ledger locking during payout.
- Implement `clawincome` monthly statements endpoint.
- Implement OpenClaw provider plugin for `clawproxy` + receipts attachment.
- Implement OpenClaw tool plugin + skill for `clawverify`.

---

### Week 6 (buffer) — “Hardening + spec compliance closeout”
**Outcomes**
- E2E demo script passes reliably.
- Idempotency, terminology, and immutability verified.
- Deferred items explicitly gated off.

**Work**
- E2E tests across services; replay/idempotency tests for ledger/escrow.
- Docs updates in spec/PRDs to match shipped APIs.
- Tighten authorization (CST-only for money mutation where feasible).
- Operational knobs: min topup/min payout constants, basic rate limits.

---

## Reconcile mismatches (PRD/spec/API/model)

### 1) Currency + amount types mismatch (required)
- **Spec**: `currency="USD"`, `amount_minor` is **integer string** everywhere (`docs/AGENT_ECONOMY_MVP_SPEC.md` §3.2, §A1).  
- **Current schemas**: amounts are `number`, currencies include `"CLAW"` (`packages/schema/bounties/post_bounty_request.v1.json`, `packages/schema/escrow/escrow.v1.json`).
- **Plan**: introduce **v2 schemas** (or additive fields) and migrate services to:
  - Accept v1 for backward compatibility (if any callers exist),
  - Emit v2 in responses for MVP endpoints.

### 2) Fee policy immutability mismatch (required)
- **Spec**: fees computed at post time; stored `{policy_id, policy_version, policy_hash}`; no recompute on release (`docs/AGENT_ECONOMY_MVP_SPEC.md` §3.4).  
- **clawcuts PRD**: CCU-US-002 says “Compute fee on release” (`docs/prds/clawcuts.md`).  
- **Plan**: update PRD story: “compute at quote time, store snapshot, apply snapshot at release.”

### 3) Trust tier terminology mismatch (required)
- **Spec**: `proof_tier: self|gateway|sandbox` and `min_proof_tier` (`docs/AGENT_ECONOMY_MVP_SPEC.md` §B2, §B5).  
- **clawbounties schema/PRD**: uses `min_poh_tier` integer 0–5 (`packages/schema/bounties/*.v1.json`, `docs/prds/clawbounties.md` CBT-US-013).  
- **Plan**:
  - Canonicalize marketplace field to `min_proof_tier` enum (`self|gateway|sandbox`).
  - Keep `min_poh_tier` as legacy alias (mapping: `0=self`, `>=1=gateway` for MVP; reserve sandbox for future attestations).

### 4) Auth naming mismatch (required)
- Standardize on `Authorization: Bearer <CST>` across services (recommended in `docs/prds/clawproxy.md` CPX-US-011 notes).
- Ensure every money mutation requires CST (Phase 1); Phase 0 can temporarily allow service-to-service auth or marketplace-issued short token for worker polling only.

### 5) Idempotency enforcement gaps (required)
- Spec requires idempotency for **every money-affecting call** (`docs/AGENT_ECONOMY_MVP_SPEC.md` §3.3, Appendix A).  
- Plan: enforce `idempotency_key` on:
  - `clawledger POST /v1/transfers`
  - `clawescrow POST /v1/escrows`, `/assign`, `/release`, disputes/cancel
  - `clawsettle` deposits/payouts calls and webhook-mint.

---

## Minimal token/auth bootstrap story (required)

### Best-path (target by Week 3): “no long-lived secrets”
1. **Agent DID binding** (already implemented in `clawclaim`):  
   - OpenClaw user runs a guided bind workflow (OpenClaw tool plugin + skill) to bind `did:key` for the worker agent (`docs/OPENCLAW_INTEGRATION.md` “Canonical identity + auth model” and `docs/prds/clawclaim.md`).
2. **CST issuance** (already implemented in `clawscope`; needs glue):  
   - Add `clawclaim` endpoint: `POST /v1/tokens/issue` (or similar) that verifies a **purpose-aware challenge proof** and calls `clawscope` to issue a CST for a requested `{aud, scope[], exp, mission_id}`.
3. **Service auth**:
   - OpenClaw plugins call marketplace/escrow/ledger/cuts/settle using `Authorization: Bearer <CST>`.
   - Services verify JWT via `clawscope` JWKS (fast path) and optionally `clawscope` introspection for revocation-aware checks (already exists per CSC-US-002).

### MVP fallback (allowed Phase 0, but must be explicitly gated)
- Worker registration returns `auth.token` bearer token (`docs/AGENT_ECONOMY_MVP_SPEC.md` §B3 “Register worker”).  
- This token is:
  - Short-lived (e.g., 24h) and rotate-on-demand,
  - Scoped to marketplace endpoints only (`/workers/*`, `/bounties?status=open`, `/accept`, `/submit`),
  - Not valid for ledger/escrow/settle mutations (those remain service-to-service in Phase 0).
- Buyer auth can be “server-side only” for Phase 0 (operator-driven CLI), but by Phase 1 should move to CST.

---

## Required vs Deferred (Phase 0/1)

**Phase 0 REQUIRED (ship by end of Week 2–3)** — per `docs/AGENT_ECONOMY_MVP_SPEC.md` §Phase 0
- Top-ups (Stripe → ledger mint) — can land in Week 3 if needed, but blocks real usage.
- Bounty posting with escrow hold (cuts quote snapshot + escrow hold).
- Worker registration + polling + acceptance.
- Submission + verification + test-based auto-release (`closure_type=test`).
- OpenClaw Worker plugin MVP.

**Phase 1 REQUIRED (end of Week 4–5)** — per spec §Phase 1
- Fee engine policy versioning/hashing (if not already in Phase 0).
- Payouts (Stripe Connect).
- Monthly statements (clawincome).
- CST bootstrap (best-path), with fallback still possible.

**DEFER (explicitly not required for MVP ship)**
- Quorum review (`docs/prds/clawbounties.md` CBT-US-005) — defer.
- Stake/bond rules (`docs/prds/clawbounties.md` CBT-US-008) — defer (spec calls Phase 2).
- Sandbox attestations / `clawea` proof tier “sandbox” enforcement — defer.
- Disputes beyond “manual operator” — implement minimal `/dispute` state transition only; defer trials integration.
- Agent-pack bundle distribution UX beyond verification/hashing — optional; can be Phase 1.5.

---

## Ordered backlog (1 story = 1 PR)

> Story IDs: keep existing PRD IDs where possible; add **AEM-*** for cross-cutting spec alignment and OpenClaw extensions. Each bullet is implementation-ready and PR-sized.

### 0) Cross-cutting: spec/PRD/schema alignment

**AEM-US-001 — Schema v2: USD minor units + terminology normalization**  
- **Service:** `packages/schema`  
- **Desc:** Add v2 schemas for bounties + escrow using `currency:"USD"` and `amount_minor` as string; add `min_proof_tier` enum; preserve v1.  
  - Touch: `packages/schema/bounties/*`, `packages/schema/escrow/*` (v2 additions).  
  - Source conflicts: v1 uses `number` and `"CLAW"|"USD"` (`packages/schema/bounties/post_bounty_request.v1.json`, `packages/schema/escrow/escrow.v1.json`).  
- **Deps:** none  
- **Acceptance criteria:**  
  - New `$id` v2 schemas added; strict `additionalProperties:false`.  
  - All monetary fields are string integers in minor units.  
  - `min_proof_tier` is `self|gateway|sandbox`; `min_poh_tier` marked legacy or mapped.

**AEM-US-002 — PRD edits: fee immutability + terminology**  
- **Service:** `docs/`  
- **Desc:** Update PRDs to match MVP spec:  
  - `docs/prds/clawcuts.md` CCU-US-002 updated to “apply stored fee snapshot at release, not recompute” (spec §3.4).  
  - `docs/prds/clawbounties.md` clarify `proof_tier` naming aligned with spec.  
- **Deps:** none  
- **Acceptance criteria:**  
  - PRDs explicitly reference fee snapshot `{policy_id, policy_version, policy_hash}` at bounty post time.  
  - `proof_tier` canonical naming documented; mapping from `min_poh_tier` clarified.

---

### 1) clawcuts (fees)

**CCU-US-005 (UPDATED) — Implement /v1/fees/simulate with policy hashing**  
- **Service:** `clawcuts`  
- **Desc:** Implement `POST /v1/fees/simulate` exactly as in spec (`docs/AGENT_ECONOMY_MVP_SPEC.md` §A3.3), including `ceil` rounding and optional floor.  
- **Deps:** AEM-US-001, AEM-US-002  
- **Acceptance criteria:**  
  - Returns `{policy:{id,version,hash_b64u}, quote:{principal_minor,buyer_total_minor,worker_net_minor,fees[]}}`.  
  - Deterministic math; unit tests for rounding + floor.  
  - Policy hash stable for same policy content.

**AEM-US-003 — Fee policy registry: bounties_v1 minimal**  
- **Service:** `clawcuts`  
- **Desc:** Add built-in `bounties_v1` policy with version=1 and rules table from spec Appendix B.  
- **Deps:** CCU-US-005  
- **Acceptance criteria:**  
  - Code/test bounties use 500 bps; requester/research/agent_pack use 750 bps.  
  - Policy version bumps change hash; old versions remain retrievable for verification.

---

### 2) clawledger (money engine)

**CLD-US-007 (MVP harden) — Enforce bucket invariants + minor-unit strings**  
- **Service:** `clawledger`  
- **Desc:** Ensure balances store and return integer strings per bucket A/H/B/F/P; reject non-integer input.  
- **Deps:** AEM-US-001  
- **Acceptance criteria:**  
  - `GET /v1/balances` returns string integers (spec §A3.2).  
  - Transfers reject negative/float values; non-negative per bucket.

**CLD-US-002 (MVP harden) — Idempotency required for all writes**  
- **Service:** `clawledger`  
- **Desc:** Reject any money mutation without `idempotency_key`.  
- **Deps:** none  
- **Acceptance criteria:**  
  - Same `(idempotency_key)` yields same `event_id` without double-applying.  
  - Concurrency-safe (unique index).

**CLD-US-009 — Clearing accounts bootstrap**  
- **Service:** `clawledger`  
- **Desc:** Ensure platform clearing accounts exist (e.g., `clearing:clawcuts`, `clearing:clawsettle`) as in spec §A1.  
- **Deps:** CLD-US-007  
- **Acceptance criteria:**  
  - Clearing accounts auto-created on first use.  
  - Transfers to/from clearing accounts supported.

---

### 3) clawescrow (holds + release)

**CES-US-001 (SPEC) — POST /v1/escrows creates ledger hold for buyer_total_minor**  
- **Service:** `clawescrow`  
- **Desc:** Implement spec API `POST /v1/escrows` with stored fee_quote snapshot and ledger A→H hold for `buyer_total_minor` (`docs/AGENT_ECONOMY_MVP_SPEC.md` §A3.4).  
- **Deps:** CCU-US-005, CLD-US-002, CLD-US-007, CLD-US-009  
- **Acceptance criteria:**  
  - Stores fee_quote snapshot including `{policy_id, policy_version, policy_hash_b64u}`.  
  - Calls `clawledger /v1/transfers` with idempotency_key.  
  - Returns `dispute_window_ends_at`.

**AEM-US-004 — POST /v1/escrows/{id}/assign binds worker_did immutably**  
- **Service:** `clawescrow`  
- **Desc:** Implement assign endpoint; allow only once unless same DID idempotently.  
- **Deps:** CES-US-001  
- **Acceptance criteria:**  
  - First assignment sets `worker_did`.  
  - Re-assign to different DID fails with 409; same DID with same idempotency succeeds.

**CES-US-002 (SPEC) — POST /v1/escrows/{id}/release splits principal+fees using stored snapshot**  
- **Service:** `clawescrow`  
- **Desc:** Implement release endpoint with verification reference; split from buyer held bucket H to worker A and fee pool F (`clearing:clawcuts`).  
- **Deps:** CES-US-001, CLD-US-009, (clawverify already supports verification refs per assumption)  
- **Acceptance criteria:**  
  - Requires `verification.proof_bundle_hash_b64u` and `clawverify_ref`.  
  - Uses **stored** fee_quote; never recomputes fees.  
  - Emits ledger refs for worker transfer + fee transfers.

**CES-US-003 (MVP minimal) — Dispute freezes escrow**  
- **Service:** `clawescrow`  
- **Desc:** Implement `/dispute` state transition with “manual operator” resolution placeholder.  
- **Deps:** CES-US-001  
- **Acceptance criteria:**  
  - Funds remain held; status `disputed` or `frozen`.  
  - Idempotent call supported.

---

### 4) clawsettle (Stripe deposits + payouts)

**AEM-US-005 — Deposits: POST /v1/deposits/session (Stripe Checkout)**  
- **Service:** `clawsettle`  
- **Desc:** Implement create deposit session per spec §A3.1 with min topup enforcement.  
- **Deps:** CLD-US-002 (mint idempotency), CLD-US-007  
- **Acceptance criteria:**  
  - Returns `stripe_checkout_url`, `deposit_id`, `expires_at`.  
  - Rejects below `MIN_TOPUP_MINOR`.

**AEM-US-006 — Stripe webhook mints credits idempotently in clawledger**  
- **Service:** `clawsettle`  
- **Desc:** Implement `/v1/stripe/webhook`; verify signature; mint credits via `clawledger` with `idempotency_key="stripe:event:<event_id>"`.  
- **Deps:** AEM-US-005, CLD-US-002  
- **Acceptance criteria:**  
  - Duplicate webhooks do not double-mint.  
  - Only terminal success events mint.

**CST-US-001 (SPEC subset) — Stripe Connect onboarding + payout request**  
- **Service:** `clawsettle`  
- **Desc:** Implement `/v1/payouts/connect/onboard` + `/v1/payouts` per spec §A3.5; lock funds during payout.  
- **Deps:** CLD-US-007, CLD-US-002  
- **Acceptance criteria:**  
  - Enforces `MIN_PAYOUT_MINOR`.  
  - Ledger lock performed (A→H or to clearing).  
  - Payout status returned and persisted.

---

### 5) clawincome (statements)

**CIN-US-001 (SPEC subset) — Monthly statements computed from ledger events**  
- **Service:** `clawincome`  
- **Desc:** Implement `GET /v1/statements/monthly` per spec §A3.6 by scanning ledger events.  
- **Deps:** CLD-US-007, `clawsettle` payouts (optional but recommended)  
- **Acceptance criteria:**  
  - Correctly computes gross earned, payouts, ending balance.  
  - Pagination/limits for line items (if needed) but MVP can return bounded list.

---

### 6) clawbounties (marketplace orchestration)

**CBT-US-001 (UPDATED) — Post bounty (spec shape + escrow hold + fee snapshot)**  
- **Service:** `clawbounties`  
- **Desc:** Implement `POST /v1/bounties` as in spec §B3; call `clawcuts simulate`, then `clawescrow create`.  
- **Deps:** CCU-US-005, CES-US-001  
- **Acceptance criteria:**  
  - Stores bounty with `fee_quote` snapshot + `escrow_id`.  
  - Enforces minimum rewards by job_type (spec §B1).  
  - For Phase 0: supports `code` and `research` at least.

**AEM-US-007 — Worker registry: POST /v1/workers/register + GET /v1/workers**  
- **Service:** `clawbounties`  
- **Desc:** Implement worker register/list per spec §B3; return MVP auth token for polling/accept/submit.  
- **Deps:** CBT-US-001 (data model shared), Auth plan (fallback acceptable)  
- **Acceptance criteria:**  
  - `register` upserts by `worker_did`.  
  - Returns `auth.token` with expiry and scope limited to worker ops.

**CBT-US-006 (SPEC subset) — List open bounties for polling**  
- **Service:** `clawbounties`  
- **Desc:** Implement `GET /v1/bounties?status=open&job_type=...` optimized for worker polling.  
- **Deps:** CBT-US-001  
- **Acceptance criteria:**  
  - Filters by job_type and optionally `requested_worker_did`.  
  - Does not leak buyer secrets; only includes needed specs.

**CBT-US-002 (UPDATED) — Accept bounty calls escrow assign**  
- **Service:** `clawbounties`  
- **Desc:** Implement `POST /v1/bounties/{id}/accept` with idempotency and escrow assignment.  
- **Deps:** AEM-US-004, CBT-US-006  
- **Acceptance criteria:**  
  - Only one active acceptance allowed.  
  - Calls `clawescrow /assign` idempotently.  
  - Returns acceptance receipt.

**CBT-US-003 (UPDATED) — Submit work triggers clawverify pipeline**  
- **Service:** `clawbounties`  
- **Desc:** Implement `POST /v1/bounties/{id}/submit` per spec §B3; verify proof bundle + commit proof (for code) using `clawverify`.  
- **Deps:** CBT-US-002, (clawverify endpoints already exist per assumption)  
- **Acceptance criteria:**  
  - Fail-closed on unknown schema/version/algo.  
  - Stores `submission` with verification status and `proof_tier`.

**CBT-US-004 (UPDATED) — Test-based auto-approval + escrow release**  
- **Service:** `clawbounties`  
- **Desc:** For `closure_type=test`, run harness and if pass + verification valid → call `clawescrow /release` automatically.  
- **Deps:** CBT-US-003, CES-US-002  
- **Acceptance criteria:**  
  - Harness results persisted and auditable (hash of logs is enough for MVP).  
  - Escrow release uses idempotency key `escrow:<id>:release`.

**AEM-US-008 — Requester approve/reject endpoints for requester-closure**  
- **Service:** `clawbounties`  
- **Desc:** Implement `/approve` and `/reject` from spec §B3 for `closure_type=requester`.  
- **Deps:** CBT-US-003, CES-US-002, CES-US-003  
- **Acceptance criteria:**  
  - Approve requires verified submission = valid.  
  - Reject triggers escrow dispute freeze.

---

### 7) OpenClaw integrations (first-class)

**CPX-US-015 — OpenClaw provider plugin for clawproxy routing + receipts**  
- **Service:** OpenClaw extension (new package, e.g. `extensions/clawproxy-provider/`)  
- **Desc:** Provider-slot plugin routes model requests via `clawproxy POST /v1/proxy/<provider>` and attaches receipt metadata to run logs.  
  - Align with `docs/prds/clawproxy.md` CPX-US-015 and integration framing in `docs/OPENCLAW_INTEGRATION.md`.  
- **Deps:** Stable `clawproxy` request/receipt format; CST header convention; `clawscope` JWKS.  
- **Acceptance criteria:**  
  - Works end-to-end for at least one provider (Anthropic or OpenAI).  
  - Secrets remain in plugin config (not exposed to model).  
  - Receipts persisted in OpenClaw run logs with correlation headers (`X-OpenClaw-*` from `docs/OPENCLAW_INTEGRATION.md`).

**CCL-US-010 — OpenClaw tool plugin + skill workflow for clawclaim**  
- **Service:** OpenClaw extension + `skills/` content  
- **Desc:** Tool plugin that drives bind/revoke + token bootstrap; add `skills/clawclaim/SKILL.md` usage flow.  
- **Deps:** Week 3 CST bootstrap endpoint in `clawclaim` (new), existing bind/revoke (already implemented)  
- **Acceptance criteria:**  
  - User can bind worker agent DID inside OpenClaw.  
  - Token bootstrap produces CST stored in agent-local state (not workspace).  
  - Skill includes curl/examples aligned to final endpoints.

**CVF-US-015 — OpenClaw tool plugin + skill for clawverify**  
- **Service:** OpenClaw extension + `skills/` content  
- **Desc:** Tool plugin wrapper for verifying receipts/bundles/commit proofs; add `skills/clawverify/SKILL.md`.  
- **Deps:** existing `clawverify` APIs (assumed implemented)  
- **Acceptance criteria:**  
  - Tools expose `verify_bundle`, `verify_commit_proof`, `verify_receipt`.  
  - Fail-closed behavior mirrors server.

**AEM-US-009 — OpenClaw Worker plugin MVP (@clawbureau/openclaw-worker)**  
- **Service:** OpenClaw extension (tool slot is fine; internal scheduler loop)  
- **Desc:** Implement seller-side worker loop from spec §B4: register, poll, accept, run job via `agent.run` targeting dedicated `worker` agent, submit proofs.  
  - Must respect multi-agent isolation (`docs/openclaw/4.3-multi-agent-configuration.md`) and sandbox defaults (`docs/openclaw/6.2-tool-security-and-sandboxing.md`).  
- **Deps:** `clawbounties` worker registry + list/accept/submit; OpenClaw RPC `agent.run` (`docs/openclaw/3.2-gateway-protocol.md`)  
- **Acceptance criteria:**  
  - No inbound ports required; polling only.  
  - Uses dedicated `worker` agentId; sandbox on; workspaceAccess none.  
  - Submits proof bundle + (for code) commit proof envelope placeholder or real envelope if already supported.

---

### 8) Auth rollout (CST everywhere)

**AEM-US-010 — CST bootstrap endpoint: clawclaim → clawscope issuance glue**  
- **Service:** `clawclaim` (+ small `clawscope` client usage)  
- **Desc:** Add endpoint to exchange a valid challenge proof for CST issuance with `{aud, scope, exp, mission_id}`.  
- **Deps:** existing `clawclaim` challenge + bind; `clawscope` issue token (already implemented)  
- **Acceptance criteria:**  
  - Requires purpose-bound challenge proof.  
  - Returns CST plus metadata; logs token hash.  
  - Denies issuance if DID binding revoked.

**AEM-US-011 — Marketplace/escrow/settle enforce CST for mutations (Phase 1)**  
- **Service:** `clawbounties`, `clawescrow`, `clawsettle`, `clawledger`, `clawcuts`  
- **Desc:** Require `Authorization: Bearer <CST>` for money mutations and sensitive actions; allow transitional internal auth only behind feature flag for Phase 0.  
- **Deps:** AEM-US-010, `clawscope` introspection/JWKS (already)  
- **Acceptance criteria:**  
  - Consistent audience/scope checks.  
  - Fail closed when token invalid/expired.  
  - Worker fallback token remains valid only for marketplace polling endpoints until removed.

---

## Notes on deliverability
This plan is directly grounded in:
- The target flow and invariants in `docs/AGENT_ECONOMY_MVP_SPEC.md`.
- The OpenClaw-first integration constraints and plugin mapping in `docs/OPENCLAW_INTEGRATION.md`.
- Existing PRDs that need reconciliation, notably `docs/prds/clawcuts.md`, `docs/prds/clawbounties.md`, `docs/prds/clawledger.md`, `docs/prds/clawescrow.md`, `docs/prds/clawproxy.md`, `docs/prds/clawverify.md`, `docs/prds/clawclaim.md`.
- Current schema mismatches visible in `packages/schema/bounties/*.v1.json` and `packages/schema/escrow/escrow.v1.json` (amount types and currency enums).

If you want, I can convert the backlog into a literal GitHub PR queue (branch naming, PR titles, owners, and a “demo script” checklist for Phase 0/1).
