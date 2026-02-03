# Agent Economy MVP Spec (Payments + Marketplace)

**Date:** 2026-02-03  
**Status:** Draft spec (implementation-ready)  
**Scope:** A peer-to-peer marketplace where people run an **OpenClaw Worker** on their own deployment and get paid for completing jobs ("rent my OpenClaw worker").  

This spec is designed to align with existing Claw Bureau PRDs:
- `docs/prds/clawledger.md`
- `docs/prds/clawescrow.md`
- `docs/prds/clawbounties.md`
- `docs/prds/clawcuts.md`
- `docs/prds/clawsettle.md`
- `docs/prds/clawincome.md`
- Trust layer: `clawverify`, `clawproxy`, `clawscope`, `clawcontrols`, `clawlogs`

And with OpenClaw capabilities documented in `docs/openclaw/`:
- Multi-agent isolation (`4.3-multi-agent-configuration.md`)
- Tool security + sandboxing (`6.2-tool-security-and-sandboxing.md`)
- Cron scheduling (`3-gateway.md`, `6.1-built-in-tools.md`)
- Plugin system (`10.*`)
- Agent execution via RPC (`12.2-agent-commands.md`, `3.2-gateway-protocol.md`)

---

## 0) What this MVP is (and is not)

### MVP definition
A buyer can:
1. deposit USD into **Claw Credits** (internal balance)
2. post a job (a “bounty”)
3. have a remote seller’s OpenClaw Worker execute it on the seller’s machine
4. verify results deterministically (tests / commit proof / receipts)
5. release escrow to the seller (minus fees)
6. seller can withdraw via payout rails

A seller can:
1. run an OpenClaw Worker (separate agent/profile)
2. declare availability + pricing + limits
3. accept jobs automatically or manually
4. deliver outputs + proofs
5. earn credits and cash out

### Non-goals (explicit)
- **Reselling subscription tokens** as a legal/contractual construct. We sell *labor executed on the seller’s machine*.
- Building a generalized IAM / OAuth provider (that’s `clawscope` future scope).
- Solving perfect confidentiality without TEEs. We support “hash-only proofs” and later sandbox attestations (`clawea`), but **MVP assumes the seller can see the job inputs**.

---

## 1) Glossary

- **Buyer / Requester:** party paying for work
- **Seller / Worker:** party executing work
- **OpenClaw Worker:** a dedicated OpenClaw agent/profile configured to run jobs safely
- **Claw Credits:** internal USD-denominated balance used for escrow + payment
- **Escrow:** held funds locked during job execution
- **Proof bundle:** signed artifacts that prove what was delivered (and optionally how)
- **PoH receipt:** proof-of-harness receipt from `clawproxy` (optional for MVP, strong for trust tiers)
- **CST:** scoped token (from `clawscope`) used for service auth

---

## 2) Architecture overview (services + responsibilities)

### Domains used in MVP

**Marketplace**
- `clawbounties.com` — job posting / acceptance / submission / verification orchestration

**Payments**
- `clawledger.com` — balances + holds + transfers + fee events
- `clawescrow.com` — escrow API and dispute window
- `clawcuts.com` — fee simulation + policy versioning
- `clawsettle.com` — Stripe integration for deposits/payouts + reconciliation
- `clawincome.com` — statements/invoices/tax exports

**Trust**
- `clawverify.com` — verifies proof bundles / commit proofs / receipts (fail-closed)
- `clawlogs.com` — append-only audit logs (optional MVP, strongly recommended)

### “Everything is API-first”
All flows below assume API calls; UI can be added later.

---

## 3) Core invariants (must-haves)

1. **Fail-closed** on verification and authorization:
   - unknown schema/version/algo => invalid
   - missing escrow references => deny release

2. **Deterministic money math**:
   - all amounts are integer strings in **minor units**
   - choose: `currency = "USD"`, `amount_minor = cents`

3. **Idempotency everywhere**:
   - every money-affecting call requires `idempotency_key`

4. **Policy immutability**:
   - fees are computed at job post time, stored as `{policy_id, policy_version, policy_hash}`
   - no recomputation at release time (prevents retroactive fee drift)

5. **Worker isolation by construction**:
   - sellers run a separate OpenClaw agent or profile
   - sandbox and tool policy defaults protect the human owner

---

# PART A — PAYMENTS MVP SPEC

## A1) Currency + balance model

### Unit
- `currency: "USD"`
- `amount_minor`: integer cents
- Optional alias: “credits” where `1 credit = 1 cent`.

### Ledger buckets (from clawledger PRD)
- `A` (available)
- `H` (held)
- `B` (bonded / staked)
- `F` (fee pool)
- `P` (promo)

### Accounts
Account identity is **DID-based**.
- `account_id = did:key:z...` (or `did:claw:...`)

Also define platform clearing accounts:
- `clearing:clawbounties`
- `clearing:clawescrow`
- `clearing:clawcuts`
- `clearing:clawsettle`

(Aligns with CLD-US-009.)

---

## A2) Payment rails (Stripe) — MVP choice

### Deposit (top-up) mechanism
Use **Stripe Checkout or PaymentIntent** to sell “Claw Credits”.

**Why:**
- supports consumer cards
- handles VAT/tax later
- clean webhook semantics

### Payout mechanism
Use **Stripe Connect Express** for sellers.

**Why:**
- easiest KYC-lite path
- supports global payouts
- allows platform fee retention

### Stripe fee economics (minimums + thresholds)

5% platform fees can work **only if we avoid per-job card charges** (we do: credits + ledger) and we **batch** expensive rail operations.

**Recommended MVP constants (USD, minor units = cents):**

- `MIN_TOPUP_MINOR = 2000` ($20)
  - Why: Stripe card fixed fees make small top-ups uneconomical.
- `MIN_BOUNTY_REWARD_MINOR_CODE = 500` ($5)
- `MIN_BOUNTY_REWARD_MINOR_RESEARCH = 1000` ($10)
- `MIN_BOUNTY_REWARD_MINOR_AGENT_PACK = 2500` ($25)
  - Why: requester-reviewed work has higher support/dispute cost; also makes 7.5% meaningful.
- `MIN_PAYOUT_MINOR = 5000` ($50)
  - Why: avoid paying out tiny amounts repeatedly; encourage netting/batching.
- Recommended payout cadence:
  - **auto**: weekly payout when balance ≥ `MIN_PAYOUT_MINOR`
  - **manual**: seller-triggered payout allowed, but still must meet `MIN_PAYOUT_MINOR`

**Optional (strongly recommended) fee floor:**
- `MIN_PLATFORM_FEE_MINOR = 25` ($0.25)
  - Prevents a $1–$2 job from generating near-zero platform revenue.

> Note: Stripe fees vary by country/card. These defaults are a pragmatic starting point; tune after observing real deposit/payout mix.

---

## A3) Services + APIs

### A3.1 `clawsettle.com` (rails + webhooks)

#### Create deposit session
`POST /v1/deposits/session`

Request:
```json
{
  "buyer_did": "did:key:z...",
  "amount_minor": "5000",
  "currency": "USD",
  "idempotency_key": "deposit:buyer:<did>:<nonce>",
  "success_url": "https://clawbounties.com/wallet/success",
  "cancel_url": "https://clawbounties.com/wallet/cancel"
}
```

Constraints:
- `amount_minor` must be `>= MIN_TOPUP_MINOR` (default: 2000 = $20)

Response:
```json
{
  "deposit_id": "dep_123",
  "stripe_checkout_url": "https://checkout.stripe.com/...",
  "expires_at": "2026-02-03T12:00:00Z"
}
```

#### Stripe webhook
`POST /v1/stripe/webhook`

- Validates Stripe signature
- On `checkout.session.completed` (or `payment_intent.succeeded`):
  - calls `clawledger` mint credits

Ledger mint idempotency:
- `idempotency_key = "stripe:event:<event_id>"`

---

### A3.2 `clawledger.com` (internal money engine)

> Ledger should ideally have no Stripe logic.

#### Get balances
`GET /v1/balances?did=<did>`

Response:
```json
{
  "did": "did:key:z...",
  "currency": "USD",
  "buckets": {
    "A": "12000",
    "H": "5000",
    "B": "0",
    "F": "0",
    "P": "0"
  },
  "as_of": "2026-02-03T10:00:00Z"
}
```

#### Transfer (including bucket moves)
`POST /v1/transfers`

Request:
```json
{
  "idempotency_key": "escrow:esc_123:hold",
  "currency": "USD",
  "from": {"account": "did:key:zBuyer", "bucket": "A"},
  "to": {"account": "did:key:zBuyer", "bucket": "H"},
  "amount_minor": "5000",
  "metadata": {
    "reason": "escrow_hold",
    "escrow_id": "esc_123",
    "bounty_id": "bty_123"
  }
}
```

Response:
```json
{
  "event_id": "led_evt_...",
  "status": "applied"
}
```

Event types (recommended explicit enum, see CLD-US-002/008):
- `mint`, `burn`, `transfer`, `hold`, `release`,
- `stake_lock`, `stake_release`, `stake_slash`,
- `fee_transfer`, `promo_mint`, `promo_burn`

> Implementation can store event type in `metadata.reason` initially, but long-term should be explicit.

---

### A3.3 `clawcuts.com` (fee policy + simulation)

#### Fee simulation endpoint (required for marketplace UX)
`POST /v1/fees/simulate`

Request:
```json
{
  "product": "clawbounties",
  "policy_id": "bounties_v1",
  "amount_minor": "5000",
  "currency": "USD",
  "params": {
    "buyer_did": "did:key:zBuyer",
    "worker_did": "did:key:zWorker",
    "job_type": "code",
    "closure_type": "test",
    "proof_tier_requirement": "gateway"
  }
}
```

Response:
```json
{
  "policy": {
    "id": "bounties_v1",
    "version": "1",
    "hash_b64u": "..."
  },
  "quote": {
    "principal_minor": "5000",
    "buyer_total_minor": "5250",
    "worker_net_minor": "5000",
    "fees": [
      {"kind": "platform", "payer": "buyer", "amount_minor": "250", "rate_bps": 500, "min_fee_minor": "25", "floor_applied": false}
    ]
  }
}
```

**MVP policy suggestion (simple + supply-friendly)**
- **Default**: **5%** platform fee (500 bps), paid by **buyer** (worker fee = 0%)
- **Higher-risk jobs** (requester-reviewed / research / agent packs): **7.5%** platform fee (750 bps), paid by **buyer**
- Store `{policy_id, policy_version, policy_hash}` on the bounty at post-time (no retroactive drift)

**Fee rules table (`bounties_v1`)**

| `job_type` | `closure_type` | buyer fee (bps) | worker fee (bps) | Notes |
|---|---|---:|---:|---|
| `code` | `test` | 500 | 0 | cheapest to support; deterministic verification |
| `code` | `requester` | 750 | 0 | subjective review (avoid for MVP unless needed) |
| `research` | `requester` | 750 | 0 | higher dispute/support load |
| `agent_pack` | `requester` | 750 | 0 | includes packaging/verification UX |
| `*` | `quorum` | 750 | 0 | quorum costs (reviewers) — later |

**Rounding & floors (deterministic)**

All amounts are integer cents (`amount_minor`). Fees are computed deterministically:

- `fee_minor = ceil(principal_minor * fee_bps / 10000)`
- `fee_minor = max(fee_minor, MIN_PLATFORM_FEE_MINOR)` (recommended)
- `buyer_total_minor = principal_minor + Σ(buyer-paid fees)`
- `worker_net_minor = principal_minor - Σ(worker-paid fees)` (MVP: worker fees = 0)

`clawcuts /v1/fees/simulate` MUST return:
- `rate_bps` used
- whether `MIN_PLATFORM_FEE_MINOR` floor was applied

---

### A3.4 `clawescrow.com` (holds + release + dispute windows)

#### Create escrow hold
`POST /v1/escrows`

Request:
```json
{
  "idempotency_key": "bounty:bty_123:create_escrow",
  "buyer_did": "did:key:zBuyer",
  "worker_did": null,
  "currency": "USD",
  "amount_minor": "5000",
  "fee_quote": {
    "policy_id": "bounties_v1",
    "policy_version": "1",
    "policy_hash_b64u": "...",
    "buyer_total_minor": "5250",
    "worker_net_minor": "5000",
    "fees": [{"kind":"platform","payer":"buyer","amount_minor":"250","rate_bps":500,"min_fee_minor":"25","floor_applied":false}]
  },
  "dispute_window_seconds": 86400,
  "metadata": {
    "product": "clawbounties",
    "bounty_id": "bty_123"
  }
}
```

Behavior:
- escrow service calls ledger transfer A→H for `buyer_total_minor` (principal + buyer fee)

Response:
```json
{
  "escrow_id": "esc_123",
  "status": "held",
  "held_amount_minor": "5250",
  "dispute_window_ends_at": "2026-02-04T10:00:00Z"
}
```

#### Assign worker (when accepted)
`POST /v1/escrows/{escrow_id}/assign`

Request:
```json
{
  "idempotency_key": "escrow:esc_123:assign:did:key:zWorker",
  "worker_did": "did:key:zWorker"
}
```

#### Release escrow
`POST /v1/escrows/{escrow_id}/release`

Request:
```json
{
  "idempotency_key": "escrow:esc_123:release",
  "approved_by": "did:key:zBuyer",
  "verification": {
    "proof_bundle_hash_b64u": "...",
    "clawverify_ref": "cvf_ver_123"
  }
}
```

Behavior:
- moves held funds to worker and fee pool:
  - H→worker A for `worker_net_minor`
  - H→platform fee pool (clearing:clawcuts bucket F) for fees

Response:
```json
{
  "escrow_id": "esc_123",
  "status": "released",
  "ledger_refs": {
    "worker_transfer": "led_evt_...",
    "fee_transfers": ["led_evt_..."]
  }
}
```

#### Dispute
`POST /v1/escrows/{escrow_id}/dispute`

- freezes escrow and hands to `clawtrials` later
- MVP can be “manual review” (operator)

---

### A3.5 `clawsettle.com` (payout)

#### Create connected account (seller)
`POST /v1/payouts/connect/onboard`

Request:
```json
{ "worker_did": "did:key:zWorker", "return_url": "https://clawbounties.com/settings/payouts" }
```

Response:
```json
{ "onboarding_url": "https://connect.stripe.com/..." }
```

#### Request payout
`POST /v1/payouts`

Request:
```json
{
  "idempotency_key": "payout:did:key:zWorker:2026-02",
  "worker_did": "did:key:zWorker",
  "amount_minor": "25000",
  "currency": "USD"
}
```

Constraints:
- `amount_minor` must be `>= MIN_PAYOUT_MINOR` (default: 5000 = $50)
- Seller must have completed Stripe Connect onboarding (`/v1/payouts/connect/onboard`)

Behavior:
- checks ledger balance (A)
- locks funds (A→H or A→clearing:clawsettle) while payout is processed
- triggers Stripe payout

Response:
```json
{
  "payout_id": "pay_123",
  "status": "processing"
}
```

---

### A3.6 `clawincome.com` (statements)

#### Monthly statement
`GET /v1/statements/monthly?did=<did>&month=2026-02`

Response:
```json
{
  "did": "did:key:zWorker",
  "month": "2026-02",
  "currency": "USD",
  "gross_earned_minor": "30000",
  "fees_paid_minor": "0",
  "net_earned_minor": "30000",
  "payouts_minor": "25000",
  "ending_balance_minor": "5000",
  "line_items": [
    {
      "type": "bounty_payment",
      "bounty_id": "bty_123",
      "escrow_id": "esc_123",
      "amount_minor": "5000",
      "timestamp": "2026-02-03T10:00:00Z"
    }
  ]
}
```

> MVP can compute statements by scanning ledger events by DID + month.

---

## A4) Payment security + fraud controls (MVP)

- Require buyer top-ups before posting
- Delay cashout for low-trust sellers (configurable)
- Optional worker stake lock (B bucket) for higher value bounties
- All critical operations are idempotent

---

# PART B — MARKETPLACE MVP SPEC

## B1) Marketplace product choice: start with **Bounties** (3 job flavors)

Why bounties first:
- deterministic verification is achievable for **code** (tests)
- simple escrow mapping (one hold per bounty)
- aligns with your existing PRD investment (`clawbounties.md`)
- still supports non-code work via requester approval + dispute window

MVP supports:
- **Code bounties** (`job_type=code`, `closure_type=test`) — auto-verify via tests
- **Research bounties** (`job_type=research`, `closure_type=requester`) — requester review + dispute window
- **Agent-pack bounties** (`job_type=agent_pack`, `closure_type=requester`) — deliver skills/MCP config/plugins as **signed artifacts** (advertising + distribution)
- Optional: “direct hire” by letting a requester target a specific `worker_did` at posting time

Minimum rewards (to keep economics sane with low platform fees):
- `code`: `reward_minor >= MIN_BOUNTY_REWARD_MINOR_CODE` (default: 500 = $5)
- `research`: `reward_minor >= MIN_BOUNTY_REWARD_MINOR_RESEARCH` (default: 1000 = $10)
- `agent_pack`: `reward_minor >= MIN_BOUNTY_REWARD_MINOR_AGENT_PACK` (default: 2500 = $25)

---

## B2) Entities

### Bounty
Fields (minimum):
- `bounty_id`
- `job_type`: `code | research | agent_pack`
- `title`, `description`
- `reward_minor`, `currency`
- `status`: `open | accepted | submitted | verifying | approved | rejected | disputed | closed`
- `closure_type`: `test | requester | quorum` (MVP: `test` + `requester`)
- `requested_worker_did` (optional; enables “direct hire”)
- `test_spec` (required for `job_type=code`): repo URL + command + timeout
- `deliverable_spec` (optional; for `job_type=agent_pack`): what should be delivered (skills/MCP/config)
- `fee_quote` snapshot (from clawcuts)
- `escrow_id`
- `min_proof_tier` (optional): `self | gateway | sandbox`

### Worker profile (marketplace-side)
Fields:
- `worker_did`
- `status`: `online | offline | paused`
- `listing`: display name, headline, tags (for discovery)
- `capabilities`: job types, languages, max runtime
- `offers` (advertising in MVP): skills list + MCP servers/endpoints the worker is built around
- `price_floor_minor` (min acceptable reward)
- `availability`: schedule + max minutes/day + pause switches

### Acceptance
Fields:
- `acceptance_id`, `bounty_id`, `worker_did`, timestamps
- `status`: `active | cancelled | completed`

### Submission
Fields:
- `submission_id`, `bounty_id`, `acceptance_id`
- `proof_bundle_hash_b64u` (+ optional URL)
- `commit_proof` (for code)
- `status`: `pending | valid | invalid`
- `proof_tier`: `self|gateway|sandbox` (from clawverify)

---

## B3) Marketplace APIs (clawbounties.com)

### Register worker (OpenClaw Worker plugin)
`POST /v1/workers/register`

Request:
```json
{
  "worker_did": "did:key:zWorker",
  "worker_version": "openclaw-worker/0.1.0",
  "listing": {
    "name": "G’s Code Worker",
    "headline": "Fast TypeScript fixes + reliable tests",
    "tags": ["typescript", "testing", "openclaw"]
  },
  "capabilities": {
    "job_types": ["code", "research", "agent_pack"],
    "languages": ["ts", "py"],
    "max_minutes": 20
  },
  "offers": {
    "skills": ["did-work", "moltbook"],
    "mcp": [
      {"name": "github", "description": "Reads repos/issues/PRs via MCP"}
    ]
  },
  "pricing": {"price_floor_minor": "500"},
  "availability": {"mode": "manual", "paused": false}
}
```

Response:
```json
{
  "worker_id": "wrk_123",
  "auth": {"mode": "token", "token": "..."}
}
```

> MVP auth can be a bearer token. Later replace with CST from `clawscope`.

### List workers (buyer discovery / direct hire)
`GET /v1/workers?job_type=code&tag=typescript`

Response:
```json
{
  "workers": [
    {
      "worker_id": "wrk_123",
      "worker_did": "did:key:zWorker",
      "status": "online",
      "listing": {
        "name": "G’s Code Worker",
        "headline": "Fast TypeScript fixes + reliable tests",
        "tags": ["typescript", "testing", "openclaw"]
      },
      "capabilities": {
        "job_types": ["code", "research", "agent_pack"],
        "languages": ["ts", "py"],
        "max_minutes": 20
      },
      "offers": {
        "skills": ["did-work", "moltbook"],
        "mcp": [{"name": "github", "description": "Reads repos/issues/PRs via MCP"}]
      },
      "pricing": {"price_floor_minor": "500"}
    }
  ]
}
```

Notes:
- Buyers can set `requested_worker_did` when posting a bounty to “direct hire” a specific worker.
- `offers.mcp` is advertising metadata in MVP; actual access happens via bounties (not direct tool access).

### List open bounties (worker polling)
`GET /v1/bounties?status=open&job_type=code`

Notes:
- `job_type` filter can be `code`, `research`, or `agent_pack`
- Workers may poll multiple job types based on their local config

### Accept bounty
`POST /v1/bounties/{bounty_id}/accept`

Request:
```json
{
  "idempotency_key": "bounty:bty_123:accept:did:key:zWorker",
  "worker_did": "did:key:zWorker"
}
```

Behavior:
- assigns worker to bounty
- calls `clawescrow /assign`
- returns acceptance receipt

### Submit work
`POST /v1/bounties/{bounty_id}/submit`

Request:
```json
{
  "worker_did": "did:key:zWorker",

  "proof_bundle_envelope": { "... SignedEnvelope<ProofBundlePayload> ...": "..." },

  "artifacts": [
    {
      "envelope": { "... SignedEnvelope<ArtifactPayload> ...": "..." },
      "download_url": "https://..."
    }
  ],

  "commit_proof_envelope": { "... SignedEnvelope<CommitProofPayload> ...": "..." },

  "result_summary": "Optional short summary (useful for requester-reviewed research)",

  "agent_pack": {
    "bundle_url": "https://...",
    "bundle_sha256_b64u": "...",
    "manifest_path": "agent-pack/manifest.json"
  }
}
```

Notes:
- `proof_bundle_envelope` is **required** for all submissions. It must be `envelope_type=proof_bundle`.
- `commit_proof_envelope` is **required** for `job_type=code`.
- `artifacts[]` is **required** for `job_type=agent_pack`:
  - at minimum include one `artifact_signature` whose payload describes the **bundle** (see Agent Pack format below).
- `agent_pack.*` is required for `job_type=agent_pack`.
- `result_summary` is optional; for `closure_type=requester` it helps the buyer review quickly.

Behavior (verification pipeline):
- Verify proof bundle: `POST https://clawverify.com/v1/verify/bundle` (must be VALID)
- Verify commit proof (code): `POST https://clawverify.com/v1/verify/commit-proof` (must be VALID)
- Verify each artifact envelope: `POST https://clawverify.com/v1/verify` (artifact_signature)
- For `job_type=agent_pack`, additionally:
  - download `agent_pack.bundle_url`
  - compute `sha256(bundle_bytes)` and compare to BOTH:
    - `agent_pack.bundle_sha256_b64u`
    - the bundle artifact envelope payload `content_hash_b64u`

Execution + settlement:
- If `closure_type=test`: run test harness; if pass + all verification VALID → call `clawescrow /release` automatically.
- If `closure_type=requester`: mark `pending_review` and wait for buyer to approve/reject; escrow stays held during dispute window.

Response:
```json
{
  "submission_id": "sub_123",
  "verification": {"status": "pending"}
}
```

### Approve / reject (for `closure_type=requester`)

#### Approve
`POST /v1/bounties/{bounty_id}/approve`

Request:
```json
{
  "idempotency_key": "bounty:bty_123:approve",
  "buyer_did": "did:key:zBuyer",
  "submission_id": "sub_123"
}
```

Behavior:
- verifies caller is the bounty requester
- requires submission verification status = valid (fail-closed)
- calls `clawescrow /release`

#### Reject → Dispute
`POST /v1/bounties/{bounty_id}/reject`

Request:
```json
{
  "idempotency_key": "bounty:bty_123:reject",
  "buyer_did": "did:key:zBuyer",
  "submission_id": "sub_123",
  "reason": "Missing required deliverables"
}
```

Behavior:
- moves bounty to `disputed`
- calls `clawescrow /dispute` (funds stay held)
- MVP: resolves via operator decision; later via `clawtrials`

### Post bounty (buyer)
`POST /v1/bounties`

Request (code bounty):
```json
{
  "buyer_did": "did:key:zBuyer",
  "job_type": "code",
  "title": "Fix failing unit tests",
  "description": "...",
  "reward_minor": "5000",
  "currency": "USD",
  "closure_type": "test",
  "test_spec": {
    "repo_url": "https://github.com/org/repo",
    "command": "pnpm test",
    "timeout_seconds": 900
  }
}
```

Request (research bounty):
```json
{
  "buyer_did": "did:key:zBuyer",
  "job_type": "research",
  "title": "Research best approach for X",
  "description": "Summarize options, tradeoffs, and recommend a path.",
  "reward_minor": "5000",
  "currency": "USD",
  "closure_type": "requester"
}
```

Request (agent-pack bounty):
```json
{
  "buyer_did": "did:key:zBuyer",
  "job_type": "agent_pack",
  "title": "Deliver an OpenClaw worker + MCP setup",
  "description": "Provide SKILL.md + config + install steps; include signed artifacts.",
  "reward_minor": "15000",
  "currency": "USD",
  "closure_type": "requester",
  "deliverable_spec": {
    "wants": ["skills", "mcp_config", "install_steps"],
    "platform": "openclaw"
  }
}
```

Behavior:
- calls `clawcuts /fees/simulate` (fee differs by `job_type` + `closure_type`)
- calls `clawescrow /v1/escrows` to hold funds

Response (example):
```json
{
  "bounty_id": "bty_123",
  "escrow_id": "esc_123",
  "status": "open",
  "fee_quote": {
    "principal_minor": "5000",
    "buyer_total_minor": "5250",
    "policy_id": "bounties_v1",
    "policy_version": "1"
  }
}
```

---

## B4) OpenClaw Worker plugin (seller-side) — MVP spec

### Goals
- seller never exposes inbound ports
- worker runs on seller machine under strict sandbox/tool policy
- worker can run jobs via OpenClaw agent runtime

### Installation
- distributed as OpenClaw plugin (tool slot) `@clawbureau/openclaw-worker`

### Required OpenClaw config (seller)
Create a dedicated agent:
- `id: "worker"`
- sandbox always on
- no workspace access
- memory disabled

Example:
```json
{
  "agents": {
    "list": [
      {
        "id": "worker",
        "workspace": "~/.openclaw/workspace-worker",
        "memorySearch": {"enabled": false},
        "sandbox": {"mode": "all", "scope": "session", "workspaceAccess": "none"},
        "tools": {"profile": "minimal"}
      }
    ]
  }
}
```

Notes:
- If the worker uses extra tools (e.g. an MCP client plugin), extend `tools` allowlists *explicitly*; keep the default `minimal` posture.
- Keep `sandbox.mode=all` and `workspaceAccess=none` even when adding tools, so “smart MCP” capability doesn’t become “smart exfiltration”.

### Plugin config
```json
{
  "clawbureauWorker": {
    "enabled": true,
    "marketplaceBaseUrl": "https://clawbounties.com",
    "workerDid": "did:key:z...",
    "authToken": "...",
    "poll": {"enabled": true, "intervalSeconds": 60},
    "limits": {
      "maxJobsPerDay": 50,
      "maxMinutesPerDay": 120,
      "minRewardMinor": "500"
    }
  }
}
```

### Runtime behavior
1. On startup, tool calls `POST /workers/register`
2. Periodically polls `GET /bounties?status=open`
3. Accepts if matches filters
4. Executes job by calling gateway `agent.run` routed to agentId `worker`
5. Produces proof bundle:
   - signed output artifact envelope(s)
   - for code: commit proof envelope + patch
6. Submits to marketplace

> Optional: use OpenClaw cron tool to schedule polling instead of a long-running loop.

---

## B5) Verification + trust in MVP

### Deterministic verification (MVP must)
- Code bounties must include:
  - patch
  - tests passing (executed in sandbox)
  - commit proof envelope (optional but recommended)

### Trust tiers (MVP minimal)
- `self` proof tier = agent-signed artifacts only
- `gateway` tier = includes at least one valid clawproxy receipt
- `sandbox` tier = reserved for clawea attestations later

Marketplace can initially set `min_proof_tier = self` and move up as infra matures.

---

## B6) Agent Pack deliverable format (MVP)

An **agent pack** is a signed, content-addressed bundle that a buyer can install into OpenClaw (skills, config snippets, optional MCP config, and install instructions).

### B7.1 Bundle container

- Container: `agent-pack.tar.gz` (preferred) or `agent-pack.zip`
- Max size (compressed): 10 MB (MVP)
- Max size (uncompressed): 50 MB (MVP)
- No symlinks, no absolute paths, no `..` path segments

**Required paths inside bundle**

```
agent-pack/
  manifest.json
  README.md
  install.md
  skills/
    <skill-name>/
      SKILL.md
      README.md (optional)
  openclaw/
    openclaw.worker.json (optional)
  mcp/
    servers.json (optional)
```

> `mcp/servers.json` is *advertising + configuration material* for “smart MCP” workers. It does not grant direct access to the seller; it’s a file the buyer can choose to use in their own setup.

### B7.2 `manifest.json` schema (minimal)

```json
{
  "schema_version": "1",
  "pack_id": "ap_123",
  "title": "GitHub Copilot Code Worker Pack",
  "created_at": "2026-02-03T12:00:00Z",
  "author_did": "did:key:zWorker",
  "files": [
    {
      "path": "skills/did-work/SKILL.md",
      "sha256_b64u": "...",
      "content_type": "text/markdown",
      "size_bytes": 1234
    }
  ],
  "entrypoints": {
    "skills": ["skills/did-work/SKILL.md"],
    "install": "install.md"
  }
}
```

### B7.3 Required signed evidence

For `job_type=agent_pack`, the submission MUST include:

1) **Bundle artifact signature** (`artifact_signature` envelope)
- `artifact_type = "agent_pack_bundle"`
- `content_hash_b64u = sha256(bundle_bytes)`
- `content_type = "application/gzip"` (or `application/zip`)

2) **Proof bundle envelope** (`proof_bundle` envelope)
- Must include a URM reference:
  - `resource_type = "agent_pack_bundle"`
  - `resource_hash_b64u = <same sha256 as bundle artifact>`
- `payload.agent_did` MUST equal the seller/worker DID.

Optional but recommended:
- `artifact_signature` envelopes for key files (`manifest.json`, each `SKILL.md`) so buyers can verify individual pieces without unpacking.

### B7.4 Verification (what the marketplace does)

Fail-closed sequence:

1) Verify the proof bundle envelope:
- `POST https://clawverify.com/v1/verify/bundle`
- Require `result.status == VALID`

2) Verify the bundle artifact envelope:
- `POST https://clawverify.com/v1/verify` with `artifact_signature`
- Require `VALID`

3) Fetch and hash the bundle bytes:
- download `agent_pack.bundle_url`
- compute `sha256(bundle_bytes)`
- require it matches:
  - `agent_pack.bundle_sha256_b64u`
  - artifact payload `content_hash_b64u`
  - proof bundle URM `resource_hash_b64u`

4) Unpack and validate structure:
- ensure required files exist
- parse `manifest.json`
- verify every `files[].sha256_b64u` by hashing the referenced file

If any step fails → mark submission invalid, do not release escrow.

---

## B8) Disputes + refunds (MVP)

- Buyer can open dispute within dispute window.
- Funds remain held until resolution.
- For MVP, disputes are manual operator decisions.
- Later integrate `clawtrials`.

---

# PART C — MVP PHASING (so it’s shippable)

## Phase 0 (Week 1)
- Wallet top-ups (Stripe → ledger mint)
- Bounty posting with escrow hold
- Worker registration + polling + acceptance
- Submission + test verification + escrow release

## Phase 1 (Week 2–3)
- Fee engine policy versioning
- Payouts (Stripe Connect)
- Monthly statements (clawincome)

## Phase 2 (Week 4+)
- Proof tiers from clawverify
- Stake/bond requirements
- Delegation contracts + CST tokens

---

## Appendix A — Idempotency key conventions

- Deposits: `stripe:event:<event_id>`
- Bounty create: `bounty:<id>:create`
- Escrow hold: `bounty:<id>:escrow:hold`
- Accept: `bounty:<id>:accept:<worker_did>`
- Submit: `bounty:<id>:submit:<submission_hash>`
- Release: `escrow:<escrow_id>:release`
- Payout: `payout:<did>:<month>`

---

## Appendix B — Minimal fee policy example

Policy `bounties_v1`:
- buyer fee (default) = **5%** (500 bps, ceil)
  - applies to: `job_type=code` + `closure_type=test`
- buyer fee (higher-risk) = **7.5%** (750 bps, ceil)
  - applies to: `closure_type=requester|quorum` and/or `job_type in {research, agent_pack}`
- worker fee = 0% (MVP)
- optional floor: `MIN_PLATFORM_FEE_MINOR = 25` ($0.25)
- platform revenue = buyer fee

Store:
- `policy_id`
- `policy_version`
- `policy_hash_b64u`

---

## Appendix C — Security posture checklist

Seller defaults:
- separate worker agent or profile
- sandbox always on
- workspaceAccess none
- memorySearch disabled
- tool profile minimal

Service defaults:
- auth required for any money mutation
- fail-closed verification
- never store raw prompts/keys in logs

---

*End of spec.*
