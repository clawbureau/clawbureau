# clawproxy.com (Gateway Receipts) — PRD

**Domain:** clawproxy.com  
**Pillar:** Infrastructure  
**Status:** Draft  

---

## 0) OpenClaw Fit (primary design target)
OpenClaw is the reference harness for Claw Bureau proof-of-harness.

`clawproxy` is designed to be consumed primarily as an OpenClaw **provider plugin** (provider slot), so that OpenClaw model traffic is proxied + receipted automatically (no “LLM manually calls HTTP proxy” patterns).

See: `docs/integration/OPENCLAW_INTEGRATION.md`.

---

## 1) Purpose
Gateway proxy that issues signed receipts for model calls (proof-of-harness). BYOK-friendly.

## 2) Target Users
- OpenClaw gateway operators (self-hosted)
- OpenClaw plugin authors (provider slot integration)
- Agents
- Platforms requiring receipts
- Auditors

## 3) MVP Scope
- POST /v1/proxy/<provider>
- Signed receipt with request/response hashes
- Receipt includes proxy DID + binding fields
- Provider routing (Anthropic/OpenAI/Google)
- WPC enforcement + redaction hooks
- Hash-only receipts (encrypted payload optional)
- Scoped token auth (CST)
- OpenClaw provider plugin reference implementation

## 4) Non-Goals (v0)
- Full billing system
- Provider-specific SDK replacement

## 5) Dependencies
- clawlogs.com (optional)
- clawverify.com (receipt verification)
- clawscope.com (scoped tokens)
- clawledger.com (platform-paid routing / settlement references)

## 6) Core User Journeys
- Agent routes call through proxy → gets receipt
- Marketplace verifies receipt → trust tier increases

## 7) User Stories

### CPX-US-001 — Proxy LLM requests with receipts
**As a** agent, **I want** my calls routed through clawproxy **so that** I get verifiable receipts.

**Acceptance Criteria:**
- Accept Authorization header API key
- Return provider response
- Attach _receipt with hashes

### CPX-US-002 — Ed25519 receipt signing
**As a** verifier, **I want** cryptographically signed receipts **so that** trust tiers are verifiable.

**Acceptance Criteria:**
- Sign receipts with proxy key
- Expose proxy DID + public key
- Fail closed if key missing

### CPX-US-003 — Provider endpoint allowlist
**As a** security engineer, **I want** no arbitrary endpoint proxying **so that** SSRF is prevented.

**Acceptance Criteria:**
- Only known provider endpoints allowed
- Reject unknown provider
- Log blocked attempts

### CPX-US-004 — Google/Gemini routing
**As a** agent, **I want** Gemini calls supported **so that** I can choose my provider.

**Acceptance Criteria:**
- Route to models/{model}:generateContent
- Include usage metadata
- Validate required model field

### CPX-US-005 — Receipt verification endpoint
**As a** platform, **I want** to validate receipts **so that** I can automate trust tiers.

**Acceptance Criteria:**
- Provide /v1/verify-receipt
- Validate signature
- Return provider/model claims

### CPX-US-006 — Rate limits and quotas
**As a** operator, **I want** to limit abuse **so that** proxy remains stable.

**Acceptance Criteria:**
- Rate limit by DID/IP
- Return 429 on limit
- Expose usage headers

### CPX-US-007 — Receipt binding fields
**As a** verifier, **I want** receipts bound to runs **so that** proofs are chainable.

**Acceptance Criteria:**
- Accept run_id and event_hash headers
- Embed binding fields in receipt
- Enforce idempotency for receipt issuance

### CPX-US-008 — Work Policy Contract enforcement
**As a** enterprise, **I want** policy enforcement **so that** confidential runs are safe.

**Acceptance Criteria:**
- Require policy_hash header in confidential mode
- Enforce provider/model allowlists from WPC
- Apply redaction/field stripping per WPC

### CPX-US-009 — Hash-only or encrypted receipts
**As a** privacy owner, **I want** hash-only receipts **so that** prompts are protected.

**Acceptance Criteria:**
- Default to hash-only receipt payloads
- Support encrypted payload receipts when enabled
- Never log plaintext prompts in confidential mode

### CPX-US-010 — Proxy DID endpoint
**As a** integrator, **I want** proxy DID metadata **so that** verification is easy.

**Acceptance Criteria:**
- GET /v1/did returns DID + public keys + kids
- Cacheable response
- Include deployment metadata

---

### CPX-US-011 — Scoped token authentication
**As a** platform, **I want** scoped tokens **so that** calls are user-bound and time-limited.

**Acceptance Criteria:**
- Require CST token for authenticated calls
- Validate audience + expiry + scope
- Log token hash with receipt

**Implementation notes (v1 guidance):**
- Prefer a single header name (pick one and document it): `Authorization: Bearer <token>` or `X-CST: <token>`.
- Fail-closed if a request is declared as user-bound (e.g. `X-Client-DID` present) but token missing/invalid.
- Token format should be consistent with `packages/schema/auth/scoped_token_claims.v1.json`.

### CPX-US-012 — Token/policy binding in receipts
**As a** verifier, **I want** receipts bound to policy **so that** authorization is provable.

**Acceptance Criteria:**
- Embed token_scope_hash in receipt
- Embed policy_hash (WPC) when present
- Fail closed if required binding fields missing

**Implementation notes (v1 guidance):**
- Receipt payload SHOULD include:
  - `token_scope_hash_b64u` (derived from token claims; deterministic)
  - `policy_hash_b64u` when WPC / confidential mode is enabled
- Fail-closed patterns:
  - if token is required for a request, but `token_scope_hash_b64u` cannot be computed → do not issue a receipt.
  - if confidential mode is enabled and `policy_hash_b64u` missing → do not issue a receipt.

### CPX-US-013 — Platform-paid inference mode
**As a** platform, **I want** a reserve-backed default **so that** users can start quickly.

**Acceptance Criteria:**
- Support platform-paid routing using reserve credits
- Mark receipts as paid/unpaid
- Record ledger reference for paid receipts

**Implementation notes (v1 guidance):**
- Introduce a request mode:
  - `X-Payment-Mode: byok|platform` (or query param) with **default = byok**.
- For `platform`:
  - proxy uses platform API keys (Gemini/FAL/etc)
  - receipt must include a deterministic `payment` section:
    - `mode: platform`
    - `reserve_provider: gemini|fal|...`
    - `ledger_ref` placeholder until ledger integration is live
- Fail-closed:
  - if payment mode is `platform` but platform key/reserve config missing → reject.

### CPX-US-014 — Public landing + skill docs
**As a** developer, **I want** public landing/docs/skill endpoints **so that** I can discover and integrate clawproxy quickly.

**Acceptance Criteria:**
- GET / returns a small HTML landing page with links to /docs and /skill.md
- GET /skill.md returns integration docs + example curl commands
- GET /robots.txt and /sitemap.xml exist (minimal)
- GET /.well-known/security.txt exists

### CPX-US-015 — OpenClaw provider plugin
**As an** OpenClaw operator, **I want** a provider plugin **so that** all model calls can route through clawproxy and produce receipts automatically.

**Acceptance Criteria:**
- Provide an OpenClaw **provider slot** plugin (TypeBox config schema)
- Support routing at least one provider end-to-end (Anthropic or OpenAI) through `POST /v1/proxy/<provider>`
- Attach receipt metadata to OpenClaw run logs (and optionally forward to clawlogs)
- Ensure token handling does not expose long-lived secrets to the LLM (plugin-owned secrets only)

## 8) Success Metrics
- Receipts issued/day
- Median proxy latency
- % signed receipts

---

*Generated for Claw Bureau monorepo. All PRDs follow a uniform structure for Ralph execution.*
