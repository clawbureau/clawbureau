> **Type:** Reference
> **Status:** CANONICAL
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-18
> **Source of truth:** Git history + `docs/roadmaps/clawsig-protocol/prd.json` + `docs/roadmaps/clawsig-protocol-v0.2/prd.json`

# Clawsig Protocol — Changelog

## v0.2.0 (2026-02-18)

**Deterministic verifier expansion release.** Adds co-signatures, selective disclosure, temporal TTL semantics, aggregate fleet verification, and offline rate-limit abuse detection.

### Shipped stories (5/5)

- **CPL-V2-001** — Protocol-level rate limiting semantics
- **CPL-V2-002** — Multi-party receipt co-signing
- **CPL-V2-003** — Receipt expiry / TTL semantics
- **CPL-V2-004** — Selective disclosure for tool receipt arguments
- **CPL-V2-005** — Aggregate proof bundles (bundle-of-bundles)

### Schema deltas (additive)

- Added:
  - `selective_disclosure.v1.json`
  - `co_signature.v1.json`
  - `tool_receipt.v2.json` + `tool_receipt_envelope.v2.json`
  - `aggregate_bundle.v1.json` + `aggregate_bundle_envelope.v1.json`
- Extended existing payload/envelope schemas without breaking v1:
  - `proof_bundle.v1.json`
    - tool receipt union handling (v1/v2 payload+envelope set)
    - `rate_limit_claims[]`
  - envelope TTL support (`expires_at`) across proof/export/receipt paths

### Verifier/runtime behavior

- Proof bundle verification now fail-closes on:
  - co-signature failure (`CO_SIGNATURE_INVALID`)
  - selective-disclosure type/root issues (`DISCLOSURE_TYPE_MISMATCH`, `DISCLOSURE_ROOT_MISMATCH`)
  - deterministic rate-limit violations (`RATE_LIMIT_WINDOW_INVALID`, `RATE_LIMIT_CLAIM_INCONSISTENT`, `RATE_LIMIT_EXCEEDED`)
- Export/aggregate verification includes:
  - deterministic temporal guards (`EXPIRED_TTL`, `CAUSAL_CLOCK_CONTRADICTION`, `FUTURE_TIMESTAMP_POISONING`)
  - strict aggregate member and fleet invariants (`AGGREGATE_*`, `FLEET_SUMMARY_MISMATCH`, `IDENTITY_CONFLICT`)
  - aggregate member strict-liability cascade (`AGGREGATE_MEMBER_INVALID`)

### Conformance and CI

- Added executable R48/R49 vector corpus and `kind: aggregate_bundle` runner mapping.
- Added CPL-V2-001 vector corpus under:
  - `packages/schema/fixtures/protocol-conformance/cpl-v2-rate-limit/`
- Cross-platform protocol verification suite expanded accordingly (node + bun + deno-capable harness).

### Merge evidence

- PR #281 → `a936c099814802df68e810d974d03017f39fd497`
- PR #282 → `4199b2b80ea5e1993e9063b8408dd81b90757e74`
- PR #283 → `7c81b6c45cf1a59fbcf157e99940ce4c09ffa4c5`
- PR #285 → `1b21d0cdb562e02347304451cc6edd137a5b99d2`

## v0.1.0 (2026-02-12)

**Initial release.** Coverage MTS — model calls, tool receipts, side-effect receipts, human approvals, capability negotiation, and offline verification.

### Primitives

5 protocol primitives defined:
1. **Gateway receipt** — LLM call proof (model, tokens, timing, signer DID)
2. **Tool receipt** — hash-only tool invocation record (args digest, result digest, duration)
3. **Side-effect receipt** — hash-only external effect record (3 classes: `network_egress`, `filesystem_write`, `external_api_write`)
4. **Human approval receipt** — approval/denial decision with capability minting (4 types: `explicit_approve`, `explicit_deny`, `auto_approve`, `timeout_deny`)
5. **Proof bundle** — signed envelope containing event chain + all receipts

### Schemas (8)

- `packages/schema/poh/gateway_receipt.v1.json` + envelope
- `packages/schema/poh/tool_receipt.v1.json` + envelope
- `packages/schema/poh/side_effect_receipt.v1.json` + envelope
- `packages/schema/poh/human_approval_receipt.v1.json` + envelope
- `packages/schema/poh/capability_request.v1.json`
- `packages/schema/poh/capability_response.v1.json`

### Conformance

- 22 test vectors across all artifact types
- Runner: `scripts/protocol/run-clawsig-protocol-conformance.mjs`
- Manifest: `packages/schema/fixtures/protocol-conformance/manifest.v1.json`

### Verification

- Offline verifier CLI: `@clawbureau/clawverify-cli`
- Verification core: `@clawbureau/clawverify-core`
- 400+ registered reason codes in `REASON_CODE_REGISTRY.md`
- Fail-closed on unknown versions, algorithms, envelope formats

### Coverage

- **M** — model identity (gateway receipts)
- **MT** — model + tools (tool receipts)
- **MTS** — model + tools + side-effects + human approvals

### Identity

- Agent identity: `did:key` (Ed25519) for signing
- Human approvers: pluggable (DID, OIDC, email, service account, GitHub)
- BYO identity: no DID migration required for human subjects

### Supply chain

- Claw Verified requirements defined (version pin + receipt emission + verification)
- Tool manifest signing (Ed25519 + JCS)
- Quarantine mode for unverified tools

### CI/CD

- Claw Verified PR pipeline (`clawsig-verified-pr.yml`)
- Protocol conformance CI (`clawsig-protocol-conformance.yml`)
- Observe + enforce modes

### SDK

- `@clawbureau/clawsig-sdk`: `createClawsigRun()`, `callLLM()`, `recordToolCall()`, `recordSideEffect()`, `recordHumanApproval()`, `finalize()`

### Tracker

All 12 CPL stories passed:
- CPL-US-001 through CPL-US-012 → `passes=true`
- Epics: CPL-MAX-001 (coverage expansion), CPL-MAX-002 (side-effects + human approval)
