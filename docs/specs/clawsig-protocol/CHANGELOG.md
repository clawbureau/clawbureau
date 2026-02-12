> **Type:** Reference
> **Status:** CANONICAL
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-12
> **Source of truth:** Git history + `docs/roadmaps/clawsig-protocol/prd.json`

# Clawsig Protocol — Changelog

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
