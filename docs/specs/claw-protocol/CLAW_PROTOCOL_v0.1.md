> **Type:** Spec
> **Status:** DRAFT
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-12
> **Source of truth:** this spec + referenced schemas (`packages/schema/**`) + verifier behavior (`services/clawverify/**`)
>
> **Scope:**
> - Define the **narrow waist** for the “Claw Protocol”: a tiny set of primitives that can be implemented by third parties.
> - Make verification **deterministic, offline-capable, and fail-closed**.
> - Make coverage claims explicit (no hand-wavy “every action attested”).

# Claw Protocol v0.1 — Narrow Waist

## 0) Goal

Claw becomes “the protocol” (not just a vendor suite) by shipping:

1) **Lowest friction**: progressive adoption (observe → receipt → enforce) and one-click governance.
2) **Highest trust**: deterministic verification, explicit coverage, and fail-closed semantics.

This spec intentionally treats higher-level systems (marketplace, escrow, ledger, UI) as **optional modules**.

---

## 1) The narrow waist (5 primitives)

The protocol defines **five composable primitives**. Everything else must be expressed as combinations of these.

### 1.1 Policy Artifact (WPC)
A signed, immutable, content-addressed policy contract.

- **Reference schema:** `packages/schema/policy/work_policy_contract.v1.json`
- **Envelope:** `packages/schema/policy/work_policy_contract_envelope.v1.json`
- **Registry service (optional reference impl):** `clawcontrols` (see `docs/prds/clawcontrols.md`)

**Required properties (protocol):**
- **Signed** by an allowlisted DID (governance-controlled).
- **Immutable** once published; updates require a new policy artifact.
- **Content-addressed**: `policy_hash_b64u = sha256_b64u(JCS(payload))`.

### 1.2 Capability Token (CST)
A short-lived capability token that is job-bound, scope-hashed, and optionally policy-pinned.

- **Reference schema:** `packages/schema/auth/scoped_token_claims.v1.json`
- **Issuer service (optional reference impl):** `clawscope` (see `docs/prds/clawscope.md`)

**Required properties (protocol):**
- **Short TTL** (policy-enforced).
- **Scope hash** derived deterministically from claims.
- **Optional policy pin**: capability can be bound to an exact `policy_hash_b64u`.
- **Offline-verifiable** where safe (JWKS) and revocation-aware where required.

### 1.3 Receipt
A signed event emitted at an **enforcement boundary**, not a “log”.

A receipt is the unit that makes runs verifiable without reconstructing internal logs.

**Receipt classes (protocol):**
- **Model gateway receipts** (SHIPPED reference impl):
  - Schema: `packages/schema/poh/gateway_receipt.v1.json`
  - Emitted by: `clawproxy` (see `docs/prds/clawproxy.md`)
- **Witnessed web receipts** (SHIPPED reference impl):
  - Schema: `packages/schema/poh/web_receipt.v1.json`
  - Emitted by: witness harnesses / web control planes
- **Tool receipts** (SHIPPED):
  - Schema: `packages/schema/poh/tool_receipt.v1.json`
  - Envelope: `packages/schema/poh/tool_receipt_envelope.v1.json`
  - SDK: `packages/clawproof-sdk` `ClawproofRun.recordToolCall()`
  - Emitted by: tool dispatcher boundaries (hash-only by default)
- **Side-effect receipts** (SHIPPED):
  - Schema: `packages/schema/poh/side_effect_receipt.v1.json`
  - Envelope: `packages/schema/poh/side_effect_receipt_envelope.v1.json`
  - SDK: `packages/clawproof-sdk` `ClawproofRun.recordSideEffect()`
  - Classes: `network_egress`, `filesystem_write`, `external_api_write`
  - Includes: target digest, request/response digests, vendor ID, bytes written
- **Human approval receipts** (SHIPPED):
  - Schema: `packages/schema/poh/human_approval_receipt.v1.json`
  - Envelope: `packages/schema/poh/human_approval_receipt_envelope.v1.json`
  - SDK: `packages/clawproof-sdk` `ClawproofRun.recordHumanApproval()`
  - Approval mints CST bound to scope + optional WPC pin
  - Types: `explicit_approve`, `explicit_deny`, `auto_approve`, `timeout_deny`

**Binding requirements (protocol):**
- Receipts that claim to apply to a run MUST carry a `receipt_binding`:
  - Schema: `packages/schema/poh/receipt_binding.v1.json`
- Binding MUST include `{run_id, event_hash_b64u}` linkage to a proof bundle event chain.

### 1.4 Bundle
A portable handoff unit that packages receipts + metadata + references.

- **Proof bundle (PoH):** `packages/schema/poh/proof_bundle.v1.json`
- **Export bundle (offline audit):**
  - `packages/schema/poh/export_bundle.v1.json`
  - `packages/schema/poh/export_bundle_manifest.v1.json`

**Required properties (protocol):**
- Content-addressed manifest (hashes for every file).
- Signed top-level envelope.
- No ambient network required to verify (offline-capable verification).

### 1.5 Verifier
A deterministic PASS/FAIL engine that can run offline.

- **Reference service:** `clawverify` (see `docs/prds/clawverify.md`)

**Protocol contract:**
- Unknown schema/version/algorithm MUST fail closed.
- Verification results MUST include machine-readable reason codes.
- Verification SHOULD support:
  - online API (hosted verifier)
  - offline CLI/library (local verifier)

---

## 2) Coverage: “action attestation” MUST be explicit

### 2.1 Definition (protocol)
An **action** is any boundary that can cause side effects:
- model calls
- tool calls
- network egress
- filesystem writes
- external API writes
- human approvals that mint new capabilities

### 2.2 Coverage statement requirement
Any product claim like “every action attested” MUST declare its coverage.

**Coverage levels (recommended):**
- **Coverage M (Model):** model gateway receipts only
- **Coverage MT (Model + Tools):** model + tool receipts
- **Coverage MTS (Model + Tools + Side-effects):** model + tool + side-effect receipts

**Current Claw Bureau public truth (2026-02-12):** Coverage MTS shipped (model + tools + side-effects + human approvals).

### 2.3 Coverage matrix

| Boundary | Receipt class | Schema | Status | Verifier support |
|----------|--------------|--------|--------|-----------------|
| Model gateway calls | `gateway_receipt` | `poh/gateway_receipt.v1.json` | **SHIPPED** | Full (signature + binding) |
| Tool dispatcher calls | `tool_receipt` | `poh/tool_receipt.v1.json` | **SHIPPED** | Full (schema + signature) |
| Network egress | `side_effect_receipt` | `poh/side_effect_receipt.v1.json` | **SHIPPED** | Full (schema + binding) |
| Filesystem writes | `side_effect_receipt` | `poh/side_effect_receipt.v1.json` | **SHIPPED** | Full (schema + binding) |
| External API writes | `side_effect_receipt` | `poh/side_effect_receipt.v1.json` | **SHIPPED** | Full (schema + binding) |
| Human approvals | `human_approval_receipt` | `poh/human_approval_receipt.v1.json` | **SHIPPED** | Full (schema + binding) |
| Witnessed web events | `web_receipt` | `poh/web_receipt.v1.json` | **SHIPPED** | Partial (schema only) |

### 2.4 What is proven / what is not proven

**Claw Protocol proofs demonstrate:**
- An LLM call was made through a specific gateway with specific request/response hashes (model receipts)
- A tool was invoked with specific argument/result digests (tool receipts, hash-only by default)
- Events occurred in a specific order (hash-linked event chain)
- A specific agent DID signed the proof bundle
- A specific policy was in effect at time of execution (policy pin)
- A receipt was bound to a specific run (receipt binding)

**Claw Protocol proofs do NOT demonstrate:**
- The content of LLM prompts/responses (only hashes, unless selective disclosure is enabled)
- That the agent "intended" a specific outcome (proofs are execution traces, not intent proofs)
- That no other actions occurred outside the attested boundaries
- That the human operator reviewed every individual action (only that capability was granted)
- Real-time correctness (proofs are after-the-fact; receipts may have propagation delay)

---

### 2.5 Two-phase execution posture

The protocol recommends a **two-phase default** for agent execution:

**Phase A (plan/diff):** Always allowed. The agent reads, analyzes, and proposes changes. No side effects. No capability required beyond the base CST.

**Phase B (apply/execute):** Requires explicit capability. The agent executes side effects (write, deploy, send). A human approval receipt mints a new CST scoped to the approved actions.

This posture ensures:
- Agents can always "think" without governance friction
- Side effects require explicit, auditable authorization
- The approval moment is receipted and bound to the proof bundle

### 2.6 Capability negotiation

Agents can request capabilities before acting:

- **Request schema:** `packages/schema/poh/capability_request.v1.json`
- **Response schema:** `packages/schema/poh/capability_response.v1.json`

**Negotiation flow:**
1. Agent sends `CapabilityRequest` with `requested_scope.actions`, `reason`, and optional `plan_hash_b64u`
2. Authority responds with `CapabilityResponse`:
   - `granted`: capability minted, `granted_capability` included
   - `denied`: deterministic `reason_code` + per-action `denied_actions` with rule references
   - `requires_approval`: human review needed, `approval_channel` provided
   - `preflight_pass` / `preflight_fail`: dry-run compliance check (no capability minted)

**Preflight mode:** When `request.preflight = true`, the authority checks compliance without minting. This allows agents to self-check before requesting human approval, reducing friction.

---

## 3) Deterministic failure semantics (protocol)

### 3.1 Denial and error codes

All protocol components MUST return deterministic, machine-readable reason codes from the canonical registry:
`docs/specs/claw-protocol/REASON_CODE_REGISTRY.md`

Code categories include: `SIGNATURE_*`, `SCHEMA_*`, `UNKNOWN_*`, `HASH_*`, `INVALID_*`, `DEPENDENCY_*`, `REPLAY_*`, `TOKEN_*`, `POLICY_*`.

### 3.2 “Verify-lite” preflight
Clients (agents/tools) SHOULD be able to preflight:
- “Will this scope be allowed under policy X?”
- “What evidence will be required?”

---

## 4) Identity is pluggable

Protocol identity MUST be **bring-your-own**:
- enterprise: OIDC / SSO / service accounts
- agent ecosystems: DID works well, but MUST NOT be the only option

Claw Bureau services may use DID internally, but protocol integrations must not require ideological adoption.

### 4.1 Canonical subject representation

All protocol primitives that carry identity use a **subject** field. The canonical representation is:

| Identity provider | Subject format | Example |
|-------------------|---------------|---------|
| DID (default) | `did:key:z6Mk...` or `did:web:...` | `did:key:z6MktzmKpfCNcKSUp7qzTrZK3c89QFvhgmK7V1GXxMH9m8XW` |
| OIDC / SSO | `oidc:<issuer>:<sub>` | `oidc:accounts.google.com:1234567890` |
| Service account | `sa:<provider>:<id>` | `sa:aws:arn:aws:iam::123:role/agent` |
| Email (fallback) | `email:<address>` | `email:agent@corp.example.com` |
| GitHub | `github:<login>` | `github:agent-bot` |

### 4.2 Mapping rules

- **Receipts**: `agent_did` field MAY contain any canonical subject format, not just DIDs.
- **Envelopes**: `signer_did` MUST be a `did:key` for cryptographic verification. Non-DID identities bind via `approver_subject` in human approval receipts or via the `subject` claim in CSTs.
- **Capability tokens (CST)**: the `sub` claim uses canonical subject format. The `kid` references the signing key.
- **Verification**: when `signer_did` is a `did:key`, full Ed25519 verification applies. For non-DID subjects, verification degrades to signature-only (the subject binding is trusted, not cryptographically provable by the verifier alone).

### 4.3 Fail-closed behavior

- Unknown subject formats MUST NOT cause verification to crash — they should be treated as opaque identifiers.
- Signature verification always requires a `did:key` — there is no signature verification for OIDC/email subjects.
- Identity binding mismatches (e.g. receipt.agent_did ≠ bundle.agent_did) MUST fail closed regardless of identity provider.

---

## 5) Claw Verified supply-chain trust

### 5.1 Verified tool requirements

A tool qualifies as **Claw Verified** when it meets all of:

1. **Version pinning**: tool manifest declares exact version + content hash
2. **Receipt emission**: tool emits `tool_receipt` (or `side_effect_receipt`) on every invocation
3. **Verifiable receipts**: receipts pass offline verification (schema + agent DID binding)

### 5.2 Tool manifest signing

Tool authors SHOULD publish a signed manifest:

```json
{
  "manifest_version": "1",
  "tool_name": "bash",
  "tool_version": "5.2.26",
  "content_hash_b64u": "<SHA-256 of tool binary/source>",
  "receipt_classes": ["tool_receipt"],
  "signer_did": "did:key:z6Mk...",
  "signature_b64u": "<Ed25519 sig>"
}
```

Verification flow:
1. Resolve `signer_did` → Ed25519 public key
2. Verify `signature_b64u` over JCS-canonicalized manifest (with `signature_b64u: ""`)
3. Verify `content_hash_b64u` matches the installed tool artifact

### 5.3 Quarantine mode

Tools that **cannot** emit verifiable receipts run in quarantine:
- **Low privilege**: no side-effect capabilities granted by default
- **Default deny**: side-effect requests from quarantined tools return `CAPABILITY_DENIED` with `reason_code: TOOL_NOT_VERIFIED`
- **Observe-only**: tool calls are logged but receipts are marked `opaque` (hash-only, no signature)

This makes compliance easier than non-compliance: verified tools get capabilities; unverified tools don't.

### 5.4 Integration with skill/provider registries

Platform registries (skill stores, provider catalogs) SHOULD:
- Display "Claw Verified" badge for tools that meet §5.1 requirements
- Default to quarantine mode for unverified tools
- Allow enterprise policies to override quarantine (explicit allow-listing)

---

## 6) Reference implementations and openness

> **Note:** Section numbering changed — this was §5 in earlier drafts.

To be a protocol, the following MUST be public (reference implementations allowed, not required):
- receipt schemas + canonicalization rules
- verifier CLI + libraries
- conformance test vectors
- minimal policy and capability reference behavior
- a minimal tool receipt SDK for tool authors

Proprietary/paid layers can include:
- hosted viewers (Trust Pulse)
- fleet dashboards
- managed sandbox hosting
- enterprise connectors

---

## 6) Roadmap

Execution tracking for Claw Protocol lives in:
- `docs/roadmaps/claw-protocol/`
