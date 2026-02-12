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
- **Tool receipts** (PLANNED): tool dispatcher boundary (tool name + args/result digests)
- **Side-effect receipts** (PLANNED): network egress, filesystem writes, external API writes
- **Human approval receipts** (PLANNED): approval boundary that mints new capability

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

**Current Claw Bureau public truth (2026-02-12):** Coverage M is shipped; MT/MTS are planned.

---

## 3) Deterministic failure semantics (protocol)

### 3.1 Denial and error codes
All protocol components MUST return deterministic, machine-readable codes (examples):
- `DENIED_POLICY` (policy rule violation)
- `DENIED_SCOPE` (capability scope insufficient)
- `DEPENDENCY_NOT_CONFIGURED` (fail-closed allowlist/governance missing)
- `REPLAY_DETECTED` (idempotency / binding replay)
- `INVALID_SIGNATURE`
- `INVALID_SCHEMA`

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

---

## 5) Reference implementations and openness

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
