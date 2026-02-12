> **Type:** Spec
> **Status:** ACTIVE
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-07
> **Source of truth:** PoH roadmap + schemas under `packages/schema/poh/*`
>
> **Scope:**
> - PoH adapter spec v1 (draft, but implementation-aligned).

# Proof-of-Harness Adapter Spec v1 (PoH)

**Status:** Draft (roadmap)

This spec defines how *execution harnesses* (OpenClaw, Pi, Claude Code, Codex, opencode, Factory Droid, ad-hoc scripts) emit a **verifiable Proof Bundle** that the Claw Bureau marketplace can use to:

- verify **what was run**, **where**, and **by whom** (agent DID)
- bind work outputs to **tamper-evident run logs** (event chain)
- bind model usage to **gateway receipts** (clawproxy receipts)
- derive a deterministic **proof tier** (`self | gateway | sandbox`) for automation (stakes, auto-approval eligibility)

This spec is intentionally pragmatic: it describes a path from today’s codebase to a coherent PoH system.

---

## 0) Glossary

- **Agent**: the logical worker identity, represented by a DID (initially `did:key` Ed25519).
- **Harness**: the runtime that executed the agent (OpenClaw gateway, Pi, Claude Code, Codex, etc.).
- **Run**: a single bounded execution attempt of a job (e.g. one bounty submission).
- **Run ID**: unique identifier used to correlate events and receipts.
- **Event Chain**: a hash-linked log of events for the run.
- **Gateway Receipt**: a signed record of an LLM call routed through a trusted proxy (clawproxy).
- **Proof Bundle**: an agent-signed envelope that packages URM reference + event chain + receipts + attestations.
- **URM**: Universal Run Manifest (the canonical manifest of inputs/outputs/config).

---

## 1) Goals / Non-goals

### Goals

1. **Cross-harness compatibility**: a verifier can treat OpenClaw vs Codex vs Pi runs uniformly.
2. **Deterministic verification**: verification is fail-closed; unknown schema/version/algo rejected.
3. **Receipt chaining**: receipts are cryptographically bound to a specific run and specific event.
4. **Tamper-evident logs**: event chain breaks if events are modified, removed, or reordered.
5. **Upgradeable trust tiers**: allow incremental hardening from `self` → `gateway` → `sandbox`.

### Non-goals (v1)

- Perfect confidentiality without TEEs.
- Proving that closed-provider inference used a specific weight set (for OpenAI/Anthropic/Gemini APIs we can only prove what the gateway observed and signed: model label + request/response hashes).
- Proving “the model’s internal reasoning.”
- Proving that a harness binary has not been modified (that requires remote attestation / reproducible builds / TEEs).

---

## 2) Trust tiers (how the marketplace should reason)

These tiers are marketplace-facing policy levels.

- **`self`**: agent-signed proofs only; no third-party receipts/attestations.
- **`gateway`**: includes ≥1 valid gateway receipt bound to the run and to specific events.
- **`sandbox`**: includes a verifiable execution attestation from an allowlisted sandbox (e.g. future `clawea`).

**Important:** harness metadata is useful for auditability, but **must not** be treated as a trust tier on its own.

**vNext note (model identity is a separate axis):** PoH tiers describe *execution provenance* (self/gateway/sandbox). They do **not** imply that a closed-provider API call used a specific weight set. Verifiers should return a **trust vector**:
- `poh_tier`: `self | gateway | sandbox`
- `model_identity_tier`: what we can claim about the model (defaults to `closed_opaque` for closed providers)

---

## 3) Canonical objects

### 3.1 Run ID

A Run ID MUST be globally unique.

Recommended format:

- `run_<base64url(16-32 random bytes)>` or `run_<uuidv4>`

A run ID MUST be included in:

- every event in the event chain (`event.run_id`)
- every receipt binding (`receipt.binding.run_id`)
- the URM (manifest)

### 3.2 Harness metadata

Harness metadata MUST be emitted and MUST be stable within a run.

Recommended shape:

```json
{
  "harness": {
    "id": "openclaw|pi|claude-code|codex|opencode|factory-droid|script",
    "version": "x.y.z",
    "runtime": "host|docker|clawea|tee",
    "config_hash_b64u": "..."
  }
}
```

Notes:

- `config_hash_b64u` should be the SHA-256 hash of the harness configuration inputs that materially affect execution.
- For OpenClaw this likely includes:
  - OpenClaw version/commit
  - agent config subset (sandbox/tool policy/model routing)
  - enabled plugin versions (especially provider/tool plugins that affect networking)

---

## 4) Event chain

### 4.1 Event shape (logical)

Each event MUST include:

- `event_id` (unique within run)
- `run_id` (the run)
- `event_type` (string enum per harness)
- `timestamp` (ISO)
- `payload_hash_b64u` (hash of the external payload JSON/blob)
- `prev_hash_b64u` (null for first)
- `event_hash_b64u` (hash of the canonical event header)

### 4.2 Hashing rules

To make event chains actually tamper-evident, verifiers MUST be able to recompute `event_hash_b64u`.

**Canonical header for hashing** (v1):

```json
{
  "event_id": "...",
  "run_id": "...",
  "event_type": "...",
  "timestamp": "...",
  "payload_hash_b64u": "...",
  "prev_hash_b64u": "..."
}
```

Hash algorithm: **SHA-256**

Encoding: **base64url**

Canonical JSON: RFC 8785 (JCS) is preferred. If unavailable, a deterministic stable stringify is acceptable only if both producer and verifier match.

**POH-US-020 (pre-hash redaction):** harnesses SHOULD redact secrets/PII in event payloads **before** computing `payload_hash_b64u`.

- This prevents “toxic proofs” where credentials end up embedded in immutable hashes (and later leak via materialization/debug tooling).
- Redaction MUST be deterministic and stable within a harness version.
- Redaction does **not** uplift trust tiers; it is a safety measure.

### 4.3 Required event types (minimum)

A harness MUST be able to emit at least:

- `run_start`
- `llm_call`
- `tool_call` (or `tool_exec`)
- `artifact_written` (for outputs)
- `run_end`

The exact event payloads can be harness-specific; only the **payload hash** must be referenced from the chain.

---

## 5) Gateway receipts (clawproxy)

### 5.1 Binding headers

When the harness routes an LLM call through clawproxy, it SHOULD provide these HTTP headers to bind the resulting receipt to the run and event chain:

| Header | Binding field | Description |
|--------|--------------|-------------|
| `X-Run-Id` | `run_id` | Run identifier — correlates all receipts in a single agent run |
| `X-Event-Hash` | `event_hash_b64u` | Base64url hash of the event-chain entry that triggered this LLM call |
| `X-Idempotency-Key` | `nonce` | Unique nonce to prevent duplicate receipt issuance (5-min TTL) |

The proxy additionally injects two server-side binding fields:

| Binding field | Source | Description |
|--------------|--------|-------------|
| `policy_hash` | Work Policy Contract | Hash of the enforced WPC (when a policy header is provided) |
| `token_scope_hash_b64u` | Scoped Token (CST) | Hash of the CST claims (when a scoped token is validated) |

All binding fields are embedded in the signed receipt payload and are **tamper-proof** — any modification breaks the Ed25519 signature.

**token_scope_hash_b64u (v1):** deterministic scope hash computed by the CST issuer as:
- `token_scope_hash_b64u = sha256_b64u(JCS({token_version, sub, aud[], scope[], owner_ref?, policy_hash_b64u?, spend_cap?, mission_id?}))`
- `aud` and `scope` MUST be normalized as sorted unique arrays
- `iat/exp/jti/nonce` MUST be excluded so re-issuance yields the same scope hash.

**Schema reference:** `packages/schema/poh/receipt_binding.v1.json`

**Implementation:** `services/clawproxy/src/idempotency.ts` (extraction) and `services/clawproxy/src/receipt.ts` (embedding + signing).

### 5.2 Receipt verification

Receipts MUST be verifiable by an allowlisted verification method:

- either `clawverify /v1/verify/receipt` (preferred long-term)
- or `clawproxy /v1/verify-receipt` (current implementation)

### 5.3 Canonical receipt envelope (resolved)

This gap is now closed (POH-US-009 + POH-US-010):

- `clawproxy` emits a canonical `_receipt_envelope` as `SignedEnvelope<GatewayReceiptPayload>` (schema-aligned).
  - It may also return a legacy `_receipt` object for backwards compatibility.
  - Receipt signer DID is `did:key` derived from the `PROXY_SIGNING_KEY` public key (see `GET /v1/did`).
- `clawverify` verifies receipts **fail-closed** against an allowlist of trusted gateway signer DIDs (`GATEWAY_RECEIPT_SIGNER_DIDS`).
- When verifying a proof bundle, `clawverify` only counts gateway receipts toward `gateway` tier when they are:
  1) signature-valid, **and**
  2) bound to the bundle’s event chain via `binding.run_id` + `binding.event_hash_b64u`.

Therefore, marketplaces can safely derive `gateway` tier from proof bundles as long as:
- the receipt signer allowlist is configured, and
- the proof bundle includes a valid event chain that the receipts bind to.

### 5.4 Model identity (vNext, enterprise-safe)

PoH receipts prove *what the gateway observed and signed*. For closed providers, that cannot include weight hashes.

To avoid over-claiming, the gateway SHOULD attach an explicit, tiered **Model Identity** object to each canonical gateway receipt.

- **Schema:** `packages/schema/poh/model_identity.v1.json`
- **Attachment point:** `gateway_receipt.payload.metadata.model_identity`
- **Stable identifier:** `gateway_receipt.payload.metadata.model_identity_hash_b64u = sha256_b64u(JCS(model_identity))`

Recommended tiers (orthogonal to PoH tier):
- `closed_opaque` — provider/model label only (default for OpenAI/Anthropic/Gemini APIs)
- `closed_provider_manifest` — provider supplies a signed/attested build manifest reference
- `openweights_hashable` — self-hosted/openweights: weights/tokenizer/config are content-addressed by hashes
- `tee_measured` — TEE evidence binds image/code/config/weights root to execution

**Rule:** `poh_tier=gateway` + `model_identity_tier=closed_opaque` is the normal closed-provider posture.

Audit binding (vNext):
- Receipts and proof bundles MAY carry `audit_result_refs[]` referencing `audit_result_attestation.v1` objects (content-addressed, optionally anchored in `clawlogs`).

---

## 6) URM (Universal Run Manifest)

### 6.1 What URM is

URM is the canonical manifest that ties together:

- identity: agent DID
- harness metadata + config hash
- inputs: bounty spec, repository state, prompt inputs
- outputs: patches/artifacts, test results
- event chain root
- receipts list / receipt root

### 6.2 v1 integration with existing ProofBundlePayload

`clawverify`’s `ProofBundlePayload` currently supports only a **URM reference**:

```ts
interface URMReference {
  urm_version: '1';
  urm_id: string;
  resource_type: string;
  resource_hash_b64u: string;
  metadata?: Record<string, unknown>;
}
```

So v1 adapters should:

1. generate a URM JSON document (new schema we will add in `packages/schema/poh/urm.v1.json`)
2. store the URM as an artifact (inline, file, or uploaded)
3. compute `resource_hash_b64u = sha256_b64u(urm_json_bytes)`
4. include a `URMReference` in the proof bundle

**POH-US-015 (URM materialization):** to make URM references meaningful, verifiers MUST hash-verify the URM bytes.

`clawverify` supports this by accepting the materialized URM document alongside the proof bundle envelope:

```json
{
  "envelope": { "...": "..." },
  "urm": { "...": "..." }
}
```

Fail closed: if the proof bundle contains `payload.urm` but the request does not provide `urm`, `clawverify` returns `INVALID` with error code `URM_MISSING`.

**OCL-US-004 (Trust Pulse, non-tier):** harnesses MAY emit a small, redacted, self-reported “trust pulse” artifact (tools used + relative file touches) for UX.

- Schema: `packages/schema/poh/trust_pulse.v1.json`
- Pointer location: `URM.metadata.trust_pulse = { schema, artifact_hash_b64u, evidence_class: "self_reported", tier_uplift: false }`
- Guardrails:
  - MUST NOT affect `proof_tier` computation.
  - MUST NOT include absolute paths or `..` traversal segments.
  - MUST remain within verifier metadata size limits.

---

## 7) Proof bundle

### 7.1 Envelope

The proof bundle MUST be a `SignedEnvelope` with:

- `envelope_type = proof_bundle`
- `signer_did = agent_did`
- `payload_hash_b64u` matching the canonical payload

This is already implemented (as types + verifier) in `services/clawverify`.

### 7.2 Payload

`services/clawverify/src/types.ts` defines:

```ts
interface ProofBundlePayload {
  bundle_version: '1'
  bundle_id: string
  agent_did: string
  urm?: URMReference
  event_chain?: EventChainEntry[]
  receipts?: SignedEnvelope<GatewayReceiptPayload>[]
  attestations?: AttestationReference[]
  metadata?: ProofBundleMetadata
}

interface ProofBundleMetadata {
  harness?: HarnessMetadata
  [key: string]: unknown
}
```

Each `GatewayReceiptPayload` inside `receipts` may carry a `binding` field:

```ts
interface GatewayReceiptPayload {
  // ... existing fields ...
  binding?: ReceiptBinding  // run_id, event_hash_b64u, nonce, policy_hash, token_scope_hash_b64u
}
```

v1 adapters SHOULD populate:

- `metadata.harness` (see §3.2) — identifies the runtime that produced the bundle
- `urm`
- `event_chain`
- `receipts` when available — each receipt SHOULD contain `binding.run_id` and `binding.event_hash_b64u` for traceability

### 7.3 Attestations (signature + allowlist)

`ProofBundlePayload.attestations` is an array of `AttestationReference` objects.

**Important security rule:** attestations MUST NOT uplift trust tiers unless they are:
- cryptographically signature-verified, **and**
- signed by an **allowlisted** attester DID.

**Signature rule (v1):**
- `attester_did` MUST be a `did:key` encoding an Ed25519 public key.
- Signed bytes are the UTF-8 bytes of **RFC 8785 JCS canonicalization** of the attestation object with:
  - `signature_b64u` set to the empty string (`""`) during canonicalization.
- `signature_b64u` is the Ed25519 signature over those canonical bytes, encoded as **base64url**.

**Binding rule (v1):**
- `subject_did` MUST equal the proof bundle `agent_did` (the attestation is about this agent/run).

**Verifier config (clawverify):**
- `ATTESTATION_SIGNER_DIDS` — comma-separated allowlist of trusted attester DIDs.

---

## 8) Execution attestations (future, but plan now)

To reach `sandbox` tier we need an **execution attestation** format signed by an allowlisted authority.

Candidates:

- `clawea` (Cloudflare sandbox attester)
- TEEs (future)

**Schema:** `packages/schema/poh/execution_attestation.v1.json`

Execution attestations can be included either:

- as an attestation envelope referenced from `ProofBundlePayload.attestations`, or
- as a dedicated `SignedEnvelope` embedded in the proof bundle metadata (or URM metadata).

vNext hardening guidance (enterprise / clawea):
- include container image digest, sandbox runtime version, enforced WPC hash/network posture summary, and resource limits in `runtime_metadata`
- anchor the attestation hash in `clawlogs` and (optionally) include an inclusion proof

---

## 9) Harness adapter implementations

For the up-to-date harness list + per-harness operational best practices, see:
- `HARNESS_REGISTRY.md`

### 9.1 OpenClaw (reference)

Recommended components (aligns with `docs/integration/OPENCLAW_INTEGRATION.md` and `docs/openclaw/10.4-claw-marketplace-integration.md`):

1. **Provider plugin** that routes model calls through `clawproxy`.
2. **Recorder tool plugin** that:
   - allocates `run_id`
   - emits event chain entries for:
     - tool calls (`exec`, `read`, `write`, etc.)
     - model calls (and stores receipts)
   - generates URM
   - assembles + signs proof bundle

OpenClaw already has:

- sandbox + tool policy layers (`docs/openclaw/6.2-tool-security-and-sandboxing.md`)
- run identifiers (`EmbeddedRunAttemptParams.runId` in openclaw runtime)

### 9.2 Pi (pi-coding-agent)

Implement a wrapper/runner that:

- routes LLM calls via clawproxy (provider base URL override)
- records tool calls (read/write/edit/bash)
- emits event chain + URM
- signs proof bundle

### 9.3 Claude Code / Codex / opencode / Factory Droid

Depending on what logs the harness exposes:

- best: parse structured tool-call logs to generate event chain
- fallback: generate minimal event chain with only LLM call events + receipts

All harnesses should be able to route model calls via clawproxy using base URL overrides.

### 9.4 Ad-hoc scripts (SDK)

Provide a small SDK (`clawsig`) to:

- open a run
- record events
- route LLM calls via clawproxy with binding headers
- close run and emit URM/proof bundle

---

## 10) Verification responsibilities (clawverify)

A verifier MUST:

- validate envelope allowlist (version/type/algo/hash)
- verify proof bundle signature
- verify receipts (SignedEnvelope<GatewayReceiptPayload> from allowlisted gateway signer DIDs)
- recompute event hashes and enforce linkage
- compute trust tier deterministically

Current gap: `verify-proof-bundle.ts` checks linkage but does not recompute `event_hash_b64u` from event headers.

---

## 11) Roadmap mapping

Primary trackers:
- `docs/roadmaps/proof-of-harness/prd.json`
- `docs/roadmaps/proof-of-harness/ROADMAP_vNext.md`

High-level mapping:
- **POH-US-001..012**: PoH v1 (adapters, schemas, canonical receipts, harness shims/registry)
- **POHVN-US-001..008**: PoH vNext (model identity axis, derivation/audit attestations, clawlogs inclusion proofs, WPC hooks, hardened sandbox attestations, future TEE path)

---

## 12) Open questions / decisions to make

### Resolved (PoH v1)

- **Receipt envelope format + DID method**: resolved by POH-US-009.
  - `clawproxy` emits canonical `_receipt_envelope` as `SignedEnvelope<GatewayReceiptPayload>`.
  - Receipts are signed by a `did:key` derived from `PROXY_SIGNING_KEY` (see `GET /v1/did`).

- **Streaming support for external harness shims**: resolved by POH-US-019.
  - `clawproxy` streams `text/event-stream` responses for `stream:true` requests and computes response hashes incrementally.
  - Receipts are delivered via deterministic SSE comment trailers and persisted via nonce idempotency; shims can recover receipts via `GET /v1/receipt/:nonce` (no full-body replay).
  - The local shim forwards SSE without buffering, strips the receipt trailers from the harness-facing stream, and captures `_receipt_envelope` for proof bundles.

- **Event hash recomputation in clawverify**: resolved by CVF-US-021.
  - `clawverify` recomputes `event_hash_b64u` for all events and rejects mismatches (fail-closed).

### Resolved (PoH vNext)

- **Audit pack standardization (Phase 0)**: resolved via deterministic pack hashing.
  - See ADR: `docs/foundations/decisions/0001-audit-pack-convention.md`.

### Still open (PoH vNext)

1) **Canonical JSON / hashing rules beyond PoH**
- Adopt RFC 8785 everywhere (recommended)
- Or define per-object stable stringify rules

2) **Provider manifests for closed providers**
- What evidence do we accept for `closed_provider_manifest` (headers vs signed blobs vs dedicated endpoints)?
- What DID method(s) do we allow for provider signatures (`did:web` with DID-doc fetch vs `did:key` only)?

3) **clawlogs inclusion proof API details**
- Exact leaf hashing rules + Merkle root cadence (daily vs hourly)
- Root discovery + inclusion proof API surface

4) **Execution attestation authority**
- clawea design and key distribution

5) **Execution attestation placement**
- Reference via `proof_bundle.attestations[]` vs embed full envelope(s) in proof bundle / URM metadata

6) **Statelessness semantics**
- What can we realistically enforce/attest in clawea sandbox runs vs future TEE runs?

---
