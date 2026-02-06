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
- Proving “the model’s internal reasoning.”
- Proving that a harness binary has not been modified (that requires remote attestation / reproducible builds / TEEs).

---

## 2) Trust tiers (how the marketplace should reason)

These tiers are marketplace-facing policy levels.

- **`self`**: agent-signed proofs only; no third-party receipts/attestations.
- **`gateway`**: includes ≥1 valid gateway receipt bound to the run and to specific events.
- **`sandbox`**: includes a verifiable execution attestation from an allowlisted sandbox (e.g. future `clawea`).

**Important:** harness metadata is useful for auditability, but **must not** be treated as a trust tier on its own.

---

## 3) Canonical objects

### 3.1 Run ID

A Run ID MUST be globally unique.

Recommended format:

- `run_<base64url(16-32 random bytes)>` or `run_<uuidv4>`

A run ID MUST be included in:

- every event in the event chain (`event.run_id`)
- every receipt binding (`receipt.binding.runId`)
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

**Schema reference:** `packages/schema/poh/receipt_binding.v1.json`

**Implementation:** `services/clawproxy/src/idempotency.ts` (extraction) and `services/clawproxy/src/receipt.ts` (embedding + signing).

### 5.2 Receipt verification

Receipts MUST be verifiable by an allowlisted verification method:

- either `clawverify /v1/verify/receipt` (preferred long-term)
- or `clawproxy /v1/verify-receipt` (current implementation)

### 5.3 Current gap (important)

**Today** there is a format mismatch:

- `clawproxy` currently emits a custom `Receipt` object (`services/clawproxy/src/types.ts`) signed by `did:web:clawproxy.com`.
- `clawverify`’s `verifyReceipt` expects a `SignedEnvelope<GatewayReceiptPayload>` whose signer DID is `did:key` (it extracts keys via `extractPublicKeyFromDidKey`).

We must pick one of these paths:

1. **Make clawproxy emit `SignedEnvelope<GatewayReceiptPayload>`** (and decide DID method: `did:key` or `did:web` with DID-doc fetch).
2. **Teach clawverify to verify the existing clawproxy receipt format**.

Until this is resolved, the marketplace cannot safely claim `gateway` tier from proof bundles alone.

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

---

## 8) Execution attestations (future, but plan now)

To reach `sandbox` tier we need an **execution attestation** format signed by an allowlisted authority.

Candidates:

- `clawea` (Cloudflare sandbox attester)
- TEEs (future)

We will add a schema placeholder (`execution_attestation.v1.json`) and include it either:

- as an attestation envelope referenced from `ProofBundlePayload.attestations`, or
- as a dedicated `SignedEnvelope` embedded in the proof bundle metadata.

---

## 9) Harness adapter implementations

### 9.1 OpenClaw (reference)

Recommended components (aligns with `docs/OPENCLAW_INTEGRATION.md` and `docs/openclaw/10.4-claw-marketplace-integration.md`):

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

Provide a small SDK (`clawproof`) to:

- open a run
- record events
- route LLM calls via clawproxy with binding headers
- close run and emit URM/proof bundle

---

## 10) Verification responsibilities (clawverify)

A verifier MUST:

- validate envelope allowlist (version/type/algo/hash)
- verify proof bundle signature
- verify receipts (once format is reconciled)
- recompute event hashes and enforce linkage
- compute trust tier deterministically

Current gap: `verify-proof-bundle.ts` checks linkage but does not recompute `event_hash_b64u` from event headers.

---

## 11) Roadmap mapping

This spec is implemented via `docs/roadmaps/proof-of-harness/prd.json`:

- **POH-US-001**: this doc
- **POH-US-002**: schemas
- **POH-US-003**: clawverify improvements
- **POH-US-004**: receipt binding + doc updates
- **POH-US-005/006**: OpenClaw plugins/recorder
- **POH-US-007/008**: external harness adapters + SDK

---

## 12) Open questions / decisions to make

1) **Receipt format unification**
- Do we migrate clawproxy to `SignedEnvelope<GatewayReceiptPayload>`?
- Or extend clawverify to accept clawproxy’s current receipt format?

2) **Proxy DID method**
- Keep `did:web:clawproxy.com` (requires DID-doc fetch to verify)
- Or switch to a `did:key` signer for receipts

3) **Canonical JSON**
- Adopt RFC 8785 everywhere (recommended)
- Or define per-object stable stringify rules

4) **Execution attestation authority**
- clawea design and key distribution

---
