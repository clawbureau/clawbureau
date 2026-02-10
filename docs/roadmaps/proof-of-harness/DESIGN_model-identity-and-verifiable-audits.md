> **Type:** Design
> **Status:** DRAFT
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-10
> **Source of truth:** PoH schemas (`packages/schema/poh/*`) + PoH roadmap (`docs/roadmaps/proof-of-harness/*`)
>
> **Scope:**
> - PoH vNext design: model identity as a separate axis + verifiable audit attestations.
> - Enterprise-safe semantics (closed-provider reality).

# PoH vNext Design — Model Identity + Verifiable Audits

This document translates the key ideas from “Attestable Audits” (arXiv:2506.23706) into **ClawBureau-native** primitives that fit the current ecosystem:

- OpenClaw is the reference harness.
- `clawproxy` is the default gateway for inference.
- Most enterprise inference uses **closed API providers** (OpenAI/Anthropic/Google).

The core design goal is to make claims **verifiable without over-claiming**.

Related:
- PoH v1 spec: `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`
- PoH vNext roadmap: `docs/roadmaps/proof-of-harness/ROADMAP_vNext.md`
- Phase 0 PR stack plan: `docs/roadmaps/proof-of-harness/PHASE0_PR_STACK.md`
- Audit pack convention (ADR): `docs/foundations/decisions/0001-audit-pack-convention.md`

---

## 0) Non-negotiable reality: closed providers can’t prove weights

For OpenAI/Anthropic/Google-style APIs:

- **Not provable**: the exact weight set, quantization, hidden system prompts, provider-side routing/state.
- **Provable (today)**: what **our gateway** (`clawproxy`) observed and signed:
  - provider/model label
  - request/response **hashes** (and optional encrypted payload)
  - usage/latency
  - binding context: `run_id`, `event_hash_b64u`, `policy_hash`, `token_scope_hash_b64u`

So we must encode these limits in our schemas and in marketplace semantics.

---

## 1) Trust becomes a vector (don’t overload PoH tiers)

We keep PoH tiers as the marketplace-facing execution provenance tiers:
- `self | gateway | sandbox` (existing)

We add an orthogonal axis:
- `model_identity_tier` — what can be claimed about the underlying model identity

Optionally later (Phase 1+) we may add a third axis:
- `audit_coverage` — what audits apply to a run/output

### 1.1 PoH tier (existing)
- **self**: agent-signed evidence only
- **gateway**: ≥1 valid `gateway_receipt` envelope bound to the bundle event chain
- **sandbox**: ≥1 allowlisted execution attestation (future: `clawea`)

### 1.2 Model identity tier (new)
Defined by `model_identity.v1`:
- `closed_opaque` — provider/model label only (default for closed-provider APIs)
- `closed_provider_manifest` — provider supplies a signed/attested build manifest reference
- `openweights_hashable` — self-hosted/openweights: weights/tokenizer/config are content-addressed by hashes
- `tee_measured` — TEE evidence binds measurements (image/code/config/weights root) to execution

**Rule:** `poh_tier=gateway` must not imply anything stronger than `model_identity_tier=closed_opaque`.

---

## 2) Minimal new primitives (Phase 0)

### 2.1 `model_identity.v1` (new PoH schema)
**Schema:** `packages/schema/poh/model_identity.v1.json`

**Attachment point (per-call):**
- `gateway_receipt.payload.metadata.model_identity`
- `gateway_receipt.payload.metadata.model_identity_hash_b64u = sha256_b64u(JCS(model_identity))`

### 2.2 `derivation_attestation.v1` (Prepare analogue)
**Schema:** `packages/schema/poh/derivation_attestation.v1.json`

Binds `input_model → output_model` under a declared transformation (quantize, fine-tune, merge, etc.).

### 2.3 `audit_result_attestation.v1` (Audit analogue)
**Schema:** `packages/schema/poh/audit_result_attestation.v1.json`

Binds an aggregated audit result to:
- model identity
- audit code hash
- dataset hash
- protocol/config hash
- optional `audit_pack.pack_hash_b64u` (Phase 0 convention; see ADR 0001)

### 2.4 `log_inclusion_proof.v1` (transparency anchoring)
**Schema:** `packages/schema/poh/log_inclusion_proof.v1.json`

Portable inclusion proofs for `clawlogs` Merkle roots.

---

## 3) How these bind into existing PoH objects

### 3.1 Receipts (`gateway_receipt`)
Receipts already sign an open `payload.metadata` object.

We standardize the following optional keys:
- `payload.metadata.model_identity`
- `payload.metadata.model_identity_hash_b64u`
- `payload.metadata.audit_result_refs[]` (hash+URI references)

### 3.2 Proof bundles (`proof_bundle`)
Proof bundles remain the canonical run evidence envelope.

We standardize optional run-level summaries via open metadata (non-breaking):
- `proof_bundle.payload.metadata.model_identity_summary`
- `proof_bundle.payload.metadata.audit_result_refs[]`

### 3.3 Execution attestations (`execution_attestation`)
Execution attestations remain the mechanism to make `sandbox` tier concrete.

Phase 1 hardening (clawea): populate `runtime_metadata` with:
- container image digest
- sandbox runtime version
- enforced WPC hash / network posture summary
- resource limits
- optional `clawlogs` anchoring (root hash + inclusion proof)

---

## 4) WPC hooks + enforcement points

WPC (via `clawcontrols`) should be able to express:
- `minimum_poh_tier`
- `minimum_model_identity_tier`
- required audit packs / attesters

Enforcement points:
- **clawproxy**: enforce provider/model allowlists + attach model identity to receipts
- **clawea**: enforce sandbox/TEE/stateless scheduling, emit execution attestations
- **clawverify**: compute trust vector; verify attestations; validate inclusion proofs; verify-under-policy when requested

---

## 5) Non-goals (Phase 0)

- Proving weight identity for closed provider APIs.
- Perfect confidentiality without TEEs.
- A single scalar tier that mixes execution provenance + model identity.
