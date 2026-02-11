> **Type:** Roadmap
> **Status:** DRAFT
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-11
> **Source of truth:** PoH PRD tracker + schema package
>
> **Scope:**
> - PoH vNext roadmap: model identity axis + verifiable audit attestations + transparency log inclusion proofs.

# Proof-of-Harness (PoH) vNext Roadmap — Model Identity + Verifiable Audits

This roadmap extends the existing PoH workstream (URM + event chain + receipts + attestations) to cover:

1) **Honest model identity** in an enterprise world dominated by closed-provider APIs
2) **Verifiable audits** (binding audit code + dataset + model identity → results)
3) A portable **transparency log** surface (`clawlogs` inclusion proofs)

Core design + planning:
- Design: `docs/roadmaps/proof-of-harness/DESIGN_model-identity-and-verifiable-audits.md`
- Phase 0 PR stack: `docs/roadmaps/proof-of-harness/PHASE0_PR_STACK.md`
- Audit pack convention (ADR): `docs/foundations/decisions/0001-audit-pack-convention.md`

Primary tracker:
- `docs/roadmaps/proof-of-harness/prd.json` (PoH user stories)

---

## Principles (hard rules)

1) **Don’t overload PoH tiers.**
   - PoH tiers remain: `self | gateway | sandbox`.
   - Add `model_identity_tier` as a separate axis.

2) **Never over-claim weights for closed providers.**
   - Closed providers default to `model_identity_tier=closed_opaque`.

3) **Hash pointers > bulky embedding.**
   - New attestations are content-addressed and referenced by hash+URI.

4) **Transparency is verifiable.**
   - “Published” means “anchored in clawlogs with an inclusion proof.”

---

## Phase 0 (weeks): No-TEE — ship semantics + primitives

### Outcomes
- Every canonical clawproxy receipt envelope includes a tiered `model_identity` object.
- clawverify returns a trust vector: `{poh_tier, model_identity_tier, risk_flags}`.
- Audit claims exist as verifiable objects:
  - `derivation_attestation` (Prepare analogue)
  - `audit_result_attestation` (Audit analogue)
  - audit packs are referenced by deterministic `audit_pack_hash_b64u` (ADR 0001)
- Schemas exist for clawlogs inclusion proofs.

### Work items (by domain)

#### packages/schema
- Add new PoH vNext schemas:
  - `poh/model_identity.v1.json`
  - `poh/derivation_attestation.v1.json`
  - `poh/audit_result_attestation.v1.json`
  - `poh/log_inclusion_proof.v1.json`
- Update:
  - `poh/gateway_receipt.v1.json` metadata docs
  - `poh/proof_bundle.v1.json` receipt metadata docs

#### clawproxy
- Emit `model_identity` + `model_identity_hash_b64u` in receipt metadata.
- Capture allowlisted provider correlation IDs/fingerprints (hash-only) when available.

#### clawverify
- Extract + validate model identity and compute `model_identity_tier`.
- Add verifiers for derivation/audit attestations (new envelope types in Phase 1 PRs).

#### clawlogs
- Define portable inclusion proof object (`log_inclusion_proof.v1`).
- Implemented MVP transparency log service (`services/clawlogs`) with append/root/proof endpoints and signed roots.

#### clawcontrols
- WPC hooks: minimum model identity tier + required audit packs/attesters.

#### Docs that must ship in Phase 0
- `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md` updated:
  - model identity axis
  - audit result references
  - canonical receipt envelope semantics
- PRDs updated:
  - `docs/prds/clawproxy.md`
  - `docs/prds/clawverify.md`
  - `docs/prds/clawlogs.md`
  - `docs/prds/clawcontrols.md`

---

## Phase 1 (months): Harden sandbox attestations (clawea)

### Outcomes
- clawea emits hardened `execution_attestation.v1` bindings so `sandbox` tier is meaningful:
  - image digest
  - sandbox runtime version
  - WPC hash / network posture summary
  - resource limits
  - optional clawlogs anchoring

### Work items
- clawea: execution attestation emission + offline export bundles.
- governance: allowlisted attesters + revocation feeds.

---

## Phase 2 (later): Optional TEE path for openweights

- `execution_type=tee_execution` carries RA evidence in `runtime_metadata`.
- Same primitives; only evidence changes.

---

## Definition of done (Phase 0)

Phase 0 is “done” when:
- a canonical clawproxy receipt (staging) includes `model_identity` metadata
- clawverify can surface `model_identity_tier` without changing PoH tier semantics
- schemas exist for derivation/audit attestations and clawlogs inclusion proofs
