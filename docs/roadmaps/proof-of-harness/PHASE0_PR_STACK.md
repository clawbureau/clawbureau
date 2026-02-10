> **Type:** Plan
> **Status:** DRAFT
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-10
> **Source of truth:** PoH roadmap + schemas
>
> **Scope:**
> - Implementation plan for Phase 0 PRs (small, reviewable stack).

# Phase 0 PR Stack Plan — PoH vNext (Model Identity + Verifiable Audits)

This file turns `ROADMAP_vNext.md` into an **implementable PR stack**.

Refs:
- Roadmap: `docs/roadmaps/proof-of-harness/ROADMAP_vNext.md`
- Design: `docs/roadmaps/proof-of-harness/DESIGN_model-identity-and-verifiable-audits.md`
- Audit pack convention: `docs/foundations/decisions/0001-audit-pack-convention.md`

---

## Hard constraints

1) **PoH tiers stay unchanged** (`self|gateway|sandbox`).
2) **Closed providers can’t prove weights** → default `model_identity.tier=closed_opaque`.
3) **Non-breaking extensions first**: extend receipt/bundle metadata; avoid schema churn.
4) **Fail-closed verification**: any new envelope types must be allowlisted in clawverify.

---

## PR-0 (this PR): Docs + Schemas + Roadmap alignment

**Branch:** `docs/poh-vnext-contracts`

Scope:
- Add PoH vNext schemas:
  - `packages/schema/poh/model_identity.v1.json`
  - `packages/schema/poh/derivation_attestation.v1.json`
  - `packages/schema/poh/audit_result_attestation.v1.json`
  - `packages/schema/poh/log_inclusion_proof.v1.json`
- Update PoH receipt/bundle schemas to document metadata attachment points:
  - `packages/schema/poh/gateway_receipt.v1.json`
  - `packages/schema/poh/proof_bundle.v1.json`
- Update docs + PRDs:
  - `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`
  - `docs/roadmaps/proof-of-harness/prd.json` (add POHVN-US-001..008)
  - `docs/prds/clawproxy.md`, `docs/prds/clawverify.md`, `docs/prds/clawlogs.md`, `docs/prds/clawcontrols.md`
  - `docs/integration/OPENCLAW_INTEGRATION.md`
  - `docs/specs/agent-economy/MVP.md`
- Add PoH vNext docs:
  - `docs/roadmaps/proof-of-harness/DESIGN_model-identity-and-verifiable-audits.md`
  - `docs/roadmaps/proof-of-harness/ROADMAP_vNext.md`
  - this file
- Add ADR:
  - `docs/foundations/decisions/0001-audit-pack-convention.md`

**Explicitly excluded:** runtime changes to `services/*`.

DoD:
- JSON parses for all new schema files.
- Doc drift fixed (no more “receipt format mismatch is current”).

---

## PR-1 (clawproxy): Emit model identity in receipt metadata

**Branch:** `feat/clawproxy/CPX-US-016-model-identity`

DoD:
- `_receipt_envelope.payload.metadata.model_identity` present
- `_receipt_envelope.payload.metadata.model_identity_hash_b64u` present
- Staging smoke script passes.

Add smoke:
- `scripts/poh/smoke-model-identity.mjs`

---

## PR-2 (clawverify): Surface trust vector fields

**Branch:** `feat/clawverify/CVF-US-016-model-identity`

DoD:
- `/v1/verify/receipt` returns model identity tier (when present)
- `/v1/verify/agent` returns PoH tier + model identity tier.

---

## PR-3 (clawverify): Verify derivation + audit result attestations (new envelope types)

**Branch:** `feat/clawverify/CVF-US-017-audit-attestations`

DoD:
- new endpoints:
  - `POST /v1/verify/derivation-attestation`
  - `POST /v1/verify/audit-result-attestation`
- schema allowlist updated
- smoke script signs a minimal attestation and verifies VALID.

---

## PR-4 (clawlogs): Minimal transparency log (optional Phase 0b)

Ship only if we’re ready to implement `clawlogs` as a service.
Otherwise Phase 0 is “schemas+docs” only.

---

## PR-5 (clawcontrols): WPC hooks for model identity + audit packs

If `services/clawcontrols` is in a different repo/worktree, land there.

---

## Merge order

1) PR-0 (docs/schemas)
2) PR-1 (clawproxy)
3) PR-2 (clawverify)
4) PR-3 (clawverify attestations)
5) Optional PR-4 (clawlogs)
6) PR-5 (clawcontrols)
