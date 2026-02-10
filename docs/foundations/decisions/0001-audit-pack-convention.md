> **Type:** Decision (ADR)
> **Status:** ACCEPTED (Phase 0)
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-10
> **Source of truth:** PoH vNext schemas + policy gating needs
>
> **Scope:**
> - How we identify “audit packs” for policy gating without prematurely introducing a new registry.

# ADR 0001 — Audit Pack Convention (Phase 0)

## Context

PoH vNext adds verifiable audit claims:
- `derivation_attestation.v1` (Prepare analogue)
- `audit_result_attestation.v1` (Audit analogue)

We need a stable way for:
- WPC policy (`clawcontrols`) to require audits
- auditor/attester providers (`clawproviders`) to advertise what they support
- receipts/bundles to reference audit coverage

Open question: do we introduce a first-class `audit_pack.v1` schema/envelope now, or keep identifiers derived from fields already present in `audit_result_attestation`?

## Decision

**We will NOT introduce a standalone `audit_pack.v1` schema/envelope in Phase 0.**

Instead, we define an audit pack by a deterministic hash computed from the audit result attestation inputs:

```
audit_pack_hash_b64u = sha256_b64u(JCS({
  audit_code_hash_b64u: audit_code.code_hash_b64u,
  dataset_hash_b64u: dataset.dataset_hash_b64u,
  protocol_name: protocol.name,
  protocol_config_hash_b64u: protocol.config_hash_b64u
}))
```

Where:
- `JCS(...)` is RFC 8785 canonical JSON.
- `sha256_b64u(...)` is SHA-256 encoded as base64url (no padding).

`audit_result_attestation.v1` may include this as:
- `audit_pack.pack_hash_b64u` (required when `audit_pack` is present)
- and optionally `audit_pack.pack_id`, `audit_pack.pack_version` for human readability.

Policy gating should reference **pack hashes** (not names).

## Consequences

### Pros
- Minimal new surface area.
- Stable, content-addressed identifier suitable for WPC allowlists.
- Works for both openweights and closed-provider enterprise flows.

### Cons
- No standalone “pack object” to attach rich metadata (license, confidentiality class, reference runner, etc.) without another artifact.

## Follow-ups (Phase 1+)

If we need richer pack metadata (enterprise compliance products), introduce:
- a descriptor artifact schema (`audit_pack_descriptor.v1`) and/or
- a full `audit_pack.v1` envelope + registry.

Triggered by real product requirements, not speculation.

## References
- `packages/schema/poh/audit_result_attestation.v1.json`
- `docs/roadmaps/proof-of-harness/DESIGN_model-identity-and-verifiable-audits.md`
- `docs/roadmaps/proof-of-harness/ROADMAP_vNext.md`
