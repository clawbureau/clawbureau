> **Type:** Roadmap
> **Status:** COMPLETE
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-03-21
> **Source of truth:** `docs/roadmaps/clawcompiler/prd.json` + `progress.txt`
>
> **Scope:**
> - Bootstrap deterministic Regulatory Evidence Compiler contracts before service-runtime rollout.
> - Establish schema, binary-semantic, and conformance foundations that Runtime v1 can build on.

# Clawcompiler Bootstrap Roadmap

This roadmap tracked the bootstrap tranche for **Clawcompiler** (Regulatory Evidence Compiler).

## Shipped bootstrap stories

- `CEC-US-001` — Deterministic compiled evidence report schema
- `CEC-US-002` — Signed compiled evidence report envelope schema
- `CEC-US-003` — Dual-plane narrative schema membrane
- `CEC-US-004` — Canonical binary semantic evidence schema contract
- `CEC-US-005` — Deterministic runtime policy state machine for binary semantic evidence
- `CEC-US-006` — Conformance fixtures for precedence and adversarial normalization

## Outcome

The bootstrap slice is complete. Clawcompiler now has deterministic schema contracts, signed report-envelope contracts, a hard narrative membrane, canonical binary-semantic evidence semantics, and conformance fixtures/runners.

## Successor roadmap

Runtime/service delivery now continues in:
- `docs/roadmaps/clawcompiler-runtime-v1/`

## Out of scope for this bootstrap slice

- No deployed `services/clawcompiler` runtime yet
- No production deploy activity
- No widening into unrelated verifier/firewall hardening stories

## Conformance anchor

- Fixtures: `packages/schema/fixtures/protocol-conformance/clawcompiler-compiled-evidence/`
- Runner: `scripts/protocol/run-clawcompiler-schema-conformance.mjs`

## Oracle intake (R45)

- Folder: `docs/roadmaps/clawcompiler/oracle/2026-02-17/`
- Index: `docs/roadmaps/clawcompiler/oracle/2026-02-17/INDEX.md`
- Canonical synthesis: `docs/roadmaps/clawcompiler/oracle/2026-02-17/R45_BINARY_SEM_CANONICAL.md`

R45 disposition:
- A accepted for depth
- C accepted as canonical base
- S rejected as final artifact, policy-language donor only
