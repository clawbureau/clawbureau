> **Type:** Roadmap
> **Status:** ACTIVE
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-17
> **Source of truth:** `docs/roadmaps/clawcompiler/prd.json` + `progress.txt`
>
> **Scope:**
> - Bootstrap deterministic Regulatory Evidence Compiler (CEC-US-001..003).
> - Establish schema contracts + conformance vectors before any service runtime.

# Clawcompiler Roadmap

This roadmap tracks the bootstrap tranche for **Clawcompiler** (Regulatory Evidence Compiler).

## Bootstrap stories (this lane)

- `CEC-US-001` — Deterministic control-matrix report schema contract
- `CEC-US-002` — Signed compiled-evidence report envelope schema contract
- `CEC-US-003` — Non-authoritative narrative schema contract with hard membrane (`authoritative:false` + fixed disclaimer)

## Out of scope for this roadmap slice

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
