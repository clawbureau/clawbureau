> **Type:** Index
> **Status:** CANONICAL
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-18
> **Source of truth:** `docs/roadmaps/*/prd.json` + `docs/roadmaps/*/progress.txt`
>
> **Scope:**
> - Roadmaps are the execution layer: concrete stories + progress logs.
> - Roadmaps are the canonical "what we’re doing next".

# Roadmaps

Roadmaps are the **execution layer** of planning: concrete stories + progress logs that can be run via `scripts/ralph/ralph.sh`.

## In progress / partially shipped

- **Clawsig Protocol v0.2**
  - Folder: `docs/roadmaps/clawsig-protocol-v0.2/`
  - Status: implementation complete in lane branch — CPL-V2-001..005 pass (CPL-V2-001 pending merge)

- **Clawcompiler bootstrap** (deterministic compiled-evidence schemas + conformance scaffolding)
  - Folder: `docs/roadmaps/clawcompiler/`
  - Status: bootstrap complete for CEC-US-001..003; runtime service not yet scheduled

## Completed roadmaps

- **Clawsig Protocol v0.1** (12/12 ✅ — Coverage MTS, offline verifier, conformance suite, capability negotiation)
  - Folder: `docs/roadmaps/clawsig-protocol/`
  - Status: complete

- **Docs IA** (4/4 ✅ — classification, archiving, status blocks, reading paths)
  - Folder: `docs/roadmaps/docs-ia/`
  - Status: complete

- **Proof-of-Harness** (20/20 ✅ — adapters, registry, specs)
  - Folder: `docs/roadmaps/proof-of-harness/`
  - Status: complete

- **Trust vNext** (59/59 ✅ — PoH hardening, identity, delegation, reputation, economy)
  - Folder: `docs/roadmaps/trust-vnext/`
  - Status: complete

## Roadmap folder contract (Ralph-compatible)

Each roadmap folder should contain:
- `prd.json`
- `progress.txt`
- `README.md`

Optional but recommended:
- `oracle/<YYYY-MM-DD>/` (prompts, outputs, INDEX)
- `specs/` (long-lived specs / protocols)
