> **Type:** Index
> **Status:** CANONICAL
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-03-20
> **Source of truth:** `docs/roadmaps/*/prd.json` + `docs/roadmaps/*/progress.txt`
>
> **Scope:**
> - Roadmaps are the execution layer: concrete stories + progress logs.
> - Roadmaps are the canonical "what we’re doing next".

# Roadmaps

Roadmaps are the **execution layer** of planning: concrete stories + progress logs that can be run via `scripts/ralph/ralph.sh`.

## In progress / partially shipped

- **Clawcompiler bootstrap** (deterministic compiled-evidence schemas + conformance scaffolding)
  - Folder: `docs/roadmaps/clawcompiler/`
  - Status: bootstrap complete for CEC-US-001..003; runtime service not yet scheduled

## Completed roadmaps

- **Clawsig Privacy Assurance v1** (10/10 ✅ — fail-closed egress, runtime hygiene, sensitivity handling, processor policy, reviewer-facing privacy posture, export packs)
  - Folder: `docs/roadmaps/clawsig-privacy-v1/`
  - Status: complete (PRs #475/#476/#477/#478/#479/#480/#481)

- **Clawsig Protocol v0.2** (5/5 ✅ — co-signatures, TTL semantics, selective disclosure, aggregate bundles, deterministic rate-limit claims)
  - Folder: `docs/roadmaps/clawsig-protocol-v0.2/`
  - Status: complete (PRs #281/#282/#283/#285)

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
