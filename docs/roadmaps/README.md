> **Type:** Index
> **Status:** CANONICAL
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-03-21
> **Source of truth:** `docs/roadmaps/*/prd.json` + `docs/roadmaps/*/progress.txt`
>
> **Scope:**
> - Roadmaps are the execution layer: concrete stories + progress logs.
> - Roadmaps are the canonical "what we’re doing next".

# Roadmaps

Roadmaps are the **execution layer** of planning: concrete stories + progress logs that can be run via `scripts/ralph/ralph.sh`.

## In progress / partially shipped

- **Clawcompiler Runtime v1** (deterministic compiler runtime, signed compiled reports, first assurance pack, auditor-facing surfaces)
  - Folder: `docs/roadmaps/clawcompiler-runtime-v1/`
  - Status: Waves 1-2 shipped, 6/10 stories complete (PRs #516/#518); Wave 3 is next
  - Beads: `monorepo-cec2`, `monorepo-cec2.1`..`monorepo-cec2.10`

## Completed roadmaps

- **Clawsig Framework vNext** (24/24 ✅ — reliability, signed policy, attestation, marketplace enforcement, reviewer/dispute UX, DLP, cross-runtime parity, transparency, revocation)
  - Folder: `docs/roadmaps/clawsig-framework-vnext/`
  - Status: complete (PRs #484/#485/#487/#489/#490/#492/#493/#495/#497/#498/#500/#501/#503/#504/#506/#507/#508/#510/#511/#513)

- **Clawcompiler bootstrap** (6/6 ✅ — deterministic compiled-evidence schemas, binary-semantic runtime contracts, conformance scaffolding)
  - Folder: `docs/roadmaps/clawcompiler/`
  - Status: complete (bootstrap/contracts complete; Runtime v1 continues in `docs/roadmaps/clawcompiler-runtime-v1/`)

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
