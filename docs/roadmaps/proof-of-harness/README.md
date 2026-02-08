> **Type:** Roadmap
> **Status:** ACTIVE
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-07
> **Source of truth:** `docs/roadmaps/proof-of-harness/prd.json` + `progress.txt`
>
> **Scope:**
> - PoH v1 spec + harness registry + tracking.
> - For PoH vNext (hardening/consulting/witnessed-web), see `docs/roadmaps/trust-vnext/`.

# Proof-of-Harness (PoH)

PoH is the evidence model that lets the marketplace verify **which harness** performed a run and that model/tool calls happened through an **allowlisted gateway** (via signed receipts), with a tamper-evident event chain.

## Key docs

- Spec (v1): `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`
- Harness registry (generated): `docs/roadmaps/proof-of-harness/HARNESS_REGISTRY.md`
  - Canonical source: `docs/roadmaps/proof-of-harness/harnesses.mjs`
- Story tracking:
  - `docs/roadmaps/proof-of-harness/prd.json`
  - `docs/roadmaps/proof-of-harness/progress.txt`

## Oracle research (2026-02-07)

- Folder: `docs/roadmaps/proof-of-harness/oracle/2026-02-07/`
- Index: `docs/roadmaps/proof-of-harness/oracle/2026-02-07/INDEX.md`
- Notable synthesis output:
  - `next-building-blocks-plan.gpt-5.2-pro.md` (ties PoH + nondeterminism/replay + subscription auth + confidential consulting + prompt injection)

## Known limitations / sharp edges

- **Streaming**: the current external-harness shim (`@clawbureau/clawproof-adapters`) buffers JSON and is not streaming/SSE-safe.
- **Subscription/web auth**: local “web evidence” is forgeable; requires a witness/attested runner to reach high trust tiers.

## Where vNext work lives

Anything beyond POH-US-012 (verifier hardening, prompt pack commitments, sandbox attestations, confidential consulting contracts, witnessed-web) is tracked in:
- `docs/roadmaps/trust-vnext/`
