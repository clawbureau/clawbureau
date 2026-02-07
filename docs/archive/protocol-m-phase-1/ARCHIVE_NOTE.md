> **Type:** Archive
> **Status:** ARCHIVE
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-07
> **Source of truth:** historical planning docs
>
> **Scope:**
> - Archived Protocol M Phase 1 planning bundle (no implementation).
> - Kept for crypto-spec reference (golden vector, rotation concept).

# Protocol M (Phase 1) — archived

This folder is a **verbatim archive** of the sibling planning directory:
- `/Users/gfw/clawd/02-Projects/protocol-m/`

It is **not** the current plan of record.

## What replaced it

Active, canonical planning + implementation now lives in the Claw Bureau monorepo:

- PoH evidence model + adapters:
  - `docs/roadmaps/proof-of-harness/README.md`
  - `docs/roadmaps/proof-of-harness/ADAPTER_SPEC_v1.md`
- Trust vNext (hardening, confidential consulting, witnessed-web):
  - `docs/roadmaps/trust-vnext/README.md`
- Agent Economy MVP spec:
  - `docs/specs/agent-economy/MVP.md`
- OpenClaw integration constraints:
  - `docs/integration/OPENCLAW_INTEGRATION.md`
- Canonical schemas:
  - `packages/schema/**`

## Why we keep this archive

Protocol M contains useful, implementation-grade crypto artifacts that may still be worth extracting:
- `golden-vector.json` (authoritative cross-implementation test vector)
- key rotation certificate concept (not yet formalized in monorepo schemas)

Any extraction should happen via explicit roadmap stories (e.g. Trust vNext / identity work).
