> **Type:** Reference
> **Status:** REFERENCE
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-07
> **Source of truth:** upstream OpenClaw documentation (mirrored here)
>
> **Scope:**
> - A local mirror of upstream OpenClaw docs.
> - Treated as reference constraints for Claw Bureau integration work.
> - Not a description of Claw Bureau’s current runtime behavior.

# OpenClaw Docs Mirror

This directory is a **local mirror** of OpenClaw documentation.

## Why it exists
Claw Bureau services are designed to integrate tightly with the OpenClaw runtime (skills + extensions/plugins). Keeping a copy of key OpenClaw docs inside this repo makes PRD/architecture work:
- reviewable in PRs
- referenceable by Oracle runs
- stable for long-lived planning docs

## Source of truth
Within this repo, `docs/openclaw/*` is treated as the **source of truth for OpenClaw integration constraints**.

Upstream OpenClaw may evolve; if/when this mirror drifts, update it intentionally (ideally in its own PR with a clear summary of changes).
