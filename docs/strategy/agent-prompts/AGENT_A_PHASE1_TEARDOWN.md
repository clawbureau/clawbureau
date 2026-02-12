# Agent A Dispatch: Phase 1 — Service Teardown

## Context

Read these files first:
- `docs/strategy/GEMINI_DEEP_THINK_REVIEW_2026-02-12.md` — the strategic mandate
- `docs/strategy/PIVOT_EXECUTION_PLAN.md` — the execution plan
- `docs/strategy/SERVICE_INVENTORY_FINAL.md` — what's currently deployed

## Your Mission

You are executing Phase 1 of the pivot: **removing dead weight services from deployment**.

The code stays in git history (tagged `v0-nation-state`). You are moving service directories to `services/_archived/` and undeploying Workers from Cloudflare.

## Services to Archive (in order)

Archive these by moving `services/<name>` to `services/_archived/<name>`:

1. `clawbounties` — marketplace (10,809 lines)
2. `escrow` — payment holds
3. `ledger` — double-entry ledger
4. `clawsettle` — Stripe settlement
5. `clawcuts` — fee engine
6. `clawclaim` — identity binding
7. `clawrep` — reputation
8. `clawtrials` — arbitration
9. `clawincome` — revenue aggregation
10. `clawinsure` — SLA insurance
11. `clawdelegate` — identity delegation
12. `claw-domains` — landing pages

## Services to Keep Deployed

- `clawverify` — Trust Oracle (ENHANCE)
- `clawproxy` — Data Plane (ENHANCE with x402)
- `clawlogs` — will absorb into clawverify later
- `clawcontrols` — will absorb into clawea later
- `clawscope` — will absorb into clawea later
- `clawea-www` — pivot to protocol site + enterprise dashboard

## Procedure for Each Archived Service

1. Move directory: `git mv services/<name> services/_archived/<name>`
2. Move associated packages if any (e.g., `packages/bounties` → `packages/_archived/bounties`)
3. Update `docs/PRD_INDEX.md` — mark service as archived
4. Do NOT undeploy from Cloudflare yet (that requires wrangler and approval)
5. Do NOT delete migrations, schemas, or test files — they're historical reference

## Also Archive

- `packages/bounties` → `packages/_archived/bounties`
- `packages/identity-auth` → `packages/_archived/identity-auth` (if solely used by archived services)

## What NOT to Touch

- `packages/schema` — schemas are reference material, keep them
- `packages/clawproof-sdk` (aka clawsig-sdk) — keep, this is the Diamond
- `packages/clawproof-adapters` (aka clawsig-adapters) — keep
- `packages/openclaw-provider-clawproxy` — keep
- `packages/clawverify-core` — keep
- `packages/clawverify-cli` — keep
- `proofs/` — historical proof artifacts, keep
- `scripts/did-work/` — keep (DID signing tooling)
- `scripts/protocol/` — keep (conformance runner)

## PR Convention

Single PR: `refactor/pivot/P1-service-teardown`

Branch from `main`, commit with message: `refactor: archive 12 dead-weight services per pivot plan`

Include in PR body a reference to `docs/strategy/GEMINI_DEEP_THINK_REVIEW_2026-02-12.md`.

## Evidence Required

- List of moved directories
- Confirmation that `clawverify`, `clawproxy`, `clawlogs`, `clawcontrols`, `clawscope`, `clawea-www` are untouched
- `npm run typecheck` passes in remaining services
