> **Type:** Index
> **Status:** CANONICAL
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-12
> **Source of truth:** `docs/prds/*`
>
> **Scope:**
> - Index of per-domain PRDs.
> - PRDs describe intended behavior; implementation status is tracked in `docs/roadmaps/*`.

# PRD Index

All domain PRDs live in `docs/prds/`.

## Active Services (The Diamond)

| Domain | PRD | Role |
|---|---|---|
| clawverify.com | docs/prds/clawverify.md | Trust Oracle — deterministic verification |
| clawproxy.com | docs/prds/clawproxy.md | Data Plane — LLM gateway + model receipts |
| clawcontrols.com | docs/prds/clawcontrols.md | Work Policy Contracts (absorbing into clawea) |
| clawscope.com | docs/prds/clawscope.md | Capability Scope Tokens (absorbing into clawea) |
| clawlogs.com | docs/prds/clawlogs.md | Transparency logs (absorbing into clawverify) |
| clawea.com | docs/prds/clawea.md | Enterprise Agents — dashboard + policy authoring |

## Active Domains (no deployed service)

| Domain | PRD |
|---|---|
| clawbureau.com | docs/prds/clawbureau.md |
| clawsig.com | docs/prds/clawsig.md |
| joinclaw.com | docs/prds/joinclaw.md |

## Archived Services

> Archived 2026-02-12 per strategic pivot (Nation-State to Notary).
> See `docs/strategy/GEMINI_DEEP_THINK_REVIEW_2026-02-12.md` for rationale.
> Code preserved in `services/_archived/` and git history (tag: `v0-nation-state`).

| Domain | PRD | Archive Reason |
|---|---|---|
| clawbounties.com | docs/prds/clawbounties.md | Marketplace — dead weight, zero liquidity |
| clawescrow.com | docs/prds/clawescrow.md | Economy — recreates Stripe Connect |
| clawledger.com | docs/prds/clawledger.md | Economy — full-reserve banking for integer cents |
| clawsettle.com | docs/prds/clawsettle.md | Economy — Stripe settlement |
| clawcuts.com | docs/prds/clawcuts.md | Economy — fee engine |
| clawclaim.com | docs/prds/clawclaim.md | Identity — bespoke DID registry, use EIP-8004 |
| clawrep.com | docs/prds/clawrep.md | Identity — custom reputation scoring |
| clawtrials.com | docs/prds/clawtrials.md | Economy — arbitration |
| clawincome.com | docs/prds/clawincome.md | Economy — revenue aggregation |
| clawinsure.com | docs/prds/clawinsure.md | Economy — SLA insurance |
| clawdelegate.com | docs/prds/clawdelegate.md | Identity — delegation |
| claw-domains | (landing pages) | Fluff — static domain landing pages |

## Archived Packages

| Package | Archive Reason |
|---|---|
| packages/_archived/bounties | Bounties library — only used by clawbounties |

## PRDs Without Deployed Services (reference only)

| Domain | PRD |
|---|---|
| clawadvisory.com | docs/prds/clawadvisory.md |
| clawcareers.com | docs/prds/clawcareers.md |
| clawforhire.com | docs/prds/clawforhire.md |
| clawgang.com | docs/prds/clawgang.md |
| clawgrant.com | docs/prds/clawgrant.md |
| clawintel.com | docs/prds/clawintel.md |
| clawmanage.com | docs/prds/clawmanage.md |
| clawmerch.com | docs/prds/clawmerch.md |
| clawportfolio.com | docs/prds/clawportfolio.md |
| clawproviders.com | docs/prds/clawproviders.md |
| clawsilo.com | docs/prds/clawsilo.md |
| clawsupply.com | docs/prds/clawsupply.md |

## Cross-domain PRDs

| Topic | PRD |
|---|---|
| Clawsig Protocol | docs/prds/clawprotocol.md |
