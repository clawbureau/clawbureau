> **Type:** Roadmap
> **Status:** ACTIVE
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-07
> **Source of truth:** `docs/roadmaps/trust-vnext/prd.json` + `progress.txt`
>
> **Scope:**
> - PoH vNext hardening + confidential consulting + prompt integrity + witnessed-web.
> - Seeded from oracle synthesis; becomes execution truth as stories complete.

# Trust vNext Roadmap

This roadmap tracks the **next building blocks** after PoH v1:

- fail-closed verifier hardening (no over-trust)
- durable anti-replay / idempotency
- prompt integrity commitments (OpenClaw system prompt is dynamically composed)
- confidential consulting primitives (CWC/WPC pinning + sandbox attestations)
- subscription/web reality (only “witnessed web” can lift trust tiers)
- buyer-as-adversary: prompt injection + untrusted repo content (Airlock pattern)

## Canonical research inputs

Oracle synthesis (recommended starting point):
- `docs/roadmaps/proof-of-harness/oracle/2026-02-07/next-building-blocks-plan.gpt-5.2-pro.md`

Supporting runs:
- Prompt injection red-team:
  - `docs/roadmaps/proof-of-harness/oracle/2026-02-07/prompt-injection-redteam.gpt-5.2-pro.md`
  - `docs/roadmaps/proof-of-harness/oracle/2026-02-07/prompt-injection-redteam.google-gemini-3-pro-preview.md`
- Replay / nondeterminism:
  - `docs/roadmaps/proof-of-harness/oracle/2026-02-07/replay-nondeterminism.gpt-5.2-pro.md`
- OpenClaw system prompt integrity:
  - `docs/roadmaps/proof-of-harness/oracle/2026-02-07/openclaw-system-prompt-integrity.gpt-5.2-pro.md`
- Subscription auth (web credits):
  - `docs/roadmaps/proof-of-harness/oracle/2026-02-07/subscription-auth.gpt-5.2-pro.md`

## Tracking files

- Stories: `docs/roadmaps/trust-vnext/prd.json`
- Progress log: `docs/roadmaps/trust-vnext/progress.txt`

## How to run (Ralph)

From this directory:

```bash
../../scripts/ralph/ralph.sh --tool pi 50
```
