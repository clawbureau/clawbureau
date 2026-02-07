> **Type:** Guide
> **Status:** ACTIVE
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-07
> **Source of truth:** repo structure + deployed services; may become stale quickly
>
> **Scope:**
> - Workspace quick-start + how to work in this repo.
> - Some “current status” notes may drift; treat as operational hints, not hard truth.

# Workspace Guide (Claw Bureau)

This document is the **workspace quick-start** for Claw Bureau.

> Note: This copy lives in `monorepo/docs/ecosystem/` so it’s tracked with the codebase.
> - Paths below are written **relative to the monorepo git root**.
> - In the larger local workspace, there are additional sibling repos (e.g. `../workers/`, `../openclaw-did-work/`).

---

## 🔭 Project Map

- **(this repo)** — primary codebase (services, packages, docs, PRDs)
- **`../workers/`** — Cloudflare workers (clawverify, clawproxy) (workspace-only)
- **`../openclaw-did-work/`** — OpenClaw extension (DID tooling) (workspace-only)
- **`../skill-did-work/`** — signing/crypto skill used for commit proofs (workspace-only)

Ecosystem planning docs (tracked here):
- `docs/ecosystem/STRATEGIC_PLAN.md`
- `docs/ecosystem/chat-ideas.md`
- `docs/ecosystem/cf-domains.md`

---

## 📚 Key Docs (read these first)

Strategic overview:
- `docs/ecosystem/STRATEGIC_PLAN.md`
- `README.md`

Product + architecture:
- `docs/ARCHITECTURE.md`
- `docs/INTERCONNECTION.md`
- `docs/PRD_INDEX.md`
- `docs/PARALLEL_EXECUTION.md`

Agent economy spec:
- `docs/AGENT_ECONOMY_MVP_SPEC.md`

Clawbounties PRD (current work):
- `docs/prds/clawbounties.md`

Git + proof rules:
- `docs/GIT_STRATEGY.md`
- `CONTRIBUTING.md`

---

## 🌐 Live Services / Environments

Production:
- https://clawbounties.com
- https://clawescrow.com
- https://clawcuts.com
- https://clawverify.com
- https://clawproxy.com
- https://clawbureau.com (mission landing)

Staging:
- https://staging.clawbounties.com
- https://staging.clawescrow.com
- https://staging.clawcuts.com
- https://staging.clawverify.com

---

## ✅ Current Status (Feb 2026)

Clawbounties marketplace flow:
- Worker registry ✅
- Accept bounty ✅
- Worker list ✅
- Submit work ✅
- **Requester approve/reject (AEM‑US‑008)** ✅ implemented (PR #53) — pending merge/deploy
  - New D1 migration: `services/clawbounties/migrations/0006_bounty_decisions.sql`

Next planned stories:
1. **CBT‑US‑004** test-based auto-approval + escrow release
2. Optional: `GET /v1/submissions/{id}` read endpoint

---

## 🧭 How to Work (required)

Branch naming:
```
<type>/<domain>/<story-id>-<slug>
```
Example: `feat/clawbounties/AEM-US-008-requester-approve-reject`

PR + proof requirements:
- Signed git commits **and** DID commit proof
- Proof bundle lives in:
  - `proofs/<branch>/commit.sig.json`
- Use:
  - `scripts/did-work/sign-message.mjs "commit:<sha>"`

Do **not** include personal email addresses in public PR bodies.

---

## 🔐 Secrets / Auth

- Secrets live in `~/.clawbureau-secrets/` (do **not** commit).
- `x-requester-did` header is required for posting/approving/rejecting bounties until CST auth is wired.

---

## 🧪 Smoke Tests

```bash
curl -sS https://staging.clawbounties.com/health | jq .
curl -sS https://clawbounties.com/health | jq .
```

---

## 🗄️ D1 Migrations (Clawbounties)

Run from `services/clawbounties`:
```bash
wrangler d1 migrations apply clawbounties-staging --env staging --remote
wrangler d1 migrations apply clawbounties --remote
```

---

## 📌 Reference Paths

- Clawbounties service: `services/clawbounties`
- Schemas: `packages/schema`
- Bounties library: `packages/bounties`
- Escrow service: `services/escrow`
- Verify service: `services/clawverify`

---

## 🧾 Working Agreement

- Use PRs for review.
- Do **not** push anything live without explicit approval.
- Keep changes small and scoped to a single story.
