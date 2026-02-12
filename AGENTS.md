# Development Rules (Claw Bureau monorepo)

This file is loaded by coding harnesses. Treat it as **repo-local operating rules**.

---

## First Message (context loading)

If the user did **not** give you a concrete task in their first message:

1) Read:
- `README.md`
- `docs/README.md`
- `docs/WHAT_TO_READ.md`

2) Ask which **domain / package / roadmap** to work on.

3) Based on the answer, read the relevant docs **in parallel** (typical set):
- `docs/PRD_INDEX.md`
- `docs/prds/<domain>.md`
- `docs/roadmaps/<topic>/README.md`
- `docs/roadmaps/<topic>/{prd.json,progress.txt}`
- If working on cross-service contracts: `docs/foundations/INTERCONNECTION.md`
- If working on git/proofs: `docs/foundations/GIT_STRATEGY.md`

---

## Repo Map (where things live)

- `services/` — deployed services (Cloudflare Workers, etc.)
- `packages/` — shared libraries (schemas, SDKs, adapters)
- `docs/` — documentation hub + PRDs + roadmaps
- `proofs/` — DID commit proofs and other proof artifacts
- `scripts/` — tooling (DID signing, PoH scripts, Ralph runner)

Docs structure:
- Foundations (binding invariants): `docs/foundations/`
- Specs (cross-domain): `docs/specs/`
- Integration: `docs/integration/`
- PRDs: `docs/prds/`
- Roadmaps (execution): `docs/roadmaps/`
- OpenClaw mirror (reference constraints): `docs/openclaw/`
- Oracle research (non-canonical inputs): `docs/oracle/`

---

## Code Quality

- Prefer **fail-closed** behavior in security-sensitive systems (verify/proxy/auth/proofs).
- Do not weaken verification to “make it pass.” Fix the root cause.
- Keep schemas versioned and additive when possible (`packages/schema/**`).
- Avoid `any` unless absolutely necessary; prefer precise types.
- Never hardcode secrets or tokens. Never log secrets.

---

## Commands / Running checks

This repo is not a single root workspace. **Run commands from the package/service you changed.**

After **code changes** (not pure documentation changes):
- For TypeScript packages/services, run (from that package root) as available:
  - `npm run typecheck`
  - `npm test` (if present)

Do **not** run long-lived or production-impacting commands unless the user explicitly asks.

---

## Secrets

All service keys and tokens live under `~/.clawsecrets/` on the operator machine.

Convention: **one file per key per environment**.

```
~/.clawsecrets/<service>/<KEY_NAME>.<env>
```

Example layout:

```
~/.clawsecrets/
  clawsettle/
    SETTLE_ADMIN_KEY.staging
    SETTLE_ADMIN_KEY.prod
    SETTLE_LOSS_READ_TOKEN.staging
    SETTLE_LOSS_READ_TOKEN.prod
    STRIPE_WEBHOOK_SIGNING_SECRET.staging
    STRIPE_WEBHOOK_SIGNING_SECRET.prod
  ledger/
    LEDGER_ADMIN_KEY.staging
    LEDGER_ADMIN_KEY.prod
    LEDGER_RISK_KEY.staging
    LEDGER_RISK_KEY.prod
  escrow/
    ESCROW_ADMIN_KEY.staging
    ...
```

**Rules:**
- Load via `cat`: `SETTLE_ADMIN_KEY="$(cat ~/.clawsecrets/clawsettle/SETTLE_ADMIN_KEY.prod)"`
- Never write secrets to `/tmp`, project dirs, or any tracked path.
- Never log secret values. Never include them in commit messages or PR bodies.
- Permissions: dirs `700`, files `600`.
- When rotating a secret via `wrangler secret put`, also update the local file.
- When a new secret is created for a service, add it here following the naming convention.

---

## Cloudflare / Wrangler safety

- Never deploy to production without explicit user approval.
- Treat any `wrangler deploy`, `wrangler d1 migrations apply --remote`, or secret updates as **high risk**.
- Prefer staging environments when validating.

---

## Git & Proof Rules

### Branch naming
Follow `docs/foundations/GIT_STRATEGY.md`.

### Proof requirements (agent work)
Agent-generated work must include proof:
- `proofs/<branch>/commit.sig.json`

Generate with:
- `scripts/did-work/sign-message.mjs "commit:<sha>"`

### Parallel-agent safe git workflow (critical)
- Only stage files you changed in this session (no sweeping adds).
- Avoid destructive commands that can destroy other agents’ work:
  - `git reset --hard`, `git checkout .`, `git clean -fd`, `git stash`
- Prefer small commits scoped to one story.

---

## Docs & Roadmaps

- PRDs describe **requirements/intent**: `docs/prds/<domain>.md`
- Roadmaps track **execution** with `prd.json + progress.txt`: `docs/roadmaps/<topic>/`
- Oracle outputs are **inputs**, not truth.
- When in doubt, link new docs from an index/README instead of adding more standalone files.

---

## Tooling rules (for harness-based agents)

- Always read files before editing.
- Avoid destructive filesystem operations.
- Keep responses concise and technical.
- No emojis in code/commits/docs.
