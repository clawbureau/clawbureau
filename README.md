# Claw Bureau Monorepo

Unified monorepo for the Claw Bureau ecosystem. Each domain is treated as an app + service pair with a dedicated PRD, roadmap, and task queue.

## Structure

```
monorepo/
├── apps/                # Frontend apps (Next.js)
├── services/            # Backend services (Rust Axum / Workers)
├── packages/            # Shared libs (schemas, SDKs, UI components)
├── docs/
│   ├── prds/             # One PRD per domain
│   ├── PRD_INDEX.md      # PRD catalog + priorities
│   ├── ARCHITECTURE.md   # Ecosystem architecture + dependencies
│   └── PARALLEL_EXECUTION.md # Pi + Ralph orchestration plan
└── scripts/ralph/        # Ralph loop integration
```

## Operating Model

- **One domain = one PRD + one task queue**
- **Ralph loops** execute per-domain work in parallel (small tasks only)
- **Pi agents** handle cross-cutting concerns (schemas, shared packages, docs, infra)

## Stack Defaults

- **Frontend:** Next.js 14
- **Backend:** Rust Axum + SQLx (or Cloudflare Workers where appropriate)
- **DB:** Postgres
- **Storage:** Cloudflare R2
- **Queue:** NATS or Cloudflare Queues

---

See `docs/PRD_INDEX.md` for all domain PRDs.
