# clawledger-lite (hackathon prototype)

Minimal ledger service for deterministic balances, idempotent events, and bucket moves.

> ⚠️ WIP — stub skeleton. Implement endpoints per docs/API.md.

Endpoints:
- `GET /v1/balances?did=...`
- `POST /v1/transfers`

Buckets:
- A (available)
- H (held)
- F (fee pool)

Note: for hackathon simplicity, `clearing:*` accounts are allowed to go negative (used for mint-like events).
