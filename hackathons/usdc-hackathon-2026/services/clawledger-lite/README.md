# clawledger-lite (hackathon prototype)

Minimal ledger service for deterministic balances, idempotent events, and bucket moves.

Endpoints:
- `GET /v1/balances?did=...`
- `POST /v1/transfers` (returns signed receipt)
- `GET /v1/events/{event_id}`
- `GET /v1/anchors`
- `POST /v1/anchors` (admin)

Buckets:
- A (available)
- H (held)
- F (fee pool)

Features:
- Signed ledger receipts (ed25519, did:key)
- Merkle root anchoring on Base Sepolia (contract: 0x5cE94B3d7f3330215acc9A746d84f216530E1988)

Note: for hackathon simplicity, `clearing:*` accounts are allowed to go negative (used for mint-like events).
