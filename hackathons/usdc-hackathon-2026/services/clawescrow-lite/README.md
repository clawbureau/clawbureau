# clawescrow-lite (hackathon prototype)

Minimal ledger-native escrow service for holds and releases.

> ⚠️ WIP — stub skeleton. Implement endpoints per docs/API.md.

Endpoints:
- `POST /v1/escrows`
- `POST /v1/escrows/{id}/assign`
- `POST /v1/escrows/{id}/release`

Environment:
- `LEDGER_URL` (URL of clawledger-lite)
- `FEE_DID` (default: clearing:clawcuts)
