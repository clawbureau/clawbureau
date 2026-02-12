# clawdelegate

Delegation control plane for delegated CST issuance, spend governance, and revocation fanout.

## Endpoints

- `POST /v1/delegations`
- `GET /v1/delegations/:id`
- `GET /v1/delegations`
- `POST /v1/delegations/:id/approve`
- `POST /v1/delegations/:id/tokens/issue`
- `POST /v1/delegations/:id/revoke`
- `POST /v1/delegations/:id/spend/reserve`
- `POST /v1/delegations/:id/spend/consume`
- `POST /v1/delegations/:id/spend/release`
- `POST /v1/delegations/:id/spend/authorize`
- `GET /v1/delegations/:id/audit`
- `GET /v1/delegations/:id/audit/export`

## Cloudflare stack

- Worker runtime + route-scoped API surface
- D1 authoritative state (`DELEGATE_DB`)
- Durable Object serialization (`DelegationDurableObject`)
- Queue-based revoke fanout (`DELEGATE_EVENTS`)
- Optional KV cache (`DELEGATE_CACHE`)
