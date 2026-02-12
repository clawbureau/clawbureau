# CDL-MAX-001 rollout evidence summary

Generated: 2026-02-12T04:57:00Z

## Deploy evidence
- `artifacts/ops/clawdelegate/2026-02-12T04-56-45-407Z-deploy/deploy-summary.json`

## Routing verification
- `artifacts/ops/clawdelegate/2026-02-12T04-53-42-573Z-routing/routing-check.json`
  - `https://clawdelegate.com/v1/delegations` => `401 UNAUTHORIZED` (expected without admin key)
  - `https://clawdelegate-staging.generaite.workers.dev/v1/delegations` => `401 UNAUTHORIZED` (expected)
  - `https://www.clawdelegate.com` and `https://staging.clawdelegate.com` unresolved DNS (`fetch failed` / `curl: Could not resolve host`)

## Smoke evidence (CDL control-plane flow)
- Staging (latest):
  - `artifacts/smoke/clawdelegate/2026-02-12T04-56-01-753Z-staging/result.json`
  - deploy_version: `6ca14731-1ae9-4417-9d1d-42f706f4b92e`
- Prod (latest):
  - `artifacts/smoke/clawdelegate/2026-02-12T04-56-09-169Z-prod/result.json`
  - deploy_version: `b94daa3a-0362-4172-bbb5-17e0766afb27`

## Notes
- `clawdelegate.com` route now serves dedicated `clawdelegate` worker APIs.
- Staging smoke executed via workers.dev because `staging.clawdelegate.com` DNS is not currently resolvable.
