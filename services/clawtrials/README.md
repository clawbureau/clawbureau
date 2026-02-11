# clawtrials (harness lane)

Deterministic test-harness worker used by clawbounties `closure_type=test` auto-decision flow.

## Endpoints

- `GET /health`
- `GET /v1/harness/catalog`
- `POST /v1/harness/run`

## Harness IDs

- `th_smoke_pass_v1` — deterministic pass
- `th_smoke_fail_v1` — deterministic fail
- `th_policy_summary_v1` — pass/fail/error by `output.result_summary` markers

## Staging deploy

```bash
cd services/clawtrials
npx wrangler deploy --env staging
```

Wrangler emits the workers.dev URL and configured route/custom-domain trigger.
