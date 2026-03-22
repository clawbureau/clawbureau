# Artifact Trace Report

- generated_at: 2026-03-22T17:33:33.114Z
- root: /private/tmp/e2edemo-v1-feature
- scanned_files: 1185
- parsed_files: 1184
- parse_errors: 1

## Artifact inventory (by kind)

- commit_signature: 456
- json: 442
- summary_json: 94
- smoke_result: 79
- proof_bundle_envelope: 35
- urm_document: 35
- verification_result: 21
- trust_pulse: 12
- conformance_summary: 10
- json_parse_error: 1

## Trace target

- run_id: run_43fec9dc-359e-42a4-a824-db94148cf171
- bundle: artifacts/simulations/marketplace-e2e-settlement/2026-02-18T15-27-47-754Z-prod/proof-bundle.json
- URM: artifacts/simulations/marketplace-e2e-settlement/2026-02-18T15-27-47-754Z-prod/urm.json
- trust pulse: n/a

### Bundle component counts

- event_chain: 7
- tool_receipts: 5

### Event types

- run_start: 1
- tool_call: 5
- run_end: 1

### Event timeline (first 20)

- 2026-02-18T15:27:47.757Z · run_start · evt_14718abb-b2db-4bdd-8baa-3608bb46967b
- 2026-02-18T15:27:47.932Z · tool_call · evt_ac606a6d-1576-48b6-a72a-ccc25f362f40
- 2026-02-18T15:27:48.720Z · tool_call · evt_c070b094-71c6-4145-b366-e232e9a8c0c6
- 2026-02-18T15:27:49.435Z · tool_call · evt_d058061b-3b54-4b5f-a9ca-b833d8e92e12
- 2026-02-18T15:27:49.491Z · tool_call · evt_818a63de-5fa7-46d2-b0c4-747d90c902d2
- 2026-02-18T15:27:50.147Z · tool_call · evt_1c070a20-c85d-4027-b538-5ca87cdde864
- 2026-02-18T15:27:50.147Z · run_end · evt_ee957c1c-03c0-4312-aa8a-5dfec7aaf85a

### Tool receipts by tool name

- http_fetch: 5

### Causal confidence distribution

- total: 0
- authoritative (>=0.99): 0
- inferred (>=0.5,<0.99): 0
- low (>0,<0.5): 0
- unattributed (0.0): 0

### CLDD discrepancy

- discrepancy: false
- claimed: n/a
- attested: n/a
- mismatch_fields: none

### URM integrity check

- expected: Ms5aFTLMZJuwEHkJzQq7raEl2YMbwfhhU451gwkE5tY
- actual: Ms5aFTLMZJuwEHkJzQq7raEl2YMbwfhhU451gwkE5tY
- match: true

### Verification results

- artifacts/simulations/marketplace-e2e-settlement/2026-02-18T15-27-47-754Z-prod/verify.json: status=PASS code=OK at=2026-02-18T15:27:50.147Z

## Related artifacts

- [json] artifacts/ops/e2e-demo/public/bundle-review.snapshot.json
- [json] artifacts/ops/e2e-demo/traces/settlement-prod.trace.json
- [json] artifacts/simulations/marketplace-e2e-settlement/2026-02-18T15-27-47-754Z-prod/health-snapshot.json
- [proof_bundle_envelope] artifacts/simulations/marketplace-e2e-settlement/2026-02-18T15-27-47-754Z-prod/proof-bundle.json
- [smoke_result] artifacts/simulations/marketplace-e2e-settlement/2026-02-18T15-27-47-754Z-prod/smoke.json
- [urm_document] artifacts/simulations/marketplace-e2e-settlement/2026-02-18T15-27-47-754Z-prod/urm.json
- [verification_result] artifacts/simulations/marketplace-e2e-settlement/2026-02-18T15-27-47-754Z-prod/verify.json
- [summary_json] artifacts/e2e/real-usecases/2026-02-18T15-28-07Z/summary.json
- [json] artifacts/e2e/real-usecases/2026-02-18T15-28-07Z/traces/settlement-prod.trace.json

