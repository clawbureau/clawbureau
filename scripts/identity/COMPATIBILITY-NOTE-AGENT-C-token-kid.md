# Compatibility Note for Agent C (requester gate consumers)

Status: effective immediately after M3/M4 identity rollout

## Key contract updates
- clawscope introspection now emits deterministic kid outcomes:
  - `TOKEN_UNKNOWN_KID`
  - `TOKEN_KID_EXPIRED`
- clawverify token-control maps these to deterministic verifier codes:
  - `TOKEN_CONTROL_KEY_UNKNOWN`
  - `TOKEN_CONTROL_KEY_EXPIRED`

## Required consumer behavior
When receiving `TOKEN_CONTROL_KEY_UNKNOWN` or `TOKEN_CONTROL_KEY_EXPIRED`:
1. Refresh key contract metadata:
   - `GET /v1/keys/rotation-contract`
   - `GET /v1/jwks`
2. Reissue requester token from clawscope canonical/legacy lane as configured.
3. Retry with the newly issued token.

Do **not** perform blind retries with the same rejected token.

## Evidence
- Interop smoke artifact:
  - `artifacts/smoke/identity-control-plane/2026-02-11T22-43-00-300Z-kid-interop/result.json`
