# Identity Control Plane Operations Runbook (M3/M4)

Status: active operational reference for clawclaim + clawscope + clawverify

## 1) Key rotation overlap windows (clawscope)

### Contract endpoints
- `GET /v1/jwks`
- `GET /v1/keys/rotation-contract`

### Deterministic contract fields
- `active_kid`: currently signing kid
- `signing_kids`: keys allowed to sign new tokens
- `verify_only_kids`: overlap-only verification keys (no signing rights)
- `expiring_kids[]`: explicit `not_after_unix` overlap cutoff per key
- `accepted_kids`: final accepted verification set

### Rotation procedure (fail-closed)
1. Prepare next signing key seed (do not remove active key yet).
2. Update `SCOPE_SIGNING_KEY` or `SCOPE_SIGNING_KEYS_JSON` to the new active key.
3. Keep previous key as overlap verification key through `SCOPE_VERIFY_PUBLIC_KEYS_JSON` with explicit `not_after_unix`.
4. Deploy staging, run kid interop smoke, then deploy prod.
5. After `not_after_unix` passes and old tokens are out of TTL window, remove overlap key.

### Error semantics
- `TOKEN_UNKNOWN_KID`: token references a kid not in accepted set.
- `TOKEN_KID_EXPIRED`: token references overlap kid past cutoff.

## 2) Revocation propagation expectations

### Paths
- `POST /v1/tokens/revoke`
- `GET /v1/revocations/stream`
- `POST /v1/tokens/introspect`
- `POST /v1/verify/token-control`

### Guarantees
- Revocation is authoritative in clawscope KV immediately after successful revoke write.
- Introspection and token-control verification fail closed for revoked tokens.
- Expected verifier error: `REVOKED`.

### Operator checklist
1. Revoke token hash.
2. Confirm stream entry appears (`/v1/revocations/stream`).
3. Confirm introspection returns `active:false, revoked:true`.
4. Confirm verifier returns invalid with `REVOKED`.

## 3) Controller transfer freeze + recovery (clawclaim)

### Paths
- `POST /v1/control-plane/controllers/{controller_did}/transfer/request`
- `POST /v1/control-plane/controllers/{controller_did}/transfer/confirm`
- `POST /v1/control-plane/challenges`

### State machine
- `active -> transfer_pending -> transferred`

### Freeze semantics
- During `transfer_pending`, mutation actions fail closed with:
  - `CONTROLLER_TRANSFER_FROZEN`

### Recovery
- Complete transfer via `transfer/confirm` with target owner signature.
- Re-run challenge issuance + policy mutations under new owner context.

## 4) Export/import portability rejection semantics

### Paths
- `POST /v1/control-plane/identity/export`
- `POST /v1/control-plane/identity/import`

### Deterministic failures
- `IMPORT_BUNDLE_TAMPERED`
- `IMPORT_BUNDLE_STALE`
- `IMPORT_REVOKED_RECORD`
- `IMPORT_ALIAS_CONFLICT`

### Operator guidance
- Never retry tampered bundle imports.
- For stale bundles, regenerate from source owner context.
- For alias conflicts, resolve source-of-truth DID continuity before import.

## 5) Offline verification confidence semantics (clawverify)

`POST /v1/verify/token-control` confidence is only as strong as:
1. current clawscope introspection availability,
2. current revocation stream state,
3. current key overlap contract freshness.

### Key interoperability mappings
- upstream `TOKEN_UNKNOWN_KID` -> verifier `TOKEN_CONTROL_KEY_UNKNOWN`
- upstream `TOKEN_KID_EXPIRED` -> verifier `TOKEN_CONTROL_KEY_EXPIRED`

### Integration action (Agent C + downstream gates)
- On `TOKEN_CONTROL_KEY_UNKNOWN` / `TOKEN_CONTROL_KEY_EXPIRED`:
  1. refresh `/v1/keys/rotation-contract` + `/v1/jwks`,
  2. reissue token,
  3. retry verification with new token.
- Do not loop retries against the same rejected token.
