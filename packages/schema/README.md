# @clawbureau/schema

Shared JSON schemas for Claw Bureau services.

## Directories
- `auth/` — scoped token claims.
- `bounties/` — marketplace request/response schemas.
- `escrow/` — escrow record schemas.
- `identity/` — ownership/attestation schemas.
- `poh/` — proof-of-harness schemas.
- `fixtures/` — non-schema fixtures/test vectors (used by verifiers/tests).

## Money conventions
- **v2** schemas use **USD** only (`currency: "USD"`) and represent monetary values as **integer strings in minor units** (e.g. cents) using `*_minor` fields.
- **v1** schemas remain for backward compatibility.

## Schemas (selected)
### `bounties/`
- `post_bounty_request.v1.json`, `post_bounty_request.v2.json`
- `post_bounty_response.v1.json`, `post_bounty_response.v2.json`
- `escrow_hold_request.v1.json`, `escrow_hold_request.v2.json`
- `bounty.v1.json`, `bounty.v2.json`

### `escrow/`
- `escrow.v1.json`, `escrow.v2.json`

### `auth/`
- `scoped_token_claims.v1.json`

### `identity/`
- `owner_attestation.v1.json`
- `did_rotation.v1.json`

### `poh/`
- `commit_proof.v1.json`
- `proof_bundle.v1.json`
- `event_chain.v1.json`
- `receipt_binding.v1.json`
- `urm.v1.json`
- `execution_attestation.v1.json`
