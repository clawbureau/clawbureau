# @clawbureau/schema

Shared JSON schemas for Claw Bureau services.

## Directories
- `auth/` — scoped token claims.
- `bounties/` — marketplace request/response schemas.
- `escrow/` — escrow record schemas.
- `identity/` — ownership/attestation schemas.
- `policy/` — policy contracts (Work Policy Contracts / WPC).
- `poh/` — proof-of-harness schemas.
- `payments/` — machine-payment settlement schemas.
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

### `policy/`
- `work_policy_contract.v1.json`
- `work_policy_contract_envelope.v1.json`
- `confidential_work_contract.v1.json`
- `confidential_work_contract_envelope.v1.json`

### `payments/`
- `machine_payment_settlement.v1.json`
- `machine_payment_settlement_envelope.v1.json`

### `poh/`
- `commit_proof.v1.json`
- `gateway_receipt.v1.json`
- `gateway_receipt_envelope.v1.json`
- `web_receipt.v1.json`
- `web_receipt_envelope.v1.json`
- `proof_bundle.v1.json`
- `proof_bundle_envelope.v1.json`
- `event_chain.v1.json`
- `receipt_binding.v1.json`
- `urm.v1.json`
- `execution_attestation.v1.json`
- `execution_attestation_envelope.v1.json`
- `prompt_pack.v1.json`
- `system_prompt_report.v1.json`
- `trust_pulse.v1.json` (self-reported UX artifact; non-tier)
- `model_identity.v1.json`
- `derivation_attestation.v1.json`
- `derivation_attestation_envelope.v1.json`
- `audit_result_attestation.v1.json`
- `audit_result_attestation_envelope.v1.json`
- `log_inclusion_proof.v1.json`
- `export_bundle_manifest.v1.json`
- `export_bundle.v1.json`

### `fixtures/`
- `protocol-m-golden-vector.v1.json`
- `log_inclusion_proof_golden.v1.json`
- `web_receipt_golden.v1.json`
- `export_bundle_golden.v1.json`
