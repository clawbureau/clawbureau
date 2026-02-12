# Compatibility Note — Agent C reviewer contract (clawrep)

Date: 2026-02-12
Scope: `POST /v1/reviewers/select`, `GET /v1/reviewers/:did`

## Result

No breaking request/response delta against existing `packages/bounties` reviewer client contract.

## Request contract (compatible additive extension)

`POST /v1/reviewers/select`
- Existing fields preserved:
  - `bounty_id: string`
  - `difficulty_scalar: number`
  - `quorum_size: number`
  - `min_reputation_score?: number`
  - `require_owner_verified?: boolean`
  - `exclude_dids?: string[]`
  - `submission_proof_tier?: "unknown"|"self"|"gateway"|"sandbox"|"tee"|"witnessed_web"`
- New optional fields (non-breaking):
  - `requester_did?: string`
  - `worker_did?: string`

## Response contract (compatible additive extension)

`POST /v1/reviewers/select`
- Existing fields preserved:
  - `bounty_id: string`
  - `reviewers: Array<{ reviewer_did: string; reputation_score: number; is_owner_verified: boolean; owner_attestation_ref?: string }>`
  - `selected_at: string (ISO datetime)`
- New optional/additive field:
  - `selection_metadata` (deterministic anti-collusion reasoning + exclusion counters)

`GET /v1/reviewers/:did`
- `404` for unknown reviewer DID
- `200` with:
  - `reviewer_did: string`
  - `reputation_score: number`
  - `is_owner_verified: boolean`
  - `owner_attestation_ref?: string`

## Determinism note

Selection ordering is deterministic for identical input (same request payload + same underlying reviewer state).
