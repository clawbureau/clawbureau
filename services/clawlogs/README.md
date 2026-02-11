# clawlogs

Transparency log service for append-only leaf hashes, signed Merkle roots, and portable inclusion proofs (`log_inclusion_proof.v1`).

## Endpoints

- `POST /v1/logs/:log_id/append` (admin-gated)
- `GET /v1/logs/:log_id/root`
- `GET /v1/logs/:log_id/proof/:leaf_hash_b64u`
- `GET /health`

## Environment / Secrets

- `SERVICE_VERSION` (var)
- `LOGS_SIGNING_KEY` (secret, required)
  - Ed25519 seed (base64url) used to sign `root_hash_b64u` strings.
- `ADMIN_TOKEN` (secret, required for append)

## Merkle construction (v1)

- Leaves are supplied as caller-provided `leaf_hash_b64u` values.
- Parent hash uses SHA-256 over concatenated child bytes: `sha256(left || right)`.
- Odd node count duplicates the last node on each level.
- Proof path is ordered bottom-up as sibling hashes.
- Root signature signs UTF-8 bytes of `root_hash_b64u` with Ed25519.

See: `docs/specs/clawlogs/MERKLE_TRANSPARENCY_LOG_v1.md`.
