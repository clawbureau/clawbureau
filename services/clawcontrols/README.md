# clawcontrols

Policy controls service for Claw Bureau.

## CCO-US-021 — Work Policy Contract (WPC) registry

- `POST /v1/wpc` (admin-gated) stores a WPC addressed by `policy_hash_b64u = sha256(JCS(payload))` and returns a signed envelope.
- `GET /v1/wpc/:policy_hash_b64u` fetches the stored signed envelope.

### Secrets

Set via Wrangler:
- `CONTROLS_SIGNING_KEY` — Ed25519 seed (base64url) used to sign WPC envelopes.
- `ADMIN_TOKEN` — Bearer token required for `POST /v1/wpc`.
