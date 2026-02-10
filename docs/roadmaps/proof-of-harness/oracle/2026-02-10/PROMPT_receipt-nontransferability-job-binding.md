# Goal
We need the most trustworthy (hard-to-game) but low-friction design to prevent **receipt borrowing / transfer attacks** in Claw Bureau Proof-of-Harness (PoH).

Today:
- `clawproxy` issues signed gateway receipts with binding fields (`run_id`, `event_hash_b64u`, `nonce`, `policy_hash`, `token_scope_hash_b64u`).
- `clawverify` verifies receipts (signature + binding to event_chain) and outputs `proof_tier`.
- `clawbounties` has replay DB (rejects reused `(agent_did, run_id)` and `(receipt_signer_did, receipt_id)`), but a worker can still borrow *previously-unused* receipts/event chains from another agent/run and submit them under their own DID.
- We added:
  - deterministic CST `token_scope_hash_b64u` issuance in `clawscope` (sha256_b64u(JCS(...)) excluding iat/exp/jti/nonce)
  - optional CST `policy_hash_b64u` pinning
  - `clawproxy` treats CST `policy_hash_b64u` as authoritative and rejects mismatching `X-Policy-Hash`.
- For CWC bounties, `clawbounties` enforces `binding.policy_hash` match, but does **not** enforce `binding.token_scope_hash_b64u` yet.

# Ask
Propose the best design that:
1) Is **very hard to game** (fail-closed; prevents receipt borrowing).
2) Creates **credible trust for humans + agents** (clear story, auditable evidence).
3) Is **easy** for workers/requesters to use (minimal manual config; works with OpenClaw plugin + external harness shims).
4) Avoids heavy operational burden (no complex infra, but ok to add one small endpoint + a D1 column/migration).

# Evaluate options
Compare at least:
- (A) Add explicit `client_did` (or subject DID) into signed receipts and enforce `client_did == proof_bundle.agent_did`.
- (B) Marketplace-issued **job-scoped CSTs** and enforcement that verified receipts have `binding.token_scope_hash_b64u == expected`.
- (C) Combination of both.

# Required output
1) Recommendation (pick one, justify).
2) Threat model: show how the recommended option defeats receipt borrowing and what residual attacks remain.
3) Concrete implementation plan (step-by-step) across services, with minimal schema/DB changes:
   - What to change in `clawbounties` (where to store expected hashes; how to issue CST; how to enforce at submit).
   - What to change in `clawscope` (if anything).
   - What to change in `clawproxy` / `clawverify` (if anything).
   - OpenClaw provider-clawproxy plugin / external shim UX changes.
4) Backward compatibility strategy:
   - How to roll out without breaking existing non-confidential bounties.
   - Where to enforce only for CWC first.
5) Deterministic error codes/messages (fail-closed) for marketplace enforcement.

Keep the plan realistic for this codebase (Cloudflare Workers, D1, DOs, Ajv-standalone constraint in Workers).
