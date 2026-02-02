Below is an implementation roadmap to complete the remaining failing stories in branch **`ralph/clawverify-phase1-trust`** for **clawverify Worker**.

Referenced inputs:
- PRD: `02-Projects/clawbureau/monorepo/docs/prds/clawverify.md`
- Current Worker router: `02-Projects/clawbureau/monorepo-worktrees-trust/clawverify/services/clawverify/src/index.ts`
- Current types: `.../src/types.ts`
- Schema allowlist/validators: `.../src/schema-registry.ts`
- Schema docs registry: `.../src/schema-docs.ts`
- JSON Schemas (authoritative for payloads):
  - Owner attestation: `02-Projects/clawbureau/monorepo/packages/schema/identity/owner_attestation.v1.json`
  - Commit proof: `02-Projects/clawbureau/monorepo/packages/schema/poh/commit_proof.v1.json`
  - Scoped token claims: `02-Projects/clawbureau/monorepo/packages/schema/auth/scoped_token_claims.v1.json`

Important mismatch to fix first (otherwise you’ll implement the wrong shapes):
- `schema-docs.ts` currently documents **different** owner_attestation/commit_proof/scoped_token payload fields than the JSON schema files above. For example:
  - `schema-docs.ts` “owner_attestation” uses `subject_did` but schema requires `agent_did`, `owner_provider`, `owner_subject_hash_b64u`, etc.
  - `schema-docs.ts` “commit_proof” uses `repo_claim_id`, `repository`, but schema requires `repo_url` (URI) and `agent_did`.
  - `schema-docs.ts` “scoped_token” is described as `token_id/audience/expires_at`, but schema is JWT-like claims: `sub/aud/scope/iat/exp/...`.
You should align implementation + docs + examples to the JSON schema files (Files 9–11).

---

## 1) Endpoints to add (exact paths/methods + request/response shapes)

### A. CVF-US-010 — Verify owner attestations
**POST `/v1/verify/owner-attestation`**

Request body:
```json
{
  "envelope": {
    "envelope_version": "1",
    "envelope_type": "owner_attestation",
    "payload": {
      "attestation_version": "1",
      "attestation_id": "attest_...",
      "agent_did": "did:key:...",
      "owner_provider": "worldid",
      "owner_subject_hash_b64u": "base64url...",
      "issued_at": "2026-02-02T12:00:00Z",
      "expires_at": "2027-02-02T12:00:00Z",
      "verification_level": "device|face|...",
      "proof_url": "https://...",
      "provider_ref": "provider-specific-id",
      "metadata": {}
    },
    "payload_hash_b64u": "base64url...",
    "hash_algorithm": "SHA-256",
    "signature_b64u": "base64url...",
    "algorithm": "Ed25519",
    "signer_did": "did:key:... (attester DID)",
    "issued_at": "2026-02-02T12:00:00Z"
  }
}
```

Response body:
```json
{
  "result": {
    "status": "VALID",
    "reason": "Owner attestation envelope verified",
    "envelope_type": "owner_attestation",
    "signer_did": "did:key:...",
    "verified_at": "..."
  },
  "owner_status": "VERIFIED",
  "attestation": {
    "attestation_id": "attest_...",
    "agent_did": "did:key:...",
    "owner_provider": "worldid",
    "provider_ref": "....",
    "expires_at": "....",
    "issued_at": "...."
  },
  "error": { "code": "...", "message": "...", "field": "..." }
}
```

Where `owner_status` is one of:
- `"VERIFIED"` (signature valid + not expired + provider reference acceptable)
- `"EXPIRED"` (cryptographically valid but expired)
- `"UNKNOWN"` (cryptographically valid, not expired, but provider reference missing/unresolvable/unsupported)

HTTP status behavior:
- `200` if `result.status === "VALID"` (even if `owner_status` is UNKNOWN; see rules below)
- `422` if `result.status === "INVALID"`

---

### B. CVF-US-011 — Verify commit proofs
**POST `/v1/verify/commit-proof`**

Request body:
```json
{
  "envelope": {
    "envelope_version": "1",
    "envelope_type": "commit_proof",
    "payload": {
      "proof_version": "1",
      "commit_sha": "40hex...",
      "repo_url": "https://github.com/org/repo",
      "agent_did": "did:key:...",
      "issued_at": "2026-02-02T12:00:00Z",

      "run_id": "run_...",
      "proof_bundle_hash_b64u": "base64url...",
      "harness": { "id": "claw", "version": "1" },
      "metadata": {}
    },
    "payload_hash_b64u": "base64url...",
    "hash_algorithm": "SHA-256",
    "signature_b64u": "base64url...",
    "algorithm": "Ed25519",
    "signer_did": "did:key:... (agent DID)",
    "issued_at": "2026-02-02T12:00:00Z"
  },

  "repo_claim": {
    "claim_id": "claim_...",
    "repo_url": "https://github.com/org/repo",
    "agent_did": "did:key:...",
    "status": "active"
  }
}
```

Notes:
- `repo_claim` is **optional**. If absent, clawverify calls future `clawclaim` service; until then you stub it (details in section 3).

Response body:
```json
{
  "result": {
    "status": "VALID",
    "reason": "Commit proof verified",
    "envelope_type": "commit_proof",
    "signer_did": "did:key:...",
    "verified_at": "..."
  },
  "commit": {
    "repo_url": "https://github.com/org/repo",
    "commit_sha": "....",
    "agent_did": "did:key:...",
    "run_id": "run_...",
    "proof_bundle_hash_b64u": "..."
  },
  "repo_claim": {
    "lookup": "PROVIDED|CLAWCLAIM|UNAVAILABLE",
    "status": "FOUND|NOT_FOUND|MISMATCH",
    "claim_id": "claim_..."
  },
  "error": { "code": "...", "message": "...", "field": "..." }
}
```

HTTP status:
- `200` if VALID
- `422` if INVALID (including “repo claim not found/mismatch”)

---

### C. CVF-US-013 — Scoped token introspection
**POST `/v1/token/introspect`** (RFC-7662-ish semantics, but for your signed envelope tokens)

Request body:
```json
{
  "token": {
    "envelope_version": "1",
    "envelope_type": "scoped_token",
    "payload": {
      "token_version": "1",
      "sub": "did:key:... (agent DID)",
      "owner_ref": "optional attestation hash or id",
      "aud": "https://service.example.com",
      "scope": ["read:artifacts", "verify:bundle"],
      "policy_hash_b64u": "base64url...",
      "token_scope_hash_b64u": "base64url...",
      "spend_cap": 10,
      "mission_id": "mission_...",
      "jti": "tok_...",
      "iat": 1760000000,
      "exp": 1760003600,
      "nonce": "..."
    },
    "payload_hash_b64u": "base64url...",
    "hash_algorithm": "SHA-256",
    "signature_b64u": "base64url...",
    "algorithm": "Ed25519",
    "signer_did": "did:key:... (issuer DID)",
    "issued_at": "2026-02-02T12:00:00Z"
  },

  "expected_audience": "https://service.example.com",
  "required_scopes": ["verify:bundle"]
}
```

Response body (always `200` for well-formed requests; `active=false` on failures):
```json
{
  "active": true,
  "sub": "did:key:...",
  "aud": ["https://service.example.com"],
  "scope": ["read:artifacts", "verify:bundle"],
  "owner_ref": "optional",
  "iat": 1760000000,
  "exp": 1760003600,
  "policy_hash_b64u": "base64url...",
  "token_scope_hash_b64u": "base64url...",
  "jti": "tok_...",
  "issuer_did": "did:key:...",
  "error": { "code": "...", "message": "...", "field": "..." }
}
```

HTTP status:
- `400` parse/shape errors (missing `token`, not JSON, etc)
- `200` with `active:false` for invalid signature/expired/audience mismatch/scope insufficient

---

### D. CVF-US-012 — One-call agent verification
**POST `/v1/verify/agent`**

Request body:
```json
{
  "agent_did": "did:key:...",
  "owner_attestation": { "envelope": { "... owner_attestation SignedEnvelope ..." } },
  "proof_bundle": { "envelope": { "... proof_bundle SignedEnvelope ..." } },
  "scoped_token": { "token": { "... scoped_token SignedEnvelope ..." } },

  "expected_audience": "https://service.example.com",
  "required_scopes": ["verify:bundle"],
  "expected_policy_hash_b64u": "base64url..."
}
```

Response body (no ambiguity: each component has an explicit status + the “overall” is computed deterministically):
```json
{
  "agent_did": "did:key:...",
  "verified_at": "2026-02-02T12:00:00Z",

  "did": {
    "valid_format": true,
    "method": "key",
    "errors": []
  },

  "owner": {
    "present": true,
    "owner_status": "VERIFIED|EXPIRED|UNKNOWN",
    "result": { "status": "VALID|INVALID", "reason": "...", "verified_at": "..." }
  },

  "poh": {
    "present": true,
    "trust_tier": "unknown|basic|verified|attested|full",
    "bundle_result": { "status": "VALID|INVALID", "reason": "...", "verified_at": "..." }
  },

  "policy": {
    "present": true,
    "token_active": true,
    "audience_ok": true,
    "scope_ok": true,
    "policy_ok": true
  },

  "overall": {
    "status": "PASS|FAIL",
    "fail_reasons": ["DID_INVALID|TOKEN_EXPIRED|..."],
    "risk_flags": ["OWNER_UNKNOWN", "NO_POH", "POLICY_MISSING"]
  }
}
```

HTTP status:
- `200` always if request parses; **fail-closed is inside `overall.status`**.
  - Rationale: one-call endpoint is an aggregator; callers should not have to infer meaning from a 422 vs 200 when some components are optional/present/missing.

---

## 2) Deterministic, fail-closed validation for each new object type

Implement new modules following the same pattern used in:
- `verify-message.ts` (File 7)
- `verify-proof-bundle.ts` (File 8)

### Shared rules (copy the pattern already used)
For each new verifier module:
1. Validate envelope is an object and has all required envelope fields (`validateEnvelopeStructure`)
2. Fail-closed allowlist checks using `schema-registry.ts` (File 5):
   - `isAllowedVersion`
   - `isAllowedType`
   - `isAllowedAlgorithm`
   - `isAllowedHashAlgorithm`
3. Validate `signer_did` via `isValidDidFormat`
4. Validate base64url fields via `isValidBase64Url`
5. Validate `issued_at` via `isValidIsoDate`
6. Validate payload structure via **hand-written type checks** (no permissive parsing)
7. Recompute hash via `computeHash(payload, hash_algorithm)` and require exact match with `payload_hash_b64u`
8. Extract public key only from `did:key` for now (matches existing crypto approach in File 7/8):
   - `extractPublicKeyFromDidKey`
9. Verify signature over **the UTF-8 bytes of** `payload_hash_b64u` (matches File 7/8)
10. Return deterministic error codes and set `INVALID` for anything unexpected

### New payload validators (shape rules)

#### Owner attestation payload (from `owner_attestation.v1.json`, File 9)
Fail-closed checks:
- `attestation_version === "1"`
- `attestation_id` non-empty string
- `agent_did` must pass `isValidDidFormat`
- `owner_provider` ∈ `["worldid","onemolt","oauth","other"]`
- `owner_subject_hash_b64u` must be base64url (use `isValidBase64Url`)
- `issued_at` ISO date-time (use `isValidIsoDate`)
- `expires_at` if present must be ISO date-time
- `proof_url` if present must be a string (optional: minimal URI check)
- `provider_ref` if present must be non-empty string and length-bounded (e.g., ≤ 256)

#### Commit proof payload (from `commit_proof.v1.json`, File 10)
Fail-closed checks:
- `proof_version === "1"`
- `commit_sha` matches `^[0-9a-f]{40}$` (strict)
- `repo_url` is string; minimally require `new URL(repo_url)` succeeds
- `agent_did` passes `isValidDidFormat`
- `issued_at` passes `isValidIsoDate`
- `proof_bundle_hash_b64u` if present must be base64url
- `harness` if present must be `{id:string, version:string}` and no extra properties

**Critical binding rule** (prevents “I sign someone else’s agent DID”):
- require `envelope.signer_did === payload.agent_did`
- if not, return INVALID with a dedicated code (see suggested codes below)

#### Scoped token claims payload (from `scoped_token_claims.v1.json`, File 11)
Fail-closed checks:
- `token_version === "1"`
- `sub` passes `isValidDidFormat`
- `aud` is string or array of strings; normalize to array
- `scope` is array of strings with `minItems: 1`
- `iat` and `exp` are integers (epoch seconds)
- `exp > now` (else expired)
- optional: `iat <= now + clockSkewSec` (else invalid)
- optional fields validated if present:
  - `policy_hash_b64u`, `token_scope_hash_b64u` base64url
  - `spend_cap` number ≥ 0

---

## 3) Commit proofs: verifying `commit.sig.json`, what is signed, repo-claim validation (future clawclaim + interim stubs)

### A. What is `commit.sig.json` (proposed v1)
Define `commit.sig.json` as *exactly* the SignedEnvelope used by `/v1/verify/commit-proof`:
- `SignedEnvelope<CommitProofPayloadV1>`
- stored in repo (recommended path): `.claw/commit.sig.json`

This aligns with the existing envelope verification model (Files 7/8): signature is over `payload_hash_b64u`, where `payload_hash_b64u = hash(JSON.stringify(payload))`.

### B. What should be signed (must be stable + bind identity + bind repo + bind commit)
Sign the commit proof payload (File 10 fields + optional bindings) containing:
- `commit_sha` (commit object identifier; already binds the Git commit content)
- `repo_url` (binds proof to a repository)
- `agent_did` (binds to agent identity)
- `issued_at` (replay window basis)
- optional but strongly recommended for phase1:
  - `run_id` (bind to a run/session)
  - `proof_bundle_hash_b64u` (bind commit to an already-verified proof bundle)

### C. What clawverify can verify *now* (without Git hosting integration)
In phase1 Worker, you can deterministically verify:
1. Envelope validity (fail-closed)
2. Signature validity
3. Agent binding: `signer_did === payload.agent_did`
4. Repo claim exists and matches (see below)

You **cannot** prove `commit.sig.json` is actually present in the commit tree without:
- fetching repo contents at that commit, or
- receiving additional proof material (e.g., a Git object proof bundle)

So be explicit in response `reason` and in docs: this verifies the cryptographic commit proof + claim linkage, not the hosting provider state.

### D. Repo claim validation (future clawclaim + interim stub)
PRD dependency mentions `clawclaim.com` (File 1 §5, story CVF-US-011).

#### Proposed clawclaim API (future)
- `GET https://clawclaim.com/v1/claims/repo?repo_url=...&agent_did=...`
Response:
```json
{
  "found": true,
  "claim": {
    "claim_id": "claim_...",
    "repo_url": "https://github.com/org/repo",
    "agent_did": "did:key:...",
    "status": "active",
    "issued_at": "..."
  }
}
```

Validation rules:
- Must be `found=true`
- `claim.repo_url === payload.repo_url`
- `claim.agent_did === payload.agent_did`
- `claim.status === "active"`

Fail-closed outcomes:
- `NOT_FOUND` → commit proof INVALID
- `MISMATCH` → INVALID
- network/error/unconfigured → INVALID (or “UNAVAILABLE” but still INVALID)

#### Interim stub implementation (no live deploy; PR-only)
Add an internal client module:
- `src/clawclaim-client.ts` exporting `lookupRepoClaim(repo_url, agent_did, env?)`

Behavior:
- If request includes `repo_claim`, validate it locally and skip remote.
- Else if `env.CLAWCLAIM_BASE_URL` missing → return `{ lookup:"UNAVAILABLE", status:"NOT_FOUND" }` and mark INVALID (fail-closed).
- Else `fetch()` the future endpoint; in tests mock `globalThis.fetch`.

This keeps production fail-closed and tests deterministic.

---

## 4) Owner attestations: expiry rules, provider references, status return values

Based on schema `owner_attestation.v1.json` (File 9) and story acceptance criteria (File 1 CVF-US-010):

### A. Expiry rules (deterministic)
- If `payload.expires_at` is present:
  - if `expires_at < now` ⇒ `owner_status="EXPIRED"`
  - treat as `result.status="INVALID"` with `error.code="EXPIRED"` (consistent with message expiry in `verify-message.ts`, File 7)
- If `payload.expires_at` is absent:
  - `owner_status` can still be `"UNKNOWN"` or `"VERIFIED"` depending on provider reference rules below
  - but you should emit a risk flag in one-call verify: `OWNER_NO_EXPIRY`
  - do **not** silently assume TTLs in verifier (that’s non-deterministic across callers)

### B. Provider reference rules
The PRD asks to “check provider reference”; schema makes `provider_ref` optional.

Fail-closed-but-usable approach:
- Envelope validity is independent: signature/hash/type correctness can still be VALID.
- Owner *status* uses provider reference rules:

`owner_status="VERIFIED"` only if all are true:
1. envelope cryptographically valid
2. not expired
3. `owner_provider` is supported enum
4. one of the following “provider evidence” is present:
   - `provider_ref` is a non-empty string (bounded length), OR
   - `proof_url` is present (optional, but if present should be a valid URL)

Otherwise:
- if cryptographically valid and not expired → `owner_status="UNKNOWN"`

### C. Status return values (explicit)
Return both:
- `result.status` = `"VALID"|"INVALID"` for the envelope verification itself
- `owner_status` = `"VERIFIED"|"EXPIRED"|"UNKNOWN"` for the sybil-resistance interpretation

This avoids overloading `VALID/INVALID` with “expired vs unknown” semantics.

---

## 5) Token introspection: signature/expiry/audience/scope validation; what to log; suggested error codes

### A. Validation rules (fail-closed)
For `/v1/token/introspect`:

1. Verify token envelope (same structure checks as other verifiers)
2. Verify `envelope_type === "scoped_token"`
3. Verify token payload per schema (File 11)
4. Signature verification:
   - signed message is `payload_hash_b64u` UTF-8 bytes (consistent with File 7/8)
5. Expiry:
   - `exp <= nowEpochSec` ⇒ `active=false`, `error.code="EXPIRED"`
6. Audience:
   - normalize `aud` to string[]
   - if `expected_audience` is provided, require it in `aud[]` else fail-closed:
     - `active=false`, `error.code="AUDIENCE_MISMATCH"` (new code recommended)
7. Scope:
   - if `required_scopes` is provided, require all are included in `scope[]`
     - else `active=false`, `error.code="INSUFFICIENT_SCOPE"` (new code recommended)
8. (Optional but recommended) time sanity:
   - if `iat > now + skewSec` ⇒ inactive with `IAT_IN_FUTURE`

### B. What to log (per CVF-US-013)
PRD: “Log token hash to clawlogs” (File 1 CVF-US-013).

You already have a D1-backed audit log system (File 3 uses `writeAuditLogEntry`; File 4 defines types). Use it as the phase1 logging substrate:

Log fields:
- `request_hash_b64u`: hash of `{ token_id? (jti), token_hash_b64u, sub, aud }` or just `computeRequestHash(body)` (File 3 already does this pattern)
- `envelope_type`: `"scoped_token"`
- `status`: `"VALID"` if `active=true`, else `"INVALID"`
- `signer_did`: prefer `token.payload.sub` (the agent identity being authorized), or store issuer in a separate field (but schema currently doesn’t support extra audit fields)

Also log a token fingerprint:
- `token_hash_b64u = computeHash(tokenEnvelope, "SHA-256")` (hash of whole token envelope object, not just payload) and include it in response for correlation.

### C. Suggested error codes to add
Current `VerificationErrorCode` in `src/types.ts` (File 4) doesn’t include auth-specific codes. Add:
- `AUDIENCE_MISMATCH`
- `INSUFFICIENT_SCOPE`
- `IAT_IN_FUTURE`
- `SUBJECT_MISMATCH` (useful for commit proofs and one-call)
- `REPO_CLAIM_NOT_FOUND`
- `REPO_CLAIM_MISMATCH`
- `DEPENDENCY_UNAVAILABLE` (for clawclaim unreachable)

If you want to avoid widening codes now, you can still return `MALFORMED_ENVELOPE` + message strings, but tests/clients will be much less deterministic.

---

## 6) One-call verify: aggregating DID validity + owner status + PoH tier + policy compliance without ambiguity

Key design goal: clients must not infer semantics from missing fields or mixed statuses.

### A. Deterministic aggregation rules
Given request includes `agent_did` plus optional components, compute:

**DID block**
- `valid_format`: `isValidDidFormat(agent_did)` (File 5)
- `method`: parse `did:key` vs `did:web`
- If invalid format → `overall.status="FAIL"` and include `DID_INVALID`

**Owner block**
- If owner_attestation missing → `present=false`, `owner_status="UNKNOWN"` and add risk flag `OWNER_MISSING`
- If present → call `verifyOwnerAttestation(envelope)`
  - propagate both `result.status` and `owner_status`

**PoH block**
- If proof_bundle missing → `present=false`, `trust_tier="unknown"` and risk `NO_POH`
- If present → call `verifyProofBundle(envelope)` (already exists, File 8)
  - Use `trust_tier` from result, but do not reinterpret it silently.
  - If you need “PoH tier” specifically, define it explicitly in response as derived-from-receipts-only; otherwise keep `trust_tier` and call it that.

**Policy block**
- If scoped_token missing → `present=false`, `token_active=false`, add risk `TOKEN_MISSING`
- If present → call `introspectToken(token, expected_audience, required_scopes)`
  - `policy_ok`: if `expected_policy_hash_b64u` provided, require token payload has matching `policy_hash_b64u`

**Overall**
- `PASS` only if:
  - DID valid_format true
  - if token provided: token_active true AND (audience_ok, scope_ok, policy_ok as applicable)
  - if owner_attestation provided: owner_status === VERIFIED (or make this caller-controlled via a request flag like `require_owner_verified: true`)
  - if proof_bundle provided: bundle result VALID (and optionally require minimum tier)

To avoid ambiguity, include:
- `fail_reasons`: machine-readable list
- `risk_flags`: weaker warnings that don’t necessarily fail

---

## 7) Test plan and fixture examples

### A. Unit test coverage (module-level)
Add tests for:
1. `verify-owner-attestation.ts`
   - valid envelope, not expired, provider_ref present ⇒ VALID + owner_status VERIFIED
   - valid envelope, expired ⇒ INVALID + owner_status EXPIRED + error EXPIRED
   - valid envelope, provider_ref missing ⇒ VALID + owner_status UNKNOWN
   - invalid signature ⇒ INVALID + SIGNATURE_INVALID
   - payload hash mismatch ⇒ INVALID + HASH_MISMATCH
2. `verify-commit-proof.ts`
   - valid + signer_did matches agent_did + repo_claim provided and matches ⇒ VALID
   - signer_did != agent_did ⇒ INVALID + SUBJECT_MISMATCH
   - commit_sha wrong format ⇒ INVALID + MALFORMED_ENVELOPE
   - repo claim missing and clawclaim unavailable ⇒ INVALID + DEPENDENCY_UNAVAILABLE (fail-closed)
   - repo claim found but mismatched agent_did ⇒ INVALID + REPO_CLAIM_MISMATCH
3. `token-introspect.ts`
   - valid token, exp in future, aud ok, required_scopes ok ⇒ active true
   - expired ⇒ active false + EXPIRED
   - audience mismatch ⇒ active false + AUDIENCE_MISMATCH
   - insufficient scope ⇒ active false + INSUFFICIENT_SCOPE
4. `verify-agent.ts`
   - only DID provided (others missing) ⇒ overall FAIL with risk flags set (or PASS if you decide optional)
   - all components valid ⇒ PASS
   - token invalid ⇒ FAIL with TOKEN_* reason

### B. Fixture strategy (deterministic signing)
Use a fixed Ed25519 test keypair and generate envelopes in-test, mirroring how existing tests likely handle artifact/message/receipt.

Fixtures to add (suggested paths):
- `services/clawverify/test/fixtures/owner_attestation.valid.json`
- `.../owner_attestation.expired.json`
- `.../commit_proof.valid.json`
- `.../scoped_token.valid.json`

Important: don’t copy the examples in `schema-docs.ts` verbatim because those example signatures are placeholders (see File 6 examples like `"example_signature"`).

### C. Mocking clawclaim lookup
In commit proof tests:
- mock `globalThis.fetch` to return deterministic JSON for the clawclaim endpoint
- also test the “unavailable” path by not setting `env.CLAWCLAIM_BASE_URL` and expecting fail-closed invalid

---

## 8) Small PR slicing plan (PR-only; git-signed commits)

Sequence PRs so each is reviewable and keeps main branch green.

### PR 1 — Align types + schema docs to authoritative JSON schemas
Files:
- `src/types.ts` (File 4): add `OwnerAttestationPayloadV1`, `CommitProofPayloadV1`, `ScopedTokenClaimsV1`; extend response types.
- `src/schema-docs.ts` (File 6): update payload fields + examples for:
  - `owner_attestation` to match `owner_attestation.v1.json` (File 9)
  - `commit_proof` to match `commit_proof.v1.json` (File 10)
  - `scoped_token` to match `scoped_token_claims.v1.json` (File 11)
Outcome: documentation endpoints reflect reality; no runtime behavior change yet.

### PR 2 — Implement CVF-US-010 verifier + endpoint
Add:
- `src/verify-owner-attestation.ts`
Modify:
- `src/index.ts` (File 3): route `POST /v1/verify/owner-attestation`
- optionally: audit log entry for `owner_attestation`
Add tests + fixtures.

### PR 3 — Add clawclaim client stub + commit proof verification + endpoint
Add:
- `src/clawclaim-client.ts` (stub + fetch-based future API)
- `src/verify-commit-proof.ts`
Modify:
- `src/index.ts`: route `POST /v1/verify/commit-proof`
Add tests covering provided-claim + fetched-claim + unavailable.

### PR 4 — Implement CVF-US-013 token introspection endpoint (+ logging)
Add:
- `src/token-introspect.ts`
Modify:
- `src/index.ts`: route `POST /v1/token/introspect`
- use `writeAuditLogEntry` with `envelope_type: 'scoped_token'` (already allowlisted in `types.ts`, File 4)
Add tests for active/inactive paths.

### PR 5 — Implement CVF-US-012 one-call agent verification endpoint
Add:
- `src/verify-agent.ts` (aggregator calling existing verifiers)
Modify:
- `src/index.ts`: route `POST /v1/verify/agent`
Add tests emphasizing “no ambiguity” aggregation rules.

### PR 6 — Cleanup/consistency pass
- Ensure error codes are consistent across verifiers
- Ensure all new endpoints are documented in schema registry endpoints (if you expose endpoint docs)
- Tighten base64url/date parsing consistency

---

If you want, I can draft the exact TypeScript interfaces and skeleton modules (`verify-owner-attestation.ts`, `verify-commit-proof.ts`, `token-introspect.ts`, `verify-agent.ts`) in the style of `verify-message.ts` (File 7) so your PRs are mostly wiring + tests.
