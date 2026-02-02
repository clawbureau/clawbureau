## Context (what’s already there)
- Proxy request/receipt flow lives in `services/clawproxy/src/index.ts` (POST `/v1/proxy/:provider`) and `services/clawproxy/src/receipt.ts` + `services/clawproxy/src/crypto.ts`.
- Policy headers + confidential mode are enforced in `services/clawproxy/src/policy.ts` (notably `X-Confidential-Mode`, `X-Policy-Hash`, `X-Receipt-Privacy-Mode`).
- Receipt schema currently binds `policyHash` via `ReceiptBinding.policyHash` in `services/clawproxy/src/types.ts` and includes binding in the signed payload via `createSigningPayload()` in `services/clawproxy/src/receipt.ts`.
- Scoped token claim schema is in `packages/schema/auth/scoped_token_claims.v1.json` and includes `token_scope_hash_b64u`, `policy_hash_b64u`, `owner_ref`, `aud`, `scope`, `iat`, `exp`, etc.

The remaining failing stories (per `monorepo-worktrees-trust/clawproxy/prd.json`) are CPX-US-011/012/013.

---

# 1) Token format + edge validation procedure (signature/expiry/audience/scope/owner_ref)

## Token format: CST v1 as JWS (JWT-compatible), Ed25519 (EdDSA)
**Wire format:** JWS Compact Serialization (three base64url segments):  
`<protectedHeaderB64u>.<claimsB64u>.<signatureB64u>`

**Protected header (example):**
```json
{
  "typ": "JWT",
  "alg": "EdDSA",
  "kid": "cst-kid-2026-01"
}
```

**Claims (must conform to `packages/schema/auth/scoped_token_claims.v1.json`):**
Required:
- `token_version: "1"`
- `sub`: Agent DID (string)
- `aud`: string or string[] (must include clawproxy audience)
- `scope`: string[] (min 1)
- `iat`, `exp`: epoch seconds

Optional but important for these stories:
- `owner_ref`: opaque string (treated as an attestation hash; do not interpret)
- `policy_hash_b64u`: binds token to a specific WPC hash
- `token_scope_hash_b64u`: integrity commit to `scope` array
- `spend_cap`: number >= 0
- `mission_id`: string
- `jti`: string

## Canonical hashing rules (edge-friendly, deterministic)
### `token_scope_hash_b64u` computation (fail-closed)
Compute:
1. **Normalize scope list**
   - Trim each scope string.
   - Reject empty strings.
   - Sort lexicographically ascending (byte/Unicode codepoint order).
2. **Canonical string**
   - `canonicalScope = scopes.join("\n")`
3. **Hash**
   - `sha256(canonicalScope)` (bytes)
4. **Encode**
   - base64url without padding

Compare against `claims.token_scope_hash_b64u` using constant-time compare (or at least avoid early-return string compare patterns).

### Token hash for logs/receipts (never include raw token)
- `token_hash_hex = sha256(rawTokenString)` using existing `sha256()` in `services/clawproxy/src/crypto.ts` (it returns hex today).
- Store **only** this hash in receipts/logs.

## Audience rules (edge)
Define allowed audiences for clawproxy:
- `https://clawproxy.com`
- `did:web:clawproxy.com` (matches `PROXY_DID` in `services/clawproxy/src/index.ts`)

Validation:
- If `aud` is string: must equal one of allowed audiences.
- If `aud` is array: must contain at least one allowed audience.

## Signature verification (edge)
### Key discovery options (phase1-safe)
Because there is no deployed clawscope in this branch, implement **both** paths:

**Path A (preferred, production-like):** JWKS URL
- Add env: `CST_JWKS_URL?: string`
- Fetch and cache JWKS (Cloudflare `caches.default` + in-memory global)
- Choose key by `kid`
- Only accept OKP Ed25519 keys (`kty:"OKP"`, `crv:"Ed25519"`)
- Verify JWS signing input: `ASCII(protectedB64u + "." + claimsB64u)` using Ed25519 verify (use WebCrypto).

**Path B (tests/dev):** static Ed25519 public key
- Add env: `CST_PUBLIC_KEY_B64U?: string` (raw 32-byte public key, base64url)
- If set, ignore JWKS URL and just verify with this key.

(You already have `importEd25519PublicKey()` in `services/clawproxy/src/crypto.ts` which imports raw Ed25519 public key bytes.)

## Expiry / time rules
- `now = Math.floor(Date.now()/1000)`
- Fail if `exp <= now - CLOCK_SKEW_SEC`
- Fail if `iat > now + CLOCK_SKEW_SEC`
- Set `CLOCK_SKEW_SEC = 60` (constant)

## Scope semantics (minimal set to satisfy CPX-US-011/013)
Define required scopes for proxy invocation and platform-paid:
- `cpx:proxy:invoke` (required for any proxied request)
- Optional narrowing:
  - `cpx:provider:openai`
  - `cpx:provider:anthropic`
  - `cpx:provider:google`
- Platform-paid:
  - `cpx:pay:platform`

Validation:
- Must contain `cpx:proxy:invoke`
- If provider-specific scope exists in token set, require it for that provider (fail-closed).
  - Example: if token contains any `cpx:provider:*`, then the request provider must be included.
  - If you want stricter: always require `cpx:provider:<provider>` for all tokens.

## owner_ref handling
- Treat `owner_ref` as opaque string.
- Do not log it raw in confidential mode unless it is already a hash-like format (still okay, but keep it as-is and do not derive anything).
- Include it in receipt binding (optional) to support later audit chains.

---

# 2) How clawproxy should authenticate requests (headers, fallback, error codes)

## Headers to use
### CST (scoped token) header
Use standard bearer token:
- `Authorization: Bearer <CST_JWS>`

### Provider API key header (BYOK)
Move upstream credentials out of `Authorization` (because CST needs it):
- `X-Provider-Api-Key: <key>`
- Optional: `X-Provider-Authorization: Bearer <key>` (if clients prefer full header value)

### Client DID (rate limit key)
Already used by rate limiter (see `services/clawproxy/src/index.ts` + rate limiting notes in PRD JSON):
- `X-Client-DID: did:...` (unchanged)

## Fallback behavior (minimize breaking but still converge)
To avoid breaking CPX-US-001 clients immediately while implementing CPX-US-011:

1. If `Authorization` is `Bearer <something-with-2-dots>` → treat as CST.
2. Else if `Authorization` is present and **no CST** was found:
   - **Legacy mode (optional, controlled by env):**
     - If `env.PROXY_ALLOW_LEGACY_AUTH === "true"`: treat `Authorization` as provider API key (current behavior).
     - Otherwise: fail with `401 TOKEN_REQUIRED`.

This lets you keep tests stable while you migrate fixtures, and still make “CST required” the default in CI by setting the env in tests.

## Error codes + HTTP statuses
Use existing error response format in `services/clawproxy/src/index.ts` (`errorResponseWithRateLimit()`).

Recommended:
- Missing CST (when required): `401` `{code:"TOKEN_REQUIRED"}`
- Malformed token/JWS: `401` `{code:"TOKEN_INVALID"}`
- Signature invalid / unknown kid: `401` `{code:"TOKEN_INVALID_SIGNATURE"}` or `{code:"TOKEN_UNKNOWN_KID"}`
- Expired: `401` `{code:"TOKEN_EXPIRED"}`
- Audience mismatch: `403` `{code:"TOKEN_AUD_MISMATCH"}`
- Missing required scope: `403` `{code:"TOKEN_SCOPE_FORBIDDEN"}`
- Token/policy mismatch: `403` `{code:"TOKEN_POLICY_MISMATCH"}`
- Platform-paid requested but not allowed: `403` `{code:"PLATFORM_PAID_NOT_ALLOWED"}`
- Platform-paid requested but no reserve/ledger available: `503` `{code:"LEDGER_UNAVAILABLE"}` (fail closed)

---

# 3) Bind receipts to tokens and policies (fields, hashing, fail-closed)

## Receipt fields to embed (signed)
Today receipt signing payload includes `binding` (see `createSigningPayload()` in `services/clawproxy/src/receipt.ts`). Extend binding and/or receipt fields so the signature commits to auth/payment facts.

### Proposed additions (minimal surface area)
Update `ReceiptBinding` in `services/clawproxy/src/types.ts` to include:
```ts
export interface ReceiptBinding {
  runId?: string;
  eventHash?: string;
  nonce?: string;
  policyHash?: string;

  // NEW (auth binding)
  tokenHash?: string;            // sha256(token) hex
  tokenScopeHashB64u?: string;   // from claims.token_scope_hash_b64u
  ownerRef?: string;             // from claims.owner_ref
  missionId?: string;            // from claims.mission_id (optional)
}
```

And add a new optional section to `Receipt`:
```ts
export interface ReceiptPayment {
  mode: 'user' | 'platform';
  paid: boolean;
  ledgerRef?: string;
}

export interface Receipt {
  ...
  payment?: ReceiptPayment; // NEW
}
```

Then update `createSigningPayload()` in `services/clawproxy/src/receipt.ts` to include `payment` if present (just like `binding`/`privacyMode` today), so it is tamper-proof.

## Hashing rules
- `tokenHash`: `sha256(rawTokenString)` using `sha256()` from `services/clawproxy/src/crypto.ts` (hex output).
- `tokenScopeHashB64u`: use the value from the token claim, but also recompute and verify it during request auth (fail-closed on mismatch).

## Fail-closed requirements (CPX-US-012)
### Always fail closed if:
- CST is required and missing/invalid.
- `token_scope_hash_b64u` claim is missing **or** doesn’t match recomputation.
- Request is in confidential mode (see `services/clawproxy/src/policy.ts`) and `X-Policy-Hash` is required but missing/unknown (already implemented) **AND** token does not bind to that policy.

### Token-policy binding rules
When `X-Policy-Hash` is present:
- If token has `policy_hash_b64u`, it **must match** header policy hash (after normalization).
- If confidential mode is on: require token `policy_hash_b64u` to be present (so authorization is provable), otherwise fail with `403 TOKEN_POLICY_MISSING`.

Normalization recommendation:
- Accept `X-Policy-Hash` as either:
  - hex (64 chars), or
  - base64url
- Convert both to raw bytes and compare bytes.

### Receipt must include:
- `binding.policyHash` (already present today via `finalBinding` in `services/clawproxy/src/index.ts`)
- `binding.tokenHash`
- `binding.tokenScopeHashB64u`
- Include `ownerRef` and `missionId` if present (optional but useful)

---

# 4) Platform-paid inference mode (reserve-backed default): routing, receipt marking, ledger reference

## Routing rules (safe and unambiguous)
Determine upstream credential source:

1) **User-paid (BYOK)** if either is present:
- `X-Provider-Api-Key`
- `X-Provider-Authorization`

2) **Platform-paid** if NO provider credential provided AND:
- token has scope `cpx:pay:platform`

Otherwise:
- fail `402` or `403` (recommend `403 PLATFORM_PAID_NOT_ALLOWED` to avoid implying billing UX exists)

## Platform provider keys (env)
Extend `Env` in `services/clawproxy/src/types.ts`:
```ts
export interface Env {
  ...
  CST_PUBLIC_KEY_B64U?: string;
  CST_JWKS_URL?: string;
  PROXY_ALLOW_LEGACY_AUTH?: string;

  PLATFORM_OPENAI_API_KEY?: string;
  PLATFORM_ANTHROPIC_API_KEY?: string;
  PLATFORM_GOOGLE_API_KEY?: string;

  CLAWLEDGER_URL?: string;
  CLAWLEDGER_API_KEY?: string; // optional auth between services
}
```

## Receipt marking (CPX-US-013)
Add to receipt:
- `payment.mode = 'platform' | 'user'`
- `payment.paid = true` only for platform-paid where ledger authorization succeeded
- `payment.ledgerRef = <string>` only for platform-paid (must be present if `paid=true`)

## Reserve-backed ledger recording (interim interface)
Assume `clawledger` exists but no concrete client yet. Implement a tiny HTTP client module, e.g. `services/clawproxy/src/ledger.ts`.

### Proposed interim endpoints
**Pre-authorization (fail closed if fails):**
`POST ${CLAWLEDGER_URL}/v1/reserve/authorize`
```json
{
  "token_hash": "<hex>",
  "mission_id": "<optional>",
  "owner_ref": "<optional>",
  "spend_cap": 1.00,
  "provider": "openai",
  "model": "gpt-4.1-mini"
}
```
Response:
```json
{ "approved": true, "ledger_ref": "ldg_abc123" }
```

If `approved:false` → return `402` `{code:"RESERVE_INSUFFICIENT"}`

**Settle (best effort, but do log failures):**
`POST ${CLAWLEDGER_URL}/v1/reserve/settle`
```json
{
  "ledger_ref": "ldg_abc123",
  "receipt_signature": "<receipt.signature>",
  "receipt_hash": "<sha256(createSigningPayload(receipt))>",
  "usage": { "input_tokens": 12, "output_tokens": 34 }
}
```

Rationale:
- You need `ledger_ref` *before* calling the provider to be “reserve-backed”.
- Settlement can be best-effort in phase1 without blocking the response (otherwise you risk returning provider output but failing the client due to ledger flake).

## Where to get usage
- OpenAI/Anthropic/Google responses often include token usage; clawproxy currently passes through provider response. Add a small extractor:
  - `extractUsage(provider, responseObj)` (new module) returning normalized `{inputTokens?, outputTokens?, totalTokens?}`.
- If missing, settle with `usage: null` and let ledger reconcile later.

---

# 5) Avoid leaking secrets in receipts/logs (confidential mode)

This must align with `services/clawproxy/src/policy.ts` + logging behavior in `services/clawproxy/src/index.ts`:
- Already: `logConfidentialRequest()` is called in confidential mode and “never logs plaintext”.

Add/ensure:
1. **Never include raw CST or provider keys** in:
   - receipts (return payload)
   - logs
   - error messages
2. In confidential mode:
   - Do not echo back request headers in errors.
   - Do not include `aud`/`sub` raw unless you explicitly want them (they are identifiers, not secrets, but can be sensitive). Prefer storing:
     - `tokenHash`, `tokenScopeHashB64u`, `ownerRef` only.
3. For platform keys:
   - Keep keys only in env.
   - Do not log which key value was used; logging “platform-paid used for provider=openai” is OK.

Implementation details:
- In auth module, when generating error messages, never string-interpolate the token.
- In receipt binding, store only `tokenHash` not token.

---

# 6) Test plan (unit tests, fixtures, negative cases)

## Test harness
Use Miniflare (or Workers test runner) to run `fetch()` against the Worker entry in `services/clawproxy/src/index.ts`. Mock:
- `globalThis.fetch` for provider calls and ledger calls.
- `env.PROXY_RATE_LIMITER` binding (fake that always allows).

## Fixtures
### Token fixtures
Create deterministic Ed25519 keys:
- Use a known 32-byte seed for CST signing in tests.
- Generate JWS compact tokens with helper `signCst(claims, kid, privateKeySeed)`.

Create tokens:
- `token_valid_invoke_user_paid`
- `token_valid_invoke_platform_paid` (includes `cpx:pay:platform`, has spend_cap)
- `token_expired`
- `token_bad_aud`
- `token_missing_scope_hash`
- `token_scope_hash_mismatch`
- `token_policy_hash_mismatch`

### Policy fixtures
Use existing `registerDemoPolicy()` from `services/clawproxy/src/policy.ts` to register a demo policy hash and WPC object.

## Unit tests (module-level)
1. `auth.ts`
   - parses JWS, rejects malformed
   - verifies Ed25519 signature (valid/invalid)
   - checks `exp/iat` with skew
   - checks `aud` string and array
   - recomputes and validates `token_scope_hash_b64u`
2. `ledger.ts`
   - authorize success/failure
   - network error → throws (and handler returns 503 fail-closed for platform-paid)
3. `receipt.ts`
   - `createSigningPayload()` includes new `binding.*` and `payment.*` deterministically

## Integration tests (Worker fetch)
1. **CST required**
   - request without CST → 401 `TOKEN_REQUIRED`
2. **Valid CST + BYOK**
   - send `Authorization: Bearer <CST>`
   - send `X-Provider-Api-Key: test-key`
   - mock provider 200 → response includes `_receipt.binding.tokenHash` and `_receipt.binding.tokenScopeHashB64u`
   - `_receipt.payment.mode === "user"`, `_receipt.payment.paid === false`
3. **Valid CST + confidential mode requires policy**
   - `X-Confidential-Mode: true` without `X-Policy-Hash` → 400 `POLICY_REQUIRED` (existing behavior in `services/clawproxy/src/index.ts`)
4. **Token-policy binding**
   - confidential mode + policy header present but token lacks/mismatches `policy_hash_b64u` → 403 `TOKEN_POLICY_MISMATCH` (or `TOKEN_POLICY_MISSING`)
5. **Platform-paid success**
   - omit `X-Provider-Api-Key`
   - token includes `cpx:pay:platform`
   - ledger authorize mocked OK returning `ledger_ref`
   - provider mocked OK
   - receipt includes `payment.mode="platform"`, `payment.paid=true`, `payment.ledgerRef`
6. **Platform-paid blocked**
   - omit provider key, token lacks `cpx:pay:platform` → 403 `PLATFORM_PAID_NOT_ALLOWED`
7. **Platform-paid fail-closed if ledger down**
   - ledger fetch throws → 503 `LEDGER_UNAVAILABLE` and **provider must not be called**
8. **Negative: expired token**
   - 401 `TOKEN_EXPIRED`
9. **Negative: signature invalid**
   - 401 `TOKEN_INVALID_SIGNATURE`

---

# 7) PR slicing plan (PR-only, git-signed commits, no deploys)

## PR 1 — CST parsing/validation utilities (CPX-US-011 groundwork)
**Files:**
- Add `services/clawproxy/src/auth.ts`
- Update `services/clawproxy/src/types.ts` (`Env` additions for CST key source)
- Possibly add `services/clawproxy/src/jwks.ts` (JWKS fetch/cache)
- Add unit tests + fixtures

**Outcome:** standalone token validation library usable by proxy handler.

## PR 2 — Enforce CST on `/v1/proxy/:provider` (CPX-US-011 completion)
**Files:**
- Modify `services/clawproxy/src/index.ts`
  - Extract CST from `Authorization`
  - Move provider key to `X-Provider-Api-Key` / `X-Provider-Authorization`
  - Add legacy fallback gated by `env.PROXY_ALLOW_LEGACY_AUTH`
  - Add receipt binding `tokenHash` and log hash (structured log)
- Tests: integration tests for missing/invalid/expired/aud/scope

**Outcome:** CPX-US-011 passes: “Require CST token”, “Validate audience+expiry+scope”, “Log token hash with receipt”.

## PR 3 — Token/policy binding in receipt + fail-closed (CPX-US-012)
**Files:**
- Update `services/clawproxy/src/types.ts` (`ReceiptBinding` additions; add `ReceiptPayment` optional type)
- Update `services/clawproxy/src/receipt.ts` (`createSigningPayload()` includes `payment`; receipt generation includes new binding fields passed in)
- Update `services/clawproxy/src/index.ts` to:
  - enforce token-policy match when `X-Policy-Hash` present (and always in confidential mode)
  - set `binding.tokenScopeHashB64u`
- Tests: policy mismatch/missing fail-closed, receipt contains required binding fields

**Outcome:** CPX-US-012 passes.

## PR 4 — Platform-paid inference mode + ledger stub client (CPX-US-013)
**Files:**
- Add `services/clawproxy/src/ledger.ts` (authorize/settle)
- Update `services/clawproxy/src/index.ts` to:
  - determine payment mode based on provider key presence
  - if platform-paid: require scope `cpx:pay:platform`, require ledger, authorize before provider call
  - set receipt `payment` fields and `ledgerRef`
- Update `services/clawproxy/src/types.ts` env vars for platform provider keys + ledger
- Tests: success, blocked, fail-closed if ledger unavailable, ensure provider not called when reserve fails

**Outcome:** CPX-US-013 passes.

## PR 5 — Confidential-mode hardening (optional but recommended)
**Files:**
- Update `services/clawproxy/src/logging.ts` (not shown here, but referenced by `services/clawproxy/src/index.ts`) to guarantee no auth header/provider key leakage
- Add tests that log calls never include raw token/key in confidential mode (if logs are test-capturable)

---

If you want, I can also draft the exact new/modified TypeScript interfaces and the expected request header contract to document in the PR description (so reviewers can validate the behavior against `docs/prds/clawproxy.md` and `packages/schema/auth/scoped_token_claims.v1.json`).
