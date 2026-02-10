## 1) Recommendation

**Pick (B): marketplace-issued job-scoped CSTs + marketplace enforcement of `binding.token_scope_hash_b64u` (and pinned `policy_hash`) for CWC submissions.**

Why this is the best fit for the stated constraints:

- **Hard to game / fail-closed:**  
  If `clawbounties` stores an *expected* `token_scope_hash_b64u` for the bounty’s CWC job token, then any borrowed receipt/event chain from a different worker/job will carry a different `binding.token_scope_hash_b64u` (because the CST scope hash deterministically includes `sub` and other auth-relevant claims) and is rejected at submit time. This directly closes the “previously-unused receipts from another agent/run” gap described in `PROMPT_receipt-nontransferability-job-binding.md` (File 1).  
  The binding field already exists in the receipt binding schema (`token_scope_hash_b64u` in `packages/schema/poh/receipt_binding.v1.json`, File 3) and is already injected by `clawproxy` when a CST is validated (see `finalBinding.tokenScopeHashB64u` in `services/clawproxy/src/index.ts`, File 7).

- **Credible trust story + auditable evidence:**  
  The marketplace can show: “This submission’s gateway receipts were produced using the **job token** issued for this bounty and this worker, under the pinned WPC policy hash.” That’s a clean, reviewable narrative with deterministic hashes:
  - `binding.policy_hash` already enforced for CWC today (in `clawbounties`, File 12; CWC policy enforcement section sets invalid when mismatched).
  - Add symmetric enforcement for `binding.token_scope_hash_b64u`.

- **Low friction UX:**  
  Workers shouldn’t manually configure per-run anti-borrowing fields. Returning a CST on **accept** (and optionally a refresh endpoint) means OpenClaw plugin + external shims just attach `X-CST` (and optionally `X-Client-DID`) to `clawproxy` calls. `clawproxy` already understands CSTs (`X-CST` / `X-Scoped-Token`) (File 7).

- **Low operational burden:**  
  No new complex infra. You add:
  - **one D1 column** on `bounties` for the expected scope hash, and
  - **one small worker endpoint** (optional but recommended) to mint/refresh the job CST.
  `clawscope` already issues deterministic `token_scope_hash_b64u` (Files 10–11) and `clawproxy` already binds it into receipts (File 7).

**Why not (A) now:** adding `client_did` into signed receipts requires schema changes and proxy changes; it’s doable, but it’s redundant if you enforce job-scoped CST binding. (A) binds receipts to an agent; (B) binds receipts to **agent + job/policy** with an issuer-controlled token hash, which is strictly stronger for marketplace “job binding”.

**Why not (C) now:** you can add (A) later as belt-and-suspenders, but (B) alone already closes the described borrowing attack with minimal churn and maximum leverage from what’s already implemented (Files 3, 7, 10–11, 12).

---

## 2) Threat model

### Assets / invariants
- Marketplace wants “gateway-tier proof” receipts to be **non-transferable across workers** and **job-bound** for CWC.
- Receipts are already bound to `run_id` + `event_hash_b64u` (PoH adapter spec, File 2 §5.1), but that binding is currently portable if an attacker copies the whole event chain + receipts and re-signs the proof bundle with their DID.

### Primary attack: receipt borrowing / transfer
**Attack:** Worker B copies Worker A’s previously-unused proof artifacts (event chain + gateway receipts) and submits them under Worker B’s DID.

**Why this works today:**  
`clawbounties` replay DB rejects reuse of `(agent_did, run_id)` and `(receipt_signer_did, receipt_id)`, but does **not** require that the receipts were produced under a token authorization that matches the submitting worker/job (File 1).

### How (B) defeats it
1. Marketplace issues a **job CST** for the accepted worker and bounty:
   - `sub = worker_did`
   - `policy_hash_b64u = pinned WPC hash from CWC`
   - `mission_id = bounty_id` (or `cwc_id`/`escrow_id`; pick one stable job identifier)
   - `scope` includes `proxy:call` and `clawproxy:call` (required by `clawproxy` validation; File 7)
   `clawscope` computes a deterministic `token_scope_hash_b64u` over auth-relevant claims (File 2 §5.1 and `services/clawscope/src/token-scope-hash.ts`, File 11).

2. When the worker uses that CST on `clawproxy` calls, `clawproxy` injects `binding.token_scope_hash_b64u` into the signed receipt (see `finalBinding.tokenScopeHashB64u` in `services/clawproxy/src/index.ts`, File 7; schema field in File 3).

3. On submission, `clawbounties` verifies receipts and enforces:  
   **all verified + run-bound receipts** have `binding.token_scope_hash_b64u == expected_for_bounty`, otherwise fail closed.

**Result:** Borrowed receipts from another worker/job carry a different scope hash (because `sub` and `mission_id` differ), so submission is rejected deterministically.

### Residual attacks (what remains)
- **Credential theft / collusion:** If Worker A gives Worker B the job CST (and/or the DID signing key), B can generate receipts that match. This is not “receipt borrowing”; it’s identity/token compromise. Mitigations are operational: short TTL CSTs + optional spend caps + audit logs (`clawscope` already has issuance audit hooks; File 10).
- **No-receipt “self tier” attempts:** Already handled by `min_proof_tier` and CWC requires gateway/sandbox (File 12 enforces `min_proof_tier`, and CWC requires tier ≥ gateway at post time).
- **Mix-and-match receipts:** Attacker includes some receipts with correct hash plus extra unrelated receipts. Mitigation: enforce that **every verified+bound receipt** in the bundle matches expected token scope hash (and policy hash), not just “at least one”.

---

## 3) Concrete implementation plan (minimal changes)

### 3.1 `clawbounties` changes (issue CST, store expected hash, enforce at submit)

#### (a) D1 schema: add one column
Add **one nullable text column** on `bounties`:

- `cwc_token_scope_hash_b64u TEXT NULL`

This matches the “ok to add a D1 column/migration” constraint (File 1).

#### (b) Environment variables
Add to `clawbounties` worker `Env` (File 12):
- `SCOPE_BASE_URL?: string` (default `https://clawscope.com`)
- `SCOPE_ADMIN_KEY?: string` (admin key for `clawscope /v1/tokens/issue`, see File 10 `requireAdmin`)
- `CST_AUD?: string` (default `clawproxy.com`)
- `ENFORCE_CWC_TOKEN_SCOPE?: string` (rollout gate; see §4)

#### (c) Issue job CST on **accept**
In `handleAcceptBounty` (File 12), after CWC countersign verification and before/after `updateBountyAccepted`:

1. If `bounty.cwc_hash_b64u` is set (CWC bounty), call `clawscope`:
   - `POST ${SCOPE_BASE_URL}/v1/tokens/issue`
   - `Authorization: Bearer ${SCOPE_ADMIN_KEY}`
   - body:
     ```json
     {
       "sub": "<worker_did>",
       "aud": "clawproxy.com",
       "scope": ["proxy:call", "clawproxy:call"],
       "policy_hash_b64u": "<bounty.cwc_wpc_policy_hash_b64u>",
       "mission_id": "<bounty.bounty_id>",
       "ttl_sec": 3600
     }
     ```
   (All these claims are supported by `clawscope` issuance request shape; File 10 `IssueTokenRequest`.)

2. `clawscope` response includes `token` and `token_scope_hash_b64u` (File 10 `/v1/tokens/issue` response).

3. Persist `cwc_token_scope_hash_b64u` into the bounty row (set-once / COALESCE).
   - Minimal SQL: extend `updateBountyAccepted()` to include:
     - `cwc_token_scope_hash_b64u = COALESCE(cwc_token_scope_hash_b64u, ?)`
   - And pass the returned hash as a new param.

4. Return the CST to the worker in the accept response as an additive field (backward compatible):
   ```json
   {
     "...existing": "...",
     "cwc_auth": {
       "cst": "<JWT>",
       "token_scope_hash_b64u": "<...>",
       "aud": "clawproxy.com",
       "expires_at": "<epoch/iso optional>"
     }
   }
   ```

#### (d) Add one small endpoint: refresh CST (recommended)
Add worker-authenticated endpoint:

- `POST /v1/bounties/{bounty_id}/cst`

Behavior:
1. Require worker auth (`requireWorker`, File 12) and verify bounty is accepted by that worker.
2. Require bounty has CWC.
3. Call `clawscope /v1/tokens/issue` with the same claims as above.
4. If `bounties.cwc_token_scope_hash_b64u` is null, set it to returned hash (backfill-on-demand).
5. If it is non-null and differs, **fail closed** with `CWC_TOKEN_SCOPE_HASH_ROTATION_FORBIDDEN` (this should never happen if inputs are stable and `clawscope` hashing is deterministic; File 11).

This endpoint keeps long-running jobs low-friction without storing CSTs in D1.

#### (e) Enforce at submit: `binding.token_scope_hash_b64u`
In `handleSubmitBounty` (File 12), you already compute:
- verified + bound receipts count
- observed `binding.policy_hash` set
- missing policy hash count  
via `computeReplayReceiptKeys()` (File 12).

Extend `computeReplayReceiptKeys()` to also compute:
- `verified_bound_token_scope_hashes: Set<string>`
- `verified_bound_missing_token_scope_hash_count: number`

Implementation detail:
- In the loop where you already parse `payload.binding.policy_hash`, also parse:
  - `binding.token_scope_hash_b64u`

Then, in the existing “Enforce CWC policy binding” block (near the end of `handleSubmitBounty`, File 12), add token scope enforcement *alongside* policy hash enforcement, but only when the proof is otherwise valid (consistent with current structure):

Required checks for CWC (fail-closed, deterministic):
1. `verifiedBoundReceiptCount > 0` else reject
2. `verifiedBoundMissingPolicyHashCount == 0` else reject
3. `verifiedBoundMissingTokenScopeHashCount == 0` else reject
4. `verified_bound_policy_hashes == { expectedPolicyHash }` else reject
5. `verified_bound_token_scope_hashes == { expectedTokenScopeHash }` else reject
   - Also reject if the set contains multiple values (mixing).

**Where does `expectedTokenScopeHash` come from?**  
From `bounty.cwc_token_scope_hash_b64u`.

If `bounty.cwc_token_scope_hash_b64u` is null and enforcement is enabled, treat as server misconfig and error out (`500`) so it’s fail-closed for confidential work.

---

### 3.2 `clawscope` changes
**None required.**  
`clawscope` already:
- issues scoped tokens with `mission_id`, `policy_hash_b64u`, etc. (File 10),
- computes deterministic `token_scope_hash_b64u` excluding `iat/exp/jti/nonce` (File 11),
- returns `token_scope_hash_b64u` on issuance (File 10).

---

### 3.3 `clawproxy` / `clawverify` changes
**None required** for the core fix.

- `clawproxy` already validates CSTs and injects `token_scope_hash_b64u` into receipt bindings (File 7: `finalBinding.tokenScopeHashB64u = validatedCst?.claims.token_scope_hash_b64u`).
- Receipt binding schema already includes `token_scope_hash_b64u` (File 3).
- `clawverify` already verifies receipts and binding to run/event chain (PoH adapter spec File 2; and `clawbounties` calls `clawverify /v1/verify/receipt`, File 12).

Operational note: for “fail-closed” confidential enforcement, workers must actually use the CST on their gateway calls so receipts contain the binding field. The marketplace enforcement above guarantees they do (missing field → reject).

---

### 3.4 OpenClaw plugin / external shim UX changes
Goal: make it “automatic” for workers.

1. **On bounty accept**, the worker client stores `accept_response.cwc_auth.cst` (new field).
2. Configure the OpenClaw provider-clawproxy plugin / shim to:
   - send `X-CST: <token>` on every proxy call
   - optionally send `X-Client-DID: <worker_did>` (nice-to-have; `clawproxy` uses it for authenticated attribution and enforces `TOKEN_SUB_MISMATCH` if present; File 7)
   - continue sending PoH binding headers `X-Run-Id`, `X-Event-Hash`, `X-Idempotency-Key` as today (PoH spec File 2 §5.1)

3. If the CST expires mid-run, call:
   - `POST /v1/bounties/{bounty_id}/cst` to refresh (new endpoint), then continue.

No manual policy hash configuration is required because:
- `clawproxy` treats CST `policy_hash_b64u` as authoritative and rejects mismatching `X-Policy-Hash` (described in File 1; implemented in `extractPolicyFromHeaders` override logic, File 8).

---

## 4) Backward compatibility / rollout strategy

### Phase 0 (now): implement but gate enforcement
- Ship D1 column + CST issuance + submit-time enforcement code behind:
  - `ENFORCE_CWC_TOKEN_SCOPE=false` initially.
- Start writing `cwc_token_scope_hash_b64u` for newly accepted CWC bounties.

### Phase 1: enforce for CWC bounties that have the expected hash
- Turn on `ENFORCE_CWC_TOKEN_SCOPE=true`, but enforce only when:
  - `bounty.cwc_hash_b64u != null` **and**
  - `bounty.cwc_token_scope_hash_b64u != null`
- This avoids breaking any “older CWC bounties” that were accepted before the column existed.

### Phase 2: fully fail-closed for all CWC
- Once you’re confident issuance is always happening, require `cwc_token_scope_hash_b64u` for any bounty with `cwc_hash_b64u` (server-side invariant). If missing: 500 + deterministic error.

### Non-confidential bounties
- Do nothing: no required CST, no token-scope enforcement. Existing flow remains unchanged (File 12).

---

## 5) Deterministic error codes/messages (marketplace enforcement)

Use `clawbounties` existing `{ error, message, details }` pattern (File 12 `errorResponse()`), and for CWC violations **return errors (422/409) rather than silently downgrading proofStatus** so it’s unambiguous and fail-closed for confidential work.

### Accept-time / token issuance
- **`SCOPE_NOT_CONFIGURED` (503)**  
  “clawscope admin credentials not configured”
- **`CWC_CST_ISSUE_FAILED` (502)**  
  “Failed to issue job CST from clawscope”
- **`CWC_TOKEN_SCOPE_HASH_ROTATION_FORBIDDEN` (500)**  
  “Stored cwc_token_scope_hash_b64u does not match newly issued deterministic hash”

### Submit-time (CWC only; when enforcement enabled)
- **`CWC_RECEIPT_REQUIRED` (422)**  
  “CWC requires at least one verified, run-bound gateway receipt”
- **`CWC_POLICY_HASH_REQUIRED` (422)**  
  “CWC requires binding.policy_hash on all verified, run-bound gateway receipts”
- **`CWC_POLICY_HASH_MISMATCH` (422)**  
  details: `{ expected_policy_hash_b64u, observed_policy_hashes: [...] }`
- **`CWC_TOKEN_SCOPE_HASH_REQUIRED` (422)**  
  “CWC requires binding.token_scope_hash_b64u on all verified, run-bound gateway receipts”
- **`CWC_TOKEN_SCOPE_HASH_MISMATCH` (422)**  
  details: `{ expected_token_scope_hash_b64u, observed_token_scope_hashes: [...] }`
- **`CWC_TOKEN_SCOPE_NOT_CONFIGURED` (500)**  
  “Bounty missing cwc_token_scope_hash_b64u; cannot verify non-transferability”

### Optional: strict “no mixing” rule
If `observed_token_scope_hashes.length > 1`:
- still **`CWC_TOKEN_SCOPE_HASH_MISMATCH` (422)** with observed list.

---

### Summary of what actually changes where
- **`clawbounties` (File 12):**
  - add `bounties.cwc_token_scope_hash_b64u`
  - issue CST on accept (call `clawscope /v1/tokens/issue`, File 10)
  - add `/v1/bounties/{id}/cst` refresh endpoint
  - extend receipt analysis to collect `binding.token_scope_hash_b64u`
  - enforce expected hash match on CWC submit (fail-closed)

- **`clawscope` (Files 10–11):** no changes
- **`clawproxy` (Files 7, 9):** no changes (already injects token scope hash)
- **OpenClaw/shims (PoH spec File 2):** attach CST automatically; refresh if needed

This design directly addresses the stated receipt borrowing attack (File 1) using already-standardized binding fields (File 3) and already-implemented deterministic CST hashing (Files 10–11), with only one D1 column and one small endpoint added.
