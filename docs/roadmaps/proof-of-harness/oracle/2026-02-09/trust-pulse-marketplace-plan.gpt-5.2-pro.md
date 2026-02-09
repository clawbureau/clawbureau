## 1) Final decisions

| Topic | Decision | Rationale | Notes / Files |
|---|---|---|---|
| Storage model | **New table** `submission_trust_pulse` (1 row per submission) | Avoid bloating `submissions` rows and list queries; Trust Pulse is optional/auxiliary | Aligns with Gemini proposal in **File 1** and current `submissions` shape in **File 3** |
| Ingestion requirement | **Optional field** on `POST /v1/bounties/{bounty_id}/submit`: `trust_pulse` may be provided | Minimal surface change; backwards-compatible with current workers | When provided, it is **strictly validated** (see acceptance criteria) |
| Binding requirement | Trust Pulse must bind to **(run_id + agent_did)** derived from the proof bundle, and (if present) URM must match too | Prevent attaching a Trust Pulse from a different run/agent to an unrelated submission | Uses existing extractors in **File 2**: `extractProofBundleAgentDid`, `extractRunIdAndEventHashesFromProofBundle` |
| URM hash enforcement | If `urm.metadata.trust_pulse.artifact_hash_b64u` exists, enforce computed hash match **fail-closed** | Meets requirement “enforce hash match” | URM schema allows arbitrary `metadata` object (**File 5**); this is a convention we enforce |
| Tier behavior | Server enforces `tier_uplift === false` and viewer continues to state “non-tier” | Must keep Trust Pulse explicitly non-tier | Viewer already validates `tier_uplift` (**File 2**, `trustPulseViewerPage.validate()`) |
| Retrieval auth | Add `GET /v1/submissions/{submission_id}/trust-pulse` gated by **admin key OR owning worker token** | “Security sane” + useful for workers without sharing admin key | Worker auth already exists in **File 2** (`requireWorker`). Admin auth already exists (`requireAdmin`) |
| Token handling | **Never** accept tokens in URL/query params; viewer uses **Authorization header** | Requirement: “Don’t leak admin/worker tokens via URL; use request headers.” | Viewer page updated (see §4/§5) |

---

## 2) Concrete endpoint definitions + auth rules

### 2.1 Ingestion (existing endpoint; request body extended)
**`POST /v1/bounties/{bounty_id}/submit`** (already exists; worker-auth)

**Auth**
- Requires **worker token**: `Authorization: Bearer <WORKER_TOKEN>` (already enforced via `requireWorker()` in **File 2**)

**Request body change (new optional field)**
```json
{
  "worker_did": "did:key:...",
  "proof_bundle_envelope": { "...": "..." },
  "urm": { "...": "..." },
  "commit_proof_envelope": { "...": "..." },
  "artifacts": [],
  "agent_pack": {},
  "result_summary": "string",
  "trust_pulse": { "trust_pulse_version": "1", "...": "..." } // NEW (optional)
}
```

**Server-side behavior (only if `trust_pulse` is provided)**
1. Validate minimal Trust Pulse v1 invariants:
   - `trust_pulse_version === "1"`
   - `evidence_class === "self_reported"`
   - `tier_uplift === false` (**hard requirement**)
   - `run_id` non-empty string
   - `agent_did` DID string (`startsWith("did:")`)
   - `tools` array, `files` array (basic shape; optionally enforce file path safety similar to schema **File 4**)
2. Canonicalize with `stableStringify()` (already in **File 2**), enforce `<= 24KB`.
3. Compute hash = `sha256B64uUtf8(canonical_string)` (already in **File 2**).
4. Derive binding context from proof bundle:
   - `agent_did` from `extractProofBundleAgentDid(proof_bundle_envelope)`
   - `run_id` from `extractRunIdAndEventHashesFromProofBundle(proof_bundle_envelope)` (use `run_id` only; event hashes irrelevant here)
   - If either is missing: **400** `TRUST_PULSE_UNBOUND` (only when trust_pulse is provided; submission otherwise proceeds as today).
5. Enforce binding:
   - `trust_pulse.agent_did === proof_bundle.agent_did`
   - `trust_pulse.run_id === proof_bundle.run_id`
   - If `urm` is provided:
     - enforce `urm.agent_did` and `urm.run_id` match those values too
6. If URM metadata includes `urm.metadata.trust_pulse.artifact_hash_b64u`:
   - enforce it equals computed hash (**fail-closed**): **400** `TRUST_PULSE_HASH_MISMATCH`
   - store status = `"verified"`
   - else store status = `"unverified"`

**Response**
- Submission response stays unchanged (`SubmitBountyResponseV1` in **File 2**). (Minimal change.)
- Trust Pulse is retrieved via the separate GET endpoint below.

---

### 2.2 Retrieval (new endpoint)
**`GET /v1/submissions/{submission_id}/trust-pulse`**

**Auth (either of)**
- **Admin**: `Authorization: Bearer <BOUNTIES_ADMIN_KEY>` (use existing `requireAdmin()` from **File 2**), OR
- **Worker**: `Authorization: Bearer <WORKER_TOKEN>` AND the submission’s `worker_did` must match authenticated worker (use existing `requireWorker()` and `getSubmissionById()` in **File 2**)

**Auth rules**
- If admin token valid: allow.
- Else if worker token valid: allow only if `submissions.worker_did === authed.worker_did`.
- Else: **401**.

**200 response**
```json
{
  "submission_id": "sub_...",
  "run_id": "run_...",
  "agent_did": "did:key:...",
  "hash_b64u": "....",
  "status": "verified",
  "created_at": "2026-02-09T..Z",
  "trust_pulse": { "...": "..." }
}
```

**404 behavior**
- If submission does not exist: `NOT_FOUND` 404 (optional detail: `{ submission_id }`)
- If submission exists but no Trust Pulse stored: `TRUST_PULSE_NOT_FOUND` 404

**Caching**
- Response should be `cache-control: no-store` (safer for sensitive admin review artifacts). This is a deviation from the worker’s default `textResponse` caching; for JSON we can set a header in this handler only.

---

## 3) Database migration SQL

Create a new migration file (next number after existing; Gemini suggested `0009_...` in **File 1**, but your repo currently shows up to **File 3** `0005_...`; pick the next actual number in-tree).

**New file:** `services/clawbounties/migrations/000X_submission_trust_pulse.sql`
```sql
-- Store Trust Pulse separately from submissions to avoid row bloat.
-- One Trust Pulse per submission_id.

CREATE TABLE IF NOT EXISTS submission_trust_pulse (
  submission_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  agent_did TEXT NOT NULL,

  trust_pulse_json TEXT NOT NULL, -- canonical JSON string (stableStringify)
  hash_b64u TEXT NOT NULL,        -- sha256 base64url of canonical string
  status TEXT NOT NULL,           -- 'verified' | 'unverified'
  created_at TEXT NOT NULL,

  FOREIGN KEY (submission_id) REFERENCES submissions(submission_id)
);

CREATE INDEX IF NOT EXISTS submission_trust_pulse_run_idx ON submission_trust_pulse(run_id);
CREATE INDEX IF NOT EXISTS submission_trust_pulse_agent_idx ON submission_trust_pulse(agent_did);
```

Notes:
- `status` intentionally only supports `verified|unverified` because we **reject mismatches** at ingestion (fail-closed). (Gemini’s `mismatch` state in **File 1** becomes unnecessary under the “enforce” requirement.)

---

## 4) PR-sized step plan and tests

### PR 1 — DB + ingestion + retrieval API
**Changes (services/clawbounties)**
1. **Migration**
   - Add migration file above.
2. **Add Trust Pulse parsing/validation helpers** (in `services/clawbounties/src/index.ts` — **File 2**)
   - `parseTrustPulseV1(input: unknown): { ok: true, tp: Record<string, unknown> } | { ok: false, code: string, message: string }`
   - `extractExpectedTrustPulseHashFromUrm(urm: Record<string, unknown>): string | null`
     - reads `urm.metadata.trust_pulse.artifact_hash_b64u` if present and string
3. **Update `handleSubmitBounty()`** (**File 2**)
   - Read `bodyRaw.trust_pulse`
   - If absent: no behavior change
   - If present:
     - validate + canonicalize + size limit + hash
     - bind to proof bundle derived `(run_id, agent_did)`; also bind to URM if provided
     - enforce URM hash if present
     - insert into `submission_trust_pulse` as part of the same write path:
       - If inserting submission uses `insertSubmissionWithReplayGuards(... db.batch(stmts))`, add a `prepareInsertSubmissionTrustPulse()` statement to that same `stmts` list.
       - Else, if using `insertSubmission()` path, do a small `db.batch([insertSubmissionStmt, insertTrustPulseStmt])` to keep “best-effort atomic” behavior.
4. **Add retrieval handler** in **File 2**
   - `handleGetSubmissionTrustPulse(submissionId, request, env, version)`
   - Auth logic: admin OR worker-owner
   - `SELECT trust_pulse_json, run_id, agent_did, hash_b64u, status, created_at FROM submission_trust_pulse WHERE submission_id = ?`
5. **Add router entry**
   - Match: `^/v1/submissions/(sub_[a-f0-9-]+)/trust-pulse$` for `GET`
   - Ensure this route is reachable **before** the blanket admin gating currently applied to `/v1/*` after worker routes in **File 2**. (Important: the current router applies `requireAdmin()` for “Bounties API (admin)” after some worker routes; the new retrieval endpoint should implement its own admin/worker auth and not be forced-admin by routing order.)

**Tests (same PR)**
- Add a small test suite (Node’s built-in `node:test` is fine) targeting extracted pure helper functions + minimal handler logic:
  1. `parseTrustPulseV1` rejects if `tier_uplift !== false`
  2. Rejects if `trust_pulse.run_id` mismatches proof bundle run_id
  3. Rejects if `trust_pulse.agent_did` mismatches proof bundle agent_did
  4. Enforces URM hash mismatch => returns `TRUST_PULSE_HASH_MISMATCH`
  5. Size limit => returns `TRUST_PULSE_TOO_LARGE`
- If you already have Miniflare/D1 test infra, add one integration test:
  - POST submit with trust_pulse => row created in `submission_trust_pulse`
  - GET retrieval with admin key returns trust_pulse JSON

---

### PR 2 — Viewer page auto-load by `submission_id`
**Changes (services/clawbounties/src/index.ts — `trustPulseViewerPage()` in File 2)**
1. Add query param support:
   - If `?submission_id=sub_...` present:
     - Render a small “Load from submission” panel above the textarea:
       - input: token (password field)
       - button: “Fetch”
       - radio/select: “Admin key” vs “Worker token” (optional; or just one “Token” field since both use Authorization Bearer)
2. On click, call:
   - `fetch(/v1/submissions/${submissionId}/trust-pulse, { headers: { Authorization: 'Bearer ' + token } })`
3. Populate textarea with `data.trust_pulse` and call existing `doRender()`
4. Display status (`verified|unverified`) + hash in the UI
5. Ensure:
   - token never goes into URL
   - do not auto-fetch without user action unless a token is already in `sessionStorage` (optional)
   - if you store anything, prefer `sessionStorage` (not `localStorage`) to reduce persistence

**Tests**
- Minimal: a DOM-less “string contains” test is usually not worth it here.
- Instead, add one unit test for a small extracted function that parses query params (optional), or treat viewer changes as manual-test covered (acceptance criteria below).

---

## 5) Doc updates needed (minimal)

Update docs page content in **File 2** `docsPage()` and skill metadata in `skillMarkdown()`:

1. **docsPage()**: add:
   - Retrieval endpoint documentation:
     - `GET /v1/submissions/{submission_id}/trust-pulse` (auth: admin key or worker token; via Authorization header)
   - Viewer auto-load usage:
     - `/trust-pulse?submission_id=sub_...` then paste token into the page UI (token is not in URL)
2. **skillMarkdown()** metadata endpoints list:
   - Add `{ method: 'GET', path: '/v1/submissions/{submission_id}/trust-pulse' }`

(These are both in **File 2**.)

---

# Acceptance criteria updates (exact)

Add/append the following acceptance criteria to the Trust Pulse marketplace auto-load work item.

## A. Submission-time storage
1. `POST /v1/bounties/{bounty_id}/submit` accepts an **optional** JSON field `trust_pulse`.
2. If `trust_pulse` is provided, the server **must** reject the request with **400** if:
   - `trust_pulse.tier_uplift` is not exactly `false`.
   - `trust_pulse.trust_pulse_version !== "1"`.
   - `trust_pulse.evidence_class !== "self_reported"`.
   - `trust_pulse.run_id` or `trust_pulse.agent_did` is missing/invalid.
3. If `trust_pulse` is provided, the server **must** bind it to the submission’s proof bundle:
   - derive `agent_did` from `proof_bundle_envelope.payload.agent_did` (existing extraction in **services/clawbounties/src/index.ts**, File 2),
   - derive `run_id` from the first event in `proof_bundle_envelope.payload.event_chain[0].run_id` (existing extraction helper in File 2),
   - reject with **400 `TRUST_PULSE_BINDING_MISMATCH`** if `trust_pulse.run_id` or `trust_pulse.agent_did` does not match the derived values.
4. If `urm` is present in the submission request, the server **must** also enforce:
   - `urm.run_id === trust_pulse.run_id`
   - `urm.agent_did === trust_pulse.agent_did`
   - else **400 `TRUST_PULSE_BINDING_MISMATCH`**.
5. The server **must** canonicalize `trust_pulse` with stable key ordering (use existing `stableStringify()` in **File 2**) and compute `hash_b64u = sha256b64u(utf8(canonical_json))`.
6. If `urm.metadata.trust_pulse.artifact_hash_b64u` is present:
   - the server **must** enforce equality to `hash_b64u`,
   - else reject with **400 `TRUST_PULSE_HASH_MISMATCH`**,
   - and store the record with `status = "verified"`.
7. If the URM hash pointer is absent, the server stores the record with `status = "unverified"`.
8. The server **must** reject Trust Pulse ingestion with **400 `TRUST_PULSE_TOO_LARGE`** if the canonical JSON string exceeds **24KB**.
9. Trust Pulse storage **must not** affect proof tier outcomes; it remains explicitly non-tier (`tier_uplift=false`) and no tier uplift logic is introduced.

## B. Retrieval endpoint (auth-gated)
1. A new endpoint exists: `GET /v1/submissions/{submission_id}/trust-pulse`.
2. The endpoint **must** require auth via request headers (no URL tokens):
   - Admin: `Authorization: Bearer <BOUNTIES_ADMIN_KEY>` (existing admin key mechanism in **File 2**), OR
   - Worker: `Authorization: Bearer <WORKER_TOKEN>` and the submission’s `worker_did` must match the authenticated worker.
3. Unauthorized requests return **401**; worker-auth requests for a submission owned by a different worker return **403**.
4. If the submission exists but no Trust Pulse is stored, return **404 `TRUST_PULSE_NOT_FOUND`**.
5. A successful response returns:
   - `submission_id`, `run_id`, `agent_did`, `hash_b64u`, `status`, `created_at`, and the parsed `trust_pulse` object.

## C. Viewer auto-load by submission_id
1. `/trust-pulse?submission_id=sub_...` **must** show UI to load Trust Pulse from the server.
2. The viewer **must not** require (or accept) tokens in the URL; it sends tokens only via `Authorization` request header.
3. On successful fetch, the viewer populates the existing textarea with the fetched `trust_pulse` JSON and renders it using the existing renderer in **File 2**.
4. The viewer displays whether the stored Trust Pulse is `verified` or `unverified` (and optionally the hash).
5. Viewer continues to validate/display that Trust Pulse is self-reported and non-tier (no tier uplift).

---

If you want, I can also sketch the exact code insertion points in **services/clawbounties/src/index.ts** (File 2) for: (a) routing order, (b) `prepareInsertSubmissionTrustPulse`, and (c) the combined admin-or-worker auth helper used by the new GET endpoint.
