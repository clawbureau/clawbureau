Below is a concrete implementation roadmap for the remaining stories on branch `ralph/clawledger-phase1-trust`, grounded in the current Worker + D1 codebase—especially the existing reserve attestation implementation in **`services/ledger/src/attestation.ts`** (File 3) and the existing schema migrations **0001/0002/0004** (Files 8–10). The PRD requirements are from **`docs/prds/clawledger.md`** (File 1) and **`prd.json`** (File 2).

---

## 1) D1 schema changes (tables + indexes) for reserve assets

### Goals
- Auditable registry of “what counts as reserves” with explicit haircut policy (CLD-US-010, File 1).
- Track observed balances over time (snapshots) with provenance and staleness checks (fail-closed).
- Allow attestation to be reproducible later (store attestations, optional but strongly recommended).

### Proposed tables

#### A. `reserve_assets` (registry / metadata)
Stores the definition/policy of each reserve asset.

```sql
-- Migration 0005_create_reserve_assets.sql

CREATE TABLE IF NOT EXISTS reserve_assets (
  id TEXT PRIMARY KEY,                    -- e.g. ras_gemini_compute, ras_fal_compute
  asset_type TEXT NOT NULL,               -- 'compute_credit' | 'fiat_cash' | 'stablecoin' | ...
  provider TEXT NOT NULL,                 -- 'gemini' | 'fal' | 'manual' | ...
  name TEXT NOT NULL,                     -- human label
  unit TEXT NOT NULL,                     -- unit of raw_amount, e.g. 'credit'
  is_eligible INTEGER NOT NULL DEFAULT 1, -- 1=true, 0=false
  haircut_bps INTEGER NOT NULL DEFAULT 10000, -- fail-closed default: 100% haircut => eligible=0
  max_age_seconds INTEGER NOT NULL DEFAULT 86400, -- staleness window; beyond => eligible=0
  provider_metadata TEXT NOT NULL DEFAULT '{}',   -- JSON string (account ids, SKU info, etc)
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_reserve_assets_provider ON reserve_assets(provider);
CREATE INDEX IF NOT EXISTS idx_reserve_assets_type ON reserve_assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_reserve_assets_eligible ON reserve_assets(is_eligible);
```

**Notes**
- `haircut_bps` in basis points: `0` means no haircut; `10000` means fully haircutted to 0. Defaulting to `10000` is the cleanest “fail-closed” posture.
- `max_age_seconds` enforces staleness. If no recent snapshot exists, the attestation counts the asset as **eligible=0**, but still reports it as present/stale.

#### B. `reserve_asset_snapshots` (time series of observed balances)
Each row is an observation of a reserve balance with provenance.

```sql
-- Migration 0006_create_reserve_asset_snapshots.sql

CREATE TABLE IF NOT EXISTS reserve_asset_snapshots (
  id TEXT PRIMARY KEY,             -- e.g. rss_<ulid>
  reserve_asset_id TEXT NOT NULL,  -- FK -> reserve_assets.id
  observed_at TEXT NOT NULL,       -- when balance was true (ISO8601)
  fetched_at TEXT NOT NULL,        -- when we recorded it (ISO8601)
  raw_amount TEXT NOT NULL,        -- integer string; same style as accounts/events (Files 3–6)
  source TEXT NOT NULL,            -- 'manual' | 'api' | 'import'
  source_ref TEXT,                 -- receipt id, statement id, API request id, etc
  snapshot_metadata TEXT NOT NULL DEFAULT '{}', -- JSON: extra fields, proofs, etc
  created_at TEXT NOT NULL,
  FOREIGN KEY (reserve_asset_id) REFERENCES reserve_assets(id)
);

-- “latest snapshot per asset” queries
CREATE INDEX IF NOT EXISTS idx_rss_asset_observed ON reserve_asset_snapshots(reserve_asset_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_rss_observed ON reserve_asset_snapshots(observed_at DESC);
```

#### C. (Recommended) `reserve_attestations` (persist what you serve)
Right now **`ReserveAttestationService.generateAttestation()`** (File 3) computes on demand and returns; for auditability, store the exact payload and signature you served.

```sql
-- Migration 0007_create_reserve_attestations.sql

CREATE TABLE IF NOT EXISTS reserve_attestations (
  id TEXT PRIMARY KEY,               -- att_...
  created_at TEXT NOT NULL,          -- same as attestation timestamp
  latest_event_hash TEXT NOT NULL,   -- included in signing today (File 3)
  payload_canonical TEXT NOT NULL,   -- canonical string that was signed (see §4)
  payload_hash TEXT NOT NULL,        -- sha256(payload_canonical)
  signature TEXT NOT NULL,           -- base64(signature bytes)
  signature_alg TEXT NOT NULL,       -- e.g. 'ECDSA_P256_SHA256'
  key_id TEXT NOT NULL,              -- rotation-friendly
  attestation_json TEXT NOT NULL     -- full JSON response body served
);

CREATE INDEX IF NOT EXISTS idx_reserve_attestations_created_at ON reserve_attestations(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reserve_attestations_payload_hash ON reserve_attestations(payload_hash);
```

This enables:
- later verification that an attestation was served,
- exact reproduction for auditors,
- key rotation (`key_id`).

---

## 2) API surface (routes) for reserve asset CRUD + attestation breakdown

The Worker router is in **`services/ledger/src/index.ts`** (File 7). Add a small reserve module (e.g. `src/reserves.ts`) and wire routes.

### Security / fail-closed (important)
The service currently has **no auth** on any endpoint (File 7). For reserve registry CRUD, add a simple fail-closed admin guard:

- Require header: `X-Admin-Token: <token>`
- Add `Env.ADMIN_TOKEN?: string` (extend `Env` in **`types.ts`**, File 4).
- Behavior:
  - If `ADMIN_TOKEN` is unset → **all reserve CRUD endpoints return 403** (fail-closed).
  - If set, require exact match.

This respects “no live deploys; PRs only” while still preventing accidental writes.

### CRUD routes

#### Registry
- `GET /reserve/assets`
  - List registry items (supports `?provider=` and `?eligible=` filters).
- `POST /reserve/assets`
  - Create registry item (id supplied or generated).
- `GET /reserve/assets/:id`
- `PATCH /reserve/assets/:id`
  - Update `is_eligible`, `haircut_bps`, `max_age_seconds`, metadata, name, etc.
- `DELETE /reserve/assets/:id`
  - Soft-delete is better, but if you want hard delete: only if no snapshots exist; otherwise 409.

#### Snapshots (append-only; auditable)
- `POST /reserve/assets/:id/snapshots`
  - Body: `{ observedAt, rawAmount, source, sourceRef?, snapshotMetadata? }`
- `GET /reserve/assets/:id/snapshots?limit=50`
- `GET /reserve/assets/:id/snapshots/latest`

### Attestation endpoint change (public)
Existing:
- `GET /attestation/reserve` in **`index.ts`** → `ReserveAttestationService.generateAttestation()` (Files 7 and 3)

Add reserve breakdown into the existing response. The PRD explicitly requires “Include reserve breakdown in signed attestation” (CLD-US-010, File 1).

#### Proposed response additions
Extend `ReserveAttestation` in **`types.ts`** (File 4) to include:

```ts
reserveBreakdown: Array<{
  reserveAssetId: string;
  provider: string;
  assetType: string;
  name: string;
  unit: string;

  // observation
  observedAt?: Timestamp;
  rawAmount?: string;

  // policy
  isEligible: boolean;
  haircutBps: number;
  maxAgeSeconds: number;

  // derived
  isStale: boolean;
  eligibleAmount: string; // floor(rawAmount * (1 - haircut))
}>;
eligibleReservesTotal: string; // sum of eligibleAmount
rawReservesTotal: string;      // sum of rawAmount (latest snapshots only)
reserveComputation: {
  asOf: Timestamp;
  snapshotCountUsed: number;
  missingSnapshotAssetIds: string[];
  staleAssetIds: string[];
};
signature: string;             // now real signature bytes b64 (see §4)
signatureAlg: string;
keyId: string;
payloadHash: string;
```

**Fail-closed logic for attestation reserves**
- If an asset is `is_eligible=1` but has **no snapshot** → eligibleAmount = 0 and it appears in `missingSnapshotAssetIds`.
- If snapshot exists but is older than `max_age_seconds` → eligibleAmount = 0 and appears in `staleAssetIds`.
- If haircut_bps invalid → treat as 10000.

This replaces the current “reserves = net minted” logic in **`computeNetMinted()`** (File 3), which is not a reserve measure (it’s more like an issuance counter).

---

## 3) Modeling compute reserves for Gemini (k) and FAL (.5k) credits

You need two concepts:
1) **Registry definition** of each provider credit bucket (Gemini, FAL).
2) **Snapshots** of current balances (manual now; automated later).

### Reserve asset registry entries (two rows)
Create these `reserve_assets` rows:

**Gemini compute credits**
- `id`: `ras_compute_gemini_k`
- `asset_type`: `compute_credit`
- `provider`: `gemini`
- `unit`: `credit` (or `inference_credit`)
- `provider_metadata` (JSON): include SKU semantics:
  - `{ "sku": "k_credits", "credits_per_unit": 1000 }`

**FAL compute credits**
- `id`: `ras_compute_fal_halfk`
- `asset_type`: `compute_credit`
- `provider`: `fal`
- `unit`: `credit`
- `provider_metadata`:
  - `{ "sku": "halfk_credits", "credits_per_unit": 500 }`

### What fields to store
In snapshots:
- `raw_amount`: store the **actual usable credits remaining**, normalized to **single-credit units** (not “packs”).
  - Gemini “k credits” → convert to credits at ingestion time:
    - if you have 12 packs, snapshot raw_amount = `12000`
  - FAL “.5k credits” similarly:
    - 12 packs → `6000`

This keeps attestation math simple: liabilities and reserves are both in “credit” integer units (matches ledger’s integer-string practice in Files 3–6).

If later you need a different unit conversion, you can do it at ingestion using `provider_metadata.credits_per_unit`.

### Refresh cadence (no live deploys; fail-closed)
- **Manual snapshots** via admin endpoint initially.
- Recommended cadence:
  - **daily** snapshots minimum (`max_age_seconds = 86400`)
  - if these balances change quickly, use **hourly** snapshots and set `max_age_seconds = 7200` (2h) to allow a missed run.

Fail-closed policy is controlled per asset by `max_age_seconds`. If ops forget to update, the system attests **0 eligible** compute reserves (but still reports the raw last-known in breakdown as stale, if you choose to include it).

### Conservative haircut policy
Start conservative, overrideable via `haircut_bps`:

- Gemini compute credits: `haircut_bps = 5000` (count 50%)
- FAL compute credits: `haircut_bps = 7000` (count 30%)

Rationale: compute credits are vendor-specific, non-cash, revocable/expiring, and may not match your liability semantics perfectly. You can tighten further (e.g., 8000–9000) without schema changes.

---

## 4) Signing the attestation (what to sign, canonicalization) + clawverify verification

Today the “signature” is `sha256("sign:" + attestationData)` in **`attestation.ts`** (File 3). That is not a verifiable digital signature.

### What should be signed
Sign a **single canonical payload** that includes:
- the full `attestation` object **excluding** signature fields
- `latestEventHash` (already part of the current signature input, File 3)
- a `schema`/`version`

Example `payloadToSign`:

```json
{
  "schema": "clawledger.reserve_attestation",
  "version": "1.1.0",
  "latestEventHash": "…",
  "attestation": {
    "id": "att_…",
    "timestamp": "…",
    "totalOutstanding": "…",
    "outstandingByBucket": { … },
    "rawReservesTotal": "…",
    "eligibleReservesTotal": "…",
    "reserveBreakdown": [ … ],
    "coverageRatio": "…",
    "isFullyBacked": true,
    "accountCount": 123,
    "balanceHash": "…"
  }
}
```

### Canonicalization (deterministic; auditable)
Use RFC 8785 JSON Canonicalization Scheme (JCS) behavior:
- UTF-8
- object keys sorted lexicographically
- no whitespace
- arrays preserved order
- numbers as JSON numbers only if used (you mostly use strings for bigints)

Implementation approach:
- Add a `canonicalizeJson(value): string` utility that recursively sorts keys and uses `JSON.stringify()` on the transformed structure.

Then:
- `payloadCanonical = canonicalizeJson(payloadToSign)`
- `payloadHash = sha256(payloadCanonical)`

### Signature algorithm
Use WebCrypto-supported asymmetric signing:
- **ECDSA P-256 with SHA-256** is widely supported in Workers.
- Env supplies a private key JWK and key id:
  - `ATTESTATION_SIGNING_KEY_JWK` (string)
  - `ATTESTATION_SIGNING_KEY_ID` (string)

Sign `payloadCanonical` bytes (or sign `payloadHash` bytes—either is fine if you specify which; simplest is sign bytes of canonical).

Return:
- `signatureAlg`: `"ECDSA_P256_SHA256"`
- `keyId`: from env
- `payloadHash`: hex sha256
- `signature`: base64 of DER signature (WebCrypto returns raw; you may need conversion—document precisely)

### Making it verifiable by clawverify
`clawverify` needs:
- the canonicalization procedure (same function / spec)
- the public key for `keyId`

Verification steps:
1) Rebuild `payloadToSign` from the response fields exactly as specified.
2) Canonicalize via JCS.
3) Hash with SHA-256 (optional if verifying directly over bytes).
4) Verify signature with public key corresponding to `keyId`.

Practical distribution:
- Either (a) hardcode known public keys in clawverify by `keyId`, or
- (b) expose `GET /attestation/keys/:keyId` returning public JWK (recommended later).
For now, simplest: embed `keyId` + keep public key mapping in clawverify repo.

Also: store `payload_canonical`, `payload_hash`, signature in `reserve_attestations` (Migration 0007 above) for audit replay.

---

## 5) Test plan (unit + fixtures + migration tests)

Assuming you’re already using a test runner (if not, add Vitest). Focus on deterministic tests with an in-memory/miniflare D1.

### A. Migration tests
1) Apply existing migrations:
   - **`migrations/0001_create_accounts.sql`** (File 8)
   - **`migrations/0002_create_events.sql`** (File 9)
   - **`migrations/0004_create_reconciliation_reports.sql`** (File 10)
2) Apply new migrations 0005–0007.
3) Assertions:
   - tables exist
   - indexes exist (query `sqlite_master`)
   - constraints: `reserve_assets.haircut_bps` default, not null fields

### B. Unit tests: reserve eligibility math (fail-closed)
Fixtures:
- create 2 reserve assets (gemini/fal) with haircuts and max_age_seconds.
- insert snapshots:
  - fresh snapshot for gemini
  - stale snapshot for fal
  - no snapshot for a third eligible asset

Assertions:
- eligibleAmount floors correctly:
  - `eligible = floor(raw * (10000 - haircut_bps)/10000)`
- stale or missing → eligible = 0
- reserveComputation lists stale/missing IDs

### C. Unit tests: attestation breakdown and totals
Insert:
- accounts with balances (via direct insert or existing services)
- ensure `balanceHash` is stable given deterministic ordering (File 3 currently orders by id)
- ensure coverage ratio uses **eligibleReservesTotal** (not net minted)

Assertions:
- totals by bucket match inserted accounts
- `coverageRatio` correctness with 4 decimals
- `isFullyBacked` computed vs eligible reserves

### D. Signature tests
- Use a fixed test private key JWK in env.
- Generate attestation; verify signature with the corresponding public key.
- Verify that modifying any field breaks signature (tamper test).

### E. CRUD route tests (admin-gated)
- With `ADMIN_TOKEN` unset:
  - POST /reserve/assets returns 403
- With correct token:
  - create asset, patch asset, list assets
  - append snapshot, read latest snapshot

### Fixture examples (checked-in JSON)
Add fixture files under something like:
- `services/ledger/test/fixtures/reserve_assets.json`
- `services/ledger/test/fixtures/reserve_snapshots.json`

Include examples for:
- Gemini k credits
- FAL .5k credits
- a stale snapshot

---

## 6) PR plan (smallest safe slices)

Constraints you gave: fail-closed, auditable, PR-only, git-signed commits, no live deploys.

### PR1 — D1 schema + types (no behavior change)
- Add migrations 0005 and 0006 (and optionally 0007).
- Extend `ReserveAttestation` types in **`services/ledger/src/types.ts`** (File 4) but keep endpoint output backwards compatible by not populating yet (or bump version field).
- Add reserve entity TS types + repository skeleton (no router wiring).

### PR2 — Reserve asset registry CRUD (admin-only; fail-closed)
- Add `ADMIN_TOKEN` to `Env` and implement header guard in router.
- Add routes + handlers in **`services/ledger/src/index.ts`** (File 7) or new `reserves.ts`.
- Add tests for auth gating and CRUD.

### PR3 — Snapshot ingestion + “latest snapshot” queries
- Implement `POST /reserve/assets/:id/snapshots` and `GET latest`.
- Add staleness calculation helper + tests.

### PR4 — Update reserve attestation to use registry + breakdown
- Modify **`ReserveAttestationService` in `src/attestation.ts`** (File 3):
  - remove/stop using `computeNetMinted()` as “reserves”
  - compute reserves from latest snapshots + eligibility rules
  - include breakdown in attestation
- Tests for totals + fail-closed rules.

### PR5 — Real cryptographic signing + persistence
- Implement canonicalization + ECDSA signing.
- Add env key handling (`ATTESTATION_SIGNING_KEY_JWK`, `…_KEY_ID`).
- Store served attestations in `reserve_attestations` (if you add Migration 0007).
- Add verification tests.

### PR6 — Seed / docs for Gemini + FAL compute reserves policy
- Add documentation (internal) explaining:
  - how to normalize k and .5k packs into raw credits
  - recommended cadence
  - default haircuts
- Add fixture scripts or examples (not production seed unless you want a migration insert).

---

If you want, I can draft the exact migration filenames/content (0005–0007), the TS interfaces to add to **`services/ledger/src/types.ts`** (File 4), and a concrete `ReserveRepository` query for “latest snapshot per asset” that’s efficient in SQLite/D1.
