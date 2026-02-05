# API (Testnet Connector) — Minimal Spec

> ⚠️ **Testnet only.** No mainnet. No real funds.

## Base URLs
- **Settle (USDC connector):** https://usdc-testnet.clawsettle.com
- **Ledger:** https://usdc-testnet.clawledger.com
- **Escrow:** https://usdc-testnet.clawescrow.com

## Conventions
- `amount_minor` is an **integer string** in **USD cents**.
- `idempotency_key` is required for all money‑affecting operations **in the JSON body**.
- `currency` must be `"USD"`.

### Response shape
Success:
```json
{ "success": true, "...": "..." }
```
Errors:
```json
{ "success": false, "error": "message", "details": "..." }
```

## Health
- `GET /health` → `{ "status": "ok" }`

---

## Ledger

### GET /v1/balances?did=<did>
Returns bucket balances: A (available), H (held), F (fee pool).

### POST /v1/transfers
Moves balances between buckets. Idempotent.

```json
{
  "from_did": "did:key:...",
  "to_did": "did:key:...",
  "amount_minor": "100",
  "currency": "USD",
  "from_bucket": "A",
  "to_bucket": "H",
  "idempotency_key": "transfer:...",
  "metadata": { "note": "optional" }
}
```

**Response (includes signed receipt)**
```json
{
  "success": true,
  "event": { "event_id": "...", "created_at": "..." },
  "receipt": {
    "event_hash": "...",
    "signature": "...",
    "alg": "ed25519-sha256",
    "did": "did:key:...",
    "public_key": "..."
  }
}
```

### GET /v1/events/{event_id}
Returns a single event plus its signed receipt.

### GET /v1/anchors
Lists anchored Merkle roots (audit checkpoints).

### POST /v1/anchors (admin)
Anchors a Merkle root for new events.

**Headers**
```
Authorization: Bearer <ANCHOR_ADMIN_KEY>
```

**Anchor contract:** `0x5cE94B3d7f3330215acc9A746d84f216530E1988` (Base Sepolia)

---

## Escrow (ledger‑native)

### POST /v1/escrows
Creates an escrow hold (A → H). Fee snapshot stored at creation.

```json
{
  "buyer_did": "did:key:...",
  "amount_minor": "500",
  "fee_minor": "25",
  "currency": "USD",
  "idempotency_key": "escrow:create:..."
}
```

### POST /v1/escrows/{id}/assign
Assigns a worker for escrow release.

```json
{ "worker_did": "did:key:..." }
```

### POST /v1/escrows/{id}/release
Releases from H → worker A and H → fee pool F using stored fee snapshot.

---

## USDC Testnet Connector (ClawSettle)

### POST /v1/usdc/deposit-intents
Creates a deposit intent and returns a platform deposit address + claim secret.

```json
{
  "buyer_did": "did:key:...",
  "amount_minor": "500",
  "currency": "USD"
}
```

**Response**
```json
{
  "intent_id": "...",
  "deposit_address": "0x...",
  "amount_usdc_base": "5000000",
  "expires_at": "...",
  "claim_secret": "..."
}
```

### POST /v1/usdc/deposits/claim
Claims a deposit by verifying tx receipt + USDC Transfer logs.

```json
{
  "intent_id": "...",
  "claim_secret": "...",
  "tx_hash": "0x..."
}
```

**Behavior**
- Verifies on-chain transfer to `deposit_address` for exact `amount_usdc_base`.
- Mints ledger credits with idempotency key `usdc:tx:<tx_hash>`.

### POST /v1/usdc/payouts
Transfers USDC from platform testnet wallet to destination.

```json
{
  "worker_did": "did:key:...",
  "amount_minor": "100",
  "destination_address": "0x...",
  "idempotency_key": "payout:..."
}
```

**Response**
```json
{
  "success": true,
  "tx_hash": "0x...",
  "status": "submitted"
}
```

---

## Safety rules
- Reject any chainId not in the allowed testnet list.
- Never accept private keys. Only accept public addresses.
- Fail‑closed on any verification mismatch.
