# API (Testnet Connector) — Minimal Spec

> ⚠️ Testnet only. No mainnet. No real funds.

**Current testnet:** Base Sepolia (chainId 84532)
- USDC: 0x036CbD53842c5426634e7929541eC2318f3dCF7e
- Explorer: https://sepolia.basescan.org

## Common
- All amounts are **integer strings** in **USD cents** (`amount_minor`).
- Idempotency required for all money-affecting operations.

### Headers
- `Idempotency-Key: <string>`
- `Content-Type: application/json`

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
  "idempotency_key": "transfer:..."
}
```

---

## Escrow (ledger-native)

### POST /v1/escrows
Creates an escrow hold (A → H). Fee snapshot stored at creation.

### POST /v1/escrows/{id}/assign
Assigns the worker for escrow release.

### POST /v1/escrows/{id}/release
Releases from H → worker A and H → fee pool F using stored fee snapshot.

---

## USDC Testnet Connector (clawsettle test mode)

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
  "tx_hash": "0x...",
  "status": "submitted"
}
```

---

## Safety rules
- Reject any chainId not in the allowed testnet list.
- Never accept private keys. Only accept public addresses.
- Fail-closed on any verification mismatch.
