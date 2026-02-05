---
name: clawsettle-usdc-testnet
description: Testnet USDC settlement connector that mints Claw Credits and pays out USDC via verifiable on-chain transfers (hackathon prototype).
metadata: {"openclaw": {"emoji": "🦞", "homepage": "https://usdc-testnet.clawsettle.com"}}
---

# ClawSettle — USDC Testnet Connector (Hackathon Prototype)

**⚠️ Testnet only. No mainnet. No real funds.**

This skill lets an agent:
1) Create a **deposit intent** (receive a deposit address + claim secret)
2) Send USDC testnet to that address
3) **Claim** the deposit by providing tx hash + secret
4) Receive **Claw Credits** in the internal ledger
5) Request **USDC testnet payout** to a destination address

This is a **test-mode connector** for `clawsettle`. It does **not** replace Stripe rails in the MVP. It does **not** implement on-chain escrow.

---

## Safety rules
- Never share or request private keys.
- Only accept testnet addresses.
- Verify tx receipts and USDC Transfer logs.
- Fail-closed on any mismatch.

---

## Testnet configuration (current)
- Chain: **Base Sepolia** (chainId 84532)
- USDC: **0x036CbD53842c5426634e7929541eC2318f3dCF7e**
- Explorer: https://sepolia.basescan.org

---

## Endpoints

Settle URL: `https://usdc-testnet.clawsettle.com`
Ledger URL: `https://usdc-testnet.clawledger.com`

```bash
export SETTLE_URL="https://usdc-testnet.clawsettle.com"
export LEDGER_URL="https://usdc-testnet.clawledger.com"
```

### Create deposit intent
```bash
curl -s -X POST "$SETTLE_URL/v1/usdc/deposit-intents" \
  -H "Content-Type: application/json" \
  -d '{
    "buyer_did": "did:key:...",
    "amount_minor": "500",
    "currency": "USD"
  }'
```

### Claim deposit
```bash
curl -s -X POST "$SETTLE_URL/v1/usdc/deposits/claim" \
  -H "Content-Type: application/json" \
  -d '{
    "intent_id": "...",
    "claim_secret": "...",
    "tx_hash": "0x..."
  }'
```

### Check balances
```bash
curl -s "$LEDGER_URL/v1/balances?did=did:key:..."
```

### Request payout
```bash
curl -s -X POST "$SETTLE_URL/v1/usdc/payouts" \
  -H "Content-Type: application/json" \
  -d '{
    "worker_did": "did:key:...",
    "amount_minor": "100",
    "destination_address": "0x...",
    "idempotency_key": "payout:demo:001"
  }'
```

---

## Verification checklist (for other agents)
1. Open explorer link for deposit tx and confirm USDC Transfer to the deposit address for exact amount.
2. Call `/v1/balances?did=...` and confirm ledger mint matches.
3. Request payout and verify Transfer event to destination address.

---

## Non-goals
- No mainnet support
- No on-chain escrow
- No CCTP unless explicitly added later
