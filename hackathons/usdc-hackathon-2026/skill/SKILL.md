---
name: clawsettle-usdc-testnet
description: Testnet USDC settlement connector for OpenClaw agents. Create deposit intents, verify on-chain transfers, mint ledger credits, and request USDC payouts. Use for hackathon/testnet verification only.
---

# ClawSettle — USDC Testnet Connector

**Testnet only. No mainnet. No real funds.**

Use this skill to verify USDC transfers on Base Sepolia, mint ledger credits, and request USDC payouts — without on‑chain escrow.

## Quick start
```bash
export SETTLE_URL="https://usdc-testnet.clawsettle.com"
export LEDGER_URL="https://usdc-testnet.clawledger.com"
```

## Workflow (sequential)
1) **Create deposit intent** → get `deposit_address` + `claim_secret`.
2) **Send USDC testnet** to `deposit_address`.
3) **Claim deposit** with `intent_id` + `claim_secret` + `tx_hash`.
4) **Check balances** to confirm mint.
5) **Request payout** to a destination address.

### 1) Create deposit intent
```bash
curl -s -X POST "$SETTLE_URL/v1/usdc/deposit-intents" \
  -H "Content-Type: application/json" \
  -d '{"buyer_did":"did:key:...","amount_minor":"500","currency":"USD"}'
```

### 2) Claim deposit
```bash
curl -s -X POST "$SETTLE_URL/v1/usdc/deposits/claim" \
  -H "Content-Type: application/json" \
  -d '{"intent_id":"...","claim_secret":"...","tx_hash":"0x..."}'
```

### 3) Check balances
```bash
curl -s "$LEDGER_URL/v1/balances?did=did:key:..."
```

### 4) Request payout
```bash
curl -s -X POST "$SETTLE_URL/v1/usdc/payouts" \
  -H "Content-Type: application/json" \
  -d '{"worker_did":"did:key:...","amount_minor":"100","destination_address":"0x...","idempotency_key":"payout:demo:001"}'
```

## Verification checklist
- Verify the **USDC Transfer** log to the deposit address for the exact amount.
- Confirm ledger mint matches `amount_minor`.
- Verify payout Transfer to destination address.

## Safety rules
- Never request or store private keys.
- Reject mainnet chain IDs.
- Fail‑closed on any verification mismatch.
- Treat `claim_secret` as sensitive.

## Resources
- Repro scripts: `../scripts/curl/`
- API spec: `../docs/API.md`
- Proof bundle: `../PROOF.md`

## Non‑goals
- No on‑chain escrow
- No mainnet support
- No CCTP unless explicitly added later
