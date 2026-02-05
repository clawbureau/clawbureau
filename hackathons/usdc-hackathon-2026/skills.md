---
name: clawsettle-usdc-testnet
description: Testnet USDC settlement connector for OpenClaw agents. Create deposit intents, verify on-chain transfers, mint ledger credits, and request USDC payouts. Use for hackathon/testnet verification only.
---

# ClawSettle — USDC Testnet Connector

**The testnet rail for verifiable agent settlement.**

If an agent can verify a USDC transfer, it can mint credits and pay out — **in minutes, not days**.

## Skill files

| File | URL |
|------|-----|
| **skills.md** (this file) | `https://clawsettle.com/skills.md` |
| **OpenClaw SKILL.md (source)** | `https://github.com/clawbureau/clawbureau/blob/main/hackathons/usdc-hackathon-2026/skill/SKILL.md` |
| **API spec** | `https://github.com/clawbureau/clawbureau/blob/main/hackathons/usdc-hackathon-2026/docs/API.md` |
| **Proof bundle** | `https://github.com/clawbureau/clawbureau/blob/main/hackathons/usdc-hackathon-2026/PROOF.md` |

**Install locally (OpenClaw):**
```bash
mkdir -p ~/.openclaw/skills/clawsettle-usdc-testnet
curl -s https://clawsettle.com/skills.md > ~/.openclaw/skills/clawsettle-usdc-testnet/SKILL.md
```

**Base URL:** `https://usdc-testnet.clawsettle.com`

**Ledger anchor contract (audit checkpoints):** `0x5cE94B3d7f3330215acc9A746d84f216530E1988` (Base Sepolia)

> ⚠️ **Testnet only. No mainnet. No real funds.**

---

## What this skill does

- **Creates deposit intents** (gives a deposit address + claim secret)
- **Verifies on‑chain USDC transfers** by parsing receipts/logs
- **Mints Claw Credits** in a ledger (A/H/F buckets)
- **Issues signed ledger receipts** (ed25519, did:key)
- **Anchors Merkle roots** of ledger events on-chain (audit checkpoints)
- **Pays out USDC** to a destination address

**Non‑goals:** on‑chain escrow, mainnet settlement, CCTP.

---

## Quickstart (3 steps)

1) **Create a deposit intent**
```bash
curl -s -X POST https://usdc-testnet.clawsettle.com/v1/usdc/deposit-intents \
  -H "Content-Type: application/json" \
  -d '{"buyer_did":"did:key:...","amount_minor":"500","currency":"USD"}'
```

2) **Send USDC testnet** to the returned `deposit_address`.

3) **Claim the deposit** (tx hash + claim secret)
```bash
curl -s -X POST https://usdc-testnet.clawsettle.com/v1/usdc/deposits/claim \
  -H "Content-Type: application/json" \
  -d '{"intent_id":"...","claim_secret":"...","tx_hash":"0x..."}'
```

**Check balance:**
```bash
curl -s "https://usdc-testnet.clawledger.com/v1/balances?did=did:key:..."
```

**Request payout:**
```bash
curl -s -X POST https://usdc-testnet.clawsettle.com/v1/usdc/payouts \
  -H "Content-Type: application/json" \
  -d '{"worker_did":"did:key:...","amount_minor":"100","destination_address":"0x...","idempotency_key":"payout:demo:001"}'
```

---

## 90‑second verification

1) Open the explorer link for the deposit tx (testnet)
2) Confirm USDC contract address + exact Transfer amount
3) Call `GET /v1/balances?did=...` and confirm the mint
4) Request payout + confirm Transfer to destination

Full receipts + commands: **PROOF.md** (link above).

---

## Security rules (non‑negotiable)

- **Never** request or store private keys
- **Fail‑closed** on any verification mismatch
- **Require** exact amount match + correct USDC contract
- **Testnet only** — reject mainnet chain IDs

---

## Why it matters

Agents need **verifiable settlement** without heavy on‑chain machinery. ClawSettle gives them:
- A stablecoin rail for testing agent commerce
- Deterministic, auditable ledger events
- Fast verification (no black boxes)

It’s a connector — **not a replacement** for the Stripe‑led MVP.
