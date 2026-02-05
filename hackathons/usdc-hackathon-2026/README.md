# ClawSettle — USDC Testnet Connector (USDC Hackathon 2026)

A **testnet-only USDC settlement connector** for OpenClaw agents. Create deposit intents, verify on-chain USDC transfers, mint Claw Credits in a ledger, and pay out USDC — **without on-chain escrow**.

**Tracks:** Skill · AgenticCommerce · SmartContract (registry)

## Quick links
- **Proof & reproducible commands:** [PROOF.md](./PROOF.md)
- **Public skill page:** [skills.md](./skills.md)
- **OpenClaw skill (agent runtime):** [skill/SKILL.md](./skill/SKILL.md)
- **Submission drafts:** [submissions/FINAL_POSTS.md](./submissions/FINAL_POSTS.md)
- **Contracts:** [contracts/](./contracts/)

## Live endpoints (custom domains)
- **Settle (USDC connector):** https://usdc-testnet.clawsettle.com
- **Ledger:** https://usdc-testnet.clawledger.com
- **Escrow:** https://usdc-testnet.clawescrow.com

Health checks:
- https://usdc-testnet.clawsettle.com/health
- https://usdc-testnet.clawledger.com/health
- https://usdc-testnet.clawescrow.com/health

## On-chain audit anchor
- **Anchor contract:** 0x5cE94B3d7f3330215acc9A746d84f216530E1988
- **Anchor tx (Merkle root):** https://sepolia.basescan.org/tx/0xf58ea7bd67e63a6641a7a5f4065eacbf84b41e78ca81c6ea318559af108c43fe

> ⚠️ **Testnet only. No mainnet. No real funds.**

## What this is (and isn’t)
**Is:**
- Verifiable USDC deposit → ledger mint → payout loop
- Idempotent ledger transfers with bucketed balances (A/H/F)
- **Signed ledger receipts** (ed25519) + **Merkle root anchoring** on-chain
- Ledger‑native escrow holds/releases

**Is not:**
- On-chain escrow
- Mainnet settlement
- Stripe replacement (**USDC here is a test‑mode connector only**)

## 90‑second verification (proof)
1) **Deposit receipt** → 5.000000 USDC transfer
   - https://sepolia.basescan.org/tx/0x8c6c2ddbdca1bedecd89d153fb5d42f3742edff4f63f5ecf81f3b4360ab554f0
2) **Payout receipt** → 1.000000 USDC transfer
   - https://sepolia.basescan.org/tx/0xb08e81f347642d000205fe4e85f247c89a52b2d989c700dfb0b9060ee1173edf
3) **Ledger balance** → `A=400` for `did:key:deposit-demo`
   ```bash
   curl -s "https://usdc-testnet.clawledger.com/v1/balances?did=did:key:deposit-demo"
   ```

Full details + exact commands: [PROOF.md](./PROOF.md)

## Quickstart (curl)
```bash
export SETTLE_URL="https://usdc-testnet.clawsettle.com"
export LEDGER_URL="https://usdc-testnet.clawledger.com"

# 1) Create deposit intent
curl -s -X POST "$SETTLE_URL/v1/usdc/deposit-intents" \
  -H "Content-Type: application/json" \
  -d '{
    "buyer_did": "did:key:...",
    "amount_minor": "500",
    "currency": "USD"
  }'

# 2) Claim deposit (after sending USDC to deposit_address)
curl -s -X POST "$SETTLE_URL/v1/usdc/deposits/claim" \
  -H "Content-Type: application/json" \
  -d '{
    "intent_id": "...",
    "claim_secret": "...",
    "tx_hash": "0x..."
  }'

# 3) Check balances
curl -s "$LEDGER_URL/v1/balances?did=did:key:..."
```

More repro scripts: [`scripts/curl/`](./scripts/curl/)

## Architecture (minimal, verifiable)
```
USDC transfer → ClawSettle verifies receipt → Ledger mint (A) → Escrow hold (H) → Payout (USDC)
```

## Repository structure
```
./
  README.md
  PROOF.md                 # Proof artifacts + reproducible curl commands
  skills.md                # Public skill page (viral, agent‑friendly)
  docs/                    # API, FAQ, messaging, plan
  skill/                   # OpenClaw skill used by agents
  submissions/             # Moltbook submission drafts
  services/                # Workers (settle, ledger, escrow)
  contracts/               # SmartContract registry
  scripts/curl/            # Repro scripts
```

## References
- `docs/AGENT_ECONOMY_MVP_SPEC.md`
- `docs/prds/clawsettle.md`
- `docs/prds/clawledger.md`
- `docs/prds/clawescrow.md`
- `02-Projects/clawbureau/usdc-hackathon-1.0.4/SKILL.md`
