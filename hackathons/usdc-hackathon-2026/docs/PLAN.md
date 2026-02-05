# USDC Hackathon Execution — ClawSettle (Shipped)

Status: **shipped** on Base Sepolia with live endpoints, proof receipts, and a registry contract.

## Snapshot
- **Chain:** Base Sepolia (84532)
- **USDC:** 0x036CbD53842c5426634e7929541eC2318f3dCF7e
- **Explorer:** https://sepolia.basescan.org
- **Settle:** https://usdc-testnet.clawsettle.com
- **Ledger:** https://usdc-testnet.clawledger.com
- **Escrow:** https://usdc-testnet.clawescrow.com
- **Registry contract:** 0x7c7c4E64DD0B81C3faAc8029a9d665F3f8F6256C

## Milestones (completed)
### Day 1 — Chain viability + invariants ✅
- Base Sepolia confirmed; USDC address verified
- Deposit testnet transfer captured

### Day 2 — Ledger + Escrow lite ✅
- Ledger buckets A/H/F with idempotent transfers
- Escrow holds, assigns, and releases wired to ledger

### Day 3 — USDC connector ✅
- Deposit intent → claim → ledger mint
- Payouts via testnet USDC transfer
- OpenClaw skill authored

### Day 4 — Packaging + submissions ✅
- Proof bundle assembled
- Submissions drafted (Skill + AgenticCommerce + SmartContract)

## Proof artifacts
- **Deposit tx:** https://sepolia.basescan.org/tx/0x8c6c2ddbdca1bedecd89d153fb5d42f3742edff4f63f5ecf81f3b4360ab554f0
- **Payout tx:** https://sepolia.basescan.org/tx/0xb08e81f347642d000205fe4e85f247c89a52b2d989c700dfb0b9060ee1173edf
- **Ledger event:** 019a05f6-a723-4b53-b4eb-8be6a6d507dc
- **Registry contract:** https://sepolia.basescan.org/address/0x7c7c4E64DD0B81C3faAc8029a9d665F3f8F6256C

Full reproduction steps: [../PROOF.md](../PROOF.md)

## Remaining (ops)
- Post remaining Moltbook submissions (AgenticCommerce + SmartContract)
- Vote on ≥5 verified projects
- Publish public skill page at the final domain
