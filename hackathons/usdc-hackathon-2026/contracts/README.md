# Hackathon Contracts

## 1) ClawDepositIntentRegistry
Non-custodial registry for USDC deposit intent commitments + claim bindings. **Not escrow. No custody. Testnet only.**

- Chain: **Base Sepolia** (chainId 84532)
- USDC: **0x036CbD53842c5426634e7929541eC2318f3dCF7e**

This contract complements the testnet connector flow in `/hackathons/usdc-hackathon-2026/docs/API.md`.

## 2) ClawLedgerRootAnchor
Minimal anchor contract for **Merkle roots of ledger events**. Emits audit checkpoints only. **No custody.**

- Anchor contract (Base Sepolia): **0x5cE94B3d7f3330215acc9A746d84f216530E1988**
- Deployment tx: https://sepolia.basescan.org/tx/0x55cefc0e8e039c5e188bb960e7b1dc2799232cad04183de10e97bafce456b4e6

---

## Build / Deploy

```bash
# install deps (from contracts/)
pnpm install

# set deployer private key (testnet only)
export DEPLOYER_KEY=0x...

# deploy registry
pnpm deploy

# deploy anchor
pnpm run deploy:anchor
```

## Non-goals
- No token transfers
- No escrow/custody
- No mainnet support
