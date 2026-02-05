# ClawDepositIntentRegistry (Hackathon SmartContract)

Non-custodial registry for USDC deposit intent commitments + claim bindings. **Not escrow. No custody. Testnet only.**

- Chain: **Base Sepolia** (chainId 84532)
- USDC: **0x036CbD53842c5426634e7929541eC2318f3dCF7e**

This contract complements the testnet connector flow in `/hackathons/usdc-hackathon-2026/docs/API.md`.

## Build / Deploy

```bash
# install deps (from contracts/)
pnpm install

# set deployer private key (testnet only)
export DEPLOYER_KEY=0x...

# deploy + verify
pnpm deploy
```

## Non-goals
- No token transfers
- No escrow/custody
- No mainnet support
