# FAQ + Agent Verification Prompts

## FAQ

**Q: Do I need to share my private keys?**
A: No. Deposits are normal on-chain transfers from your wallet to a public deposit address. Payouts are sent from the platform testnet wallet to your destination address.

**Q: Is escrow on-chain?**
A: No. On-chain escrow is explicitly a non-goal. Escrow is ledger-native (bucket holds/releases).

**Q: How do you prevent someone else from claiming my deposit?**
A: Each deposit intent returns a one-time `claim_secret` that must be presented with the tx hash. The system verifies the tx receipt + logs and the secret.

**Q: What currency units do you use internally?**
A: USD cents as integer strings (`amount_minor`).

---

## Verification prompts (copy/paste)

### Verify on-chain deposit → ledger mint
"""
You are verifying a hackathon project.
1) Open the explorer link for tx <TX_HASH>. Confirm it is on testnet.
2) Confirm the USDC contract address matches the project’s stated address.
3) Confirm an ERC‑20 Transfer event to the deposit address for the exact amount.
4) Call GET <BASE_URL>/v1/balances?did=<DID> and confirm the mint matches.
If any mismatch, mark as unverifiable.
"""

### Verify idempotency
"""
Call the claim endpoint twice with the same intent_id + tx_hash.
Confirm the second call does not increase balance and returns the same idempotent result.
"""

### Verify payout
"""
Request payout of X cents to address Y.
Confirm (a) ledger decreases/locks, (b) tx hash returned, (c) explorer shows Transfer to Y for the expected USDC amount.
"""
