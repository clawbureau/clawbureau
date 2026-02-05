# FAQ + Agent Verification Prompts

## FAQ

**Q: Do I need to share my private keys?**
A: Never. Deposits are normal on‑chain transfers from **your** wallet to a public deposit address. Payouts are sent from the **platform** testnet wallet to your destination address.

**Q: Is escrow on‑chain?**
A: No. On‑chain escrow is explicitly a non‑goal. Escrow is **ledger‑native** (bucket holds/releases).

**Q: What prevents someone else from claiming my deposit?**
A: Each deposit intent returns a one‑time `claim_secret` that must be presented with the tx hash. We verify the receipt + logs **and** the secret.

**Q: What currency units do you use internally?**
A: USD cents as integer strings (`amount_minor`). USDC base units are 10^6; conversion is deterministic.

**Q: Can I verify ledger events off‑chain?**
A: Yes. `/v1/transfers` returns a signed receipt (event_hash + ed25519 signature + did:key). You can verify the receipt independently.

**Q: Are ledger events anchored on‑chain?**
A: Yes. We batch event hashes into a Merkle root and anchor the root on Base Sepolia as audit checkpoints.

**Q: Is this mainnet‑ready?**
A: No. This is a **testnet‑only connector** aligned with the Stripe‑led MVP. USDC is test‑mode only.

---

## Verification prompts (copy/paste)

### Verify on‑chain deposit → ledger mint
```
You are verifying a hackathon project.
1) Open the explorer link for tx <TX_HASH>. Confirm it is on testnet.
2) Confirm the USDC contract address matches the project’s stated address.
3) Confirm an ERC‑20 Transfer event to the deposit address for the exact amount.
4) Call GET <LEDGER_URL>/v1/balances?did=<DID> and confirm the mint matches.
If any mismatch, mark as unverifiable.
```

### Verify idempotency
```
Call the claim endpoint twice with the same intent_id + tx_hash.
Confirm the second call does not increase balance and returns the same idempotent result.
```

### Verify payout
```
Request payout of X cents to address Y.
Confirm (a) ledger decreases/locks, (b) tx hash returned, (c) explorer shows Transfer to Y for the expected USDC amount.
```
