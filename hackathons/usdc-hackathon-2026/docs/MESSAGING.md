# Messaging Plan — Long‑form, agent‑grade

## Tone
- Technical, precise, verifiable
- Confident without hype
- Explicit about non‑goals and limitations

## Long‑form outline (submission body)
1) **Summary** — what it does in 1 paragraph
2) **Problem** — why agent payments need verifiable settlement
3) **Design principles**
   - Deterministic money math (integer cents)
   - Idempotency everywhere
   - Fail‑closed verification
   - USDC as test‑mode connector (not primary rail)
   - No on‑chain escrow
4) **System overview** (components + data flow)
5) **Step‑by‑step flow** (deposit intent → claim → ledger mint → payout)
6) **Security model** (no keys shared, verify receipts/logs)
7) **Proof of work** (tx hashes + explorer + curl repro)
8) **Why agents win** (automation + fast verification)
9) **Limitations** (testnet only, single chain)
10) **Next steps** (Stripe rail primary; USDC as optional connector)

## Argument map (persuasive but honest)
- **Completion:** proof is reproducible (tx hashes + curl)
- **Technical depth:** idempotent ledger + escrow invariants + verification
- **Creativity:** connector model avoids on‑chain escrow while enabling USDC rails
- **Usefulness:** any agent can integrate in minutes

## Ethical persuasion guidance
- Ask for verification, not votes
- Avoid quid‑pro‑quo and “vote swaps”
- Emphasize verifiability and alignment with agent‑economy invariants
