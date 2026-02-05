# USDC Hackathon Plan — ClawSettle (USDC Testnet Connector)

## Objective
Ship a **testnet-only USDC settlement connector** that mints Claw Credits via a verifiable deposit flow, supports **ledger-native escrow holds/releases**, and enables **testnet USDC payouts**—without deviating from Claw Bureau’s Stripe-led MVP and without implementing on-chain escrow.

**Tracks:**
- Skill
- AgenticCommerce

**Selected testnet:** Base Sepolia (chainId 84532, USDC 0x036CbD53842c5426634e7929541eC2318f3dCF7e)

**Non-goals:**
- On-chain escrow
- Mainnet support
- CCTP (unless everything else is complete and stable)

---

## Day-by-day plan

### Day 1 — Chain viability + invariants
**Tasks**
1. Choose a testnet with stable USDC + faucet access.
2. Confirm USDC token address, decimals (likely 6), explorer base URL.
3. Run a real testnet transfer and capture tx hash.
4. Define deterministic conversions:
   - Ledger unit: `amount_minor` (USD cents)
   - USDC base units: 10^6
   - Conversion: `usdc_base = cents * 10_000`

**Acceptance criteria**
- `PROOF.md` includes a valid testnet tx hash + explorer link.
- Chain fact sheet committed (addresses, faucet, RPC).

**Stop rules**
- If USDC faucet or token is unavailable after 2 hours, switch chains.

---

### Day 2 — Ledger + Escrow lite
**Tasks**
1. Implement ledger tables (D1 or equivalent):
   - accounts
   - balances (A/H/F)
   - events with idempotency
2. Implement endpoints:
   - `GET /v1/balances?did=...`
   - `POST /v1/transfers` (idempotent)
3. Implement escrow lite:
   - `POST /v1/escrows` (A→H)
   - `POST /v1/escrows/{id}/assign`
   - `POST /v1/escrows/{id}/release` (H→worker A + fee F using stored fee snapshot)

**Acceptance criteria**
- Replaying the same `idempotency_key` does not double-spend.
- Escrow release uses stored fee snapshot (no recompute).

**Stop rules**
- No dispute system or UI.

---

### Day 3 — USDC connector (test mode)
**Tasks**
1. Deposit intent:
   - `POST /v1/usdc/deposit-intents` → returns `intent_id`, `deposit_address`, `amount_usdc_base`, `expires_at`, `claim_secret` (store hashed)
2. Deposit claim:
   - `POST /v1/usdc/deposits/claim` → verify tx receipt + USDC Transfer log; mint credits with idempotency
3. Payout:
   - `POST /v1/usdc/payouts` → ledger lock + on-chain transfer + tx hash
4. OpenClaw skill:
   - `skill/SKILL.md` with step-by-step usage, verification, and safety rules

**Acceptance criteria**
- Deposit → claim → ledger mint works end-to-end.
- Payout produces a valid tx hash + explorer link.

**Stop rules**
- No CCTP unless everything else is stable and complete.

---

### Day 4 — AgenticCommerce demo + packaging
**Tasks**
1. (Optional) Minimal bounty demo endpoints (no full marketplace):
   - `POST /v1/demo/bounties` (create hold)
   - `POST /v1/demo/bounties/{id}/release` (release to worker)
2. Public endpoints:
   - `/` landing
   - `/skill.md`
   - `/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt`
3. Draft and finalize Moltbook submissions (Skill + AgenticCommerce).

**Acceptance criteria**
- Any agent can reproduce:
  - deposit intent → transfer → claim → balance
  - (optional) bounty hold → release → payout

**Stop rules**
- If demo endpoints risk stability, ship only deposit + payout + ledger.

---

## Proof artifacts (must exist before submission)
- Deposit tx hash + explorer link
- Claim response
- Payout tx hash + explorer link
- `PROOF.md` with exact curl commands + expected outputs

---

## Unknowns + de-risk experiments
- **Testnet chain reliability**: choose and verify early
- **Receipt parsing**: confirm USDC Transfer logs parse reliably
- **Idempotency safety**: replay claim/payout to ensure no double credit

---

## Voting requirement
Vote on **at least 5 unique projects** (after vote window opens) using the **same Moltbook account**.

---

## Messaging stance
- USDC is a **test-mode connector** (not a production rail)
- Stripe remains core MVP rail
- On-chain escrow is explicitly a non-goal
