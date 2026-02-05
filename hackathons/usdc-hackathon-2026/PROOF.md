# PROOF — USDC Hackathon (ClawSettle Testnet Connector)

> ⚠️ Testnet only. No mainnet. No real funds.

## Chain fact sheet
- Chain name: **Base Sepolia**
- Chain ID: **84532**
- USDC token address: **0x036CbD53842c5426634e7929541eC2318f3dCF7e**
- USDC decimals: **6**
- Explorer base URL: **https://sepolia.basescan.org**
- Faucets:
  - USDC: https://faucet.circle.com/
  - ETH: https://faucet.quicknode.com/base/sepolia
- Platform deposit address: **0xe6Fb9eaE850a01B4FbFa186449793Bccf3cbDB10**

## Service URLs
- **Settle (USDC connector):** https://usdc-testnet.clawsettle.com
- **Ledger:** https://usdc-testnet.clawledger.com
- **Escrow:** https://usdc-testnet.clawescrow.com

## 90-second verification (no secrets)
1) **Deposit receipt** → confirm USDC Transfer log:
   - From: `0xadAe75273a444BF8B5100E55F7512cc48c8b58dc`
   - To: `0xe6Fb9eaE850a01B4FbFa186449793Bccf3cbDB10`
   - Amount: **5.000000 USDC** (5,000,000 base units)
   - Tx: https://sepolia.basescan.org/tx/0x8c6c2ddbdca1bedecd89d153fb5d42f3742edff4f63f5ecf81f3b4360ab554f0
2) **Payout receipt** → confirm USDC Transfer log:
   - From: `0xe6Fb9eaE850a01B4FbFa186449793Bccf3cbDB10`
   - To: `0xadAe75273a444BF8B5100E55F7512cc48c8b58dc`
   - Amount: **1.000000 USDC** (1,000,000 base units)
   - Tx: https://sepolia.basescan.org/tx/0xb08e81f347642d000205fe4e85f247c89a52b2d989c700dfb0b9060ee1173edf
3) **Ledger balance** → should show `A=400` (USD cents):
   ```bash
   curl -s "https://usdc-testnet.clawledger.com/v1/balances?did=did:key:deposit-demo"
   ```
   Expected:
   ```json
   {
     "did": "did:key:deposit-demo",
     "balances": {
       "A": "400",
       "H": "0",
       "F": "0"
     }
   }
   ```

---

## Deposit proof

- Deposit tx hash: **0x8c6c2ddbdca1bedecd89d153fb5d42f3742edff4f63f5ecf81f3b4360ab554f0**
- Explorer link: https://sepolia.basescan.org/tx/0x8c6c2ddbdca1bedecd89d153fb5d42f3742edff4f63f5ecf81f3b4360ab554f0

### Transfer details (decoded from receipt)
- From: `0xadAe75273a444BF8B5100E55F7512cc48c8b58dc`
- To: `0xe6Fb9eaE850a01B4FbFa186449793Bccf3cbDB10`
- Amount (base units): `5,000,000` (**5.000000 USDC**)
- Gas used: `62,159`
- Effective gas price: `1,200,500 wei`

### Claim response
```json
{
  "success": true,
  "ledger": {
    "success": true,
    "event": {
      "event_id": "019a05f6-a723-4b53-b4eb-8be6a6d507dc",
      "idempotency_key": "usdc:tx:0x8c6c2ddbdca1bedecd89d153fb5d42f3742edff4f63f5ecf81f3b4360ab554f0",
      "type": "transfer",
      "from_did": "clearing:clawsettle",
      "to_did": "did:key:deposit-demo",
      "amount_minor": "500",
      "currency": "USD",
      "from_bucket": "A",
      "to_bucket": "A",
      "metadata_json": null,
      "created_at": "2026-02-05T00:25:02.196Z"
    }
  }
}
```

---

## Payout proof

- Payout tx hash: **0xb08e81f347642d000205fe4e85f247c89a52b2d989c700dfb0b9060ee1173edf**
- Explorer link: https://sepolia.basescan.org/tx/0xb08e81f347642d000205fe4e85f247c89a52b2d989c700dfb0b9060ee1173edf

### Transfer details (decoded from receipt)
- From: `0xe6Fb9eaE850a01B4FbFa186449793Bccf3cbDB10`
- To: `0xadAe75273a444BF8B5100E55F7512cc48c8b58dc`
- Amount (base units): `1,000,000` (**1.000000 USDC**)
- Gas used: `45,059`
- Effective gas price: `1,200,000 wei`

### Payout response
```json
{
  "success": true,
  "tx_hash": "0xb08e81f347642d000205fe4e85f247c89a52b2d989c700dfb0b9060ee1173edf",
  "status": "submitted"
}
```

### Idempotency replay (same key)
```json
{
  "success": true,
  "payout": {
    "payout_id": "f903dc2c-61e7-4121-89a1-f1931702cd03",
    "worker_did": "did:key:deposit-demo",
    "amount_minor": "100",
    "destination_address": "0xadAe75273a444BF8B5100E55F7512cc48c8b58dc",
    "idempotency_key": "payout:demo:001",
    "tx_hash": "0xb08e81f347642d000205fe4e85f247c89a52b2d989c700dfb0b9060ee1173edf",
    "status": "submitted",
    "created_at": "2026-02-05T00:25:18.588Z"
  }
}
```

## Signed ledger receipt proof (ed25519)
- Event id: **c69b44a6-9e97-4807-82f7-cff24fa3c11a**
- Event hash (sha256): **818db3ccf671efec1944352bb6a1cd0768467d1c41ce64b8a9ee0eedccfb38b4**
- Signature: **ccHgUGVmor9oT4xsY6847ogyE3ojh6/ZNhBDdzV1KRbkl4KvPLXF6ooM9PkcT1RsE6cpWyYo97aPzEmg/ZatBQ==**
- Signature alg: **ed25519-sha256**
- Signing DID: **did:key:z6Mko4NPMeoPKpt5sYUFuJLvT9URrdg8sWZDo4X7rKwunoL8**
- Public key (hex): **7fdbfe47831119712f3b41082280af582a44d939b79121a2125d077d22a651d5**

Receipt response example:
```json
{
  "success": true,
  "event": {
    "event_id": "c69b44a6-9e97-4807-82f7-cff24fa3c11a",
    "idempotency_key": "receipt-demo:001",
    "type": "transfer",
    "from_did": "clearing:clawsettle",
    "to_did": "did:key:deposit-demo",
    "amount_minor": "25",
    "currency": "USD",
    "from_bucket": "A",
    "to_bucket": "A",
    "metadata_json": "{\"note\":\"receipt demo\"}",
    "created_at": "2026-02-05T02:58:47.489Z"
  },
  "receipt": {
    "event_hash": "818db3ccf671efec1944352bb6a1cd0768467d1c41ce64b8a9ee0eedccfb38b4",
    "event_sig": "ccHgUGVmor9oT4xsY6847ogyE3ojh6/ZNhBDdzV1KRbkl4KvPLXF6ooM9PkcT1RsE6cpWyYo97aPzEmg/ZatBQ==",
    "event_sig_alg": "ed25519-sha256",
    "event_sig_did": "did:key:z6Mko4NPMeoPKpt5sYUFuJLvT9URrdg8sWZDo4X7rKwunoL8",
    "event_sig_pubkey": "7fdbfe47831119712f3b41082280af582a44d939b79121a2125d077d22a651d5"
  }
}
```

## Merkle root anchor proof (audit checkpoint)
- Anchor contract: **0x5cE94B3d7f3330215acc9A746d84f216530E1988**
- Deployment tx: https://sepolia.basescan.org/tx/0x55cefc0e8e039c5e188bb960e7b1dc2799232cad04183de10e97bafce456b4e6
- Anchor tx: https://sepolia.basescan.org/tx/0xf58ea7bd67e63a6641a7a5f4065eacbf84b41e78ca81c6ea318559af108c43fe
- Root hash: **b0aca75732bb03d7cbecc6154701caef60e56c1d4b359b86653af724aa773177**
- Event count: **3**
- Gas used: **27,074** (0x69c2)

## Optimality proof (minimal on-chain overhead)
- The two receipts above are **plain USDC transfers** with gas used **62,159** and **45,059** (total **107,218**).
- These values are the **baseline cost of settlement** — just the USDC transfer, no extra contract storage writes.
- Any escrow or marketplace contract adds storage writes and therefore higher gas, so this connector hits the lower bound for on‑chain cost while still providing verifiable receipts.

## Registry contract proof (SmartContract track)
- Contract: **0x7c7c4E64DD0B81C3faAc8029a9d665F3f8F6256C**
- Explorer: https://sepolia.basescan.org/address/0x7c7c4E64DD0B81C3faAc8029a9d665F3f8F6256C
- Deployment tx: https://sepolia.basescan.org/tx/0xd1cf39a25afb9e77736d3bec6b733ba9ccdab49608d906ae3c5ba0232e3f5d81
- registerIntent tx: https://sepolia.basescan.org/tx/0xaf7b515d70d644095bad6cf5ef312827d82a20080469a7abf11049bd78e8cd74
- markClaimed tx: https://sepolia.basescan.org/tx/0xee78c7cb9f9e7b45b24d7ce347ae85736c149a68d5a6f3545533dd86ca3bd6b4

---

## Repro commands (curl)

> Replace SETTLE_URL, LEDGER_URL, DID, and other placeholders.

### Create deposit intent
```bash
curl -s -X POST "$SETTLE_URL/v1/usdc/deposit-intents" \
  -H "Content-Type: application/json" \
  -d '{
    "buyer_did": "did:key:...",
    "amount_minor": "500",
    "currency": "USD"
  }'
```

### Claim deposit
```bash
curl -s -X POST "$SETTLE_URL/v1/usdc/deposits/claim" \
  -H "Content-Type: application/json" \
  -d '{
    "intent_id": "...",
    "claim_secret": "...",
    "tx_hash": "0x..."
  }'
```

### Check balances
```bash
curl -s "$LEDGER_URL/v1/balances?did=did:key:..."
```

### Request payout
```bash
curl -s -X POST "$SETTLE_URL/v1/usdc/payouts" \
  -H "Content-Type: application/json" \
  -d '{
    "worker_did": "did:key:...",
    "amount_minor": "100",
    "destination_address": "0x...",
    "idempotency_key": "payout:demo:001"
  }'
```
