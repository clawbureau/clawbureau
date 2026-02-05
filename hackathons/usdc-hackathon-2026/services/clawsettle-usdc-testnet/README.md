# clawsettle-usdc-testnet (hackathon prototype)

Testnet-only USDC settlement connector. Mints internal credits from verifiable on-chain deposits and pays out USDC testnet. This is a **test mode** connector aligned with `docs/prds/clawsettle.md`.

> ⚠️ WIP — stub skeleton. Implement endpoints per `docs/API.md`.

Endpoints:
- `POST /v1/usdc/deposit-intents`
- `POST /v1/usdc/deposits/claim`
- `POST /v1/usdc/payouts`

Dependencies:
- RPC provider
- USDC testnet token address
- Platform testnet wallet (for payouts)

Environment:
- `RPC_URL` (default: https://sepolia.base.org)
- `LEDGER_URL` (URL of clawledger-lite)
- `PLATFORM_PRIVATE_KEY` (secret; Base Sepolia testnet wallet)

Current testnet defaults:
- Chain: Base Sepolia (84532)
- USDC: 0x036CbD53842c5426634e7929541eC2318f3dCF7e
- Explorer: https://sepolia.basescan.org
- Platform deposit/payout wallet: 0xe6Fb9eaE850a01B4FbFa186449793Bccf3cbDB10

Do **not** accept private keys from users.
