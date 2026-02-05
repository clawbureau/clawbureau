#!/usr/bin/env bash
set -euo pipefail

LEDGER_URL=${LEDGER_URL:-"https://usdc-testnet.clawledger.com"}
DID=${DID:-"did:key:..."}

curl -s "$LEDGER_URL/v1/balances?did=$DID" | jq
