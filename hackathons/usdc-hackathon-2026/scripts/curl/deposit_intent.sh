#!/usr/bin/env bash
set -euo pipefail

SETTLE_URL=${SETTLE_URL:-"https://usdc-testnet.clawsettle.com"}
BUYER_DID=${BUYER_DID:-"did:key:..."}
AMOUNT_MINOR=${AMOUNT_MINOR:-"500"}

curl -s -X POST "$SETTLE_URL/v1/usdc/deposit-intents" \
  -H "Content-Type: application/json" \
  -d "{\"buyer_did\":\"$BUYER_DID\",\"amount_minor\":\"$AMOUNT_MINOR\",\"currency\":\"USD\"}" | jq
