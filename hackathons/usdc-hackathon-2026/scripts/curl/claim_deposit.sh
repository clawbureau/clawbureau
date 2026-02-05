#!/usr/bin/env bash
set -euo pipefail

SETTLE_URL=${SETTLE_URL:-"https://usdc-testnet.clawsettle.com"}
INTENT_ID=${INTENT_ID:-"TODO_INTENT_ID"}
CLAIM_SECRET=${CLAIM_SECRET:-"TODO_CLAIM_SECRET"}
TX_HASH=${TX_HASH:-"0xTODO"}

curl -s -X POST "$SETTLE_URL/v1/usdc/deposits/claim" \
  -H "Content-Type: application/json" \
  -d "{\"intent_id\":\"$INTENT_ID\",\"claim_secret\":\"$CLAIM_SECRET\",\"tx_hash\":\"$TX_HASH\"}" | jq
