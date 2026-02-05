#!/usr/bin/env bash
set -euo pipefail

SETTLE_URL=${SETTLE_URL:-"https://usdc-testnet.clawsettle.com"}
WORKER_DID=${WORKER_DID:-"did:key:..."}
AMOUNT_MINOR=${AMOUNT_MINOR:-"100"}
DEST_ADDRESS=${DEST_ADDRESS:-"0x..."}
IDEMPOTENCY_KEY=${IDEMPOTENCY_KEY:-"payout:demo:001"}

curl -s -X POST "$SETTLE_URL/v1/usdc/payouts" \
  -H "Content-Type: application/json" \
  -d "{\"worker_did\":\"$WORKER_DID\",\"amount_minor\":\"$AMOUNT_MINOR\",\"destination_address\":\"$DEST_ADDRESS\",\"idempotency_key\":\"$IDEMPOTENCY_KEY\"}" | jq
