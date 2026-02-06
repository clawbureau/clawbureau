#!/usr/bin/env bash
#
# clawproof-wrap — wrapper that routes external harness LLM calls
# through clawproxy and produces a verifiable proof bundle.
#
# Usage:
#   clawproof-wrap <harness-id> -- <command> [args...]
#
# Examples:
#   clawproof-wrap claude-code -- claude "fix the bug"
#   clawproof-wrap codex -- codex "implement feature"
#   clawproof-wrap pi -- pi "run tests"
#   clawproof-wrap opencode -- opencode "refactor module"
#   clawproof-wrap factory-droid -- factory-droid run --task "build"
#
# Environment:
#   CLAWPROOF_PROXY_URL    — clawproxy base URL (required)
#   CLAWPROOF_PROXY_TOKEN  — bearer token for proxy auth (optional)
#   CLAWPROOF_KEY_FILE     — path to JWK key file (default: .clawproof-key.json)
#   CLAWPROOF_OUTPUT_DIR   — output dir for proof artifacts (default: .clawproof/)
#
# The wrapper:
#   1. Injects provider base URL env vars (ANTHROPIC_BASE_URL, OPENAI_BASE_URL)
#      pointing to clawproxy so all LLM calls are proxied
#   2. Spawns the harness command as a subprocess
#   3. Records events and collects receipts
#   4. Produces a signed proof bundle + URM on completion
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLI_SCRIPT="$SCRIPT_DIR/../dist/cli.js"

# Check if the CLI has been built
if [ ! -f "$CLI_SCRIPT" ]; then
  # Try the src version with tsx/ts-node
  CLI_SRC="$SCRIPT_DIR/../src/cli.ts"
  if command -v npx &>/dev/null; then
    exec npx tsx "$CLI_SRC" "$@"
  else
    echo "clawproof: error: package not built and npx not available" >&2
    echo "clawproof: run 'npm run build' in packages/clawproof-adapters first" >&2
    exit 1
  fi
fi

exec node "$CLI_SCRIPT" "$@"
