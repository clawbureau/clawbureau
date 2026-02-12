#!/usr/bin/env bash
#
# clawsig-wrap — wrapper that routes external harness LLM calls
# through clawproxy and produces a verifiable proof bundle.
#
# Usage:
#   clawsig-wrap <harness-id> -- <command> [args...]
#
# Examples:
#   clawsig-wrap claude-code -- claude "fix the bug"
#   clawsig-wrap codex -- codex "implement feature"
#   clawsig-wrap pi -- pi "run tests"
#   clawsig-wrap opencode -- opencode "refactor module"
#   clawsig-wrap factory-droid -- factory-droid run --task "build"
#
# Environment:
#   CLAWSIG_PROXY_URL    — clawproxy base URL (required)
#   CLAWSIG_PROXY_TOKEN  — bearer token for proxy auth (optional)
#   CLAWSIG_KEY_FILE     — path to JWK key file (default: <repo>/.clawsig-key.json)
#   CLAWSIG_OUTPUT_DIR   — output dir for proof artifacts (default: <repo>/artifacts/poh/<branch>/)
#
# Optional post-run offline verification (CPL-US-010):
#   CLAWSIG_VERIFY        — set to 1 to verify the generated proof bundle offline
#   CLAWSIG_VERIFY_CONFIG — config path (default: packages/schema/fixtures/clawverify.config.clawbureau.v1.json)
#   CLAWSIG_VERIFY_STRICT — set to 1 to fail the wrapper when verification FAILs
#
# The wrapper:
#   1. Injects provider base URL env vars (ANTHROPIC_BASE_URL, OPENAI_BASE_URL)
#      pointing to clawproxy so all LLM calls are proxied
#   2. Spawns the harness command as a subprocess
#   3. Records events and collects receipts
#   4. Produces a signed proof bundle + URM on completion
#

set -euo pipefail

# Backward compat: accept legacy CLAWPROOF_* env vars with deprecation warning
for _old_var in CLAWPROOF_PROXY_URL CLAWPROOF_PROXY_TOKEN CLAWPROOF_KEY_FILE CLAWPROOF_OUTPUT_DIR CLAWPROOF_VERIFY CLAWPROOF_VERIFY_CONFIG CLAWPROOF_VERIFY_STRICT; do
  _new_var="${_old_var/CLAWPROOF_/CLAWSIG_}"
  if [ -n "${!_old_var:-}" ] && [ -z "${!_new_var:-}" ]; then
    export "$_new_var=${!_old_var}"
    echo "clawsig: WARNING: $\_old_var is deprecated, use $_new_var instead" >&2
  fi
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLI_SCRIPT="$SCRIPT_DIR/../dist/cli.js"

# Check if the CLI has been built
if [ ! -f "$CLI_SCRIPT" ]; then
  # Try the src version with tsx/ts-node
  CLI_SRC="$SCRIPT_DIR/../src/cli.ts"
  if command -v npx &>/dev/null; then
    exec npx tsx "$CLI_SRC" "$@"
  else
    echo "clawsig: error: package not built and npx not available" >&2
    echo "clawsig: run 'npm run build' in packages/clawsig-adapters first" >&2
    exit 1
  fi
fi

exec node "$CLI_SCRIPT" "$@"
