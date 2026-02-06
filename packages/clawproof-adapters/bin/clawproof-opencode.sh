#!/usr/bin/env bash
# Convenience wrapper for Opencode with clawproof.
# Usage: clawproof-opencode -- opencode "refactor module"
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/clawproof-wrap.sh" opencode "$@"
