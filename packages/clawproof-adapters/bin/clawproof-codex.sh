#!/usr/bin/env bash
# Convenience wrapper for Codex with clawproof.
# Usage: clawproof-codex -- codex "implement feature"
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/clawproof-wrap.sh" codex "$@"
