#!/usr/bin/env bash
# Convenience wrapper for Pi with clawproof.
# Usage: clawproof-pi -- pi "fix the tests"
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/clawproof-wrap.sh" pi "$@"
