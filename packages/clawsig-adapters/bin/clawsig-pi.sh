#!/usr/bin/env bash
# Convenience wrapper for Pi with clawsig.
# Usage: clawsig-pi -- pi "fix the tests"
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/clawsig-wrap.sh" pi "$@"
