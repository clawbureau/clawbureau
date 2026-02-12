#!/usr/bin/env bash
# Convenience wrapper for Codex with clawsig.
# Usage: clawsig-codex -- codex "implement feature"
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/clawsig-wrap.sh" codex "$@"
