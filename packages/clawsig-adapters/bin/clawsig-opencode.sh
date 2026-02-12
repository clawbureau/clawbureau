#!/usr/bin/env bash
# Convenience wrapper for Opencode with clawsig.
# Usage: clawsig-opencode -- opencode "refactor module"
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/clawsig-wrap.sh" opencode "$@"
