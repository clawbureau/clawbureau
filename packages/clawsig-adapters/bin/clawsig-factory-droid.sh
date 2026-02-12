#!/usr/bin/env bash
# Convenience wrapper for Factory Droid with clawsig.
# Usage: clawsig-factory-droid -- factory-droid run --task "build"
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/clawsig-wrap.sh" factory-droid "$@"
