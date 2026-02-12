#!/usr/bin/env bash
# Convenience wrapper for Claude Code with clawsig.
# Usage: clawsig-claude-code -- claude "fix the bug"
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/clawsig-wrap.sh" claude-code "$@"
