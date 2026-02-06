#!/usr/bin/env bash
# Convenience wrapper for Claude Code with clawproof.
# Usage: clawproof-claude-code -- claude "fix the bug"
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/clawproof-wrap.sh" claude-code "$@"
