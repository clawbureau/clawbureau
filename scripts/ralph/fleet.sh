#!/bin/bash
# Fleet Ralph - single long-running loop across multiple domain worktrees.
#
# Default targets: phase1-trust worktrees (verify -> proxy -> ledger -> bounties).
#
# Usage:
#   ./scripts/ralph/fleet.sh [max_cycles]
#
# Optional env vars:
#   WORKTREES_TRUST_ROOT=...          # root containing trust worktrees
#   FLEET_SESSION=...                # shared pi session file path
#   PI_PROVIDER / PI_MODEL / PI_THINKING / PI_TOOLS  # forwarded into ralph.sh via env

set -e

MAX_CYCLES="${1:-200}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MONOREPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

WORKTREES_TRUST_ROOT="${WORKTREES_TRUST_ROOT:-$MONOREPO_ROOT/../monorepo-worktrees-trust}"

# Shared session across all targets (optional but recommended for continuity)
FLEET_SESSION="${FLEET_SESSION:-$MONOREPO_ROOT/.pi/ralph.fleet.session.jsonl}"
mkdir -p "$(dirname "$FLEET_SESSION")"

TARGETS=(clawverify clawproxy clawledger clawbounties clawescrow)

has_failing_story() {
  local prd="$1"
  jq -e '.userStories[] | select(.passes==false)' "$prd" >/dev/null 2>&1
}

echo "Fleet Ralph starting"
echo "- trust worktrees root: $WORKTREES_TRUST_ROOT"
echo "- shared pi session:    $FLEET_SESSION"
echo "- max cycles:           $MAX_CYCLES"

echo ""

for cycle in $(seq 1 "$MAX_CYCLES"); do
  echo "==============================================================="
  echo "  Fleet Cycle $cycle of $MAX_CYCLES"
  echo "==============================================================="

  any=false

  for name in "${TARGETS[@]}"; do
    dir="$WORKTREES_TRUST_ROOT/$name"

    if [[ ! -d "$dir" ]]; then
      echo "- $name: missing dir ($dir) -> skip"
      continue
    fi

    if [[ ! -f "$dir/prd.json" ]]; then
      echo "- $name: missing prd.json -> skip"
      continue
    fi

    if ! has_failing_story "$dir/prd.json"; then
      echo "- $name: no failing stories -> skip"
      continue
    fi

    any=true
    echo "- $name: running 1 iteration"

    # Run one iteration; ralph.sh exits 1 when max iterations reached without COMPLETE.
    # That's expected for 1-iteration slices, so we ignore the exit code.
    set +e
    (
      cd "$dir" \
      && ./scripts/ralph/ralph.sh --tool pi --pi-session "$FLEET_SESSION" 1
    )
    status=$?
    set -e

    echo "  $name: iteration done (exit=$status)"
    echo ""
  done

  if [[ "$any" == "false" ]]; then
    echo "All targets have no failing stories. Fleet complete."
    exit 0
  fi

  sleep 2
done

echo "Fleet reached max cycles ($MAX_CYCLES)."
exit 0
