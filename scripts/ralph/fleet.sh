#!/bin/bash
# Fleet Ralph - single long-running loop across multiple domain worktrees.
#
# This is intended for "run all night" mode where you want ONE process, but you
# still want branch/work isolation.
#
# Default targets: phase1-trust worktrees (verify -> proxy -> ledger -> bounties).
#
# Usage:
#   ./scripts/ralph/fleet.sh [max_iterations]
#
# Optional env vars:
#   WORKTREES_TRUST_ROOT=...          # root containing trust worktrees
#   FLEET_SESSION=...                # shared pi session file path
#   PI_PROVIDER / PI_MODEL / PI_THINKING / PI_TOOLS  # forwarded into ralph.sh via env

set -e

MAX_ITERATIONS="${1:-200}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MONOREPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

WORKTREES_TRUST_ROOT="${WORKTREES_TRUST_ROOT:-$MONOREPO_ROOT/../monorepo-worktrees-trust}"

# Shared session across all targets (optional but recommended for continuity)
FLEET_SESSION="${FLEET_SESSION:-$MONOREPO_ROOT/.pi/ralph.fleet.session.jsonl}"
mkdir -p "$(dirname "$FLEET_SESSION")"

# Priority order (round-robin within this list)
TARGETS=(clawverify clawproxy clawledger clawbounties clawescrow)

has_failing_story() {
  local prd="$1"
  jq -e '.userStories[] | select(.passes==false)' "$prd" >/dev/null 2>&1
}

pick_next_target() {
  local start_idx="$1"
  local n="${#TARGETS[@]}"

  for ((offset=0; offset<n; offset++)); do
    local idx=$(((start_idx + offset) % n))
    local name="${TARGETS[$idx]}"
    local dir="$WORKTREES_TRUST_ROOT/$name"

    if [[ ! -d "$dir" ]]; then
      continue
    fi

    if [[ ! -f "$dir/prd.json" ]]; then
      continue
    fi

    if has_failing_story "$dir/prd.json"; then
      echo "$idx:$name:$dir"
      return 0
    fi
  done

  return 1
}

echo "Fleet Ralph starting"
echo "- trust worktrees root: $WORKTREES_TRUST_ROOT"
echo "- shared pi session:    $FLEET_SESSION"
echo "- max iterations:       $MAX_ITERATIONS"
echo ""

next_idx=0

for iter in $(seq 1 "$MAX_ITERATIONS"); do
  selection=$(pick_next_target "$next_idx" || true)
  if [[ -z "$selection" ]]; then
    echo "All targets have no failing stories. Fleet complete."
    exit 0
  fi

  sel_idx="${selection%%:*}"
  rest="${selection#*:}"
  name="${rest%%:*}"
  dir="${rest#*:}"

  # advance pointer for round-robin
  n="${#TARGETS[@]}"
  next_idx=$(((sel_idx + 1) % n))

  echo "==============================================================="
  echo "  Fleet Iteration $iter of $MAX_ITERATIONS"
  echo "  Target: $name"
  echo "==============================================================="

  # Run one iteration; ralph.sh exits 1 when max iterations reached without COMPLETE.
  # That's expected for 1-iteration slices, so we ignore the exit code.
  set +e
  (
    cd "$dir" \
    && ./scripts/ralph/ralph.sh --tool pi --pi-session "$FLEET_SESSION" 1
  )
  status=$?
  set -e

  echo "Target $name: iteration done (exit=$status)"
  echo ""

  sleep 2
done

echo "Fleet reached max iterations ($MAX_ITERATIONS)."
exit 0
