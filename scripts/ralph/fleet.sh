#!/bin/bash
# Fleet Ralph - single long-running loop across multiple domain worktrees.
#
# This is intended for "run all night" mode where you want ONE process, but you
# still want branch/work isolation.
#
# Usage:
#   ./scripts/ralph/fleet.sh [max_iterations]
#
# Optional env vars:
#   WORKTREES_ROOT=...               # root containing worktrees (default: ../monorepo-worktrees-trust)
#   WORKTREES_TRUST_ROOT=...         # legacy alias for WORKTREES_ROOT
#
#   FLEET_TARGETS="a b c"            # explicit targets (space or comma separated)
#   FLEET_AUTO_TARGETS=1             # auto-discover targets: all <root>/* dirs that contain a prd.json (e.g. services/*/prd.json)
#   FLEET_WATCH=1                    # when no targets have failing stories, sleep+retry instead of exiting
#
#   FLEET_SESSION=...                # shared pi session file path
#   PI_PROVIDER / PI_MODEL / PI_THINKING / PI_TOOLS  # forwarded into ralph.sh via env

set -e

MAX_ITERATIONS="${1:-200}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MONOREPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

WORKTREES_ROOT_DEFAULT="$MONOREPO_ROOT/../monorepo-worktrees-trust"
WORKTREES_ROOT="${WORKTREES_ROOT:-${WORKTREES_TRUST_ROOT:-$WORKTREES_ROOT_DEFAULT}}"

# Shared session across all targets (optional but recommended for continuity)
FLEET_SESSION="${FLEET_SESSION:-$MONOREPO_ROOT/.pi/ralph.fleet.session.jsonl}"
mkdir -p "$(dirname "$FLEET_SESSION")"

# Targets
DEFAULT_TARGETS=(clawverify clawproxy clawledger clawbounties clawescrow)

if [[ -n "${FLEET_TARGETS:-}" ]]; then
  # shellcheck disable=SC2206
  TARGETS=( ${FLEET_TARGETS//,/ } )
elif [[ -n "${FLEET_AUTO_TARGETS:-}" ]]; then
  # Auto-discover targets: any immediate child dir under WORKTREES_ROOT
  # that contains a prd.json somewhere inside (ignoring node_modules).
  # shellcheck disable=SC2207
  TARGETS=( $(
    find "$WORKTREES_ROOT" \
      -mindepth 2 -maxdepth 4 \
      -name prd.json \
      -not -path '*/node_modules/*' \
      -not -path '*/.git/*' \
      -print 2>/dev/null \
    | sed "s|^${WORKTREES_ROOT}/||" \
    | cut -d/ -f1 \
    | sort -u
  ) )
else
  TARGETS=("${DEFAULT_TARGETS[@]}")
fi

has_failing_story() {
  local prd="$1"
  jq -e '.userStories[] | select(.passes==false)' "$prd" >/dev/null 2>&1
}

find_prd_file() {
  local target_root="$1"

  if [[ -f "$target_root/prd.json" ]]; then
    echo "$target_root/prd.json"
    return 0
  fi

  # Common layout: <worktree>/services/<service>/prd.json
  local found
  found=$(find "$target_root" \
    -maxdepth 4 \
    -name prd.json \
    -not -path '*/node_modules/*' \
    -not -path '*/.git/*' \
    -print -quit 2>/dev/null || true)

  if [[ -n "$found" ]]; then
    echo "$found"
    return 0
  fi

  return 1
}

pick_next_target() {
  local start_idx="$1"
  local n="${#TARGETS[@]}"

  for ((offset=0; offset<n; offset++)); do
    local idx=$(((start_idx + offset) % n))
    local name="${TARGETS[$idx]}"
    local dir="$WORKTREES_ROOT/$name"
    local prd
    local run_dir

    if [[ ! -d "$dir" ]]; then
      continue
    fi

    prd=$(find_prd_file "$dir" || true)
    if [[ -z "$prd" ]]; then
      continue
    fi

    if has_failing_story "$prd"; then
      run_dir="$(dirname "$prd")"
      echo "$idx:$name:$run_dir:$prd"
      return 0
    fi
  done

  return 1
}

echo "Fleet Ralph starting"
echo "- worktrees root:        $WORKTREES_ROOT"
echo "- shared pi session:     $FLEET_SESSION"
echo "- max iterations:        $MAX_ITERATIONS"
echo "- targets (${#TARGETS[@]}):         ${TARGETS[*]}"
echo ""

next_idx=0

for iter in $(seq 1 "$MAX_ITERATIONS"); do
  selection=$(pick_next_target "$next_idx" || true)
  if [[ -z "$selection" ]]; then
    if [[ -n "${FLEET_WATCH:-}" ]]; then
      echo "All targets have no failing stories. Sleeping (FLEET_WATCH=1)…"
      sleep 60
      continue
    fi

    echo "All targets have no failing stories. Fleet complete."
    exit 0
  fi

  sel_idx="${selection%%:*}"
  rest="${selection#*:}"
  name="${rest%%:*}"
  rest="${rest#*:}"
  run_dir="${rest%%:*}"
  prd="${rest#*:}"

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
  # Use the monorepo-root runner so all worktrees benefit from the same
  # up-to-date harness features (Pi support, instruction seeding rules, etc).
  (
    cd "$run_dir" \
    && "$MONOREPO_ROOT/scripts/ralph/ralph.sh" --tool pi --pi-session "$FLEET_SESSION" 1
  )
  status=$?
  set -e

  if [[ "$status" -eq 0 ]]; then
    echo "Target $name: iteration done (exit=0)"
  elif [[ "$status" -eq 1 ]]; then
    echo "Target $name: iteration done (exit=1; expected for 1-iteration slices)"
  else
    echo "Target $name: iteration done (exit=$status; unexpected)"
  fi

  echo ""

  sleep 2
done

echo "Fleet reached max iterations ($MAX_ITERATIONS)."
exit 0
