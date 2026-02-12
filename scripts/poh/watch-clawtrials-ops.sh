#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
NODE_SCRIPT="${REPO_ROOT}/scripts/poh/watch-clawtrials-arbitration-ops.mjs"

usage() {
  cat <<'USAGE'
Usage:
  scripts/poh/watch-clawtrials-ops.sh once [label]
  scripts/poh/watch-clawtrials-ops.sh daily-3x
  scripts/poh/watch-clawtrials-ops.sh hourly-72h [label]

Modes:
  once        Run one watch pass (12 iterations per env, includes auth + contract checks).
  daily-3x    Run 3 one-shot passes back-to-back (day1/day2/day3 labels).
  hourly-72h  Run full 72-hour foreground watch loop (hourly snapshots).

Auth:
  Reads TRIALS_ADMIN_KEY from environment.
  If unset, falls back to /tmp/clawtrials-admin.key when present.
USAGE
}

if [[ ! -f "${NODE_SCRIPT}" ]]; then
  echo "watch script not found: ${NODE_SCRIPT}" >&2
  exit 1
fi

MODE="${1:-once}"
if [[ $# -gt 0 ]]; then
  shift
fi

if [[ -z "${TRIALS_ADMIN_KEY:-}" && -f /tmp/clawtrials-admin.key ]]; then
  export TRIALS_ADMIN_KEY="$(< /tmp/clawtrials-admin.key)"
fi

if [[ -z "${TRIALS_ADMIN_KEY:-}" ]]; then
  echo "warning: TRIALS_ADMIN_KEY not set; authorized metrics check will be skipped" >&2
fi

run_once() {
  local label="$1"
  node "${NODE_SCRIPT}" \
    --mode once \
    --iterations 12 \
    --pause-ms 150 \
    --label "${label}"
}

case "${MODE}" in
  once)
    LABEL="${1:-72h-watch-manual}"
    run_once "${LABEL}"
    ;;
  daily-3x)
    run_once "72h-watch-day1"
    run_once "72h-watch-day2"
    run_once "72h-watch-day3"
    ;;
  hourly-72h)
    LABEL="${1:-72h-watch}"
    node "${NODE_SCRIPT}" \
      --mode daemon \
      --duration-hours 72 \
      --interval-minutes 60 \
      --iterations 4 \
      --pause-ms 100 \
      --label "${LABEL}"
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    echo "unknown mode: ${MODE}" >&2
    usage
    exit 1
    ;;
esac
