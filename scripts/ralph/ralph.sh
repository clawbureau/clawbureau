#!/bin/bash
# Ralph Wiggum - Long-running AI agent loop
# Usage: ./ralph.sh [--tool amp|claude|pi] [max_iterations]
#
# Pi mode notes:
# - Uses the installed `pi` CLI in print mode (-p)
# - Persists a per-run session by default at: <run_dir>/.pi/ralph.session.jsonl
# - Configure model selection via flags (see below) or Pi settings.json

set -e

# Parse arguments
TOOL="amp"  # Default to amp for backwards compatibility
MAX_ITERATIONS=10

# Pi options (can also be supplied via env vars)
PI_PROVIDER="${PI_PROVIDER:-}"
PI_MODEL="${PI_MODEL:-}"
PI_THINKING="${PI_THINKING:-high}"
PI_TOOLS="${PI_TOOLS:-read,bash,edit,write,grep,find,ls}"
PI_SESSION="${PI_SESSION:-}"
PI_NO_SESSION="${PI_NO_SESSION:-}"

while [[ $# -gt 0 ]]; do
  case $1 in
    --tool)
      TOOL="$2"
      shift 2
      ;;
    --tool=*)
      TOOL="${1#*=}"
      shift
      ;;

    # Pi options
    --pi-provider)
      PI_PROVIDER="$2"
      shift 2
      ;;
    --pi-model)
      PI_MODEL="$2"
      shift 2
      ;;
    --pi-thinking)
      PI_THINKING="$2"
      shift 2
      ;;
    --pi-tools)
      PI_TOOLS="$2"
      shift 2
      ;;
    --pi-session)
      PI_SESSION="$2"
      shift 2
      ;;
    --pi-no-session)
      PI_NO_SESSION="1"
      shift
      ;;

    *)
      # Assume it's max_iterations if it's a number
      if [[ "$1" =~ ^[0-9]+$ ]]; then
        MAX_ITERATIONS="$1"
      fi
      shift
      ;;
  esac
done

# Validate tool choice
if [[ "$TOOL" != "amp" && "$TOOL" != "claude" && "$TOOL" != "pi" ]]; then
  echo "Error: Invalid tool '$TOOL'. Must be 'amp', 'claude', or 'pi'."
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_DIR="$PWD"

if [ -f "$RUN_DIR/prd.json" ]; then
  PRD_FILE="$RUN_DIR/prd.json"
  PROGRESS_FILE="$RUN_DIR/progress.txt"
  ARCHIVE_DIR="$RUN_DIR/archive"
  LAST_BRANCH_FILE="$RUN_DIR/.last-branch"
else
  PRD_FILE="$SCRIPT_DIR/prd.json"
  PROGRESS_FILE="$SCRIPT_DIR/progress.txt"
  ARCHIVE_DIR="$SCRIPT_DIR/archive"
  LAST_BRANCH_FILE="$SCRIPT_DIR/.last-branch"
fi

# Archive previous run if branch changed
if [ -f "$PRD_FILE" ] && [ -f "$LAST_BRANCH_FILE" ]; then
  CURRENT_BRANCH=$(jq -r '.branchName // empty' "$PRD_FILE" 2>/dev/null || echo "")
  LAST_BRANCH=$(cat "$LAST_BRANCH_FILE" 2>/dev/null || echo "")

  if [ -n "$CURRENT_BRANCH" ] && [ -n "$LAST_BRANCH" ] && [ "$CURRENT_BRANCH" != "$LAST_BRANCH" ]; then
    # Archive the previous run
    DATE=$(date +%Y-%m-%d)
    # Strip "ralph/" prefix from branch name for folder
    FOLDER_NAME=$(echo "$LAST_BRANCH" | sed 's|^ralph/||')
    ARCHIVE_FOLDER="$ARCHIVE_DIR/$DATE-$FOLDER_NAME"

    echo "Archiving previous run: $LAST_BRANCH"
    mkdir -p "$ARCHIVE_FOLDER"
    [ -f "$PRD_FILE" ] && cp "$PRD_FILE" "$ARCHIVE_FOLDER/"
    [ -f "$PROGRESS_FILE" ] && cp "$PROGRESS_FILE" "$ARCHIVE_FOLDER/"

    # Archive pi session if it exists (best-effort)
    DEFAULT_PI_SESSION="$RUN_DIR/.pi/ralph.session.jsonl"
    if [ -f "$DEFAULT_PI_SESSION" ]; then
      mkdir -p "$ARCHIVE_FOLDER/pi"
      cp "$DEFAULT_PI_SESSION" "$ARCHIVE_FOLDER/pi/ralph.session.jsonl" || true
    fi

    echo "   Archived to: $ARCHIVE_FOLDER"

    # Reset progress file for new run
    echo "# Ralph Progress Log" > "$PROGRESS_FILE"
    echo "Started: $(date)" >> "$PROGRESS_FILE"
    echo "---" >> "$PROGRESS_FILE"
  fi
fi

# Track current branch
if [ -f "$PRD_FILE" ]; then
  CURRENT_BRANCH=$(jq -r '.branchName // empty' "$PRD_FILE" 2>/dev/null || echo "")
  if [ -n "$CURRENT_BRANCH" ]; then
    echo "$CURRENT_BRANCH" > "$LAST_BRANCH_FILE"
  fi
fi

# Initialize progress file if it doesn't exist
if [ ! -f "$PROGRESS_FILE" ]; then
  echo "# Ralph Progress Log" > "$PROGRESS_FILE"
  echo "Started: $(date)" >> "$PROGRESS_FILE"
  echo "---" >> "$PROGRESS_FILE"
fi

echo "Starting Ralph - Tool: $TOOL - Max iterations: $MAX_ITERATIONS"

defaultPiSession() {
  echo "$RUN_DIR/.pi/ralph.session.jsonl"
}

# Proof lifecycle: ensure a tracked DID commit proof exists.
# Set RALPH_AUTO_PROOF=0 to disable.
RALPH_AUTO_PROOF="${RALPH_AUTO_PROOF:-1}"

autoProofIfNeeded() {
  local iter_start_iso="$1"

  if [[ "$RALPH_AUTO_PROOF" == "0" ]]; then
    return 0
  fi

  if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    return 0
  fi

  # Only run if at least one commit occurred during this iteration.
  if ! git reflog --since="$iter_start_iso" --format='%gs' 2>/dev/null | grep -qE '^commit'; then
    return 0
  fi

  local branch
  branch=$(git branch --show-current 2>/dev/null || true)
  if [[ -z "$branch" ]]; then
    echo "Auto-proof: skipped (detached HEAD)" >&2
    return 0
  fi

  local proof_dir="proofs/${branch}"
  local proof_path="${proof_dir}/commit.sig.json"

  # If HEAD already looks like a proof-only commit for this branch, do nothing.
  local changed
  changed=$(git diff --name-only HEAD^..HEAD 2>/dev/null || true)
  if [[ -n "$changed" ]]; then
    local all_in_proofs="1"
    local has_commit_sig=""
    while IFS= read -r f; do
      [[ -z "$f" ]] && continue
      if [[ "$f" == "$proof_path" ]]; then
        has_commit_sig="1"
      fi
      if [[ "$f" != "$proof_dir/"* ]]; then
        all_in_proofs=""
        break
      fi
    done <<< "$changed"

    if [[ -n "$all_in_proofs" && -n "$has_commit_sig" ]]; then
      return 0
    fi
  fi

  # Only proceed if the worktree is clean OR the only dirty file is the proof file.
  local status
  status=$(git status --porcelain 2>/dev/null || true)
  if [[ -n "$status" ]]; then
    local only_proof="1"
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      local p="${line:3}"
      if [[ "$p" != "$proof_path" ]]; then
        only_proof=""
        break
      fi
    done <<< "$status"

    if [[ -z "$only_proof" ]]; then
      echo "Auto-proof: skipped (dirty worktree has changes beyond $proof_path)" >&2
      return 0
    fi
  fi

  local work_commit
  work_commit=$(git rev-parse HEAD 2>/dev/null || true)
  if [[ -z "$work_commit" ]]; then
    return 0
  fi

  local short
  short=$(git rev-parse --short "$work_commit" 2>/dev/null || echo "${work_commit:0:7}")

  mkdir -p "$proof_dir"

  local sign_script="$SCRIPT_DIR/../did-work/sign-message.mjs"

  set +e
  node "$sign_script" "commit:${work_commit}" > "$proof_path"
  local rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "Auto-proof: signing failed (exit=$rc). Skipping." >&2
    return 0
  fi

  git add "$proof_path"
  if git commit -S -m "chore(proofs): add commit proof for ${short}"; then
    echo "Auto-proof: committed ${proof_path} for ${short}"
  else
    echo "Auto-proof: failed to commit proof for ${short}" >&2
  fi
}

for i in $(seq 1 $MAX_ITERATIONS); do
  echo ""
  echo "==============================================================="
  echo "  Ralph Iteration $i of $MAX_ITERATIONS ($TOOL)"
  echo "==============================================================="

  ITER_START_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)

  # Run the selected tool with the ralph prompt
  if [[ "$TOOL" == "amp" ]]; then
    OUTPUT=$(cat "$SCRIPT_DIR/prompt.md" | amp --dangerously-allow-all 2>&1 | tee /dev/stderr) || true
  elif [[ "$TOOL" == "claude" ]]; then
    # Claude Code: use --dangerously-skip-permissions for autonomous operation, --print for output
    OUTPUT=$(claude --dangerously-skip-permissions --print < "$SCRIPT_DIR/CLAUDE.md" 2>&1 | tee /dev/stderr) || true
  else
    # Pi Coding Agent (non-interactive)
    if ! command -v pi >/dev/null 2>&1; then
      echo "Error: 'pi' command not found. Install with: npm install -g @mariozechner/pi-coding-agent"
      exit 1
    fi

    PI_CMD=(pi -p --thinking "$PI_THINKING" --tools "$PI_TOOLS")

    if [[ -n "$PI_PROVIDER" ]]; then
      PI_CMD+=(--provider "$PI_PROVIDER")
    fi
    if [[ -n "$PI_MODEL" ]]; then
      PI_CMD+=(--model "$PI_MODEL")
    fi

    # Session handling
    if [[ -n "$PI_NO_SESSION" ]]; then
      PI_CMD+=(--no-session)
    else
      if [[ -z "$PI_SESSION" ]]; then
        PI_SESSION="$(defaultPiSession)"
      fi
      mkdir -p "$(dirname "$PI_SESSION")"
      PI_CMD+=(--session "$PI_SESSION")
    fi

    # Instruction attachment policy:
    # - Always attach PI.md in --pi-no-session mode.
    # - Otherwise, attach PI.md once per session + PI.md content hash.
    #   (This matters for shared sessions like fleet.sh, where the session file is
    #    non-empty but a new process still needs to be seeded with the Ralph rules.)
    # - Set PI_ALWAYS_ATTACH_INSTRUCTIONS=1 to force attaching PI.md every iteration.
    PI_PROMPT_ARGS=()
    PI_MD="$SCRIPT_DIR/PI.md"
    ATTACH_PI_MD=""
    INSTR_MARKER=""

    if [[ -n "$PI_NO_SESSION" ]]; then
      ATTACH_PI_MD="1"
    else
      # Hash PI.md to detect updates across runs/processes.
      if command -v sha256sum >/dev/null 2>&1; then
        PI_MD_HASH=$(sha256sum "$PI_MD" | awk '{print $1}')
      elif command -v shasum >/dev/null 2>&1; then
        PI_MD_HASH=$(shasum -a 256 "$PI_MD" | awk '{print $1}')
      else
        PI_MD_HASH=$(openssl dgst -sha256 "$PI_MD" | awk '{print $NF}')
      fi

      INSTR_MARKER="${PI_SESSION}.pi-md.${PI_MD_HASH}.seen"

      if [[ -n "${PI_ALWAYS_ATTACH_INSTRUCTIONS:-}" ]]; then
        ATTACH_PI_MD="1"
      elif [[ ! -f "$PI_SESSION" || ! -s "$PI_SESSION" ]]; then
        ATTACH_PI_MD="1"
      elif [[ ! -f "$INSTR_MARKER" ]]; then
        ATTACH_PI_MD="1"
      fi
    fi

    if [[ -n "$ATTACH_PI_MD" ]]; then
      PI_PROMPT_ARGS+=("@$PI_MD")
    fi

    PI_PROMPT_ARGS+=("Ralph iteration $i/$MAX_ITERATIONS. Continue the Ralph loop in the current repo. Read prd.json + progress.txt in the run directory and complete exactly ONE failing story (highest priority).")

    OUTPUT=$("${PI_CMD[@]}" "${PI_PROMPT_ARGS[@]}" 2>&1 | tee /dev/stderr) || true

    # Mark instructions as seeded for this session + PI.md content hash (best effort).
    if [[ -n "$ATTACH_PI_MD" && -n "$INSTR_MARKER" ]]; then
      echo "seeded $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$INSTR_MARKER" 2>/dev/null || true
    fi
  fi

  # Auto-commit commit.sig.json proof for new work commits (best-effort).
  autoProofIfNeeded "$ITER_START_ISO"

  # Check for completion signal
  if echo "$OUTPUT" | grep -q "<promise>COMPLETE</promise>"; then
    echo ""
    echo "Ralph completed all tasks!"
    echo "Completed at iteration $i of $MAX_ITERATIONS"
    exit 0
  fi

  echo "Iteration $i complete. Continuing..."
  sleep 2
done

echo ""
echo "Ralph reached max iterations ($MAX_ITERATIONS) without completing all tasks."
echo "Check $PROGRESS_FILE for status."
exit 1
