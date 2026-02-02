# Ralph Integration

Ralph is a long-running agent loop intended to be run **per domain** in its own terminal (or per git worktree).

This repo ships a harness-aware Ralph runner at:

- `scripts/ralph/ralph.sh`

It supports multiple backends:
- `--tool claude` (Claude Code)
- `--tool pi` (Pi Coding Agent, recommended)

---

## Fleet mode (single loop across many worktrees)

Run the trust worktrees (default targets):

```bash
./scripts/ralph/fleet.sh 200
```

Run **all** worktrees under `monorepo-worktrees-full/` (auto-discover targets):

```bash
WORKTREES_ROOT=../monorepo-worktrees-full \
FLEET_AUTO_TARGETS=1 \
./scripts/ralph/fleet.sh 200
```

If you want Fleet to *wait* instead of exiting when everything is green:

```bash
FLEET_WATCH=1 ./scripts/ralph/fleet.sh 200
```

---

## Recommended: Pi harness mode

Pi mode runs non-interactively via the installed `pi` CLI (`@mariozechner/pi-coding-agent`) and persists a per-run session file in the run directory by default:

- `<run_dir>/.pi/ralph.session.jsonl`

### Fleet/shared session note
When using a **shared session** (like `scripts/ralph/fleet.sh`), the session file is usually non-empty, so a fresh process would normally skip attaching `PI.md`.

`ralph.sh` therefore auto-attaches `PI.md` **once per session + PI.md content hash** using a small marker file next to the session file:

- `<session>.pi-md.<sha256>.seen`

You can force attaching `PI.md` every iteration with:

```bash
export PI_ALWAYS_ATTACH_INSTRUCTIONS=1
```

### Commit proof automation
`ralph.sh` will (best-effort) auto-generate and **commit** `proofs/<branch>/commit.sig.json` when it detects at least one git commit occurred during an iteration.

Disable with:

```bash
export RALPH_AUTO_PROOF=0
```

### Run

From a directory containing `prd.json` + `progress.txt` (often the root of a domain worktree):

```bash
./scripts/ralph/ralph.sh --tool pi 50
```

### Configure model (optional)

You can set Pi options via flags:

```bash
./scripts/ralph/ralph.sh --tool pi \
  --pi-provider anthropic \
  --pi-model claude-sonnet-4-20250514 \
  --pi-thinking high \
  50
```

Or via env vars:

```bash
export PI_PROVIDER=anthropic
export PI_MODEL=claude-sonnet-4-20250514
export PI_THINKING=high
./scripts/ralph/ralph.sh --tool pi 50
```

---

## Per-domain setup

1) Generate `prd.json` from the PRD in `docs/prds/<domain>.md`.

2) Place `prd.json` + `progress.txt` in the directory you will run Ralph from.

Ralph will prefer `./prd.json` when present (so worktrees can keep their own PRD state).

---

## Parallelization

Run multiple domains in parallel by using:
- separate terminals, and
- separate git worktrees (recommended) to avoid branch collisions.
