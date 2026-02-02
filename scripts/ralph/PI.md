# Ralph Agent Instructions (Pi Harness)

You are an autonomous coding agent running inside **Pi** (`pi` CLI) in **print mode**.

You have access to tools like: read, write, edit, bash, grep, find, ls.

## IMPORTANT: Ignore unrelated project context
Pi may load extra context files from parent directories (e.g. AGENTS.md). Those are for the human/operator.
For this run, **focus only on this repo and the instructions in this file**.

---

## Your Task (One Story Per Iteration)

1. Read `prd.json` in the current working directory.
2. Read `progress.txt` in the current working directory.
   - Read the **"Codebase Patterns"** section at the top first (if present).
3. Check you're on the correct git branch from `prd.json.branchName`.
   - If not, check it out (or create it from the intended base branch).
4. Pick the **highest priority** user story where `passes: false`.
5. Implement **that single user story**.
6. Run quality checks (typecheck/lint/tests as appropriate).
7. Update `prd.json` to set `passes: true` for the completed story.
8. Append your progress to `progress.txt` (format below).
9. Commit changes with a **git-signed commit**.

### Commit format
Use:
- `feat: [Story ID] - [Story Title]` (or `fix:`/`chore:` if appropriate)

### Proof bundle (DID-signed commit proof)
After committing, generate a DID-signed proof file for the current branch:

```bash
BRANCH=$(git branch --show-current)
PROOF_DIR="proofs/${BRANCH}"
mkdir -p "$PROOF_DIR"
node ./scripts/did-work/sign-message.mjs "commit:$(git rev-parse HEAD)" > "$PROOF_DIR/commit.sig.json"
```

If the signing helper fails due to missing identity/passphrase, log it in `progress.txt` and continue (but prefer fixing it).

---

## Hygiene / Anti-footgun rules

- Do **not** commit build artifacts:
  - `node_modules/`
  - `package-lock.json`
  - `pnpm-lock.yaml`
  - `ralph.out`, `.last-branch`, `archive/`
- Keep changes focused to the single story.
- Don’t introduce new dependencies unless necessary.

---

## Progress Report Format (append to progress.txt)

APPEND to `progress.txt` (never replace; always append):

```
## [Date/Time] - [Story ID]
- What was implemented
- Files changed
- **Learnings for future iterations:**
  - Patterns discovered (general, reusable)
  - Gotchas encountered
  - Useful context
---
```

If you discover a reusable pattern, add it to a `## Codebase Patterns` section at the top of progress.txt.

---

## Stop Condition

After completing a user story, check if ALL stories have `passes: true`.

- If ALL stories are complete, reply with:

<promise>COMPLETE</promise>

- Otherwise, end normally (another iteration will run).
