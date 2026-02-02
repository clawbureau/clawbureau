## Merge Roadmap: phase1-trust worktrees → clean PRs → `trust-layer-prd-update`

**Canonical sources (per PRD `branchName`):**
- `monorepo-worktrees-trust/clawledger/prd.json` → `ralph/clawledger-phase1-trust`
- `monorepo-worktrees-trust/clawescrow/prd.json` → `ralph/clawescrow-phase1-trust`
- `monorepo-worktrees-trust/clawbounties/prd.json` → `ralph/clawbounties-phase1-trust`
- `monorepo-worktrees-trust/clawverify/prd.json` → `ralph/clawverify-phase1-trust`
- `monorepo-worktrees-trust/clawproxy/prd.json` → `ralph/clawproxy-phase1-trust`

**Repo policy constraints (must comply):**
- PR requirements + proof bundle format: `docs/GIT_STRATEGY.md` (File 1)
- Parallel dev rules: `docs/PARALLEL_EXECUTION.md` (File 2)
- Shared-contract + schema stability rules: `docs/INTERCONNECTION.md` (File 3)
- PRDs live under `docs/prds/` and one `prd.json` per domain (File 4)
- Agent commit proof generation command: `scripts/ralph/CLAUDE.md` (File 6), using `scripts/did-work/sign-message.mjs`

---

# 1) Recommended PR order + dependency graph

### Why ordering matters
There are two distinct dependency types:

1) **Runtime/contract dependencies** (Interconnection):  
`docs/INTERCONNECTION.md` requires that cross-service trust is enforced by contracts and verification (File 3). In practice:
- `clawledger` is foundational for holds/transfers/settlement.
- `clawproxy` issues receipts that `clawverify` must validate.
- `clawbounties` composes escrow + ledger (stake ops) and later will rely on verify for proof tiers / commit proofs.

2) **Merge-conflict dependencies** (shared files):  
Anything that touches shared paths like `/packages/schema/` or shared scripts (e.g. `scripts/did-work/sign-message.mjs`) can create unnecessary conflicts if merged late or in parallel.

### Recommended PR stack (highest signal / lowest conflict first)

**PR-0 (Shared foundation / hygiene / any shared tooling diffs)**  
- Only if needed (see section 3).  
- Purpose: eliminate shared-file drift and stop noise files from ever entering PRs.

**PR-1: `clawledger` (CLD-US-001..009)**  
- Foundation for escrow holds/releases and stake bucket semantics (ledger buckets + stake/fee event types).  
- Note: `CLD-US-010` and `CLD-US-011` are still `passes:false` in `monorepo-worktrees-trust/clawledger/prd.json` (File 7). Keep them explicitly **out of scope**.

**PR-2: `clawverify` (CVF-US-001..009)**  
- Core verification API for envelopes/receipts/bundles/event chains; required by marketplace trust tier automation (File 13).  
- `CVF-US-010..013` remain out of scope.

**PR-3: `clawproxy` (CPX-US-001..010)**  
- Receipts issuance & policy enforcement.  
- It has an internal verify-receipt endpoint (`/v1/verify-receipt`) (File 16), but platform-wide verification still belongs to `clawverify`.  
- `CPX-US-011..013` remain out of scope.

**PR-4: `clawescrow` (CES-US-001..006)**  
- Depends conceptually on ledger capabilities (holds/releases/partial releases), but is mostly isolated code.  
- Merge after ledger so reviewers can validate the client interfaces line up with the canonical ledger semantics.

**PR-5: `clawbounties` (CBT-US-001..008)**  
- Marketplace composes: escrow holds, ledger stake lock/slash semantics (progress log notes it does stake operations) (File 12).  
- Its remaining stories `CBT-US-009..014` are out of scope.

### Dependency graph (merge + review)

```mermaid
graph TD
  PR0[PR-0 Shared tooling/hygiene (optional)] --> PR1[PR-1 clawledger CLD-US-001..009]
  PR0 --> PR2[PR-2 clawverify CVF-US-001..009]
  PR0 --> PR3[PR-3 clawproxy CPX-US-001..010]
  PR1 --> PR4[PR-4 clawescrow CES-US-001..006]
  PR1 --> PR5[PR-5 clawbounties CBT-US-001..008]
  PR4 --> PR5
  PR2 --> PR5
  PR3 --> PR2
```

Notes:
- `clawproxy → clawverify` is a contract alignment dependency (receipt schema/claims).
- `clawescrow → clawbounties` because bounties creates escrow holds and later disputes freeze holds (File 12).
- `clawverify → clawbounties` because bounties’ next-phase stories require trust tier & commit proof verification; merging verify earlier reduces churn later.

---

# 2) For each PR: scope, checklist, proof artifacts, CI gates

Below are **PR templates** you can copy/paste into GitHub PR descriptions.

## PR-0 (Optional but recommended): Shared foundation / trust hygiene
**Branch suggestion:** `chore/core/CORE-0-trust-hygiene`  
**Base:** `trust-layer-prd-update`  
**Scope (ONLY):**
- If multiple phase1 branches touched shared files, consolidate into one canonical shared version:
  - `scripts/did-work/sign-message.mjs` (explicitly called out in your request)
  - any shared schema package changes under `/packages/schema/`
- Add/adjust `.gitignore` rules to prevent:
  - `**/progress.txt`
  - `**/ralph.out/**` (or `ralph.out`)
  - `**/node_modules/**`
  - `**/.wrangler/**`
  - `**/*.log`
  - `**/package-lock.json` (see section 5 for recommended allow/deny pattern)
- Optional: add a CI check that fails if any of the forbidden files are tracked in a PR.

**Checklist (per `docs/GIT_STRATEGY.md`, File 1):**
- [ ] PR title includes a tracking ID (CORE-0 acceptable if you don’t have a PRD story ID)
- [ ] Tests/typecheck pass
- [ ] Proof bundle included (see below)
- [ ] Core owners review (shared packages/scripts)

**Required proof artifacts:**
- `/proofs/<pr-id>/commit.sig.json` (DID-signed commit proof)
- Also include the standard proof bundle structure from File 1:
  - `/proofs/<pr-id>/artifact.sig.json`
  - `/proofs/<pr-id>/receipt.json`
  - `/proofs/<pr-id>/manifest.json` (include list of normalized shared files and rationale)

**CI gates (minimum):**
- `npm run typecheck` (repo-wide or at least packages touched)
- `npm test` if present
- A “forbidden files” check (custom script or grep in CI)

---

## PR-1: clawledger — merge Phase1 trust (CLD-US-001..009)
**Branch suggestion:** `feat/clawledger/CLD-US-001-phase1-trust-merge`  
**Base:** `trust-layer-prd-update`

**Scope (IN):**
- `services/ledger/**` as implemented (accounts, events, holds, reconciliation, attestation, transfers, stake/fee events, clearing/settlement)
- Migrations under `services/ledger/migrations/**`
- `services/ledger/wrangler.toml` cron trigger (reconciliation job) as noted in progress log (File 8)

**Explicitly OUT of scope (must be stated in PR):**
- `CLD-US-010` Reserve asset registry
- `CLD-US-011` Compute reserve assets  
(both `passes:false` in `monorepo-worktrees-trust/clawledger/prd.json`, File 7)

**Acceptance checklist (copy from PRD for stories included):**
- [ ] CLD-US-001: Create account on first use; unique DID; return balance; typecheck passes
- [ ] CLD-US-002: Append-only events; idempotency key required; hash chain/logging; typecheck passes
- [ ] CLD-US-003: Hold/release; prevent negative balances; typecheck passes
- [ ] CLD-US-004: Replay reconciliation + alerts + export; typecheck passes
- [ ] CLD-US-005: Reserve attestation endpoint; signed attestation; typecheck passes
- [ ] CLD-US-006: Balances + transfers + webhook; typecheck passes
- [ ] CLD-US-007: Buckets A/H/B/F/P; enforce non-negative; API exposure; typecheck passes
- [ ] CLD-US-008: Stake/fee/promo event types; link metadata; hash-chained log entry; typecheck passes
- [ ] CLD-US-009: Clearing accounts + settlement refs; typecheck passes

**Required proof artifacts:**
- `/proofs/<pr-id>/commit.sig.json` (DID-signed message for the PR tip commit)
- Strongly recommended: `manifest.json` lists:
  - merged commit SHAs (from `ralph/clawledger-phase1-trust`)
  - which PRD stories are included/excluded and why (CLD-US-010/011 excluded)
- Ensure git signing: verify with `git log --show-signature`

**CI gates:**
- `npm run typecheck` (ledger workspace/package)
- Unit tests if present (or `npm test`)
- Optional but valuable for Workers:
  - `wrangler build` (no deploy) if available in scripts
- Lint if configured

---

## PR-2: clawverify — merge Phase1 trust (CVF-US-001..009)
**Branch suggestion:** `feat/clawverify/CVF-US-001-phase1-trust-merge`  
**Base:** `trust-layer-prd-update`

**Scope (IN):**
- `services/clawverify/**` (Cloudflare Worker verification API)
- D1 audit log integration as implemented (`/v1/provenance/init`, provenance retrieval, chain verification) (File 17)
- Schema registry endpoints and allowlist behaviors (`/v1/schemas/allowlist`, `/v1/schemas/validate`) (File 17)

**Out of scope (must be stated):**
- `CVF-US-010..013` remain `passes:false` (File 13)

**Acceptance checklist (stories included):**
- [ ] CVF-US-001 artifact verification fail-closed
- [ ] CVF-US-002 message verification returns signer DID
- [ ] CVF-US-003 receipt verification returns provider/model
- [ ] CVF-US-004 batch verification limit + per-item results
- [ ] CVF-US-005 audit provenance with hash chain + retrieval
- [ ] CVF-US-006 docs + schema registry endpoints
- [ ] CVF-US-007 proof bundle verification + trust tier computation
- [ ] CVF-US-008 event chain verification + error codes
- [ ] CVF-US-009 schema allowlist deterministic validation

**Required proof artifacts:**
- `/proofs/<pr-id>/commit.sig.json`
- Proof bundle per File 1 with `manifest.json` referencing:
  - endpoints added (can cite `services/clawverify/src/index.ts`, File 17)
  - allowlisted schema IDs list location (in code per progress log)

**CI gates:**
- `npm run typecheck` for `services/clawverify`
- Unit tests if present
- Lint

---

## PR-3: clawproxy — merge Phase1 trust (CPX-US-001..010)
**Branch suggestion:** `feat/clawproxy/CPX-US-001-phase1-trust-merge`  
**Base:** `trust-layer-prd-update`

**Scope (IN):**
- `services/clawproxy/**` including:
  - Proxy endpoint: `POST /v1/proxy/:provider`
  - DID endpoint: `GET /v1/did`
  - Verify receipt: `POST /v1/verify-receipt`
  - Rate limiting, idempotency, WPC enforcement, privacy modes  
(see `services/clawproxy/src/index.ts`, File 16)

**Out of scope:**
- `CPX-US-011..013` are `passes:false` (File 15)

**Acceptance checklist:**
- [ ] CPX-US-001 proxy with `_receipt` hashes
- [ ] CPX-US-002 Ed25519 signing + fail closed when missing key
- [ ] CPX-US-003 provider allowlist (SSRF prevention) + logging
- [ ] CPX-US-004 Gemini routing
- [ ] CPX-US-005 verify receipt endpoint returns claims
- [ ] CPX-US-006 rate limiting + 429 + headers
- [ ] CPX-US-007 receipt binding fields (run_id, event_hash, idempotency)
- [ ] CPX-US-008 WPC enforcement + redaction
- [ ] CPX-US-009 hash-only/encrypted receipts + confidential logging rules
- [ ] CPX-US-010 DID doc + cache headers

**Required proof artifacts:**
- `/proofs/<pr-id>/commit.sig.json`
- Proof bundle manifest should enumerate any environment variables required (e.g., `PROXY_SIGNING_KEY`, `PROXY_ENCRYPTION_KEY`) so reviewers can reproduce local checks without deployment.

**CI gates:**
- `npm run typecheck` for `services/clawproxy`
- Lint/tests if present

---

## PR-4: clawescrow — merge Phase1 trust (CES-US-001..006)
**Branch suggestion:** `feat/clawescrow/CES-US-001-phase1-trust-merge`  
**Base:** `trust-layer-prd-update`

**Scope (IN):**
- `services/escrow/**`
- `packages/schema/escrow/escrow.v1.json` as created (File 10 indicates schema added)

**Acceptance checklist:**
- [ ] CES-US-001 create escrow hold (reduces balance, returns id, metadata/terms)
- [ ] CES-US-002 release escrow (transfer to agent, record ledger event, emit webhook)
- [ ] CES-US-003 dispute window (freeze + escalate to trials)
- [ ] CES-US-004 milestones (partial release + remaining tracking)
- [ ] CES-US-005 cancellation (release hold, audit log)
- [ ] CES-US-006 status API (GET status object + timestamps)

**Required proof artifacts:**
- `/proofs/<pr-id>/commit.sig.json`
- Proof bundle manifest should list:
  - ledger client interface versions (V1..V4) as described in progress log (File 10)
  - optional dependency behavior (WebhookEmitter/AuditLogger/TrialsClient)

**CI gates:**
- `npm run typecheck` for `services/escrow`
- Any unit tests if present

---

## PR-5: clawbounties — merge Phase1 trust (CBT-US-001..008)
**Branch suggestion:** `feat/clawbounties/CBT-US-001-phase1-trust-merge`  
**Base:** `trust-layer-prd-update`

**Scope (IN):**
- `packages/bounties/**` (actions, types, service clients; Zod schemas)
- `packages/schema/bounties/**` (multiple `.v1.json` schemas per progress log, File 12)

**Out of scope:**
- `CBT-US-009..014` are `passes:false` (File 11)

**Acceptance checklist:**
- [ ] CBT-US-001 post bounty (create escrow hold, closure type)
- [ ] CBT-US-002 accept bounty (eligibility, reserve slot, receipt)
- [ ] CBT-US-003 submit work (signature envelope + proof bundle hash)
- [ ] CBT-US-004 test-based auto approval
- [ ] CBT-US-005 quorum review with signed votes
- [ ] CBT-US-006 search/filter/sort + trust requirements in listing
- [ ] CBT-US-007 dispute handling routes to trials + freeze payout
- [ ] CBT-US-008 stake requirements (bonded bucket lock/release/slash)

**Required proof artifacts:**
- `/proofs/<pr-id>/commit.sig.json`
- Proof bundle manifest should list which external service clients are stubbed/assumed (EscrowService, EligibilityService, TrialsService, StakeService) as described in `progress.txt` (File 12).

**CI gates:**
- `npm run typecheck` for packages involved (`packages/bounties`, schemas)
- Unit tests if present
- Lint

---

# 3) Handling shared changes without conflicts (scripts + schemas)

This is the critical operational rule set to keep PRs parallelizable.

### 3.1 Shared file triage (do this once up front)
Before opening any PRs, compute which paths overlap between domain branches:

```bash
git fetch origin

# Compare each phase1 branch against the target base
for b in \
  ralph/clawledger-phase1-trust \
  ralph/clawescrow-phase1-trust \
  ralph/clawbounties-phase1-trust \
  ralph/clawverify-phase1-trust \
  ralph/clawproxy-phase1-trust
do
  echo "=== $b shared-file scan ==="
  git diff --name-only origin/trust-layer-prd-update...origin/$b \
    | egrep '^(scripts/|packages/schema/|package-lock\.json|progress\.txt|ralph\.out|node_modules/)' || true
done
```

If *any* shared path appears in more than one branch (e.g. `scripts/did-work/sign-message.mjs`), you have two options:

### Option A (preferred): PR-0 Shared foundation
- Land a single “shared canonical” change first (PR-0).
- Then subsequent PRs **must not modify** those shared files (they may conflict otherwise).

### Option B: “First merge wins” + conflict resolution in later merges
- Merge PRs in the recommended order.
- If later merge conflicts on shared files, resolve by:
  - preferring the already-merged canonical version
  - re-applying *only additive* schema additions per `docs/INTERCONNECTION.md` versioning rules (File 3)

### 3.2 Schema rules (from `docs/INTERCONNECTION.md`, File 3)
- Never “fork schema” inside domains.
- Changes must be additive; breaking changes require version bump and RFC.
- Practical merge technique:
  - allow new files like `packages/schema/escrow/escrow.v1.json` and `packages/schema/bounties/*.v1.json` to land as-is (low conflict, new paths)
  - if two branches touch the same schema file, resolve by creating a new version (`.v2.json`) rather than editing in place.

### 3.3 Shared scripts (e.g. `scripts/did-work/sign-message.mjs`)
- Treat this as **core-owned**.
- Merge only via PR-0 or a dedicated “core” PR.
- In domain PRs, prefer *using* the script, not editing it.

---

# 4) Git command sequence: fairness, conflict policy, worktree hygiene

This sequence preserves fairness guarantees in `docs/GIT_STRATEGY.md` (File 1) and avoids rewriting signed commits.

## 4.1 Non-negotiable fairness rules
- **Do not rebase** published PR branches (rebasing changes commit SHAs, breaks commit proofs, and invalidates “canonical completed work”).
- **Do not squash merge** (squash changes SHAs; same issue).
- Use **merge commits** and ensure merges are **GPG-signed** (`git commit -S` / `commit.gpgsign=true`).

## 4.2 One-time setup (recommended)
```bash
git config commit.gpgsign true
git config pull.rebase false
git config merge.ff false
git config rerere.enabled true   # helps consistent conflict resolution across PRs
```

## 4.3 Worktree layout (clean parallel execution)
Create a dedicated integration worktree per PR:

```bash
git fetch origin

# Base worktree for target branch
git worktree add ../wt-base origin/trust-layer-prd-update

# Example: ledger PR worktree
git worktree add ../wt-ledger -b feat/clawledger/CLD-US-001-phase1-trust-merge origin/trust-layer-prd-update
```

## 4.4 Merge a phase1-trust branch into a PR branch (preserve commit SHAs)
Inside the PR worktree (example ledger):

```bash
cd ../wt-ledger
git fetch origin

# Merge the canonical work branch without rebasing
git merge --no-ff -S origin/ralph/clawledger-phase1-trust

# If conflicts occur:
# - resolve
# - git add <files>
# - git commit -S   (this completes the merge commit, signed)
```

**Conflict resolution policy (consistent + auditable):**
- For domain-owned files under `services/<domain>` or `packages/<domain>`: prefer **incoming** (`theirs`) because phase1-trust is canonical for that domain.
- For shared core files under `packages/schema` or `scripts/`: prefer **already merged base** unless the change is additive and required. If required, move to PR-0 or create a follow-up core PR.

Enable rerere to keep resolutions consistent across merges (see config above).

## 4.5 Generate PR proof bundle (required)
From `scripts/ralph/CLAUDE.md` (File 6), adjusted for PR branch:

```bash
# choose a PR id string (example)
PR_ID="pr-clawledger-phase1"

mkdir -p proofs/$PR_ID

# DID-sign the PR tip commit (merge commit or last commit on branch)
node ./scripts/did-work/sign-message.mjs "commit:$(git rev-parse HEAD)" > proofs/$PR_ID/commit.sig.json

# Add your standard bundle files per docs/GIT_STRATEGY.md (File 1)
# proofs/$PR_ID/artifact.sig.json
# proofs/$PR_ID/receipt.json
# proofs/$PR_ID/manifest.json

git add proofs/$PR_ID
git commit -S -m "chore: add proof bundle for $PR_ID"
```

(If you want the PR to remain “no extra commits”, you can include proofs in the merge commit itself by preparing them before the merge commit; but operationally it’s usually cleaner to add a dedicated signed commit for proofs.)

## 4.6 Keep PR branch up to date without rebasing
```bash
git fetch origin
git merge --no-ff -S origin/trust-layer-prd-update
```

## 4.7 Worktree hygiene / cleanup
After PR merge:
```bash
git worktree remove ../wt-ledger
git worktree prune
git branch -d feat/clawledger/CLD-US-001-phase1-trust-merge
```

---

# 5) Keeping `ralph.out` / `progress.txt` / `package-lock` / `node_modules` out of PRs

### 5.1 Add hard ignores (recommended via PR-0)
Add/ensure these patterns in the repo root `.gitignore`:

```gitignore
# Agent logs / progress
progress.txt
**/progress.txt
ralph.out
**/ralph.out/**

# Dependencies
node_modules/
**/node_modules/

# Cloudflare tooling
.wrangler/
**/.wrangler/

# General logs
*.log
npm-debug.log*
pnpm-debug.log*
yarn-debug.log*
yarn-error.log*
```

### 5.2 package-lock.json policy (pick one; don’t mix)

**Policy A (strongly recommended in monorepos): only root lockfile is allowed**
```gitignore
# Ignore all package-locks by default...
**/package-lock.json
# ...but allow the root one (if you use npm)
!package-lock.json
```

**Policy B: no lockfiles in repo (if you use pnpm/yarn and lockfile lives elsewhere)**
```gitignore
**/package-lock.json
```

Then enforce in CI with a simple check:
```bash
# Fail if any package-lock is staged (or exists) in forbidden locations
git ls-files '**/package-lock.json' | grep -v '^package-lock.json$' && exit 1 || true
```

### 5.3 Prevent accidental commits locally
- Before committing, run:
  ```bash
  git status --porcelain
  ```
- If unwanted files are already tracked (worst case), remove them once:
  ```bash
  git rm -r --cached node_modules ralph.out progress.txt
  ```
- Consider a local pre-commit hook to block them:
  - `.git/hooks/pre-commit` that greps `git diff --cached --name-only` for forbidden patterns.

### 5.4 “Worktree spillover” protection
Because your canonical work lives under `monorepo-worktrees-trust/*`, ensure those directories are not tracked:
- Add to `.gitignore`:
  ```gitignore
  monorepo-worktrees-trust/
  ```
- Verify nothing is tracked:
  ```bash
  git ls-files | grep '^monorepo-worktrees-trust/' || true
  ```

---

## Final operational summary (what you actually do next)

1) Run the shared-file triage script (Section 3.1).  
2) If shared overlaps exist: open **PR-0** first (tooling + ignore rules + canonical shared script/schema).  
3) Create PR branches from `trust-layer-prd-update` and **merge** (not rebase, not squash) each canonical phase1 branch in this order:
   - PR-1 ledger (CLD-US-001..009)
   - PR-2 verify (CVF-US-001..009)
   - PR-3 proxy (CPX-US-001..010)
   - PR-4 escrow (CES-US-001..006)
   - PR-5 bounties (CBT-US-001..008)
4) For each PR: add `/proofs/<pr-id>/commit.sig.json` + standard proof bundle layout from `docs/GIT_STRATEGY.md` (File 1), and ensure every commit is git-signed.

If you want, I can turn the above into a ready-to-run checklist per PR (including exact branch names and a single copy/paste PR description body per domain), but I’ll need confirmation on your lockfile policy (root-only vs none) and whether `monorepo-worktrees-trust/` is currently tracked by git.
