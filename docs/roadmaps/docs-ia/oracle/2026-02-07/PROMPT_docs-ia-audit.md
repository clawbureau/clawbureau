# Oracle prompt: Docs IA + Scope/Freshness Cleanup (Gemini)

We maintain a large documentation tree under `docs/`.

Problem:
- Many docs no longer reflect current state, or are aspirational without being clearly marked.
- It’s hard to know **what to read first**, what is **canonical**, and what is **archived research**.
- We want to reorganize docs so it is *easy to reason* about the system and to implement changes safely.

Context:
- This repo is the Claw Bureau monorepo.
- We already introduced a docs hub (`docs/README.md`), ecosystem folder (`docs/ecosystem/`), roadmaps (`docs/roadmaps/*` with `prd.json` + `progress.txt`), and PoH oracle batches colocated with the PoH roadmap.
- OpenClaw docs under `docs/openclaw/` are a **local mirror** of upstream OpenClaw docs; they are reference constraints, not our implementation.

Your task:

1) Propose a **clear information architecture (IA)** for `docs/`.
   - Folder structure
   - What belongs where
   - What should be indexed by default

2) Define a **"docs status" convention** that makes it impossible to mistake old/aspirational docs for current truth.
   - Minimal friction, but strong signal
   - Examples of a status banner/header block
   - Which documents MUST include status (hubs, specs, PRDs, roadmaps)

3) Produce a **canonical reading map** (4 audiences):
   - New contributor (5–10 minutes)
   - Marketplace engineer (clawbounties/escrow/ledger)
   - Trust/PoH engineer (clawproxy/clawverify/PoH)
   - OpenClaw integration engineer

4) Audit the current doc set and output a **classification**:
   - Canonical / Active / Draft / Reference / Archive
   - For each: Keep / Move / Rename / Add banner / Split / Delete (delete only if clearly safe)

5) Give a **concrete implementation plan** (as if preparing a PR):
   - Exact moves/renames (a mapping list is fine)
   - Which indexes/READMEs must be updated
   - Any link-fix strategy
   - A suggested sequence (small PRs) to avoid chaos

Constraints:
- Prefer archiving to deleting.
- Don’t break the existing roadmap structure (`docs/roadmaps/*/prd.json` + `progress.txt`).
- Keep `docs/openclaw/` as a mirror/reference section; do not intermingle it with our own specs.
- Be explicit about unknowns.
- Be opinionated: we want *one clear path*.

Output format:
- IA proposal
- Status convention
- Reading map
- Classification & actions
- PR implementation plan
