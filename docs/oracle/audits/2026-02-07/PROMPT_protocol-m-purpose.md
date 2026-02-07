# Oracle prompt: What is Protocol M for now?

We have a sibling folder outside the monorepo: `/Users/gfw/clawd/02-Projects/protocol-m/`.
It contains planning docs for “Protocol M — Phase 1”. There is no code there.

We need to decide:
- What is the purpose of `protocol-m` **now**, given the current Claw Bureau monorepo state (PoH, schemas, DID commit proofs, clawproxy/clawverify, OpenClaw integration)?
- Is `protocol-m` still an active plan, a reference artifact, or should it be archived/merged into the monorepo docs?

## Tasks

1) Summarize what `protocol-m` contains and what it was trying to achieve.
2) Compare it against what is already implemented or planned in the Claw Bureau monorepo:
   - docs/ecosystem/STRATEGIC_PLAN.md
   - docs/specs/agent-economy/MVP.md
   - docs/roadmaps/proof-of-harness/* + oracle synthesis
   - packages/schema/* (identity/poh/auth schemas)
3) Decide the best role for `protocol-m` going forward:
   - Keep as separate planning repo?
   - Move into monorepo `docs/archive/`?
   - Translate into a roadmap (`docs/roadmaps/...`) or PRD updates?
4) Provide a concrete plan (small PRs) for what to do next.

Constraints:
- Prefer archiving to deleting.
- We want the monorepo to be the primary source of truth.

Output format:
- What it is
- Overlap with monorepo
- Gaps / unique value
- Recommendation
- Next steps
