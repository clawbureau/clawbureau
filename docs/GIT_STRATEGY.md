> **Type:** Spec
> **Status:** CANONICAL
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-07
> **Source of truth:** `CONTRIBUTING.md` + repo conventions
>
> **Scope:**
> - Git workflow rules: branch naming, PR requirements, proof requirements.

# Claw Bureau Git Strategy

This repo is designed for **multi-agent, multi-domain parallel development** with explicit trust and fairness guarantees.

## 1) Branching Model

**Trunk-based, with protected main.**

- `main` is always releasable.
- All work happens in short‑lived branches.
- Branch names must include domain + PRD story ID.

**Branch name format:**

```
<type>/<domain>/<story-id>-<slug>
```

Examples:
- `ralph/clawbounties/CBT-US-004-auto-approve`
- `feat/clawledger/CLD-US-002-ledger-event-write`
- `fix/clawproxy/CPX-US-003-allowlist`

## 2) PR Requirements (Fairness + Trust)

Each PR must include:

1. **PRD Story ID** in title
2. **Acceptance checklist** copied from PRD
3. **Proof bundle** for agent work (if applicable)

### Proof Bundle (Agent Work)
If a PR is produced by an agent, include at minimum:

```
/proofs/<branch>/
  └── commit.sig.json     # DID-signed message signature for `commit:<hash>`
```

Optional / future PoH bundle files:

```
/proofs/<branch>/
  ├── artifact.sig.json   # signature envelope
  ├── receipt.json        # gateway receipt(s)
  └── manifest.json       # URM / event chain (if applicable)
```

Ralph runs use a 2-commit pattern: story commit → proof commit (containing `commit.sig.json` for its parent commit).

This ensures other agents can verify that work was executed as claimed.

## 3) Code Ownership (Interconnection Fairness)

We avoid central bottlenecks by defining **domain ownership**.

- Each domain has a CODEOWNER team
- Shared packages require cross‑pillar review

`CODEOWNERS` should map:

```
/apps/clawbounties/   @clawbureau/labor
/services/clawbounties/ @clawbureau/labor
/packages/schema/     @clawbureau/core
```

## 4) Acceptance Gates

A PR may only merge if:

- ✅ Tests pass (unit + typecheck)
- ✅ Acceptance criteria satisfied
- ✅ Proof bundle provided for agent work
- ✅ Cross‑domain changes reviewed by core owners

## 5) Ralph Execution Alignment

Each domain uses **one PRD + one prd.json**. Ralph loops must:

- Work only on a **single story per iteration**
- Commit with story ID
- Update `prd.json` (`passes: true`) and `progress.txt`

## 6) Shared Package Rules

Shared packages live in `/packages/` and follow strict stability rules:

- Breaking changes require RFC
- New schema versions must be **additive**
- Legacy versions must remain valid for at least 2 releases

## 7) Trust Model (Agent Fairness)

We treat agent contributions as **first‑class citizens**, but require verification.

- Signed artifacts required
- Receipts required for proof‑of‑harness
- No anonymous contributions to critical systems

This ensures both **humans and agents** have equal, verifiable standing.

---

**Principle:** No hidden privilege. Everything verifiable. Every contribution traceable.
