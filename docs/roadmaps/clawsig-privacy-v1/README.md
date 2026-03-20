> **Type:** Roadmap
> **Status:** COMPLETE
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-03-20
> **Completion:** Merged in PRs #475–#481
> **Source of truth:** `prd.json` + `progress.txt` in this folder

# Clawsig Privacy Assurance v1 — Egress Control, Sensitivity Handling, Privacy Proofs

## Context

Today Clawsig proofs are strong on **provenance**:

- who ran the work
- which gateway/provider/model were involved
- whether the run reached gateway tier
- what telemetry was observed around the run

But they are much weaker on **non-disclosure**. A proof bundle can show where data did go, but it cannot yet make a strong claim that **unauthorized third-party sharing was prevented by policy**.

This roadmap is the next execution layer for Clawsig: move from **detect-only provenance** toward **prevent + attest privacy controls** that make the following claim honest and reviewable:

> Unauthorized third-party sharing was prevented by fail-closed policy, and any approved sharing followed the configured provider/model/region/retention rules.

## Product Goal

Turn privacy posture from "raw telemetry plus reviewer interpretation" into a first-class proof surface.

### What v1 should let us claim

- Proofed runs use deny-by-default outbound policy.
- Proofed runs only reach approved processors through Clawproxy.
- Sensitive classes are checked before egress.
- Policy actions (allow / redact / block / require approval) are recorded as signed receipts.
- Reviewers get a clean privacy posture report instead of raw CLDD/network noise.

### What v1 does **not** claim

- It does **not** prove legal compliance by itself.
- It does **not** prove a third party retained nothing after receipt.
- It does **not** remove the need for legal/contract review.
- It does **not** require remote attestation yet (that is a v2 hardening lane).

## Architecture Decisions

### 1) Prevention beats observation

If outbound traffic is not fail-closed, we are mostly collecting after-the-fact evidence. Privacy assurance requires **deny-by-default egress** in proofed mode.

### 2) Proxy-only model execution for proofed mode

If a proofed run can call providers directly, the privacy story collapses. Proofed mode must force model traffic through Clawproxy or fail closed.

### 3) Classify before egress, not after

We need to know whether the outbound payload contains secrets, PII, customer-restricted content, or other sensitive classes **before** we send it.

### 4) Policy receipts should be explicit and signed

Privacy posture should not be inferred from a pile of net events. The bundle/report should carry explicit signed receipts for:

- egress policy
- runtime hygiene
- data handling
- processor policy

### 5) Reviewer UX is part of the control

If the evidence is only readable by engineers staring at JSON, the product is incomplete. `clawsig prove` must render privacy posture in buyer/reviewer language.

### 6) Attested runners are v2, not a v1 blocker

Remote attestation / measured runtime identity is valuable, but v1 should first lock down egress, processor policy, DLP, and proof UX.

## Epic Breakdown

### Epic 1: Egress Control (`monorepo-prv`) — P1 foundation

Fail-closed outbound policy for proofed runs.

- `monorepo-prv.1` — `PRV-EGR-001`: fail-closed outbound allowlist
- `monorepo-prv.2` — `PRV-EGR-002`: proxy-only model execution in proofed mode
- `monorepo-prv.3` — `PRV-EGR-003`: signed egress policy receipt

### Epic 2: Runtime Hygiene (`monorepo-prv`) — P1 hardening

Reduce ambient/noisy runtime behavior so privacy signals are interpretable.

- `monorepo-prv.4` — `PRV-RUN-001`: minimal proofed sandbox profile
- `monorepo-prv.5` — `PRV-RUN-002`: runtime hygiene receipt + CLDD noise budget

### Epic 3: Sensitivity + Processor Policy (`monorepo-prv`) — P1/P2 control plane

Classify sensitive data before egress and restrict where it may go.

- `monorepo-prv.6` — `PRV-DLP-001`: pre-egress sensitivity classifier
- `monorepo-prv.7` — `PRV-DLP-002`: block/redact/approval action engine + data-handling receipt
- `monorepo-prv.8` — `PRV-POL-001`: processor policy engine + processor receipt

### Epic 4: Reviewer / Audit UX (`monorepo-prv`) — P2 productization

Turn the above controls into a reviewer-facing proof surface.

- `monorepo-prv.9` — `PRV-UX-001`: privacy posture report in `clawsig prove`
- `monorepo-prv.10` — `PRV-AUD-001`: privacy/compliance export pack

## Dependency Graph

```text
PRV-EGR-001 fail-closed outbound allowlist
  └── PRV-EGR-002 proxy-only model execution
        ├── PRV-EGR-003 signed egress policy receipt
        ├── PRV-DLP-001 pre-egress sensitivity classifier
        │     └── PRV-DLP-002 block/redact/approval engine + data-handling receipt
        └── PRV-POL-001 processor policy engine + processor receipt

PRV-RUN-001 minimal proofed sandbox profile
  └── PRV-RUN-002 runtime hygiene receipt + CLDD noise budget

PRV-EGR-003 + PRV-RUN-002 + PRV-DLP-002 + PRV-POL-001
  └── PRV-UX-001 privacy posture report in clawsig prove
        └── PRV-AUD-001 privacy/compliance export pack
```

## Sequencing (4 weeks)

### Week 1 — Prevent unauthorized egress

| Bead | What | Depends on |
|---|---|---|
| `monorepo-prv.1` | Deny-by-default outbound policy for proofed runs | — |
| `monorepo-prv.2` | Force proofed model traffic through Clawproxy | `monorepo-prv.1` |
| `monorepo-prv.3` | Emit signed egress policy receipt | `monorepo-prv.1`, `monorepo-prv.2` |

### Week 2 — Clean runtime signals

| Bead | What | Depends on |
|---|---|---|
| `monorepo-prv.4` | Minimal proofed sandbox/runtime profile | — |
| `monorepo-prv.5` | Runtime hygiene receipt + signal bucketing | `monorepo-prv.4` |

### Week 3 — Sensitivity + processor policy

| Bead | What | Depends on |
|---|---|---|
| `monorepo-prv.6` | Pre-egress sensitivity classifier | `monorepo-prv.2` |
| `monorepo-prv.7` | Block/redact/approval engine + data-handling receipt | `monorepo-prv.6` |
| `monorepo-prv.8` | Processor/model/region/retention policy engine | `monorepo-prv.2` |

### Week 4 — Reviewer-facing privacy proof

| Bead | What | Depends on |
|---|---|---|
| `monorepo-prv.9` | Privacy posture section in `clawsig prove` | `monorepo-prv.3`, `monorepo-prv.5`, `monorepo-prv.7`, `monorepo-prv.8` |
| `monorepo-prv.10` | Privacy/compliance export pack | `monorepo-prv.9` |

## Docs to Write

| Doc | Path | When |
|---|---|---|
| Egress policy spec | `docs/specs/clawsig-protocol/PRIVACY_EGRESS_POLICY_v1.md` | Week 1 |
| Runtime hygiene spec | `docs/specs/clawsig-protocol/PRIVACY_RUNTIME_HYGIENE_v1.md` | Week 2 |
| Sensitive data handling spec | `docs/specs/clawsig-protocol/SENSITIVE_DATA_HANDLING_v1.md` | Week 3 |
| Processor policy spec | `docs/specs/clawsig-protocol/PROCESSOR_POLICY_v1.md` | Week 3 |
| Reviewer proof UX spec | `docs/specs/clawsig-protocol/PRIVACY_PROOF_REPORT_v1.md` | Week 4 |

## Success Criteria

- Proofed mode blocks unauthorized outbound destinations by default.
- Direct provider access is unavailable in proofed mode.
- Sensitive classes are classified before egress and acted on deterministically.
- Approved processors/models/regions/retention profiles are enforced and receipted.
- `clawsig prove` renders privacy posture in a reviewer-facing way.
- Exported privacy packs make the boundary between "what is proven" and "what is not proven" explicit.

## Out of Scope for v1

- Remote attestation / measured boot / TEE-backed runners
- Formal legal compliance verdicts
- Third-party retention audits
- Full enterprise DLP policy authoring UI

Those belong in a later `PRV-ATT-*` / privacy-v2 lane once the prevention + receipt + UX path is real and deployed.
