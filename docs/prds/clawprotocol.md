> **Type:** PRD
> **Status:** DRAFT
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-12
> **Source of truth:** this PRD (intent) + `docs/specs/clawsig-protocol/CLAWSIG_PROTOCOL_v0.1.md` + `docs/roadmaps/clawsig-protocol/prd.json`
>
> **Scope:**
> - Product requirements for **Clawsig Protocol** as an open narrow waist.
> - This is intentionally cross-service and modular: third parties should be able to implement the protocol without adopting Claw’s full stack.

# Clawsig Protocol — PRD

## Implementation status (current)

- **Spec (canonical):** `docs/specs/clawsig-protocol/CLAWSIG_PROTOCOL_v0.1.md`
- **Execution roadmap:** `docs/roadmaps/clawsig-protocol/{prd.json,progress.txt}`
- **Reference implementations (current services):**
  - Policy registry: `clawcontrols` (`docs/prds/clawcontrols.md`)
  - Capability tokens: `clawscope` (`docs/prds/clawscope.md`)
  - Model gateway receipts: `clawproxy` (`docs/prds/clawproxy.md`)
  - Verification API: `clawverify` (`docs/prds/clawverify.md`)

---

## 0) Thesis

To become “the protocol”, Claw must win on:
- **lowest friction** (progressive adoption + one approval moment)
- **highest trust** (deterministic verification + explicit coverage)

Security alone earns procurement. A protocol earns preference.

---

## 1) Purpose

Define a tiny protocol surface (the “narrow waist”) that enables:
- portable receipts and proof bundles
- deterministic verification (offline-capable)
- explicit capability governance with minimal human clicks

Everything else (marketplace, escrow, ledger, reputation, UI) is a **module**.

---

## 2) Non-goals

- Making payments/escrow/reputation mandatory for protocol adoption.
- Requiring DID as the only identity model.
- Shipping “perfect confidentiality” without TEEs.

---

## 3) Requirements (protocol-level)

### 3.1 Narrow waist primitives
The protocol MUST define and keep stable:
1. Policy Artifact (WPC)
2. Capability Token (CST)
3. Receipt (enforcement boundary event)
4. Bundle (portable handoff unit)
5. Verifier (deterministic PASS/FAIL + reason codes)

### 3.2 Explicit coverage
Any claim like “every action attested” MUST specify what counts as an action and which boundaries are receipted.

### 3.3 Deterministic semantics
- Fail-closed on unknown schema/version/algo.
- Stable reason codes and machine-readable denial shapes.
- Idempotency and replay safety as a first-class contract.

### 3.4 Human love UX
Protocol governance MUST be supportable via:
- two-phase execution defaults (plan/diff → apply)
- a single approval moment that mints scoped capability

### 3.5 Agent ergonomics
Agents MUST be able to:
- request capability (standard shape)
- receive deterministic denials (`DENIED_POLICY(tool=X, rule=Y)` style)
- preflight verify-lite compliance before executing

### 3.6 Identity and settlement are pluggable
- Identity is bring-your-own (OIDC/service accounts/DID).
- Settlement is optional (protocol does not require escrow/ledger).

---

## 4) Success metrics

- Third-party implementations exist that pass conformance vectors.
- Offline verification is common (hosted viewer optional).
- Adoption wedge succeeds (GitHub diff-first approvals becomes the easiest safe path).
- Coverage claims are trusted because they are explicit and testable.
