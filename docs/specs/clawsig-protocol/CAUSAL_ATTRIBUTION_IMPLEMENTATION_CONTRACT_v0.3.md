> Type: Implementation Contract (Decision Freeze)
> Status: ACCEPTED
> Owner: @clawbureau/core
> Last reviewed: 2026-02-18
> Source inputs:
> - `/tmp/clawbureau-deepthink-attribution-2026-02-18/out/final-blueprint.md` (`sha256:9206047de667598121bd21b8bdfdb6cdfe5942b96ddee1b3ab0375387018e563`)
> - `/tmp/clawbureau-deepthink-attribution-2026-02-18/out/synth-core.md` (`sha256:0ef8845b2c7fc586fb95e264eb88cf62eb1b23ee71a1c6332c4b18b61a05b384`)
> - `/tmp/clawbureau-deepthink-attribution-2026-02-18/out/synth-label.md` (`sha256:0ddd9b45108840fd345acf0ec10276ea4ececbe2dfe6d38f7882edb9ccb66fdc`)
> - `/tmp/clawbureau-deepthink-attribution-2026-02-18/out/synth-delivery.md` (`sha256:42a15e88d65789bb5ea7d175ac7b8448bbdd299589901ed48ef427cd7d29ae2f`)

# Causal attribution v0.3 — accepted implementation contract

This document freezes the accepted scope for CAV-US-001..004.

## Story map (frozen)

- **CAV-US-001**: additive schema contract for causal linkage fields.
- **CAV-US-002**: fail-closed verifier contract over present causal fields.
- **CAV-US-003**: runtime emission wiring for tool-span linkage.
- **CAV-US-004**: delivery/labeling/coverage UX and policy hardening.

## Accepted additive fields (schema contract)

All fields are additive and optional. Legacy bundles remain valid when fields are absent.

### `receipt_binding.v1`

- `span_id?: string`
  - semantics: unique causal span identifier for the receipt.
- `parent_span_id?: string`
  - semantics: parent span reference (same bundle causal graph).
- `tool_span_id?: string`
  - semantics: root tool span reference for side effects/derived receipts.
- `phase?: "setup" | "planning" | "reasoning" | "execution" | "observation" | "reflection" | "teardown"`
  - semantics: deterministic lifecycle phase marker.
- `attribution_confidence?: number`
  - range: `[0.0, 1.0]`.
  - deterministic classes:
    - `1.0` authoritative
    - `0.5` inferred overlap
    - `0.0` unattributed

### `proof_bundle.v1`

- no breaking mutation.
- additive alignment only if needed for verifier/runtime parity with emitted arrays.

## Accepted verifier fail-closed behavior

Checks are enforced **only when causal fields are present**.

Accepted fail reasons:

- `CAUSAL_REFERENCE_DANGLING`
  - when `parent_span_id` or `tool_span_id` references a span id not present in the same bundle causal index.
- `CAUSAL_CYCLE_DETECTED`
  - when parent-span traversal produces a cycle.
- `CAUSAL_PHASE_INVALID`
  - when `binding.phase` exists but is outside the deterministic allowed phase set.
- `CAUSAL_CONFIDENCE_OUT_OF_RANGE`
  - when confidence exists but is outside `[0.0, 1.0]`.
- `MALFORMED_ENVELOPE`
  - schema-level invalid causal shape failures (excluding explicit phase/confidence code mappings).

## Compatibility contract (legacy bundles)

- If causal fields are absent, verifier preserves current v0.2 behavior.
- No new required fields in existing envelope payloads.
- No trust-tier downgrade purely for missing causal fields in this tranche.

## Deferred items (explicitly not in this vertical slice)

- **CLDD strict enforcement** (coverage liveness deficit deterministic tier slashing).
- **UI confidence rendering polish** and global degraded-state visual treatment.
- **Strict WPC policy coupling** (e.g., `require_strict_causality`) beyond existing policy behavior.
- **Cross-bundle/remote DAG hydration** beyond single-bundle verifier scope.

## Explicit non-goals

- no architecture rewrite of receipt model.
- no runtime policy weakening to increase pass rates.
- no online dependency added to verifier (offline-first invariant remains).
- no breaking schema/version migration for existing v0.2 artifacts.
