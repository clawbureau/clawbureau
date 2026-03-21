> **Type:** Roadmap
> **Status:** ACTIVE
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-03-21
> **Source of truth:** `docs/roadmaps/clawcompiler-runtime-v1/prd.json` + `progress.txt`
>
> **Scope:**
> - Build the first deployed Clawcompiler runtime on top of the shipped schema/bootstrap contracts.
> - Compile only from pre-verified authoritative evidence; never reinterpret invalid evidence.

# Clawcompiler Runtime v1 — Deterministic compiled evidence from verified proof artifacts

## Context

`docs/roadmaps/clawcompiler/` completed the bootstrap tranche for Clawcompiler: deterministic report schemas, signed envelope contracts, the narrative membrane, binary semantic evidence contracts, and conformance fixtures. What is still missing is the runtime and product layer that turns verified proof artifacts into auditor-consumable compiled evidence.

This roadmap covers that next step.

## Product Goal

Turn Clawcompiler into the service that can honestly say:

> Given already-verified Clawsig / Clawverify evidence, produce a deterministic, signed, portable control-matrix report whose authoritative results are machine-verifiable and whose human-readable layer can never override the facts.

## Principles

- Compile from authoritative verification facts only.
- Fail closed on unknown schemas, invalid upstream evidence, or ambiguous rule inputs.
- Keep the compiled matrix authoritative; narrative remains optional and explicitly non-authoritative.
- Make identical inputs + rules produce byte-identical authoritative outputs.
- Keep offline verification and portability first-class.

## Implementation status

- **Wave 1 shipped** via PR #516:
  - `CEC-RT-001` verified-evidence ingest contract
  - `CEC-RT-002` deterministic control-pack runtime
  - `CEC-RT-003` fail-closed compiler state machine
- Current roadmap progress: **3/10 shipped stories**
- Next up: **Wave 2** (`CEC-RT-004`..`CEC-RT-006`)

## Tracks

### Track A — Ingest + evaluation foundations
- `CEC-RT-001` verified-evidence ingest contract
- `CEC-RT-002` deterministic control-pack runtime
- `CEC-RT-003` fail-closed compiler state machine

### Track B — Authoritative compiled artifacts
- `CEC-RT-004` deterministic compiled report generation
- `CEC-RT-005` signed compiler service/runtime
- `CEC-RT-006` compiled-report verification in CLI/service

### Track C — First assurance program
- `CEC-RT-007` AI execution assurance control pack
- `CEC-RT-008` waiver + compensating-control semantics

### Track D — Auditor/operator surface
- `CEC-RT-009` export-pack / viewer integration
- `CEC-RT-010` non-authoritative narrative runtime

## Dependency Spine

```text
verified evidence ingest -> control-pack runtime -> fail-closed compiler state machine -> deterministic report generation -> signed compiler runtime -> compiled-report verification
                                                            \-> AI execution assurance pack -> waiver semantics -> export/viewer + narrative surfaces
```

## Execution Waves

### Wave 1 — Runtime foundations
- `CEC-RT-001` verified-evidence ingest contract
- `CEC-RT-002` deterministic control-pack runtime
- `CEC-RT-003` fail-closed compiler state machine

### Wave 2 — Authoritative compile runtime
- `CEC-RT-004` deterministic compiled report generation
- `CEC-RT-005` signed compiler service/runtime
- `CEC-RT-006` compiled-report verification in CLI/service

### Wave 3 — First real assurance pack
- `CEC-RT-007` AI execution assurance control pack
- `CEC-RT-008` waiver + compensating-control semantics

### Wave 4 — Product surface
- `CEC-RT-009` export-pack / viewer integration
- `CEC-RT-010` non-authoritative narrative runtime with hard membrane

## What this roadmap intentionally does not claim yet

- broad SOC 2 / ISO / multi-framework coverage at launch
- free-form LLM-authored authoritative compliance conclusions
- replacing `clawverify` cryptographic verification with compiler-side reinterpretation
- generic policy-authoring UX beyond what is needed to run one deterministic assurance pack

## Success Criteria

- Deterministic compile output is byte-identical for identical evidence + rules.
- Compiled reports are signer-verifiable and portable offline.
- The first AI execution assurance pack is useful for buyer / auditor review.
- Waivers can only degrade outcomes conservatively and leave residual markers.
- Export/viewer surfaces can explain compiled outcomes without weakening authoritative control results.
