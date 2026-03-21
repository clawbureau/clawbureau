> **Type:** Roadmap
> **Status:** COMPLETE
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-03-21
> **Source of truth:** `prd.json` + `progress.txt` in this folder

# Clawsig Framework vNext — Attestation, Signed Policy, Marketplace Enforcement, Review UX

## Context

Privacy Assurance v1 made proofed runs meaningfully better: fail-closed egress, signed privacy receipts, reviewer-facing posture reports, and export packs.

The next step is broader **framework trust**:

- make assurance policy a signed control plane instead of ambient config
- make runners themselves measurable/attested
- enforce assurance requirements in the marketplace, not just in reports
- productize review/dispute surfaces
- expand beyond one runtime family
- add transparency + revocation so trust roots can evolve safely

## Product Goal

Turn Clawsig into a framework that can honestly say:

> This run followed a signed policy, executed in a measured runner, satisfied the marketplace requirements for this task, and produced reviewer/auditor artifacts that explain exactly what is and is not proven.

## Tracks

### Track A — Reliability foundations
- `AF2-REL-001` repair clawverify-cli submit/test debt
- `AF2-REL-002` deterministic SIGTERM proof finalization
- `AF2-REL-003` canonical receipt-only proof bundles
- `AF2-REL-004` release guardrail for green proof-production paths

### Track B — Signed policy control plane
- `AF2-POL-001` signed policy bundle schema + envelope
- `AF2-POL-002` hierarchical policy resolution
- `AF2-POL-003` signed approval receipts
- `AF2-POL-004` policy-hash-bound verification

### Track C — Attested enforcement
- `AF2-ATT-001` runner measurement manifest
- `AF2-ATT-002` signed runner attestation receipt
- `AF2-ATT-003` attested trust-tier uplift
- `AF2-ATT-004` attestation posture in prove/export

### Track D — Marketplace enforcement
- `AF2-MKT-001` bounty-level assurance requirements
- `AF2-MKT-002` submission gating on required evidence
- `AF2-MKT-003` payout and review policy by assurance tier

### Track E — Reviewer/dispute product surface
- `AF2-REV-001` hosted reviewer/export-pack viewer
- `AF2-REV-002` side-by-side run comparison
- `AF2-REV-003` reviewer signoff receipt + dispute-note binding

### Track F — DLP sophistication
- `AF2-DLP-001` richer sensitivity taxonomy + custom rules
- `AF2-DLP-002` structured redaction + simulation mode

### Track G — Cross-runtime parity
- `AF2-XRT-001` python proofed adapter parity
- `AF2-XRT-002` browser/automation proofed adapter parity

### Track H — Transparency + revocation
- `AF2-TRN-001` transparency log for assurance receipts
- `AF2-TRN-002` revocation for runner/policy/reviewer keys

## Dependency Spine

```text
Reliability cleanup → signed policy bundles/resolution → attestation → marketplace enforcement
                                           └──────→ richer DLP / cross-runtime parity
Attestation + export/reviewer surfaces → reviewer/dispute UX → transparency + revocation
```

## Execution Waves

### Wave 1 — Foundations
- Reliability cleanup (`AF2-REL-001..004`)
- Signed policy bundle + resolution (`AF2-POL-001..002`)
- Runner measurement manifest (`AF2-ATT-001`)

### Wave 2 — Verifiable control plane
- Signed approval receipts + policy-hash binding (`AF2-POL-003..004`)
- Signed runner attestation + verifier uplift (`AF2-ATT-002..003`)
- DLP taxonomy foundation (`AF2-DLP-001`)

### Wave 3 — Enforcement + reviewer surface
- Attestation posture in prove/export (`AF2-ATT-004`)
- Marketplace gating (`AF2-MKT-001..002`)
- Hosted review/export-pack viewer (`AF2-REV-001`)
- Python adapter parity (`AF2-XRT-001`)

### Wave 4 — Expansion + trust hardening
- Payout/review routing by assurance tier (`AF2-MKT-003`)
- Side-by-side review + reviewer signoff (`AF2-REV-002..003`)
- Structured redaction + simulation (`AF2-DLP-002`)
- Browser adapter parity (`AF2-XRT-002`)
- Transparency log + revocation (`AF2-TRN-001..002`)

## What this roadmap intentionally does not claim yet
- universal legal/compliance automation
- perfect non-disclosure guarantees across all environments
- TEE/measured-boot guarantees without delivered attestation lanes

## Outcome

Framework vNext is now complete: all 24 planned stories shipped across reliability, signed policy, attestation, marketplace enforcement, reviewer UX, DLP, cross-runtime parity, transparency, and revocation.

## Success Criteria
- Framework test/release surfaces are green on canonical proof paths
- Proofed runs bind to signed policy artifacts instead of ambient config
- Attested runs can earn a stronger verifier trust tier
- Marketplace contracts can require assurance levels and gate submissions automatically
- Review/export surfaces become first-class dispute/audit tools
- Cross-runtime parity is no longer aspirational
- Trust roots can be anchored and revoked explicitly
