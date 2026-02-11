> **Type:** Spec
> **Status:** ACTIVE
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-11
> **Source of truth:**
> - `services/clawea-www/schemas/integration-manifest.v1.schema.json`
> - `services/clawea-www/src/content/integrations-manifest.v1.json`
> - `services/clawea-www/scripts/integration-manifest.ts`

# Integration Manifest v1 (SEO/AEO + Product Alignment)

## Purpose

`integrations-manifest.v1` is the canonical source of truth for:

1. Product claims safety (what we can and cannot say publicly).
2. Programmatic SEO/AEO generation grounding.
3. Connector/workflow secure-default posture.
4. Release-gate readiness by integration.

The manifest is fail-closed: if required data is missing or contradictory, generation and checks fail.

## Schema intent

Top-level sections:

- `schema_name`, `schema_version`
- `manifest` (identity, provenance)
- `platform` (global shipped/planned capability truth table)
- `integrations[]` (per connector/workflow profile)

Per integration record requires:

- Identity: `id`, `name`, `vendor`, `category`
- Connectivity: `modes_supported` (`mcp|api|plugin|ai_tool`)
- Action surface: `operations` (`read|write|admin|event`)
- Auth posture: `auth_modes` (`oauth|api_key|service_account|webhook`)
- Egress posture: `required_egress_hosts`
- Policy defaults: `default_wpc_controls`
- Approvals: `approval_requirements.write/admin`
- Proof posture: `proof_artifacts`
- Lifecycle: `status` (`shipped|beta|planned|implementable|deprecated`)
- Evidence: `source_urls` (allowlisted official URLs)
- Release gates: `release_gates.{security,ops,proof,docs}`
- Claim safety:
  - `claims.public_availability`
  - `claims.allowed[]`
  - `claims.must_not_imply[]`

## Release gates

Release-gate rules enforced by checker:

- `status=shipped` requires all release gates = `pass`.
- Non-shipped entries must include claim-safety guardrails in `must_not_imply`.
- `claims.public_availability` must exactly match `status`.
- Write/admin operations require approval requirements to be `required`.

## SEO/AEO fail-closed generation rules

Generation (`scripts/model-writeoff.ts`) consumes this manifest and enforces:

1. Global truth table is manifest-driven (no hardcoded shipped/planned list).
2. Integration targets get manifest-specific context:
   - allowed claims only
   - must-not-imply phrases
   - integration status and modes
3. If a required integration record is missing for a target slug, generation fails immediately.
4. Candidate QA fails on:
   - `claim_state_violations`
   - `endpoint_invention_violations`
   - `shipped_planned_mismatch`

## Validation commands

From `services/clawea-www`:

```bash
npx tsx scripts/check-integration-manifest.ts
npx tsx scripts/check-integration-manifest.ts --json
```

Write-off compliance metrics:

```bash
npx tsx scripts/writeoff-metrics.ts --run sample-output/model-writeoff/<run-id>
```

Outputs:
- `METRICS.json`
- `COMPLIANCE_SUMMARY.md`
