> **Type:** Guide
> **Status:** CANONICAL
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-18
> **Source of truth:**
> - `docs/specs/clawsig-protocol/CLAWSIG_PROTOCOL_v1.0.md`
> - `docs/specs/clawsig-protocol/REASON_CODE_REGISTRY.md`
> - `packages/clawverify-core/`, `packages/clawverify-cli/`, `packages/schema/`
>
> **Scope:**
> - Practical v0.2 adoption for integrators (SDK/CLI/core usage, fixture verification, CI gates).
> - Internal docs/examples only (no external publish workflow in this guide).

# Clawsig Protocol — Adoption Guide (v0.2)

This guide updates integration flows from legacy v0.1 assumptions to **v0.2 shipped behavior on main**.

## What changed in v0.2 (high-signal)

| Capability | v0.1 | v0.2 |
|---|---|---|
| Tool receipt semantics | v1 only | v1 + v2 union support, co-signature + selective disclosure validation |
| Temporal semantics | limited | deterministic TTL + causal/future timestamp guards |
| Aggregate verification | not available | signed aggregate bundles with strict-liability member cascade |
| Rate-limit claims | not defined | deterministic offline `rate_limit_claims[]` checks (proof + aggregate) |
| Conformance vectors | v0.1 baseline | expanded R48/R49 + CPL-V2-001 executable vectors |

---

## 1) Fastest path: run the v0.2 quickstart vectors

Use the compact v0.2 fixture set to confirm your local verifier/toolchain before deeper integration.

### Build required packages

```bash
cd packages/clawverify-core && npm install && npm run build && cd ../..
cd packages/clawverify-cli && npm install && npm run build && cd ../..
```

### Run quickstart

```bash
node scripts/protocol/run-clawsig-v0.2-quickstart.mjs
```

Quickstart fixtures:

- `docs/examples/clawsig-v0.2-quickstart/manifest.v1.json`
- `docs/examples/clawsig-v0.2-quickstart/README.md`

Output summary:

- `artifacts/examples/clawsig-v0.2-quickstart/<timestamp>/summary.json`

---

## 2) Verify your own artifacts (CLI)

### Proof bundle

```bash
clawverify verify proof-bundle \
  --input path/to/proof_bundle_envelope.json \
  --config packages/schema/fixtures/protocol-conformance/clawverify.config.conformance.v1.json
```

### Aggregate bundle

```bash
clawverify verify aggregate-bundle \
  --input path/to/aggregate_bundle_envelope.json \
  --config packages/schema/fixtures/protocol-conformance/clawverify.config.conformance.v1.json
```

### Export path auto-dispatch

`verify export-bundle` can auto-dispatch aggregate envelopes when envelope type indicates `aggregate_bundle`.

---

## 3) v0.2 proof payload features you should emit

### 3.1 Co-signature-ready tool receipts (R48)

- Keep v1 compatibility where needed.
- For v2 tool receipts, include co-signatures when multi-party attestation is expected.
- Failures are deterministic (`CO_SIGNATURE_INVALID`).

### 3.2 Selective disclosure for tool receipt fields (R48)

- Use typed disclosure leaves and merkle-root commitments.
- Verifier fail codes are deterministic (`DISCLOSURE_TYPE_MISMATCH`, `DISCLOSURE_ROOT_MISMATCH`).

### 3.3 Temporal validity (R49)

- Use valid ISO-8601 timestamps.
- Ensure causal ordering and expected TTL windows.
- Deterministic temporal fail codes include `EXPIRED_TTL`, `CAUSAL_CLOCK_CONTRADICTION`, `FUTURE_TIMESTAMP_POISONING`.

### 3.4 Rate-limit claims (CPL-V2-001)

Emit optional `payload.rate_limit_claims[]` when you need offline abuse/burst evidence.

Required claim core fields:

- `claim_version`, `scope`, `scope_key`
- `window_start`, `window_end`
- `max_requests`, `observed_requests`

Optional token counters (must be paired):

- `max_tokens_input` + `observed_tokens_input`
- `max_tokens_output` + `observed_tokens_output`

Deterministic fail codes:

- `RATE_LIMIT_WINDOW_INVALID`
- `RATE_LIMIT_CLAIM_INCONSISTENT`
- `RATE_LIMIT_EXCEEDED`

---

## 4) Aggregate bundle adoption notes

When composing fleet-level envelopes:

- keep `envelope.signer_did === payload.issuer_did`
- ensure member array canonical sort and dedupe invariants
- avoid identity self-dealing (`payload.issuer_did` must not equal member `agent_did`)
- ensure summary reconciliation (`fleet_summary.*` must match computed values)

Common deterministic fail codes:

- `AGGREGATE_SIGNER_MISMATCH`
- `UNSORTED_MEMBER_ARRAY`
- `AGGREGATE_DUPLICATE_RUN_ID` / `AGGREGATE_DUPLICATE_BUNDLE_ID`
- `AGGREGATE_MEMBER_INVALID`
- `FLEET_SUMMARY_MISMATCH`

---

## 5) CI gate recommendation

Keep a lightweight quickstart gate for PRs touching protocol/verifier paths:

```bash
node scripts/protocol/run-clawsig-v0.2-quickstart.mjs
node scripts/protocol/run-clawsig-verified-pr.mjs
```

Use full conformance when making schema/runtime contract changes:

```bash
node scripts/protocol/run-clawsig-protocol-conformance.mjs
```

---

## 6) Migration checklist (v0.1 → v0.2)

- [ ] Update integration docs to reference `CLAWSIG_PROTOCOL_v1.0.md` (not v0.1-only docs).
- [ ] Validate tool receipt handling against v1/v2 union behavior.
- [ ] Add aggregate verification path where fleet-level artifacts are used.
- [ ] Add optional rate-limit claims if offline abuse evidence is required.
- [ ] Ensure CI includes quickstart and verified-pr runners.

---

## References

- Protocol spec: `docs/specs/clawsig-protocol/CLAWSIG_PROTOCOL_v1.0.md`
- Reason codes: `docs/specs/clawsig-protocol/REASON_CODE_REGISTRY.md`
- Quickstart vectors: `docs/examples/clawsig-v0.2-quickstart/manifest.v1.json`
- Integration starter packs: `docs/examples/integrations/README.md`
- Full conformance manifest: `packages/schema/fixtures/protocol-conformance/manifest.v1.json`
- Offline verifier runner: `scripts/protocol/run-clawsig-protocol-conformance.mjs`
