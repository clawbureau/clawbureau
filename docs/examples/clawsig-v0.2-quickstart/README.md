# Clawsig v0.2 quickstart fixture set

This folder contains a **minimal integrator-facing vector manifest** for validating a local `clawverify` installation against key v0.2 protocol capabilities:

- baseline proof-bundle verification
- tool-receipt v2 + co-signature path
- aggregate bundle verification
- deterministic rate-limit claim pass/fail behavior

## Run

From repo root:

```bash
node scripts/protocol/run-clawsig-v0.2-quickstart.mjs
```

The runner writes a summary artifact to:

- `artifacts/examples/clawsig-v0.2-quickstart/<timestamp>/summary.json`

## Notes

- The quickstart vectors reference canonical protocol-conformance fixtures under `packages/schema/fixtures/protocol-conformance/`.
- This is a compact smoke/adoption set, **not** a full conformance replacement.
