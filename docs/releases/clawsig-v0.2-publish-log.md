# Clawsig v0.2.0 — npm publish log

Date: 2026-02-18

Scope:

- `@clawbureau/schema@0.2.0`
- `@clawbureau/clawverify-core@0.2.0`
- `@clawbureau/clawverify-cli@0.2.0`

## Pre-publish checks

- `node scripts/release/check-clawsig-v0.2-checklist-integrity.mjs` ✅
- `node scripts/release/check-clawsig-v0.2-enterprise-pilot-pack-integrity.mjs` ✅
- `node scripts/release/run-clawsig-v0.2-package-prep.mjs` ✅

Prep summary:

- `artifacts/release/clawsig-v0.2-package-prep/2026-02-18T14-18-45-458Z/summary.json`

## Publish results

### `@clawbureau/schema@0.2.0`

- status: **published**
- publish command (requested): `npm publish --access public --provenance`
- provenance result: local provider unsupported (`EUSAGE: Automatic provenance generation not supported for provider: null`)
- fallback used: `npm publish --access public`
- npm: <https://www.npmjs.com/package/@clawbureau/schema/v/0.2.0>

### `@clawbureau/clawverify-core@0.2.0`

- status: **skipped (already exists)**
- npm: <https://www.npmjs.com/package/@clawbureau/clawverify-core/v/0.2.0>

### `@clawbureau/clawverify-cli@0.2.0`

- status: **skipped (already exists)**
- npm: <https://www.npmjs.com/package/@clawbureau/clawverify-cli/v/0.2.0>

## Clean install verification

### Exact requested triplet

```bash
npm install @clawbureau/schema@0.2.0 @clawbureau/clawverify-core@0.2.0 @clawbureau/clawverify-cli@0.2.0
```

- install: ✅
- `node node_modules/@clawbureau/clawverify-cli/dist/cli.js version`: ❌
- failure: missing transitive package `@clawbureau/clawsig-sdk`

### With explicit sdk dependency

```bash
npm install @clawbureau/schema@0.2.0 @clawbureau/clawverify-core@0.2.0 @clawbureau/clawverify-cli@0.2.0 @clawbureau/clawsig-sdk@0.4.1
```

- install: ✅
- `clawverify version` output: `clawverify 0.1.1`
- expected: `clawverify 0.2.0`
- status: ❌ mismatch

## Machine summary

- `artifacts/release/clawsig-v0.2-npm-publish/2026-02-18T14-26-39Z/summary.json`

## Post-publish closure fix (C1)

Date: 2026-02-18

Root cause confirmed:

1. `clawverify version` was hardcoded in CLI source instead of deriving from package metadata, allowing runtime drift when release versions changed.
2. Prior published CLI metadata contained local (`file:`) dependency specs for transitive packages, causing clean install closure breaks.

Fix delivered:

- `packages/clawverify-cli/src/cli.ts`
  - version command now uses runtime package version helper (`formatCliVersion()`), not a hardcoded literal.
- `packages/clawverify-cli/src/version.ts`
  - reads `../package.json` at runtime and emits deterministic `clawverify <version>`.
- `scripts/release/run-clawsig-v0.2-package-prep.mjs`
  - added dependency-closure guard (fails on local `file:/link:/workspace:` dependency specs)
  - added runtime dependency presence checks for `@clawbureau/clawsig-sdk` + `@clawbureau/clawverify-core`
  - added command transcript output (`commands.log`)
  - preserved fail-closed version parity gate (`clawverify version` must equal package version)

Validation evidence:

- `artifacts/release/clawsig-v0.2-package-prep/2026-02-18T15-21-27-235Z/summary.json`
- `artifacts/release/clawsig-v0.2-package-prep/2026-02-18T15-21-27-235Z/commands.log`

## Notes

- No deploy actions in this lane.
- This log records publish state + verification outcomes only.
