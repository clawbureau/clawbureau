# Clawsig v0.2.0 — Package Release Prep Checklist

Status: **PREP COMPLETE (NO PUBLISH EXECUTED)**

Date: 2026-02-18

## Scope

- `@clawbureau/schema`
- `@clawbureau/clawverify-core`
- `@clawbureau/clawverify-cli`

Target alignment: `0.2.0` for all three packages.

## Completed checks

- [x] Package versions aligned to `0.2.0`.
- [x] `npm pack` smoke run for all three packages.
- [x] Install-from-tarball sanity check passed in clean temp project.
- [x] CLI tarball version command returns `clawverify 0.2.0`.
- [ ] npm publish (intentionally not executed in this lane).

## Canonical machine-readable artifact

- `docs/releases/clawsig-v0.2-package-release-checklist.v1.json`
- Signature envelope: `proofs/chore/release/CPL-V2-package-prep/release-checklist.sig.json`

Checklist JSON digest:

- `sha256: ca774ae95594110f659bcb9dd2d5ea65332d8491e45556ba5a206a1b58f9180c`

## Pack/install smoke evidence

Runner:

- `scripts/release/run-clawsig-v0.2-package-prep.mjs`

Summary artifact (local run):

- `artifacts/release/clawsig-v0.2-package-prep/2026-02-18T00-37-58-412Z/summary.json`

Tarball hashes:

- `clawbureau-schema-0.2.0.tgz`
  - `sha256: acde5a4d8c5424cfd399dd2131990675554b77d5a2228b15ecfed252c4b0b4f0`
- `clawbureau-clawverify-core-0.2.0.tgz`
  - `sha256: 5ff0e6f458f185becfb8a7b577034f8714a9425905319e35cebf0817ea7e28d8`
- `clawbureau-clawverify-cli-0.2.0.tgz`
  - `sha256: a1e33bad4a1a71ec11eca64e7d35604cf14557c3987d14400e66a63255af03fe`

## Safety note

This lane performs **release preparation only**:

- version alignment
- tarball pack/install smoke
- signed checklist artifact

No registry publish, no deploy, and no external announcement/post actions were executed.
