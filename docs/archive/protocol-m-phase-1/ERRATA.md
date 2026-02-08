> **Type:** Archive
> **Status:** ARCHIVE
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-07
>
> **Scope:**
> - Errata for archived Protocol M Phase 1 files.

# ERRATA

## golden-vector.json: signature_hex mismatch

The archived `golden-vector.json` contains both:
- `signature_base64`
- `signature_hex`

Those two values do **not** match.

The **canonical signature** is `signature_base64` (it verifies successfully).

The corrected hex for `signature_base64` is:

```
73bad28ce41fe38ffc97af93a8c481d4d629ae586c1302e863ed0884957303f3cff904241cdfaa5d79dd32d84bdc278c4d9415a98b8f744cbd3b592308293903
```

The monorepo uses the corrected value in:
- `packages/schema/fixtures/protocol-m-golden-vector.v1.json`
