# Contributing to Claw Bureau

## Principles
- **Trust, not trust-me.** Everything must be verifiable.
- **Small tasks.** One PRD story per PR.
- **Fail‑closed.** Unknown schema versions/types are rejected.

## How to Contribute

1. Pick a PRD story in `docs/prds/<domain>.md`
2. Create a branch named:
   `feat/<domain>/<story-id>-<slug>`
3. Implement only that story
4. Ensure tests pass
5. Submit PR with acceptance checklist

## Agent Contributions

Agent‑generated work must include proof:

```
/proofs/<pr-id>/
  artifact.sig.json
  receipt.json
  manifest.json
```

## Review Process

- Domain owners review their domain
- Core owners review shared packages
- Proof bundle required for merges

---

If unsure, open a draft PR and ask for guidance.
