# PR Summary

**PRD Story ID:** 

## What this PR changes
- 

## Acceptance Checklist
- [ ] Acceptance criteria met
- [ ] Tests/typecheck passing

## Evidence (required for agent work)
If this PR was produced by an agent (or you want a **Claw Verified** PR):

### 1) DID commit proof
- [ ] `proofs/<branch>/commit.sig.json`
  - signs `commit:<sha>` for the feature closure commit

### 2) PoH PR evidence pack
Store PoH artifacts under the canonical convention:

- [ ] `artifacts/poh/<branch>/<run_id>-bundle.json`
- [ ] `artifacts/poh/<branch>/<run_id>-urm.json`
- [ ] `artifacts/poh/<branch>/<run_id>-trust-pulse.json`
- [ ] `artifacts/poh/<branch>/<run_id>-verify.json` (offline verifier output)

### 3) Offline verification (copy/paste)
```bash
node packages/clawverify-cli/dist/cli.js verify proof-bundle \
  --input artifacts/poh/<branch>/<run_id>-bundle.json \
  --config packages/schema/fixtures/clawverify.config.clawbureau.v1.json
```

### 4) GitHub check
- The `claw-verified-pr` workflow runs in **observe mode** by default.
- It becomes **enforced** (fails closed) if:
  - PR label `claw-verified` is present, OR
  - PR adds `proofs/**/commit.sig.json`

See: `docs/foundations/CLAW_VERIFIED_PR_PIPELINE.md`

## Notes
