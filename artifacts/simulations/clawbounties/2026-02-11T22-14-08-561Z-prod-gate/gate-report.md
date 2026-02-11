# CBT-OPS-003 Prod Gate Report

- Generated at: 2026-02-11T22:14:08.561Z
- Environment: staging
- Recommendation: **READY_FOR_PROD_GOVERNANCE_REVIEW**

## Blockers
- None detected by deterministic preflight pack.

## Required checks
- [x] routes.clawbounties.health (206ms)
- [x] routes.clawtrials.health (128ms)
- [x] routes.clawtrials.catalog (26ms)
- [x] routes.clawtrials.harness-run (24ms)
- [x] auth.requester.post-missing-token (24ms)
- [x] auth.requester.post-valid-token (2521ms)
- [x] auth.worker.register-and-self (185ms)
- [x] auth.requester.submission-list (188ms)
- [x] harness.integration.auto-decision (2861ms)
- [x] harness.integration.invalid-replay (1547ms)

## Optional checks
- [x] auth.admin.get-bounty (45ms)

## Governance note
- Passing this gate does not bypass governance. Explicit GO PROD approval is still required.
