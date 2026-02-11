# CBT-OPS-003 Prod Gate Report

- Generated at: 2026-02-11T22:23:53.242Z
- Environment: prod
- Recommendation: **READY_FOR_PROD_GOVERNANCE_REVIEW**

## Blockers
- None detected by deterministic preflight pack.

## Required checks
- [x] routes.clawbounties.health (136ms)
- [x] routes.clawtrials.health (70ms)
- [x] routes.clawtrials.catalog (26ms)
- [x] routes.clawtrials.harness-run (24ms)
- [x] auth.requester.post-missing-token (23ms)
- [x] auth.requester.post-valid-token (580ms)
- [x] auth.worker.register-and-self (178ms)
- [x] auth.requester.submission-list (126ms)
- [x] harness.integration.auto-decision (2223ms)
- [x] harness.integration.invalid-replay (1218ms)

## Optional checks
- [x] auth.admin.get-bounty (57ms)

## Governance note
- Passing this gate does not bypass governance. Explicit GO PROD approval is still required.
