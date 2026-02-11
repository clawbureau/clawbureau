# CBT-OPS-003 Prod Gate Report

- Generated at: 2026-02-11T23:13:25.303Z
- Environment: prod
- Recommendation: **READY_FOR_PROD_GOVERNANCE_REVIEW**

## Blockers
- None detected by deterministic preflight pack.

## Required checks
- [x] routes.clawbounties.health (78ms)
- [x] routes.clawtrials.health (139ms)
- [x] routes.clawtrials.catalog (24ms)
- [x] routes.clawtrials.harness-run (24ms)
- [x] auth.requester.post-missing-token (22ms)
- [x] auth.requester.legacy-header-rejected (69ms)
- [x] auth.requester.post-valid-token (542ms)
- [x] auth.worker.register-and-self (461ms)
- [x] auth.requester.submission-list (130ms)
- [x] harness.integration.auto-decision (2280ms)
- [x] harness.integration.invalid-replay (1289ms)

## Optional checks
- [ ] auth.admin.get-bounty (0ms)

## Governance note
- Passing this gate does not bypass governance. Explicit GO PROD approval is still required.
