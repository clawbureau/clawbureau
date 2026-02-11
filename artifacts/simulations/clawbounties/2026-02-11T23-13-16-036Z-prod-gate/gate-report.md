# CBT-OPS-003 Prod Gate Report

- Generated at: 2026-02-11T23:13:16.036Z
- Environment: staging
- Recommendation: **READY_FOR_PROD_GOVERNANCE_REVIEW**

## Blockers
- None detected by deterministic preflight pack.

## Required checks
- [x] routes.clawbounties.health (62ms)
- [x] routes.clawtrials.health (95ms)
- [x] routes.clawtrials.catalog (26ms)
- [x] routes.clawtrials.harness-run (26ms)
- [x] auth.requester.post-missing-token (24ms)
- [x] auth.requester.legacy-header-rejected (63ms)
- [x] auth.requester.post-valid-token (1485ms)
- [x] auth.worker.register-and-self (382ms)
- [x] auth.requester.submission-list (127ms)
- [x] harness.integration.auto-decision (2521ms)
- [x] harness.integration.invalid-replay (1209ms)

## Optional checks
- [ ] auth.admin.get-bounty (0ms)

## Governance note
- Passing this gate does not bypass governance. Explicit GO PROD approval is still required.
