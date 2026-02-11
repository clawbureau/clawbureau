# CBT-OPS-003 Prod Gate Report

- Generated at: 2026-02-11T21:54:21.876Z
- Environment: staging
- Recommendation: **BLOCKED**

## Blockers
- auth.requester.post-valid-token: expected 200/201, got 401 (REQUESTER_TOKEN_INVALID): {
  "error": "REQUESTER_TOKEN_INVALID",
  "message": "Requester scoped token is invalid or expired",
  "details": {
    "upstream_error": "TOKEN_UNKNOWN_KID"
  }
}
- auth.requester.submission-list: ASSERT_FAILED: requester bounty id not available
- harness.integration.auto-decision: post test bounty failed (401, REQUESTER_TOKEN_INVALID): {
  "error": "REQUESTER_TOKEN_INVALID",
  "message": "Requester scoped token is invalid or expired",
  "details": {
    "upstream_error": "TOKEN_UNKNOWN_KID"
  }
}
- harness.integration.invalid-replay: post invalid harness bounty failed (401, REQUESTER_TOKEN_INVALID): {
  "error": "REQUESTER_TOKEN_INVALID",
  "message": "Requester scoped token is invalid or expired",
  "details": {
    "upstream_error": "TOKEN_UNKNOWN_KID"
  }
}

## Required checks
- [x] routes.clawbounties.health (236ms)
- [x] routes.clawtrials.health (172ms)
- [x] routes.clawtrials.catalog (23ms)
- [x] routes.clawtrials.harness-run (25ms)
- [x] auth.requester.post-missing-token (18ms)
- [ ] auth.requester.post-valid-token (91ms)
- [x] auth.worker.register-and-self (589ms)
- [ ] auth.requester.submission-list (0ms)
- [ ] harness.integration.auto-decision (30ms)
- [ ] harness.integration.invalid-replay (30ms)

## Optional checks
- [ ] auth.admin.get-bounty (0ms)

## Governance note
- Passing this gate does not bypass governance. Explicit GO PROD approval is still required.
