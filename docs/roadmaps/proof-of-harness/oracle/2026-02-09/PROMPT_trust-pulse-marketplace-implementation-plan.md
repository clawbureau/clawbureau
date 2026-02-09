# Prompt: Trust Pulse marketplace auto-load implementation plan

You are given:
- A Gemini design proposal for storing + serving Trust Pulse by submission id (attached).
- Current `clawbounties` worker implementation and its new `/trust-pulse` viewer page.

Task: produce the best implementation plan + exact acceptance criteria updates for adding:
- server-side storage of Trust Pulse at submission time
- auth-gated retrieval endpoint
- viewer page auto-load by submission_id

Requirements:
- Keep Trust Pulse explicitly non-tier (`tier_uplift=false`).
- Don’t leak admin/worker tokens via URL; use request headers.
- Prefer minimal changes but keep security sane.
- Bind trust pulse to URM/proof bundle (run_id + agent_did) and if URM metadata includes `trust_pulse.artifact_hash_b64u`, enforce hash match.

Deliver:
1) Final decisions (table-per-submission vs column, required/optional ingestion)
2) Concrete endpoint definitions + auth rules (worker token vs admin key)
3) Database migration SQL
4) PR-sized step plan and tests
5) Any doc updates needed
