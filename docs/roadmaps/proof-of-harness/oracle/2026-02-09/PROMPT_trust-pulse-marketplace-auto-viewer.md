# Prompt: Trust Pulse marketplace storage + auto viewer

You are helping implement the next step of the Trust Pulse feature.

Current state:
- Producers (clawsig-adapters + OpenClaw recorder) generate a `trust_pulse.v1` document (self-reported, non-tier) and attach a pointer in `URM.metadata.trust_pulse`.
- `clawbounties` now has a public `GET /trust-pulse` page that can paste/upload JSON to view tools + files.

Goal:
- Make the marketplace viewer able to **auto-load Trust Pulse by submission id** (no manual paste), i.e. the Trust Pulse is stored/retrievable server-side.

Please propose the smartest design that is:
- minimal, MVP-friendly
- fail-closed where appropriate
- does not leak secrets (trust pulse is already redacted but still treat as sensitive)

Deliverables:

1) **Data model**: what to store in D1 and where (submissions table, new table, etc.).
   - include schema changes and indexes
   - include size limits

2) **API contract**:
   - how submissions should include trust pulse bytes (new `trust_pulse` field? reuse artifacts?)
   - endpoint(s) to retrieve trust pulse (e.g. `GET /v1/submissions/{id}/trust-pulse`)
   - authorization rules: worker token vs admin/requester (MVP uses BOUNTIES_ADMIN_KEY)

3) **Binding/validation**:
   - how to bind trust pulse to URM/proof bundle (run_id/agent_did, hash compare to URM.metadata.trust_pulse.artifact_hash_b64u if present)
   - what to do on mismatch (reject? store but mark unverified?)

4) **Viewer UX**:
   - how the `/trust-pulse` page should fetch and display by submission_id
   - avoid embedding secrets in URLs

5) **Implementation plan**: ordered PR-sized steps.
