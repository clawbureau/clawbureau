# Oracle prompt: Sensitive agent-to-agent consulting (sandboxed, non-gameable)

We are building an agent economy / trust platform where agents can hire other agents (agent-to-agent delegation) to do work.

New requirement:
- Jobs may be sensitive (private GitHub repos, sensitive files, PII).
- Buyer wants strong assurance that:
  1) their data was not shared with tools/egress destinations not permitted,
  2) only the hired agent saw the files (no human involvement),
  3) the hired agent could not be prompt-injected / exploited by malicious repo contents,
  4) the overall system is hard/impossible to game.
- It must be very easy to:
  - create a contract/policy,
  - install/run the worker harness,
  - verify results.
- Legit users should not feel friction; security should be "by construction".

Current primitives in our system:
- `clawproxy` gateway receipts + Work Policy Contract (WPC) headers (`X-Policy-Hash`, `X-Confidential-Mode`, redaction rules, privacy modes).
- Scoped tokens (CST) with token_scope_hash bound into receipts.
- PoH proof bundle: URM + event chain + receipts + optional attestations.
- Planned execution attestation service: `clawea`.
- Delegation contracts planned in `clawdelegate`.

Task:
1) Propose a first-principles architecture for **confidential agent-to-agent consulting**.
   - Distinguish what can be proven without TEEs vs what requires TEEs.
   - Define clear trust tiers for sensitive work (e.g. self, receipted, sandbox-attested, TEE-attested).
2) Define the contract/policy object(s):
   - what fields are required,
   - how they’re signed (which DID),
   - how they bind to CST tokens + clawproxy receipts + proof bundles.
   - how they translate into harness/tool policies (OpenClaw, Pi, Claude Code, etc).
3) Define how to prevent *exfiltration* while still enabling useful work:
   - network egress mediation,
   - tool allowlists,
   - DLP/redaction pipelines,
   - output scanning,
   - secret handling.
4) Define how to prevent *prompt injection / malicious inputs* from the buyer side (e.g. repo contains adversarial instructions):
   - harness-level instruction hygiene,
   - untrusted-content handling patterns,
   - separation-of-duties patterns (planner vs executor),
   - sandbox boundaries.
5) Define verifications:
   - what clawverify must check,
   - what new envelope types or schemas we should add (if any),
   - how the marketplace should gate auto-approval and stakes.
6) Provide a concrete incremental roadmap (next 8–15 stories) across domains (clawproxy/clawverify/clawcontrols/clawdelegate/clawea/openclaw integration) that gets us to a usable confidential consulting product.

Constraints:
- Fail-closed whenever possible.
- Be explicit about assumptions/unknowns.
- Prioritize approaches that make it hard for agents to "forget" required steps (enforce via runtime/plugins, not prompts).

Output format:
- Executive summary
- Trust tier matrix
- Contract/policy format proposal
- Enforcement design
- Verification design
- Roadmap
