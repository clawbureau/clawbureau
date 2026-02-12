# Oracle prompt: PoH first principles (2026)

We are building a trust platform / agent economy where workers submit artifacts and we verify “proof of harness” (PoH).

Context (current system):
- `clawproxy` is a gateway that proxies LLM calls to providers (Anthropic/OpenAI/Google) and emits signed receipts (`_receipt_envelope`) that include binding fields (`run_id`, `event_hash_b64u`, `nonce`, `policy_hash`, `token_scope_hash_b64u`).
- `clawsig` SDK/adapters record a hash-linked event chain, generate a URM, collect receipts, and sign a proof bundle.
- `clawverify` verifies the proof bundle, verifies receipt signatures against an allowlist, and enforces receipt↔event-chain binding.

Task:
1) From first principles, define what we should be trying to prove in an “agent-run world” (2026). Separate: identity, execution integrity, model usage integrity, tool usage integrity, output integrity.
2) Enumerate the minimum evidence objects required and which can be optional.
3) Threat model + top attack vectors (gaming the system) for each evidence type, and mitigations.
4) Evaluate our current architecture (URM + event chain + gateway receipts + allowlists + binding enforcement). Identify gaps and what changes would most improve robustness.
5) Propose a roadmap (next 5–10 incremental stories) that improves security and autonomy while keeping adoption feasible.

Constraints:
- Must be fail-closed where possible.
- Must not rely on chain-of-thought.
- Assume malicious/clever workers.
- Explicitly call out unknowns and what to measure/verify.

Output format:
- Start with a 1-page executive summary.
- Then: evidence model, threat model, mitigations, roadmap.
