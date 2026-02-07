# Oracle prompt: Synthesize PoH + confidential consulting into next building blocks plan

We have completed multiple oracle research runs in this folder. We are building a 2026 agent trust platform / agent economy.

Goal:
Produce a single, coherent **Next Building Blocks Plan** that ties together:
- Proof-of-Harness (PoH): URM + event chain + gateway receipts + allowlists + binding enforcement
- Subscription auth realities (ChatGPT / Gemini web / Claude web)
- Confidential agent-to-agent consulting for sensitive repos/PII
- Prompt injection / untrusted buyer inputs (repo-as-adversary)
- OpenClaw-specific reality: harness includes dynamic system prompt composition + personality .md docs
- Replay/nondeterminism: we cannot rely on bit-identical LLM output reproduction
- Autonomy-by-construction: integrations via plugins/extensions/hooks, not "remember to do X"
- Non-gameability: system must be hard to cheat/tamper with

Task:
1) Write an **executive summary** (1 page) of the target architecture and why it works.
2) Define a **trust tier model** (marketplace-facing) that is consistent across the system.
   - Include: self / gateway-receipted / sandbox-attested / TEE-attested / (optional) witnessed-web.
   - Clearly state what each tier proves and what it does NOT prove.
3) Define the **evidence model** end-to-end:
   - proof bundle, event chain, URM, gateway receipts, policy bindings, prompt pack commitments, egress receipts, execution attestations.
   - Call out schema changes needed (new envelope types, additions to URM/bundle metadata).
4) Define the **policy/contract model** for sensitive consulting:
   - buyer ↔ worker contract (CWC), WPC, delegation contract, CST bindings.
   - How hashes/signatures bind to receipts and bundles.
5) Define the **enforcement-by-construction design**, OpenClaw-first:
   - where to enforce: OpenClaw plugins (provider/tool/memory), clawea sandbox runner, clawproxy, clawverify.
   - how to prevent: prompt injection, exfiltration, sandbox escape, policy downgrade.
   - include the “Airlock” / untrusted content handling patterns.
6) Define the **verification hardening work** needed right now (fail-closed correctness fixes):
   - especially event-hash recomputation, signer/payload DID equality, strict schema validation, durable idempotency, replay DB, etc.
7) Produce a concrete **roadmap of 12–20 stories** with:
   - story id suggestion (e.g. POH-US-013, CPX-US-0xx, CVF-US-0xx, CEA-US-0xx, CCO-US-0xx, CDL-US-0xx)
   - domain ownership
   - acceptance criteria
   - dependency ordering
8) Provide a short section: **Docs/code changes checklist** (files to update) so we can implement efficiently.

Constraints:
- Fail-closed where possible.
- Do not rely on chain-of-thought.
- Explicitly handle nondeterminism: define what “replay” means.
- Be explicit about unknowns and what to measure/validate.
- Prefer mechanisms that do not require trusting a worker’s local machine for high tiers.

Output format:
- Executive summary
- Tier model
- Evidence model + schema deltas
- Contract/policy model
- Enforcement architecture
- Verification hardening
- Roadmap (numbered)
- Implementation checklist
