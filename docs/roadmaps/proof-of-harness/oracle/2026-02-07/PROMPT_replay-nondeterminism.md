# Oracle prompt: Replays, non-determinism, and OpenClaw prompt packs

We’re building a trust platform (agent economy) with Proof-of-Harness (PoH) and planned sandbox execution attestations (clawea).

New issue: **harness ≠ just “a CLI binary.”**

In OpenClaw, the “harness” includes dynamic system-prompt construction and plug-and-play agent personalities defined by workspace `.md` docs (e.g. `AGENTS.md`, `SOUL.md`, `TOOLS.md`, skills snapshots), plus runtime config (tools policy, sandboxing, provider routing), plus the underlying LLM/provider.

This creates two problems:
1) **Replays are hard**: To “replay” a run in a sandbox for verification/dispute resolution, you’d need the same prompt pack + tools + repo state + model configuration — but much of that is sensitive.
2) **Even with the same prompt**, LLM outputs are **non-deterministic** (tokenization, sampling, provider nondeterminism), so a replay will not match bit-for-bit.

Task:
1) From first principles, define what “replay” should mean for a trust platform. Distinguish:
   - deterministic reproduction (bit-identical),
   - policy compliance verification,
   - behavioral similarity checks,
   - artifact-level reproducibility (tests/CI),
   - audit trace verification.

2) Propose a robust design that **does not rely on deterministic output reproduction**, but still allows strong verification and dispute resolution.
   - For code: tests/CI, commit proof, build reproducibility.
   - For non-code: rubric evaluation, judges, provenance.

3) Propose a concrete scheme for a **Prompt Pack / Harness Pack**:
   - what files/sections are included,
   - how to compute a stable hash/commitment (config_hash_b64u + prompt_root_hash),
   - how to handle *sensitive* prompt packs (encryption, selective disclosure),
   - how to bind the pack to URM + event chain + receipts + attestation.

4) For sandbox attestation (clawea):
   - how should the attester verify “this exact prompt pack was loaded” without revealing it publicly?
   - what claims should the attestation include?

5) Identify the minimum changes needed in our schemas + verifiers to support this:
   - new schema objects (prompt_pack.v1.json?),
   - additions to URM/proof bundle metadata,
   - verification rules.

6) Provide a staged roadmap (8–12 steps) that moves us from today to a “replay-safe / dispute-safe” system.

Constraints:
- Fail-closed wherever possible.
- Do NOT require chain-of-thought.
- Explicitly call out where nondeterminism forces a different verification strategy.

Output format:
- Executive summary
- Definitions (replay taxonomy)
- Proposed evidence model additions
- Attestation claims
- Roadmap
