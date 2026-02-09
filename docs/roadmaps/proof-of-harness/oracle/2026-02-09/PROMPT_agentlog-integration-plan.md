# Prompt: agentlog → PoH/OpenClaw integration plan (Trust Platform)

You have:
- A repo analysis of `/Users/gfw/code/agentlog` (attached).
- Claw Bureau PoH artifacts and code snippets (attached).

Task: Produce an actionable engineering + product plan to extract **real trust-platform value** from agentlog for OpenClaw users, while keeping **trust uplift fail-closed** and non-gameable.

Deliver:

1) **Decisions**: Which 2-3 integration directions are worth doing vs not worth doing (and why).
2) **Proposed roadmap items**: new POH/TRUST/OpenClaw stories (IDs, titles, AC) that we should add to `docs/roadmaps/trust-vnext/prd.json` (or PoH roadmap if more appropriate).
3) **Implementation plan**: 2-3 phases with PR-sized steps. For each step:
   - scope and files likely touched
   - tests needed
   - backwards-compat considerations
4) **Security model**: explicitly classify what data is self-reported vs cryptographically verifiable; propose guardrails to prevent false tier uplift.
5) **Developer UX**: how OpenClaw users would experience this (skills, flags, default behaviors).

Constraints:
- No raw transcript exfiltration. Derived + redacted artifacts only.
- Keep PoH core minimal; any semantic summaries must not uplift proof tier.
- Prefer harness-level enforcement/instrumentation over wrappers where possible.
