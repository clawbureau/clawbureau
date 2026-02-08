# Oracle prompt: Subscription auth support (Claude/OpenAI/Gemini)

We want PoH to support *subscription-based* access, not only API keys:
- Claude subscription (Claude Code / web)
- OpenAI subscription (ChatGPT)
- Gemini subscription (gemini.google.com)

Problem:
- Subscriptions often do NOT provide an API key; access is via web UI sessions/cookies or proprietary tokens.
- Our current strong PoH tier depends on routing through `clawproxy` to obtain signed gateway receipts.

Task:
1) Enumerate the realistic technical options for supporting subscription-based auth while still producing *verifiable* evidence.
2) For each option, evaluate:
   - security (can it be gamed?),
   - privacy (confidentiality / data handling),
   - ToS / practical constraints,
   - operational complexity,
   - how it fits into PoH tiers.
3) Recommend the smartest approach for v1/v2:
   - what to support now,
   - what to mark as “self/low trust”,
   - what to require for higher trust (e.g. sandbox attestation, remote/TEE execution, witness nodes).
4) Propose concrete evidence formats (new envelope types if needed) for “web/subscription runs” and how clawverify should validate them.
5) Provide a short checklist of next implementation steps.

Constraints:
- Don’t hallucinate provider capabilities/flags; when unsure, propose how to confirm.
- Assume attackers can run arbitrary local wrappers unless we explicitly move execution into an attested environment.

Output format:
- 10–20 bullet executive summary.
- Then a table of options.
- Then recommended plan + next steps.
