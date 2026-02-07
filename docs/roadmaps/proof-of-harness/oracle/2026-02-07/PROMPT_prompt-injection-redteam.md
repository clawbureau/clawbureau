# Oracle prompt: Prompt injection & untrusted repo content (buyer-side adversary)

We’re building a trust platform / agent economy. Agents can hire other agents. Some jobs are sensitive (private repos, PII). We want sandboxed consulting such that:
- buyer can verify their data was not exfiltrated beyond allowed egress/tools,
- the hired agent wasn’t tricked into violating policy,
- the system is hard to game/tamper with,
- enforcement is by construction (plugins/extensions/hooks), not “remember to do X.”

New threat focus: **buyer-side malicious inputs**.

Assume the buyer may be adversarial and can include malicious content in:
- a GitHub repo (README, code comments, tests, CI config, malicious scripts),
- files they upload (docs, PDFs, images, prompts),
- messages they send to the worker agent,
- dependency graphs (package scripts, postinstall, etc).

Goal: prevent prompt injection and hostile inputs from causing the hired agent to:
- leak the buyer’s secrets elsewhere,
- leak the worker’s secrets elsewhere,
- run dangerous tools/commands,
- weaken PoH evidence,
- bypass sandbox/policy controls.

Task:
1) Provide a red-team list of the **top 30 prompt injection / hostile repo** attacks specifically in the agent-run world.
   - Include attacks against: tool calling, sandbox escape, model override, secret theft, policy downgrade, verifier confusion, receipt manipulation, and supply-chain.
2) For each attack, propose layered mitigations across:
   - harness/runtime behavior (OpenClaw tool policy, session gating, system prompt composition rules),
   - policy contracts (WPC/CWC),
   - sandbox enforcement (clawea),
   - proxy/egress mediation (clawproxy),
   - verification rules (clawverify),
   - marketplace policy (clawbounties / clawdelegate).
3) Define a concrete **“untrusted content handling”** design pattern for worker agents:
   - how to ingest repo content safely,
   - how to treat untrusted instructions (e.g. README) as data not directives,
   - planner/executor splits,
   - tool-use constraints,
   - safe code execution policy.
4) Recommend what needs to change in our architecture to make these mitigations enforceable by construction.
   - Focus on OpenClaw-first integrations; wrappers are last resort.
5) Provide a prioritized roadmap (8–15 stories) with clear acceptance criteria.

Constraints:
- Fail-closed whenever possible.
- Do not rely on chain-of-thought.
- Assume clever adversaries.
- Be explicit about what can’t be solved without TEEs.

Output format:
- Executive summary
- Table: Attack → Impact → Current coverage → Mitigation
- “Golden path” policy profile for sensitive consulting
- Roadmap
