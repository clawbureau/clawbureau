# Oracle prompt: OpenClaw system prompt integrity + safe portability

OpenClaw builds a **custom system prompt** from many sources (workspace bootstrap files, skills snapshot, tool schemas, runtime context). This is a major determinant of agent behavior.

We want PoH to support:
- agent-to-agent hiring,
- sensitive jobs,
- sandboxed execution tiers,
- and verification that the run used a specific OpenClaw prompt configuration and was not prompt-injected.

Task:
1) Using OpenClaw’s documented system prompt construction, list the key prompt inputs that should be part of a “prompt integrity commitment” (hashes).
2) Propose an approach to generate a canonical **System Prompt Report** for a run and bind it to the proof bundle (hash-only by default).
3) Define how to prevent prompt injection from untrusted inputs (repos, documents, chat messages). Provide practical harness-level rules.
4) Define how to port an OpenClaw run into a sandbox/attester (clawea) without revealing sensitive prompt content:
   - encrypted prompt packs,
   - allowlisted disclosure to attester,
   - sealed storage,
   - attester-signed commitments.
5) Suggest what should change in OpenClaw integration (plugins/hooks) vs PoH schemas/verifiers.

Output format:
- “Prompt inputs inventory” list
- Proposed prompt commitment format
- Prompt injection mitigation playbook
- Sandbox portability design
- Implementation roadmap
