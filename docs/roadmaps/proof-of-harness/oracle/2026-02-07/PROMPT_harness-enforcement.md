# Oracle prompt: Harness-specific enforcement + autonomy

Goal: PoH should be *automatic* and hard to “forget to do”.

We currently have:
- OpenClaw native plugin path (provider plugin + recorder)
- External harness wrappers (clawproof-adapters) using a local shim

Task:
1) For each harness:
   - OpenClaw
   - Claude Code
   - Codex CLI
   - OpenCode
   - Pi (pi-coding-agent)

   Identify the best integration point(s) to enforce PoH automatically:
   - plugins/extensions/hooks
   - provider registry overrides
   - MCP interception
   - config-level enforcement
   - wrapper scripts as last resort

2) For each harness, propose:
   - best-practice “golden path” configuration
   - how to ensure binding headers + receipts are always produced
   - how to ensure event chain includes tool calls (where possible)
   - how to handle streaming (SSE) without losing receipts

3) Highlight where our current assumptions are wrong (e.g. env var base URL overrides that aren’t actually supported).

4) Propose a compatibility matrix (harness × features) and what we should test in CI.

Output format:
- A per-harness playbook.
- A compatibility matrix.
- A short list of high-leverage engineering changes.
