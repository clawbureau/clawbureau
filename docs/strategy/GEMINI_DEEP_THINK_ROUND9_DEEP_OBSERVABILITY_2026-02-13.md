# Gemini Deep Think Round 9: Deep Execution Observability

> Received: 2026-02-13
> Focus: How to observe bash internals, file reads, network connections, subprocess trees
> Also covered: DX red team, HN vulnerabilities, spec audit, competitive threats, FATAL blind spot

## Key Findings

### Already Fixed (Prior Rounds)
- P0 undici/fetch interception → PR #219
- P0 Ghost bundle → PR #219 (VaaS upload)
- P0 Empty policy / Observe mode → PR #220
- Spec ambiguities (all 4) → PR #218
- Passthrough mode for OAuth agents → PR #224
- Causal Sieve (HTTP parsing + git diff) → PR #223

### NEW Critical Issue: Differential Provenance (FATAL)
The GitHub App blocks PRs where a human edits a file after the agent ran,
because the content hash in the side_effect_receipt doesn't match the final
git commit. This breaks the core 2026 workflow where developers iteratively
edit AI-generated code.

**Fix:** When a file has a receipt but hash doesn't match, split the PR into:
- Lines attested by agent receipts
- Lines modified by human after agent
Report: PASS (Agent: 84 lines, Human: 3 lines modified)
Only FAIL if file has NO receipt at all (truly unattested).

### Deep Observability Architecture (Future Work)
Composite monitoring layers (no root required):
1. Causal Sieve (HTTP parsing) — what the LLM intended
2. BASH_ENV + trap DEBUG — what bash actually executed  
3. fs.watch / FSEvents / inotify — real-time file mutations
4. lsof polling — network connections
5. PATH wrappers — capture curl/wget/python/node
6. git diff at boundaries — final reconciliation

### HN Defense Points
- "API key exfiltration" → clawproxy is open-source, deploy your own
- "curl bypass" → no receipts = blocked PR, bypass guarantees failure
- "kinematic snake oil" → optional heuristic, not cryptographic guarantee

### Competitive Strategy
- Cloudflare AI Gateway: integrate as their audit layer
- Anthropic MCP: release mcp-clawsig-middleware
- GitHub Copilot: win open-source CLI agents first
