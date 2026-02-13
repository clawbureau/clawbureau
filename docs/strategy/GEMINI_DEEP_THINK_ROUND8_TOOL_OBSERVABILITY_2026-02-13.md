# Gemini Deep Think Round 8: Tool Observability Crisis

> Received: 2026-02-13
> Focus: How to observe agent tool invocations without OS-level access
> Decision: Causal Sieve architecture (proxy parsing + git diff + TCP Guillotine)

## Key Findings

### OS Tracing is a Trap
- eBPF/dtrace require root - "sudo npx" = dead on arrival
- Container sandboxing kills DX (no local SSH keys, git config, IDE)
- LD_PRELOAD/DYLD_INSERT brittle (Go static binaries, macOS SIP)
- MCP MITM only covers MCP tools, not native code execution

### The Causal Sieve Architecture
1. **Deep Stream Parsing (Intent Sieve)**: Parse SSE in-flight, extract tool_calls/tool_use from LLM responses
2. **TCP Guillotine (Active Mitigation)**: Sever TCP if LLM requests blocked tool before JSON completes
3. **Temporal Diffing**: git diff between tool_call and tool_result to synthesize side_effect_receipts
4. **GitHub App Reconciliation**: PR diff minus receipts > 0 = UNATTESTED_MUTATION = block

### Honest Messaging: "Causal Intent-to-Impact Verification"
- Not "we watch everything the agent does"
- Instead: "every line of code in your PR has a cryptographic causal link to an LLM's intent"
- Files in diff without corresponding tool_receipt = blocked
- Shifts burden from "watch OS" to "verify chain of custody for code"

### Strategic Decision: Option 3 (Hybrid, launch with nuanced claim)
- Enterprises care about securing the PR, not the laptop (CrowdStrike does that)
- The PR is the enterprise boundary
- Causal Sieve + GitHub App = unreplicable moat (own gateway + CI/CD)

## Execution Mandate
1. Update local-proxy.ts to parse LLM HTTP traffic and synthesize tool_receipts
2. Update local-proxy.ts to run git diff sequentially and synthesize side_effect_receipts
3. GitHub App reconciliation already built (PR #220) - verify it works with real receipts
4. Rewrite HN post with "Causal Sieve" framing
