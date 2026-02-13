# Gemini Deep Think Round 11: The Endgame Architecture

> Received: 2026-02-13
> Focus: Launch sequence, supply-side blitz, competitive defense, revenue, honest assessment

## Key Numbers
- **Probability of market relevance in 12 months: 15%**
- **Biggest mistake: The Agent Economy marketplace distraction**
- **Single decision to increase probability: Partner with Vanta/Drata**
- **Revenue wedge: Private Mode ($49/mo) — don't publish receipts to public ledger**
- **Meter: Verified PRs (the value moment), not receipts/bundles**
- **Cloudflare deadline: 60 days before they add Ed25519 to AI Gateway**

## Launch Day (72h Sequence)
1. H0-4: Deploy all services, publish npm, make express-demo public, GitHub App public
2. H4-8: HN post with prompt injection demo (blocked curl exfiltration)
3. H8-24: TROUBLESHOOTING.md for SSL/VPN/Windows issues
4. H24-48: D1 write contention — need Queue batching for RT Log
5. H48-72: Contributor onboarding with good-first-issue templates

## HN Post
- Title: "Show HN: Don't trust your AI agent. Verify it. (CF Workers + Ed25519)"
- Link: The express-demo PR showing blocked network egress
- Hook: Prompt injection hidden in HTML comment, agent curls .env to remote server

## Supply-Side (8 Frameworks)
- cline: Env var injection via VS Code setting
- aider: OPENAI_API_BASE through litellm
- OpenHands: Mount sentinel-shell.sh into Docker
- crewAI: Delegation hook on execute_task
- langchain: Native BaseCallbackHandler
- autogen: OpenAIWrapper.create middleware
- browser-use: Playwright page.route interception
- vercel/ai: wrapClawsig(model) middleware

## MCP Middleware
- Wrap MCP Server Transport (not client)
- Stdio: shim intercepts stdin/stdout JSON-RPC
- SSE: reverse proxy between agent and MCP server
- Inject receipt into _meta.clawsig_receipt field
- Command: npx clawsig mcp-wrap -- npx @modelcontextprotocol/server-postgres

## Revenue
- Free: 100 PRs/mo, public RT Log
- Pro: $49/mo, 500 private PRs, Private Mode
- Enterprise: $999/mo, custom WPC, Sentinel, SOC2
- Never fail-closed on billing (NEUTRAL check + FOMO)
- Meter verified PRs, not receipts

## Competitive Defense
- GitHub Copilot Verified (9/10): We verify causality, not authorship
- Anthropic native signing (8/10): They can't see bash/filesystem
- OpenAI tool attestation (7/10): Same — they own M, we own MTS
- YC clone (4/10): Compliance is the moat, not crypto
- KPoM flaw (5/10): Always was a heuristic, core signatures still hold

## VC Gut Reaction
"Brilliant core insight. Masterful execution. Unfocused founders.
Fund the security protocol on the condition they delete the marketplace."
