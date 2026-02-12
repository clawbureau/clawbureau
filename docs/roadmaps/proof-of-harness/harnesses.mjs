/**
 * Proof-of-Harness (PoH) Harness Registry
 *
 * This file is the canonical list of harnesses we recognize in PoH metadata.
 * It serves the same role as vercel-labs/skills `src/agents.ts`: one place
 * that "knows about" all supported harness IDs + how they connect.
 *
 * Update this file, then run:
 *   node scripts/poh/sync-harness-registry.mjs
 */

/**
 * @typedef {Object} HarnessEntry
 * @property {string} id PoH harness identifier (metadata.harness.id)
 * @property {string} displayName Human-friendly name
 * @property {'native'|'external-cli'|'sdk'} kind
 * @property {'supported'|'experimental'|'planned'} status
 * @property {string[]} knowsOfFiles Repo files that implement this harness integration
 * @property {string[]} connectsVia One-liner bullets describing how it routes through clawproxy + emits PoH artifacts
 * @property {string[]} recommendedCommands Example invocations (best-effort)
 * @property {Record<string,string>} baseUrlOverrides Env vars / config keys used to override provider base URLs
 * @property {string[]} upstreamAuth Typical upstream auth inputs for the harness (env vars / flags)
 * @property {string[]} bestPractices Operator guidance to maximize PoH quality
 * @property {string[]} limitations Known gaps / caveats
 */

/** @type {HarnessEntry[]} */
export const harnesses = [
  {
    id: 'openclaw',
    displayName: 'OpenClaw',
    kind: 'native',
    status: 'supported',
    knowsOfFiles: [
      'packages/openclaw-provider-clawproxy/openclaw.plugin.json',
      'packages/openclaw-provider-clawproxy/src/openclaw.ts',
      'packages/openclaw-provider-clawproxy/src/recorder.ts',
      'services/clawproxy/src/index.ts',
      'services/clawverify/src/verify-proof-bundle.ts',
    ],
    connectsVia: [
      'OpenClaw plugin patches global fetch() to route supported provider HTTP calls through `clawproxy` (`POST /v1/proxy/:provider`).',
      'Plugin hooks allocate `run_id`, emit an event chain, inject PoH binding headers per call, capture receipts (JSON or SSE trailer; streaming fallback recovers via `GET /v1/receipt/:nonce` without full-body replay), compute prompt commitments, generate URM + Trust Pulse, and sign the proof bundle.',
    ],
    recommendedCommands: [
      'openclaw plugins install @openclaw/provider-clawproxy',
      'openclaw plugins enable provider-clawproxy',
      '# Configure in openclaw.json:',
      '# plugins.entries["provider-clawproxy"].config.baseUrl = "https://clawproxy.com"',
      '# plugins.entries["provider-clawproxy"].config.mode = "enforce"',
    ],
    baseUrlOverrides: {
      'plugins.entries.provider-clawproxy.config.baseUrl': 'clawproxy base URL (e.g. https://clawproxy.com)',
      'plugins.entries.provider-clawproxy.config.token': 'optional CST/JWT for proxy auth (platform-paid mode)',
    },
    upstreamAuth: [
      'BYOK: user/provider key passed via OpenClaw auth context (plugin forwards via X-Provider-API-Key)',
      'Platform-paid: CST/JWT via Authorization + X-Client-DID (clawproxy)',
    ],
    bestPractices: [
      'Enable the OpenClaw `provider-clawproxy` plugin so PoH binding headers are injected per LLM call (and calls cannot silently bypass receipts).',
      'Ensure clawproxy emits canonical `_receipt_envelope` and clawverify is configured with an allowlist (`GATEWAY_RECEIPT_SIGNER_DIDS`).',
      'For `gateway` tier, require receipts to be bound to the event chain (enforced by clawverify; POH-US-010).',
      'Compute a meaningful harness `config_hash_b64u` (tool policy, provider plugins, model routing, sandbox mode).',
    ],
    limitations: [
      'Intercepts only strict upstream endpoints by default (api.openai.com chat completions, api.anthropic.com messages; Gemini optional). OpenAI-compatible third-party baseUrls are intentionally NOT proxied.',
      'OpenAI Responses API (`/v1/responses`) is supported via clawproxy; ensure provider URL selection / compat routing is enabled so these calls receive gateway receipts.',
      'OpenClaw harness metadata is informative but NOT a trust tier by itself; tier is derived from verified receipts/attestations.',
    ],
  },

  {
    id: 'script',
    displayName: 'Ad-hoc scripts (clawsig SDK)',
    kind: 'sdk',
    status: 'supported',
    knowsOfFiles: [
      'packages/clawsig-sdk/src/run.ts',
      'services/clawproxy/src/index.ts',
      'services/clawverify/src/verify-proof-bundle.ts',
    ],
    connectsVia: [
      '`@clawbureau/clawsig-sdk` calls `clawproxy` directly and injects PoH binding headers (run/event/nonce).',
      'SDK collects `_receipt_envelope`, builds URM + event chain, and signs a proof bundle with an agent DID key.',
    ],
    recommendedCommands: [
      '# Programmatic (Node): use @clawbureau/clawsig-sdk createRun() + callLLM() + finalize()',
    ],
    baseUrlOverrides: {
      '(sdk config)': 'proxyBaseUrl passed to createRun({ proxyBaseUrl })',
    },
    upstreamAuth: [
      'Upstream provider key via headers (recommended: X-Provider-API-Key).',
      'Optional proxy auth via Authorization: Bearer <CST/JWT> (platform-paid mode).',
    ],
    bestPractices: [
      'Always call via SDK helpers so receipts include binding.run_id + binding.event_hash_b64u.',
      'Avoid putting upstream provider keys in Authorization when you also need CST in Authorization (use X-Provider-API-Key).',
      'Record at least: run_start, llm_call, tool_call (if any), artifact_written, run_end.',
    ],
    limitations: [
      'If you bypass callLLM()/proxyLLMCall() and hit providers directly, you lose gateway receipts and drop to self tier.',
    ],
  },

  {
    id: 'claude-code',
    displayName: 'Claude Code',
    kind: 'external-cli',
    status: 'supported',
    knowsOfFiles: [
      'packages/clawsig-adapters/src/adapters/claude-code.ts',
      'packages/clawsig-adapters/src/shim.ts',
      'packages/clawsig-adapters/src/session.ts',
    ],
    connectsVia: [
      'clawsig-adapters starts a local shim server and points `ANTHROPIC_BASE_URL` at it.',
      'Shim forwards each request to clawproxy via session.proxyLLMCall() to inject PoH binding headers + capture receipts.',
    ],
    recommendedCommands: [
      'clawsig-wrap claude-code -- claude --print "fix the failing test"',
    ],
    baseUrlOverrides: {
      ANTHROPIC_BASE_URL: '<shim>/v1/anthropic',
    },
    upstreamAuth: [
      'ANTHROPIC_API_KEY (upstream provider key)',
    ],
    bestPractices: [
      'Use `--print` (non-interactive) for repeatable output and easier log capture.',
      'Prefer simple tool call visibility; if tool logs are not present, expect a minimal tool_call chain.',
      'Keep upstream provider key as `ANTHROPIC_API_KEY`; clawsig does not replace provider keys.',
    ],
    limitations: [
      'Shim currently assumes non-streaming JSON responses; if the harness uses streaming-only flows, support may be partial.',
    ],
  },

  {
    id: 'codex',
    displayName: 'Codex CLI',
    kind: 'external-cli',
    status: 'supported',
    knowsOfFiles: [
      'packages/clawsig-adapters/src/adapters/codex.ts',
      'packages/clawsig-adapters/src/shim.ts',
      'packages/clawsig-adapters/src/session.ts',
    ],
    connectsVia: [
      'clawsig-adapters starts a local shim server and points `OPENAI_BASE_URL` at it.',
      'Shim extracts upstream key from Authorization and forwards to clawproxy as X-Provider-API-Key.',
    ],
    recommendedCommands: [
      'clawsig-wrap codex -- codex exec --json "implement the feature"',
    ],
    baseUrlOverrides: {
      OPENAI_BASE_URL: '<shim>/v1/openai',
    },
    upstreamAuth: [
      'OPENAI_API_KEY (upstream provider key)',
    ],
    bestPractices: [
      'Use `codex exec --json` to emit JSONL events; clawsig can extract tool_call events best-effort.',
      'If you see streaming-related errors, try non-interactive subcommands (exec/review) rather than the interactive TUI.',
    ],
    limitations: [
      'Tool-call parsing is currently heuristic and may miss events depending on Codex output format.',
    ],
  },

  {
    id: 'opencode',
    displayName: 'OpenCode',
    kind: 'external-cli',
    status: 'supported',
    knowsOfFiles: [
      'packages/clawsig-adapters/src/adapters/opencode.ts',
      'packages/clawsig-adapters/src/shim.ts',
      'packages/clawsig-adapters/src/session.ts',
    ],
    connectsVia: [
      'clawsig-adapters starts a local shim server and points provider base URLs at it.',
      'Shim forwards to clawproxy with PoH binding headers and captures `_receipt_envelope`.',
    ],
    recommendedCommands: [
      'clawsig-wrap opencode -- opencode run --format json "refactor module"',
    ],
    baseUrlOverrides: {
      ANTHROPIC_BASE_URL: '<shim>/v1/anthropic',
      OPENAI_BASE_URL: '<shim>/v1/openai',
    },
    upstreamAuth: [
      'ANTHROPIC_API_KEY and/or OPENAI_API_KEY (depending on provider/model)',
    ],
    bestPractices: [
      'Use `opencode run --format json` for machine-readable tool call extraction.',
      'Prefer running a single provider family per run (avoid ambiguous routing if the harness mixes providers).',
    ],
    limitations: [
      'Some OpenCode configurations may route via custom providers not covered by shim inference (openai/anthropic/google only).',
    ],
  },

  {
    id: 'pi',
    displayName: 'Pi (pi-coding-agent)',
    kind: 'external-cli',
    status: 'experimental',
    knowsOfFiles: [
      'packages/clawsig-adapters/src/adapters/pi.ts',
      'packages/clawsig-adapters/src/shim.ts',
      'packages/clawsig-adapters/src/session.ts',
      'scripts/ralph/ralph.sh',
    ],
    connectsVia: [
      'clawsig-adapters starts a local shim server and points provider base URLs at it.',
      'Shim forwards to clawproxy with PoH binding headers and captures receipts.',
    ],
    recommendedCommands: [
      'clawsig-wrap pi -- pi -p "run the tests"',
    ],
    baseUrlOverrides: {
      ANTHROPIC_BASE_URL: '<shim>/v1/anthropic',
      OPENAI_BASE_URL: '<shim>/v1/openai',
    },
    upstreamAuth: [
      'ANTHROPIC_API_KEY / OPENAI_API_KEY (depending on provider)',
    ],
    bestPractices: [
      'Use `-p/--print` for non-interactive runs; prefer a single provider per run when possible.',
      'If you use custom providers via Pi extensions/models.json, ensure their baseUrl is also pointed at the shim.',
    ],
    limitations: [
      'Pi providers often use streaming APIs; shim streaming support is currently limited, so compatibility may vary by provider/model.',
    ],
  },

  {
    id: 'factory-droid',
    displayName: 'Factory Droid',
    kind: 'external-cli',
    status: 'planned',
    knowsOfFiles: [
      'packages/clawsig-adapters/src/adapters/factory-droid.ts',
      'packages/clawsig-adapters/src/shim.ts',
      'packages/clawsig-adapters/src/session.ts',
    ],
    connectsVia: [
      'Planned: use clawsig-adapters shim routing (same as other external CLIs).',
    ],
    recommendedCommands: [
      'clawsig-wrap factory-droid -- factory-droid run --task "build feature"',
    ],
    baseUrlOverrides: {
      ANTHROPIC_BASE_URL: '<shim>/v1/anthropic',
      OPENAI_BASE_URL: '<shim>/v1/openai',
    },
    upstreamAuth: [
      'ANTHROPIC_API_KEY / OPENAI_API_KEY',
    ],
    bestPractices: [
      'Emit structured JSON logs for tool calls so tool_call extraction is reliable.',
    ],
    limitations: [
      'No reference harness binary is bundled in this repo; adapter support is best-effort until we add a real integration test.',
    ],
  },

  {
    id: 'gemini-cli',
    displayName: 'Gemini CLI',
    kind: 'external-cli',
    status: 'planned',
    knowsOfFiles: [
      'services/clawproxy/src/providers.ts',
    ],
    connectsVia: [
      'Planned: route Google Generative AI calls through clawproxy provider=google and capture receipts in a PoH bundle.',
    ],
    recommendedCommands: [
      '# TODO: add a clawsig-adapters harness adapter once we confirm Gemini CLI base URL override behavior.',
    ],
    baseUrlOverrides: {
      '(unknown)': 'Need research: which env vars/flags control Gemini CLI base URL',
    },
    upstreamAuth: [
      'GEMINI_API_KEY (likely)',
    ],
    bestPractices: [
      'Prefer deterministic model IDs (e.g. models/gemini-*) so clawproxy can build the correct Google URL.',
    ],
    limitations: [
      'No adapter implementation yet.',
    ],
  },
];

export default harnesses;
