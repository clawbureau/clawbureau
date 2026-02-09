# PoH Harness Registry

This file is **generated** from `docs/roadmaps/proof-of-harness/harnesses.mjs`.
Edit the registry, then run `node scripts/poh/sync-harness-registry.mjs`.

## Supported / planned harnesses

| Harness | ID | Kind | Status | Connects via |
|---|---|---|---|---|
| Claude Code | `claude-code` | external-cli | supported | clawproof-adapters starts a local shim server and points `ANTHROPIC_BASE_URL` at it. |
| Codex CLI | `codex` | external-cli | supported | clawproof-adapters starts a local shim server and points `OPENAI_BASE_URL` at it. |
| Factory Droid | `factory-droid` | external-cli | planned | Planned: use clawproof-adapters shim routing (same as other external CLIs). |
| Gemini CLI | `gemini-cli` | external-cli | planned | Planned: route Google Generative AI calls through clawproxy provider=google and capture receipts in a PoH bundle. |
| OpenClaw | `openclaw` | native | supported | OpenClaw plugin patches global fetch() to route supported provider HTTP calls through `clawproxy` (`POST /v1/proxy/:provider`). |
| OpenCode | `opencode` | external-cli | supported | clawproof-adapters starts a local shim server and points provider base URLs at it. |
| Pi (pi-coding-agent) | `pi` | external-cli | experimental | clawproof-adapters starts a local shim server and points provider base URLs at it. |
| Ad-hoc scripts (clawproof SDK) | `script` | sdk | supported | `@clawbureau/clawproof-sdk` calls `clawproxy` directly and injects PoH binding headers (run/event/nonce). |

---

## Claude Code (`claude-code`)

- **Kind:** external-cli
- **Status:** supported

### Key implementations ("knows of" this harness)

- [`packages/clawproof-adapters/src/adapters/claude-code.ts`](../../../packages/clawproof-adapters/src/adapters/claude-code.ts)
- [`packages/clawproof-adapters/src/shim.ts`](../../../packages/clawproof-adapters/src/shim.ts)
- [`packages/clawproof-adapters/src/session.ts`](../../../packages/clawproof-adapters/src/session.ts)

### How it connects

- clawproof-adapters starts a local shim server and points `ANTHROPIC_BASE_URL` at it.
- Shim forwards each request to clawproxy via session.proxyLLMCall() to inject PoH binding headers + capture receipts.

### Base URL overrides

- `ANTHROPIC_BASE_URL`: <shim>/v1/anthropic

### Upstream auth

- ANTHROPIC_API_KEY (upstream provider key)

### Recommended commands

```bash
clawproof-wrap claude-code -- claude --print "fix the failing test"
```

### Best practices

- Use `--print` (non-interactive) for repeatable output and easier log capture.
- Prefer simple tool call visibility; if tool logs are not present, expect a minimal tool_call chain.
- Keep upstream provider key as `ANTHROPIC_API_KEY`; clawproof does not replace provider keys.

### Limitations

- Shim currently assumes non-streaming JSON responses; if the harness uses streaming-only flows, support may be partial.

---

## Codex CLI (`codex`)

- **Kind:** external-cli
- **Status:** supported

### Key implementations ("knows of" this harness)

- [`packages/clawproof-adapters/src/adapters/codex.ts`](../../../packages/clawproof-adapters/src/adapters/codex.ts)
- [`packages/clawproof-adapters/src/shim.ts`](../../../packages/clawproof-adapters/src/shim.ts)
- [`packages/clawproof-adapters/src/session.ts`](../../../packages/clawproof-adapters/src/session.ts)

### How it connects

- clawproof-adapters starts a local shim server and points `OPENAI_BASE_URL` at it.
- Shim extracts upstream key from Authorization and forwards to clawproxy as X-Provider-API-Key.

### Base URL overrides

- `OPENAI_BASE_URL`: <shim>/v1/openai

### Upstream auth

- OPENAI_API_KEY (upstream provider key)

### Recommended commands

```bash
clawproof-wrap codex -- codex exec --json "implement the feature"
```

### Best practices

- Use `codex exec --json` to emit JSONL events; clawproof can extract tool_call events best-effort.
- If you see streaming-related errors, try non-interactive subcommands (exec/review) rather than the interactive TUI.

### Limitations

- Tool-call parsing is currently heuristic and may miss events depending on Codex output format.

---

## Factory Droid (`factory-droid`)

- **Kind:** external-cli
- **Status:** planned

### Key implementations ("knows of" this harness)

- [`packages/clawproof-adapters/src/adapters/factory-droid.ts`](../../../packages/clawproof-adapters/src/adapters/factory-droid.ts)
- [`packages/clawproof-adapters/src/shim.ts`](../../../packages/clawproof-adapters/src/shim.ts)
- [`packages/clawproof-adapters/src/session.ts`](../../../packages/clawproof-adapters/src/session.ts)

### How it connects

- Planned: use clawproof-adapters shim routing (same as other external CLIs).

### Base URL overrides

- `ANTHROPIC_BASE_URL`: <shim>/v1/anthropic
- `OPENAI_BASE_URL`: <shim>/v1/openai

### Upstream auth

- ANTHROPIC_API_KEY / OPENAI_API_KEY

### Recommended commands

```bash
clawproof-wrap factory-droid -- factory-droid run --task "build feature"
```

### Best practices

- Emit structured JSON logs for tool calls so tool_call extraction is reliable.

### Limitations

- No reference harness binary is bundled in this repo; adapter support is best-effort until we add a real integration test.

---

## Gemini CLI (`gemini-cli`)

- **Kind:** external-cli
- **Status:** planned

### Key implementations ("knows of" this harness)

- [`services/clawproxy/src/providers.ts`](../../../services/clawproxy/src/providers.ts)

### How it connects

- Planned: route Google Generative AI calls through clawproxy provider=google and capture receipts in a PoH bundle.

### Base URL overrides

- `(unknown)`: Need research: which env vars/flags control Gemini CLI base URL

### Upstream auth

- GEMINI_API_KEY (likely)

### Recommended commands

```bash
# TODO: add a clawproof-adapters harness adapter once we confirm Gemini CLI base URL override behavior.
```

### Best practices

- Prefer deterministic model IDs (e.g. models/gemini-*) so clawproxy can build the correct Google URL.

### Limitations

- No adapter implementation yet.

---

## OpenClaw (`openclaw`)

- **Kind:** native
- **Status:** supported

### Key implementations ("knows of" this harness)

- [`packages/openclaw-provider-clawproxy/openclaw.plugin.json`](../../../packages/openclaw-provider-clawproxy/openclaw.plugin.json)
- [`packages/openclaw-provider-clawproxy/src/openclaw.ts`](../../../packages/openclaw-provider-clawproxy/src/openclaw.ts)
- [`packages/openclaw-provider-clawproxy/src/recorder.ts`](../../../packages/openclaw-provider-clawproxy/src/recorder.ts)
- [`services/clawproxy/src/index.ts`](../../../services/clawproxy/src/index.ts)
- [`services/clawverify/src/verify-proof-bundle.ts`](../../../services/clawverify/src/verify-proof-bundle.ts)

### How it connects

- OpenClaw plugin patches global fetch() to route supported provider HTTP calls through `clawproxy` (`POST /v1/proxy/:provider`).
- Plugin hooks allocate `run_id`, emit an event chain, inject PoH binding headers per call, capture receipts (JSON or SSE trailer; streaming fallback recovers via `GET /v1/receipt/:nonce` without full-body replay), compute prompt commitments, generate URM + Trust Pulse, and sign the proof bundle.

### Base URL overrides

- `plugins.entries.provider-clawproxy.config.baseUrl`: clawproxy base URL (e.g. https://clawproxy.com)
- `plugins.entries.provider-clawproxy.config.token`: optional CST/JWT for proxy auth (platform-paid mode)

### Upstream auth

- BYOK: user/provider key passed via OpenClaw auth context (plugin forwards via X-Provider-API-Key)
- Platform-paid: CST/JWT via Authorization + X-Client-DID (clawproxy)

### Recommended commands

```bash
openclaw plugins install @openclaw/provider-clawproxy
openclaw plugins enable provider-clawproxy
# Configure in openclaw.json:
# plugins.entries["provider-clawproxy"].config.baseUrl = "https://clawproxy.com"
# plugins.entries["provider-clawproxy"].config.mode = "enforce"
```

### Best practices

- Enable the OpenClaw `provider-clawproxy` plugin so PoH binding headers are injected per LLM call (and calls cannot silently bypass receipts).
- Ensure clawproxy emits canonical `_receipt_envelope` and clawverify is configured with an allowlist (`GATEWAY_RECEIPT_SIGNER_DIDS`).
- For `gateway` tier, require receipts to be bound to the event chain (enforced by clawverify; POH-US-010).
- Compute a meaningful harness `config_hash_b64u` (tool policy, provider plugins, model routing, sandbox mode).

### Limitations

- Intercepts only strict upstream endpoints by default (api.openai.com chat completions, api.anthropic.com messages; Gemini optional). OpenAI-compatible third-party baseUrls are intentionally NOT proxied.
- OpenAI Responses API (`/v1/responses`) is supported via clawproxy; ensure provider URL selection / compat routing is enabled so these calls receive gateway receipts.
- OpenClaw harness metadata is informative but NOT a trust tier by itself; tier is derived from verified receipts/attestations.

---

## OpenCode (`opencode`)

- **Kind:** external-cli
- **Status:** supported

### Key implementations ("knows of" this harness)

- [`packages/clawproof-adapters/src/adapters/opencode.ts`](../../../packages/clawproof-adapters/src/adapters/opencode.ts)
- [`packages/clawproof-adapters/src/shim.ts`](../../../packages/clawproof-adapters/src/shim.ts)
- [`packages/clawproof-adapters/src/session.ts`](../../../packages/clawproof-adapters/src/session.ts)

### How it connects

- clawproof-adapters starts a local shim server and points provider base URLs at it.
- Shim forwards to clawproxy with PoH binding headers and captures `_receipt_envelope`.

### Base URL overrides

- `ANTHROPIC_BASE_URL`: <shim>/v1/anthropic
- `OPENAI_BASE_URL`: <shim>/v1/openai

### Upstream auth

- ANTHROPIC_API_KEY and/or OPENAI_API_KEY (depending on provider/model)

### Recommended commands

```bash
clawproof-wrap opencode -- opencode run --format json "refactor module"
```

### Best practices

- Use `opencode run --format json` for machine-readable tool call extraction.
- Prefer running a single provider family per run (avoid ambiguous routing if the harness mixes providers).

### Limitations

- Some OpenCode configurations may route via custom providers not covered by shim inference (openai/anthropic/google only).

---

## Pi (pi-coding-agent) (`pi`)

- **Kind:** external-cli
- **Status:** experimental

### Key implementations ("knows of" this harness)

- [`packages/clawproof-adapters/src/adapters/pi.ts`](../../../packages/clawproof-adapters/src/adapters/pi.ts)
- [`packages/clawproof-adapters/src/shim.ts`](../../../packages/clawproof-adapters/src/shim.ts)
- [`packages/clawproof-adapters/src/session.ts`](../../../packages/clawproof-adapters/src/session.ts)
- [`scripts/ralph/ralph.sh`](../../../scripts/ralph/ralph.sh)

### How it connects

- clawproof-adapters starts a local shim server and points provider base URLs at it.
- Shim forwards to clawproxy with PoH binding headers and captures receipts.

### Base URL overrides

- `ANTHROPIC_BASE_URL`: <shim>/v1/anthropic
- `OPENAI_BASE_URL`: <shim>/v1/openai

### Upstream auth

- ANTHROPIC_API_KEY / OPENAI_API_KEY (depending on provider)

### Recommended commands

```bash
clawproof-wrap pi -- pi -p "run the tests"
```

### Best practices

- Use `-p/--print` for non-interactive runs; prefer a single provider per run when possible.
- If you use custom providers via Pi extensions/models.json, ensure their baseUrl is also pointed at the shim.

### Limitations

- Pi providers often use streaming APIs; shim streaming support is currently limited, so compatibility may vary by provider/model.

---

## Ad-hoc scripts (clawproof SDK) (`script`)

- **Kind:** sdk
- **Status:** supported

### Key implementations ("knows of" this harness)

- [`packages/clawproof-sdk/src/run.ts`](../../../packages/clawproof-sdk/src/run.ts)
- [`services/clawproxy/src/index.ts`](../../../services/clawproxy/src/index.ts)
- [`services/clawverify/src/verify-proof-bundle.ts`](../../../services/clawverify/src/verify-proof-bundle.ts)

### How it connects

- `@clawbureau/clawproof-sdk` calls `clawproxy` directly and injects PoH binding headers (run/event/nonce).
- SDK collects `_receipt_envelope`, builds URM + event chain, and signs a proof bundle with an agent DID key.

### Base URL overrides

- `(sdk config)`: proxyBaseUrl passed to createRun({ proxyBaseUrl })

### Upstream auth

- Upstream provider key via headers (recommended: X-Provider-API-Key).
- Optional proxy auth via Authorization: Bearer <CST/JWT> (platform-paid mode).

### Recommended commands

```bash
# Programmatic (Node): use @clawbureau/clawproof-sdk createRun() + callLLM() + finalize()
```

### Best practices

- Always call via SDK helpers so receipts include binding.run_id + binding.event_hash_b64u.
- Avoid putting upstream provider keys in Authorization when you also need CST in Authorization (use X-Provider-API-Key).
- Record at least: run_start, llm_call, tool_call (if any), artifact_written, run_end.

### Limitations

- If you bypass callLLM()/proxyLLMCall() and hit providers directly, you lose gateway receipts and drop to self tier.

---

