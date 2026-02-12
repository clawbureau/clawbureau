Here is the PoH enforcement strategy, tailored for the specific capabilities discovered in the provided file/help artifacts.

### 1-2. Per-Harness Playbook

#### **Global Strategy: The "Shim" vs. "Native" Divide**
The current `clawsig-adapters` shim is necessary for closed-source CLIs (Claude, Codex), but **unnecessary overhead** for extensible agents like Pi and OpenClaw.

---

### Harness 1: OpenClaw (Native)

*   **Integration Point:** Native Plugin Hook (Existing).
*   **Enforcement:**
    *   **Mechanism:** Determine the "Config Hash" by hashing the active agent configuration. If `@openclaw/provider-clawproxy` is absent, the hash changes, invalidating previous trust chains.
    *   **Golden Path Configuration:**
        1.  Configure `provider-clawproxy` as the **only** allowed provider for the `gateway` tier.
        2.  Set `enforce_clean_startup: true` in the recorder to ensure no events occur before the plugin initializes.
*   **Binding & Receipts:** Handled natively by `packages/openclaw-provider-clawproxy/src/provider.ts`. The plugin already injects `X-Run-Id`.
*   **Tool Chains:** The OpenClaw runtime emits internal events. The recorder just needs to listen.
*   **Streaming:** The current provider implementation (`provider.ts`) already handles `stream` by parsing chunks and extracting `_receipt` from the stream end. No changes needed.

---

### Harness 2: Claude Code

*   **Integration Point:** Wrapper + Env Vars + JSON Stream.
*   **Enforcement:** `clawsig-wrap claude-code`.
*   **Golden Path Configuration:**
    *   **Command:** use `--output-format=stream-json` (or `json`) and `--input-format=stream-json`.
    *   **Reasoning:** The `parseToolEvents` in `adapter/claude-code.ts` currently relies on regexing `toolPattern`. This is brittle. Using `stream-json` provides structured data.
    *   **Wrapper Logic:**
        ```bash
        # Suggested invocation
        clawsig-wrap claude-code -- claude --print --output-format=stream-json "task"
        ```
*   **Binding & Receipts:** Controlled by `shim.ts`. The adapter points `ANTHROPIC_BASE_URL` to the local shim.
*   **Tool Chains:** Switch `adapters/claude-code.ts` from regex parsing to `JSON.parse()` of the `stream-json` output chunks to capture tool inputs/outputs accurately.
*   **Streaming:**
    *   **Critical Gap:** `shim.ts` currently `await readJsonBody(req)` and sends a single JSON response. This **breaks** Claude Code's streaming features.
    *   **Fix:** `shim.ts` must become a streaming proxy. It should pipe the request to `clawproxy`, pipe the response back to Claude, and utilize a `Transform` stream to snag the `_receipt_envelope` without blocking the flow.

---

### Harness 3: Codex CLI

*   **Integration Point:** Wrapper + JSON Mode.
*   **Enforcement:** `clawsig-wrap codex`.
*   **Golden Path Configuration:**
    *   **Command:** `codex exec --json`. Use the `exec` subcommand for automation/PoH generation rather than the TUI.
    *   **Config:** Pass `--config model_provider=openai` (or compatible) via the wrapper to ensure it hits the network (and thus the proxy) rather than trying to load local models.
*   **Binding & Receipts:** `OPENAI_BASE_URL` override in `adapters/codex.ts` works correctly via the shim.
*   **Tool Chains:** The `--json` flag emits JSONL. `adapters/codex.ts` already attempts to parse JSON, but `exec --json` is the only way to guarantee this format is emitted.
*   **Streaming:** `codex exec` is generally non-streaming (waits for completion). If `codex` requests streaming, `shim.ts` update mentioned above is required.

---

### Harness 4: OpenCode

*   **Integration Point:** Wrapper + Format Flag.
*   **Enforcement:** `clawsig-wrap opencode`.
*   **Golden Path Configuration:**
    *   **Command:** `opencode run --format json`.
*   **Binding & Receipts:** `adapters/opencode.ts` overrides base URLs correctly.
*   **Tool Chains:** Switch `adapters/opencode.ts` from regex (`Tool: \w+`) to parsing the structured JSON output provided by `--format json`.

---

### Harness 5: Pi (pi-coding-agent)

*   **Integration Point:** **Custom Extension** (Replaces Shim).
*   **Enforcement:** `pi --extension ./packages/poh-pi-extension/dist/index.js`.
*   **Current Restriction:** The file `packages/clawsig-adapters/src/adapters/pi.ts` currently uses the shim.
*   **Proposed Change (High Leverage):**
    *   Pi supports `pi.registerProvider`. We should build a small TS extension that registers a provider `clawproxy`.
    *   This extension can inject `X-Run-Id` headers using the `headers` property in `registerProvider`.
    *   **Benefit:** Removes the need for the ephemeral HTTP shim server. Pi connects directly to `CLAWPROXY_BASE_URL`.
*   **Golden Path Configuration:**
    ```bash
    # No shim needed. The extension handles routing.
    pi --extension ./poh-pi.js --provider clawproxy --model claude-3-5-sonnet
    ```
*   **Binding & Receipts:**
    *   *Headers:* Injected by the extension.
    *   *Receipts:* Pi's extension API (based on `docs/custom-provider.md`) allows defining a custom `streamSimple` function. We can implement this to read the `_receipt` from the Clawproxy response body directly within the Pi process, then save it to a sidecar file that `clawsig-wrap` (running as parent) can pick up.

---

### 3. Faulty Assumptions & Corrections

1.  **Assumption:** "We need a local HTTP shim for all external CLIs."
    *   **Correction:** **Pi** has a robust Extension API that allows header injection and URL overriding natively. We should use that instead of the shim for Pi, as it's more robust against port conflicts and overhead.
2.  **Assumption:** "Regex parsing logs is sufficient for tool events."
    *   **Correction:** All tools (Claude, Codex, OpenCode) have JSON output flags. We must enforce these flags in the wrapper to guarantee 100% accurate tool call hashing. Regex is fragile and breaks the "hard to forget" goal if the output format changes slightly.
3.  **Assumption:** "The shim supports streaming."
    *   **Correction:** `packages/clawsig-adapters/src/shim.ts` uses `readJsonBody` which buffers the entire request, and `sendJson` which buffers the entire response. This **breaks** any harness that relies on Server-Sent Events (SSE) or long-polling. The shim must be rewritten to support streaming passthrough.
4.  **Assumption:** "Environment variables are enough for Base URL overrides."
    *   **Correction:** Some tools (like Pi) might default to internal provider logic if specific "provider" flags aren't set. We must strictly map the harness arguments (like `--provider`) in the wrapper to match the shimmed endpoints.

---

### 4. Compatibility Matrix & CI Plan

| Harness | Enforcement Method | Tool Capture Strategy | Binding Injection | Receipt Capture | Streaming Support |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **OpenClaw** | Native Plugin | Internal Events | Plugin Headers | Plugin (Stream-aware) | ✅ Native |
| **Claude Code** | `clawsig-wrap` | `stream-json` output | Shim | Shim | ❌ **Broken in Shim** |
| **Codex CLI** | `clawsig-wrap` | `--json` output | Shim | Shim | ⚠️ Partial (Exec only) |
| **OpenCode** | `clawsig-wrap` | `--format json` | Shim | Shim | ❌ **Broken in Shim** |
| **Pi** | `pi --extension` | Extension Event Hooks | Extension Headers | Extension (Custom Stream) | ✅ Extension API |

**CI Test Plan:**
1.  **Proof Validity:** Verify `clawverify` accepts the final bundle from all 5 harnesses.
2.  **Streaming Passthrough:** Test `Claude Code` with a large output prompting a stream; ensure the shim doesn't hang or buffer until timeout.
3.  **Tool Hash:** Run a deterministic tool use (e.g., "list current directory") and assert the `tool_call` event in the PoH bundle matches the expected hash.

---

### 5. High-Leverage Engineering Changes

1.  **Rewrite `shim.ts` for Streaming:**
    *   Modify `packages/clawsig-adapters/src/shim.ts` to use Node.js streams (`req.pipe(proxyReq)`).
    *   Implement a **PassThrough stream** for the response that buffers chunks to detect the `_receipt_envelope` (usually at the end) while simultaneously flushing data to the CLI client.

2.  **Create `@clawbureau/pi-extension`:**
    *   Drop the Shim usage for Pi.
    *   Create a simple Pi extension (see `docs/custom-provider.md`) that registers `clawproxy` as a provider and handles the PoH binding headers and receipt extraction natively.

3.  **Switch Adapters to JSON Modes:**
    *   Update `adapters/claude-code.ts` to force `--output-format=stream-json`.
    *   Update `adapters/codex.ts` to force `--json`.
    *   Update parsers to handle JSON lines instead of regex.

4.  **Auto-Config Generation:**
    *   Instead of asking users to set env vars manually, `clawsig-wrap` should automatically generate a temporary configuration file (e.g., `codex` TOML or `pi` settings) that points to the proxy, and pass that config file to the subprocess.
