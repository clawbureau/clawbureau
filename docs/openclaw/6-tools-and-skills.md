Menu

## Tools and Skills

Relevant source files
- [.npmrc](https://github.com/openclaw/openclaw/blob/bf6ec64f/.npmrc)
- [CHANGELOG.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/CHANGELOG.md)
- [README.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md)
- [assets/avatar-placeholder.svg](https://github.com/openclaw/openclaw/blob/bf6ec64f/assets/avatar-placeholder.svg)
- [docs/gateway/configuration-examples.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/configuration-examples.md)
- [docs/gateway/configuration.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/configuration.md)
- [docs/gateway/sandbox-vs-tool-policy-vs-elevated.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/sandbox-vs-tool-policy-vs-elevated.md)
- [docs/gateway/sandboxing.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/sandboxing.md)
- [docs/multi-agent-sandbox-tools.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/multi-agent-sandbox-tools.md)
- [docs/tools/elevated.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/tools/elevated.md)
- [docs/tools/index.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/tools/index.md)
- [extensions/memory-core/package.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/extensions/memory-core/package.json)
- [package.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json)
- [pnpm-lock.yaml](https://github.com/openclaw/openclaw/blob/bf6ec64f/pnpm-lock.yaml)
- [pnpm-workspace.yaml](https://github.com/openclaw/openclaw/blob/bf6ec64f/pnpm-workspace.yaml)
- [scripts/clawtributors-map.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/clawtributors-map.json)
- [scripts/update-clawtributors.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/update-clawtributors.ts)
- [scripts/update-clawtributors.types.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/update-clawtributors.types.ts)
- [src/agents/bash-tools.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/bash-tools.ts)
- [src/agents/pi-embedded-helpers.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-helpers.ts)
- [src/agents/pi-embedded-runner-extraparams.live.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner-extraparams.live.test.ts)
- [src/agents/pi-embedded-runner-extraparams.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner-extraparams.test.ts)
- [src/agents/pi-embedded-runner.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner.ts)
- [src/agents/pi-embedded-subscribe.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-subscribe.ts)
- [src/agents/pi-tools.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-tools.ts)
- [src/agents/sandbox.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/sandbox.ts)
- [src/config/types.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/types.ts)
- [src/config/zod-schema.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/zod-schema.ts)
- [src/index.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/index.ts)
- [ui/package.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/ui/package.json)
- [ui/src/styles.css](https://github.com/openclaw/openclaw/blob/bf6ec64f/ui/src/styles.css)
- [ui/src/styles/layout.mobile.css](https://github.com/openclaw/openclaw/blob/bf6ec64f/ui/src/styles/layout.mobile.css)

This page documents OpenClaw's **tool system** (agent-invokable capabilities) and **skills system** (prompt-injected usage guidance). Tools are the executable actions agents can take (exec, read, browser, etc.), while skills provide structured documentation and examples that help agents use tools effectively.

**Related pages:**

- For sandbox configuration that controls where tools execute, see [Sandboxing](https://deepwiki.com/openclaw/openclaw/6.2-tool-security-and-sandboxing)
- For exec approval workflows and security policies, see [Tool Security and Sandboxing](https://deepwiki.com/openclaw/openclaw/6.2-tool-security-and-sandboxing)
- For skill management commands and workspace organization, see [Skills System](https://deepwiki.com/openclaw/openclaw/6.3-skills-system)

---

## Tool System Overview

OpenClaw provides **first-class agent tools** exposed directly to model providers via structured schemas. Tools replace legacy `openclaw-*` skills with typed, validated capabilities. The agent receives tool schemas in its system prompt and invokes them through the model provider's tool-calling protocol.

**Tool categories:**

- **Runtime**: `exec`, `process` - execute shell commands and manage background processes
- **Filesystem**: `read`, `write`, `edit`, `apply_patch` - file operations
- **Sessions**: `sessions_list`, `sessions_history`, `sessions_send`, `sessions_spawn`, `session_status` - cross-session coordination
- **Memory**: `memory_search`, `memory_get` - vector/BM25 hybrid search over workspace files
- **Web**: `web_search`, `web_fetch` - Brave Search API and content extraction
- **UI**: `browser`, `canvas` - browser control (CDP) and visual workspace (A2UI)
- **Automation**: `cron`, `gateway` - scheduled tasks and gateway management
- **Messaging**: `message` - send messages via configured channels
- **Nodes**: `nodes` - invoke device-local capabilities (camera, screen, system commands)
- **Channel-specific**: `slack`, `discord`, etc. - platform-native actions
- **Plugin tools**: optional tools from extensions like `lobster`, `llm-task`

**Tool registration:** Tools are assembled by `createOpenClawCodingTools` in [src/agents/pi-tools.ts 152-367](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-tools.ts#L152-L367) which combines:

- Base coding tools from `@mariozechner/pi-coding-agent` (read, write, edit)
- `createExecTool` and `createProcessTool` from [src/agents/bash-tools.ts 1-10](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/bash-tools.ts#L1-L10)
- `createOpenClawTools` for OpenClaw-specific capabilities (browser, canvas, nodes, etc.)
- Channel agent tools from `listChannelAgentTools`
- Plugin tools from loaded extensions

**Sources:**

- [docs/tools/index.md 1-220](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/tools/index.md#L1-L220)
- [src/agents/pi-tools.ts 152-367](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-tools.ts#L152-L367)
- [README.md 122-125](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md#L122-L125)

---

## Tool Registration and Policy Resolution

```
Final Tool SetPolicy ApplicationTool Creation PipelineOpenClawConfig
agents.defaults.toolsSession Key
(main vs non-main)Model Provider
(anthropic, openai, etc)resolveEffectiveToolPolicy
src/agents/pi-tools.policy.tsresolveGroupToolPolicy
channel + sender policiesresolveSubagentToolPolicy
spawned session rulescreateOpenClawCodingTools
src/agents/pi-tools.ts:152codingTools
@mariozechner/pi-coding-agentcreateExecTool
bash-tools.exec.tscreateProcessTool
bash-tools.process.tscreateOpenClawTools
agents/openclaw-tools.tslistChannelAgentTools
agents/channel-tools.tsPlugin tools
via plugin-sdktools.allow
tools.deny
tools.profiletools.byProvider
provider-specific restrictionsagents.list[].tools
per-agent overridesPer-channel/sender
group tool policiessandbox.tools
sandbox restrictionsfilterToolsByPolicy
src/agents/pi-tools.policy.tsexpandPolicyWithPluginGroups
group:* expansionAnyAgentTool[]
sent to model providerJSON schemas
for model request
```

**Tool policy precedence (most restrictive wins):**

1. `tools.profile` or `tools.byProvider[provider].profile` - base allowlist
2. Agent-specific `agents.list[].tools.profile` override
3. Global `tools.allow` / `tools.deny`
4. Provider-specific `tools.byProvider[provider].allow` / `tools.byProvider[provider].deny`
5. Agent-specific `agents.list[].tools.allow` / `agents.list[].tools.deny`
6. Group-level policies (per channel/sender in [src/agents/pi-tools.policy.ts 162-207](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-tools.policy.ts#L162-L207))
7. Sandbox tool restrictions (`sandbox.tools.allow` / `sandbox.tools.deny`)
8. Subagent restrictions (when `sessionKey` indicates spawned session)

**Policy types:**

- `tools.profile`: `"minimal"` (session\_status only), `"coding"` (fs + runtime + sessions + memory), `"messaging"` (message + sessions), `"full"` (no restrictions)
- `tools.allow` / `tools.deny`: explicit tool name lists, supports wildcards (`"*"`) and tool groups (`"group:fs"`, `"group:runtime"`, etc.)
- `tools.byProvider`: narrows global policy for specific providers or `provider/model` combinations
- `tools.alsoAllow`: additive allowlist when using profiles (doesn't replace profile baseline)

**Sources:**

- [src/agents/pi-tools.ts 154-211](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-tools.ts#L154-L211)
- [src/agents/pi-tools.policy.ts 1-207](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-tools.policy.ts#L1-L207)
- [docs/tools/index.md 16-127](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/tools/index.md#L16-L127)
- [docs/gateway/configuration.md 1-1500](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/configuration.md#L1-L1500)

---

## Tool Execution Pipeline

```
"Approval Systemtools.exec.ask""Host System(gateway or node)""Docker Container(if sandboxed)""Sandbox ContextresolveSandboxContext""exec toolcreateExecTool""Tool HandlersubscribeEmbeddedPiSession""Model Provider(Anthropic/OpenAI/etc)""Tool SelectionfilterToolsByPolicy""Agent RuntimerunEmbeddedPiAgent""Approval Systemtools.exec.ask""Host System(gateway or node)""Docker Container(if sandboxed)""Sandbox ContextresolveSandboxContext""exec toolcreateExecTool""Tool HandlersubscribeEmbeddedPiSession""Model Provider(Anthropic/OpenAI/etc)""Tool SelectionfilterToolsByPolicy""Agent RuntimerunEmbeddedPiAgent"alt[Approval required]alt[Approved or not needed][Denied]alt[Sandboxed + not elevated][Host execution (elevated or not sandboxed)]createOpenClawCodingTools(config, sessionKey, modelProvider)resolveEffectiveToolPolicy(global + agent + provider)resolveGroupToolPolicy(channel + sender)filterToolsByPolicy(tools, policies)AnyAgentToolStream request(messages, tools, system prompt)tool_call event(name: "exec", params)Tool invocation(command, host, security, ask)Resolve execution context(session sandboxed?)Execute in container(sandbox.containerName)stdout, stderr, exitCodeCheck approval rules(security: deny|allowlist|full)Prompt user(send approval request)Approval response(approve/deny)Execute command(gateway or node)stdout, stderr, exitCodePermission deniedTool result(success/error + output)Continue with result(next turn)Assistant response(text or more tool calls)
```

**Execution context resolution:**[src/agents/sandbox/context.ts 1-100](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/sandbox/context.ts#L1-L100) determines where tools run:

- `sandbox.mode: "off"` → all tools run on host
- `sandbox.mode: "non-main"` → non-main sessions run in Docker
- `sandbox.mode: "all"` → all sessions run in Docker
- `tools.elevated` gate → allowed sessions can override to host with `/elevated on`

**Exec tool host selection:**[src/agents/bash-tools.exec.ts 1-600](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/bash-tools.exec.ts#L1-L600) resolves `host` parameter:

- `host: "sandbox"` → use sandbox container (if available)
- `host: "gateway"` → run on gateway host (requires elevated mode if sandboxed)
- `host: "node"` → invoke on paired device via `node.invoke` protocol

**Approval flow:**[src/agents/bash-tools.exec.ts 200-400](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/bash-tools.exec.ts#L200-L400) checks `tools.exec.ask`:

- `ask: "off"` → no prompts
- `ask: "on-miss"` → prompt if not in allowlist
- `ask: "always"` → prompt every command
- Allowlists stored in `~/.openclaw/exec-approvals.json` per agent

**Sources:**

- [src/agents/pi-tools.ts 152-367](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-tools.ts#L152-L367)
- [src/agents/bash-tools.ts 1-10](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/bash-tools.ts#L1-L10)
- [src/agents/sandbox/context.ts 1-100](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/sandbox/context.ts#L1-L100)
- [docs/gateway/sandboxing.md 1-150](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/sandboxing.md#L1-L150)
- [docs/tools/elevated.md 1-50](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/tools/elevated.md#L1-L50)

---

## Built-in Tool Inventory

### Runtime Tools

**`exec`** - Execute shell commands

- Core parameters: `command`, `yieldMs`, `background`, `timeout`, `elevated`, `host`, `security`, `ask`, `node`, `pty`
- Returns `status: "running"` with `sessionId` when backgrounded
- Requires `process` tool for background support (otherwise runs synchronously)
- `elevated` flag runs on host when sandboxed (gated by `tools.elevated` policy)
- `host` parameter: `"sandbox"` (default if sandboxed), `"gateway"` (host), `"node"` (paired device)
- `security` parameter: `"deny"` (block all), `"allowlist"` (check allowlist), `"full"` (allow all)
- `ask` parameter: `"off"`, `"on-miss"`, `"always"` (approval prompts)
- Implementation: [src/agents/bash-tools.exec.ts 1-600](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/bash-tools.exec.ts#L1-L600)

**`process`** - Manage background exec sessions

- Actions: `list`, `poll`, `log`, `write`, `kill`, `clear`, `remove`
- `poll` returns incremental output and exit status when complete
- `log` supports line-based `offset` / `limit` (omit `offset` for tail mode)
- Sessions scoped per agent (isolation via `scopeKey`)
- Implementation: [src/agents/bash-tools.process.ts 1-200](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/bash-tools.process.ts#L1-L200)

### Filesystem Tools

**`read`** - Read file contents

- Parameters: `path`, `startLine`, `endLine`
- Sandbox-rooted when `sandbox.mode !== "off"` (see [src/agents/pi-tools.read.ts 1-100](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-tools.read.ts#L1-L100))
- Supports workspace-relative and absolute paths
- Claude Code compatibility via param normalization

**`write`** - Create or overwrite files

- Parameters: `path`, `content`
- Disabled in sandboxes with `workspaceAccess: "ro"`
- Sandboxed writes target container filesystem

**`edit`** - Apply line-based edits

- Parameters: `path`, `edits` (array of `{startLine, endLine, content}`)
- Disabled in read-only sandboxes
- Optimized for multi-region modifications

**`apply_patch`** - Apply structured patches (experimental)

- Enabled via `tools.exec.applyPatch.enabled` (OpenAI models only)
- Supports multi-file hunks in unified diff format
- Implementation: [src/agents/apply-patch.ts 1-300](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/apply-patch.ts#L1-L300)

### Session Tools

**`sessions_list`** - Discover active sessions

- Returns session keys, metadata, last activity
- Used for agent-to-agent discovery

**`sessions_history`** - Fetch transcript logs

- Parameters: `sessionKey`, `limit`, `offset`
- Returns message history for cross-session context

**`sessions_send`** - Message another session

- Parameters: `sessionKey`, `message`, `replyMode`, `announceMode`
- `replyMode`: `"REPLY_SKIP"` (no reply), `"REPLY_WAIT"` (wait for reply), `"REPLY_STREAM"` (stream reply)
- `announceMode`: `"ANNOUNCE_SKIP"` (silent), `"ANNOUNCE_SEND"` (notify target session)
- Enables agent-to-agent coordination without channel switching

**`sessions_spawn`** - Create subagent session

- Parameters: `sessionKey`, `message`, `thinkingLevel`, `model`
- Spawns isolated session with inherited tool policies
- Subagent tool restrictions via `resolveSubagentToolPolicy`

**`session_status`** - Get current session state

- Returns: `sessionKey`, `model`, `thinkingLevel`, `tokenCount`, `cost`
- Always allowed (even with `tools.profile: "minimal"`)

### Memory Tools

**`memory_search`** - Hybrid vector + BM25 search

- Parameters: `query`, `limit`, `threshold`
- Searches workspace files indexed via `@openclaw/memory-core`
- Returns ranked snippets with file paths and line numbers
- Configuration: `memorySearch.provider`, `memorySearch.model`

**`memory_get`** - Fetch specific memory entry

- Parameters: `id` (from `memory_search` results)
- Returns full content for selected memory chunk

### Web Tools

**`web_search`** - Brave Search API

- Parameters: `query`, `count` (1-10)
- Requires `BRAVE_API_KEY` and `tools.web.search.enabled`
- Response caching (default 15 minutes)
- Configuration: `tools.web.search.maxResults`

**`web_fetch`** - Extract readable content

- Parameters: `url`, `selector`, `format`
- Uses `@mozilla/readability` for content extraction
- Supports CSS selector filtering and markdown/text output

### UI Tools

**`browser`** - Browser control via CDP

- Actions: `navigate`, `click`, `type`, `scroll`, `evaluate`, `snapshot`, `upload`
- Requires `browser.enabled` and Chrome/Chromium
- Supports multiple profiles via `browser.profiles`
- `target` parameter: `"default"` (host browser), `"sandbox"` (container browser), `"custom"` (specific CDP URL)
- Sandboxed sessions default to container browser (override with `sandbox.browser.allowHostControl`)

**`canvas`** - A2UI visual workspace

- Actions: `push`, `reset`, `eval`, `snapshot`
- Renders interactive UI on iOS/Android/macOS Canvas hosts
- Requires paired node with Canvas capability

### Automation Tools

**`cron`** - Scheduled task management

- Actions: `create`, `update`, `list`, `delete`, `trigger`
- Cron expressions via `croner` library
- Stores schedules in `cron.store` path
- Configuration: `cron.enabled`, `cron.maxConcurrentRuns`

**`gateway`** - Gateway management

- Actions: `restart`, `config.get`, `config.apply`, `config.patch`
- Requires owner-level permissions in groups
- Used for runtime configuration updates

### Messaging Tools

**`message`** - Send messages via channels

- Parameters: `action`, `channel`, `accountId`, `to`, `threadId`, `text`, `attachments`
- Actions: `sendMessage`, `editMessage`, `deleteMessage`, `addReaction`, `threadReply`
- Channel-specific: `listActions` for platform capabilities
- Auto-threading support for Slack via `currentChannelId` / `currentThreadTs`

### Node Tools

**`nodes`** - Device-local capabilities

- Actions: `camera.snap`, `camera.clip`, `screen.record`, `location.get`, `system.run`, `system.notify`
- Requires paired device (macOS/iOS/Android via Bonjour/DNS-SD discovery)
- Permissions enforced by device TCC (camera, screen recording, location)
- Node targeting via `nodeId` or `nodeName` parameters

### Channel-Specific Tools

Channels can register additional tools via `listChannelAgentTools`:

- **`slack`**: `slack.login`, `slack.channels`, `slack.users`
- **`discord`**: `discord.login`, `discord.guilds`, `discord.channels`
- Platform-native actions exposed as tools (e.g., emoji reactions, thread replies)

**Sources:**

- [docs/tools/index.md 167-220](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/tools/index.md#L167-L220)
- [src/agents/pi-tools.ts 228-300](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-tools.ts#L228-L300)
- [src/agents/bash-tools.exec.ts 1-600](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/bash-tools.exec.ts#L1-L600)
- [src/agents/bash-tools.process.ts 1-200](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/bash-tools.process.ts#L1-L200)

---

**Tool profiles** provide baseline allowlists before explicit `allow` / `deny` rules:

| Profile | Included Tools |
| --- | --- |
| `minimal` | `session_status` |
| `coding` | `group:fs`, `group:runtime`, `group:sessions`, `group:memory`, `image` |
| `messaging` | `group:messaging`, `sessions_list`, `sessions_history`, `sessions_send`, `session_status` |
| `full` | No restrictions (all tools available) |

**Tool groups** expand to multiple tools:

| Group | Tools |
| --- | --- |
| `group:runtime` | `exec`, `bash`, `process` |
| `group:fs` | `read`, `write`, `edit`, `apply_patch` |
| `group:sessions` | `sessions_list`, `sessions_history`, `sessions_send`, `sessions_spawn`, `session_status` |
| `group:memory` | `memory_search`, `memory_get` |
| `group:web` | `web_search`, `web_fetch` |
| `group:ui` | `browser`, `canvas` |
| `group:automation` | `cron`, `gateway` |
| `group:messaging` | `message` |
| `group:nodes` | `nodes` |
| `group:openclaw` | All built-in tools (excludes plugin tools) |

**Provider-specific restrictions:**

```
{
  tools: {
    profile: "coding",
    byProvider: {
      "google-antigravity": { profile: "minimal" },
      "openai/gpt-5.2": { allow: ["group:fs", "sessions_list"] }
    }
  }
}
```

**Agent-specific overrides:**

```
{
  tools: { profile: "coding" },
  agents: {
    list: [
      {
        id: "support",
        tools: { profile: "messaging", allow: ["slack", "discord"] }
      }
    ]
  }
}
```

**Group-level policies** (per channel/sender):

```
{
  channels: {
    whatsapp: {
      groups: {
        "120363424282127706@g.us": {
          tools: {
            allow: ["read", "message"],
            deny: ["exec", "write", "browser"]
          },
          bySender: {
            "+15555550123": {
              tools: { allow: ["exec", "write"] }
            }
          }
        }
      }
    }
  }
}
```

**Plugin-only allowlists:** If `tools.allow` references only unknown or unloaded plugin tool names, OpenClaw logs a warning and ignores the allowlist to keep core tools available. Use `tools.alsoAllow` for additive plugin tool enablement:

```
{
  tools: {
    profile: "coding",
    alsoAllow: ["lobster", "llm-task"]  // Adds plugin tools without removing core
  }
}
```

**Sources:**

- [docs/tools/index.md 16-159](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/tools/index.md#L16-L159)
- [docs/gateway/configuration.md 300-500](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/configuration.md#L300-L500)
- [src/agents/pi-tools.policy.ts 1-207](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-tools.policy.ts#L1-L207)
- [src/agents/tool-policy.ts 1-300](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/tool-policy.ts#L1-L300)

---

## Tool Execution Context and Sandboxing

```
Security PolicyHost ExecutionSandboxed ExecutionExecution Context ResolutionSandboxedHosthost=nodeAllowedDeniedSession Key
(main vs non-main)sandbox.mode
(off|non-main|all)/elevated directive
(on|off|full|ask)exec tool 'host' param
(sandbox|gateway|node)resolveSandboxContext
src/agents/sandbox/context.tsCheck tools.elevated gate
+ agents.list[].tools.elevatedsandbox.containerName
(session|agent|shared)sandbox.workspaceAccess
(none|ro|rw)/workspace
(container workdir)Docker exec
via dockerodeGateway Host
(where gateway process runs)Paired Node
(macOS/iOS/Android)Exec Approval System
~/.openclaw/exec-approvals.jsontools.exec.safeBins
(allowlist)exec.security
(deny|allowlist|full)exec.ask
(off|on-miss|always)tools.elevated
(global + agent gates)
```

**Sandbox scope:**

- `scope: "session"` → one container per session (isolated workspaces)
- `scope: "agent"` → one container per agent (shared across sessions)
- `scope: "shared"` → one container for all sandboxed sessions

**Workspace access modes:**

- `workspaceAccess: "none"` → tools see sandbox workspace under `~/.openclaw/sandboxes/<scope>/<id>`
- `workspaceAccess: "ro"` → agent workspace mounted read-only at `/agent` (disables write/edit)
- `workspaceAccess: "rw"` → agent workspace mounted read-write at `/workspace`

**Elevated mode escape hatch:**

- `/elevated on` or `elevated: true` in exec params → run on gateway host
- Requires both `tools.elevated` (global) and `agents.list[].tools.elevated` (per-agent) gates to allow
- Only changes behavior when sandboxed (already on host otherwise)
- `/elevated full` → run on host + skip exec approvals (`security=full` + `ask=off`)
- See [Elevated Mode](https://deepwiki.com/openclaw/openclaw/6.2-tool-security-and-sandboxing) for directive syntax and precedence

**Node execution:**

- `host: "node"` + `node: "macOS-Mini"` → invoke on paired device via `node.invoke` protocol
- Node capabilities: `camera.snap`, `camera.clip`, `screen.record`, `location.get`, `system.run`, `system.notify`
- Requires device pairing (Bonjour/DNS-SD discovery)
- Node approvals stored per-node in device-local allowlist

**Sources:**

- [docs/gateway/sandboxing.md 1-150](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/sandboxing.md#L1-L150)
- [docs/tools/elevated.md 1-50](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/tools/elevated.md#L1-L50)
- [docs/gateway/sandbox-vs-tool-policy-vs-elevated.md 1-100](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/sandbox-vs-tool-policy-vs-elevated.md#L1-L100)
- [src/agents/sandbox/context.ts 1-100](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/sandbox/context.ts#L1-L100)
- [src/agents/bash-tools.exec.ts 200-400](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/bash-tools.exec.ts#L200-L400)

---

## Skills System

**Skills** are structured documentation files that inject tool usage guidance into agent prompts. Skills live in `~/.openclaw/workspace/skills/<skill-name>/SKILL.md` and are automatically discovered and loaded by the agent runtime.

```
Prompt InjectionSkill DiscoverySkill Managementopenclaw skills
(list|show|refresh)Skill installation
(download, extract, verify)Skill binaries
(skills//bin/)tools.exec.safeBins
(auto-allow skill bins)Agent Workspace
~/.openclaw/workspaceskills/
(skill subdirectories)SKILL.md
(usage documentation)skill.json
(optional metadata)Scan skills directory
chokidar file watcherParse skill.json
(dependencies, install)Load SKILL.md content
(usage examples)Validate skill structureSystem Prompt Builder
createSystemPromptOverrideTOOLS.md section
(tool inventory)Skills content
(usage guidance)Bootstrap files
(AGENTS.md, SOUL.md)Final System Prompt
(sent to model provider)
```

**Skill structure:**

```
~/.openclaw/workspace/skills/
├── github/
│   ├── SKILL.md          # Usage documentation (required)
│   ├── skill.json        # Metadata (optional)
│   └── bin/              # Optional binaries
├── notion/
│   ├── SKILL.md
│   └── skill.json
└── custom-skill/
    └── SKILL.md
```

**SKILL.md format:**

- Markdown format with usage examples, parameter descriptions, and common patterns
- Injected into system prompt under "Available Skills" section
- Should include tool invocation examples with expected parameters
- Can reference external documentation or APIs

**skill.json metadata (optional):**

```
{
  "name": "github",
  "description": "GitHub API integration",
  "dependencies": ["gh"],  // Required CLI tools
  "install": {
    "type": "download",    // download|npm|pip|homebrew|none
    "url": "https://...",  // For download type
    "extractTo": "bin/"
  },
  "autoAllowBins": true    // Add skill bins to safeBins
}
```

**Skill discovery:** Skills are scanned at agent startup and when workspace files change (via `chokidar` file watcher). The agent runtime caches skill content and rebuilds the system prompt when skills change.

**Sandboxed skill access:**

- `workspaceAccess: "none"` → OpenClaw mirrors eligible skills into sandbox workspace at `skills/`
- `workspaceAccess: "rw"` → workspace skills readable from `/workspace/skills`
- `workspaceAccess: "ro"` → workspace skills readable from `/agent/skills`

**Skill binaries:** Skills can bundle executables in `skills/<skill>/bin/`. When `autoAllowBins: true` in `skill.json`, these binaries are automatically added to `tools.exec.safeBins` (bypassing exec approvals).

**Sources:**

- [README.md 294-299](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md#L294-L299)
- [docs/tools/index.md 160-161](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/tools/index.md#L160-L161)
- [docs/gateway/sandboxing.md 52-57](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/sandboxing.md#L52-L57)
- [CHANGELOG.md 17](https://github.com/openclaw/openclaw/blob/bf6ec64f/CHANGELOG.md#L17-L17) [CHANGELOG.md 30](https://github.com/openclaw/openclaw/blob/bf6ec64f/CHANGELOG.md#L30-L30) [CHANGELOG.md 154](https://github.com/openclaw/openclaw/blob/bf6ec64f/CHANGELOG.md#L154-L154)

---

## Plugin Tools

Plugins extend the tool system by registering additional tools via the plugin SDK. Plugin tools integrate with the same policy and execution pipelines as built-in tools.

**Plugin tool registration:**

```
// extensions/lobster/index.ts
export default {
  name: "lobster",
  tools: [
    {
      name: "lobster",
      description: "Execute Lobster workflow",
      parameters: {
        type: "object",
        properties: {
          file: { type: "string" },
          argsJson: { type: "string" }
        },
        required: ["file"]
      },
      execute: async (params) => {
        // Tool implementation
      }
    }
  ]
};
```

**Plugin tool metadata:** Tools registered by plugins are tracked via `getPluginToolMeta` in [src/plugins/tools.ts 1-100](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/plugins/tools.ts#L1-L100) Metadata includes:

- Plugin name and slot type
- Tool group membership (for policy expansion)
- Config requirements (e.g., API keys)

**Plugin tool policies:**

- Plugin tools respect the same `tools.allow` / `tools.deny` policies
- Tool groups can include plugin tools: `group:*` expands to all tools including plugins
- Plugin-specific groups: `buildPluginToolGroups` organizes plugin tools by provider
- `tools.alsoAllow` enables additive plugin tool allowlisting without removing core tools

**Built-in plugin tools:**

**`lobster`** (optional) - Typed workflow runtime

- Requires Lobster CLI installed on gateway host
- Parameters: `file` (workflow path), `argsJson` (JSON string arguments)
- Supports resumable approvals and typed workflow steps
- Configuration: Enable via `lobster` plugin in `extensions/lobster`

**`llm-task`** (optional) - JSON-only LLM step

- Parameters: `prompt`, `schema` (optional JSON schema for validation)
- Returns structured JSON output from model
- Used for workflow integration and typed responses
- Configuration: Enable via `llm-task` plugin in `extensions/llm-task`

**Channel plugin tools:** Messaging channel plugins can register channel-specific tools:

- `slack.login`, `slack.channels`, `slack.users` (Slack plugin)
- `discord.login`, `discord.guilds`, `discord.channels` (Discord plugin)
- `matrix.rooms`, `matrix.sync` (Matrix plugin)

**Plugin tool discovery:** Plugins are loaded from:

1. Bundled extensions in `extensions/` (shipped with OpenClaw)
2. Installed npm plugins (e.g., `@openclaw/memory-core`)
3. Workspace plugins in `~/.openclaw/plugins/` (local development)

Plugins declare tools via `openclaw.extensions` manifest in `package.json`:

```
{
  "openclaw": {
    "extensions": ["./index.ts"],
    "configSchema": { /* TypeBox schema */ }
  }
}
```

**Sources:**

- [docs/tools/index.md 160-165](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/tools/index.md#L160-L165)
- [CHANGELOG.md 19](https://github.com/openclaw/openclaw/blob/bf6ec64f/CHANGELOG.md#L19-L19) [CHANGELOG.md 232-233](https://github.com/openclaw/openclaw/blob/bf6ec64f/CHANGELOG.md#L232-L233)
- [src/agents/pi-tools.ts 300-336](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-tools.ts#L300-L336)
- [src/plugins/tools.ts 1-100](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/plugins/tools.ts#L1-L100)
- [extensions/lobster/package.json 1-20](https://github.com/openclaw/openclaw/blob/bf6ec64f/extensions/lobster/package.json#L1-L20)
- [extensions/llm-task/package.json 1-20](https://github.com/openclaw/openclaw/blob/bf6ec64f/extensions/llm-task/package.json#L1-L20)

<svg id="mermaid-fu8dstus3vp" width="100%" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 2412 512" style="max-width: 512px;" role="graphics-document document" aria-roledescription="error"><g></g><g><path class="error-icon" d="m411.313,123.313c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32-9.375,9.375-20.688-20.688c-12.484-12.5-32.766-12.5-45.25,0l-16,16c-1.261,1.261-2.304,2.648-3.31,4.051-21.739-8.561-45.324-13.426-70.065-13.426-105.867,0-192,86.133-192,192s86.133,192 192,192 192-86.133 192-192c0-24.741-4.864-48.327-13.426-70.065 1.402-1.007 2.79-2.049 4.051-3.31l16-16c12.5-12.492 12.5-32.758 0-45.25l-20.688-20.688 9.375-9.375 32.001-31.999zm-219.313,100.687c-52.938,0-96,43.063-96,96 0,8.836-7.164,16-16,16s-16-7.164-16-16c0-70.578 57.422-128 128-128 8.836,0 16,7.164 16,16s-7.164,16-16,16z"></path><path class="error-icon" d="m459.02,148.98c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l16,16c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16.001-16z"></path><path class="error-icon" d="m340.395,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16-16c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l15.999,16z"></path><path class="error-icon" d="m400,64c8.844,0 16-7.164 16-16v-32c0-8.836-7.156-16-16-16-8.844,0-16,7.164-16,16v32c0,8.836 7.156,16 16,16z"></path><path class="error-icon" d="m496,96.586h-32c-8.844,0-16,7.164-16,16 0,8.836 7.156,16 16,16h32c8.844,0 16-7.164 16-16 0-8.836-7.156-16-16-16z"></path><path class="error-icon" d="m436.98,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688l32-32c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32c-6.251,6.25-6.251,16.375-0.001,22.625z"></path><text class="error-text" x="1440" y="250" font-size="150px" style="text-anchor: middle;">Syntax error in text</text> <text class="error-text" x="1250" y="400" font-size="100px" style="text-anchor: middle;">mermaid version 11.12.2</text></g></svg> <svg id="mermaid-7khuxtjp8f" width="100%" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 2412 512" style="max-width: 512px;" role="graphics-document document" aria-roledescription="error"><g></g><g><path class="error-icon" d="m411.313,123.313c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32-9.375,9.375-20.688-20.688c-12.484-12.5-32.766-12.5-45.25,0l-16,16c-1.261,1.261-2.304,2.648-3.31,4.051-21.739-8.561-45.324-13.426-70.065-13.426-105.867,0-192,86.133-192,192s86.133,192 192,192 192-86.133 192-192c0-24.741-4.864-48.327-13.426-70.065 1.402-1.007 2.79-2.049 4.051-3.31l16-16c12.5-12.492 12.5-32.758 0-45.25l-20.688-20.688 9.375-9.375 32.001-31.999zm-219.313,100.687c-52.938,0-96,43.063-96,96 0,8.836-7.164,16-16,16s-16-7.164-16-16c0-70.578 57.422-128 128-128 8.836,0 16,7.164 16,16s-7.164,16-16,16z"></path><path class="error-icon" d="m459.02,148.98c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l16,16c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16.001-16z"></path><path class="error-icon" d="m340.395,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16-16c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l15.999,16z"></path><path class="error-icon" d="m400,64c8.844,0 16-7.164 16-16v-32c0-8.836-7.156-16-16-16-8.844,0-16,7.164-16,16v32c0,8.836 7.156,16 16,16z"></path><path class="error-icon" d="m496,96.586h-32c-8.844,0-16,7.164-16,16 0,8.836 7.156,16 16,16h32c8.844,0 16-7.164 16-16 0-8.836-7.156-16-16-16z"></path><path class="error-icon" d="m436.98,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688l32-32c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32c-6.251,6.25-6.251,16.375-0.001,22.625z"></path><text class="error-text" x="1440" y="250" font-size="150px" style="text-anchor: middle;">Syntax error in text</text> <text class="error-text" x="1250" y="400" font-size="100px" style="text-anchor: middle;">mermaid version 11.12.2</text></g></svg>