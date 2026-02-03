Menu

## Gateway

Relevant source files
- [.npmrc](https://github.com/openclaw/openclaw/blob/bf6ec64f/.npmrc)
- [CHANGELOG.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/CHANGELOG.md)
- [README.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md)
- [assets/avatar-placeholder.svg](https://github.com/openclaw/openclaw/blob/bf6ec64f/assets/avatar-placeholder.svg)
- [docs/cli/index.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/cli/index.md)
- [docs/gateway/index.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/index.md)
- [docs/gateway/troubleshooting.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/troubleshooting.md)
- [docs/index.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/index.md)
- [docs/start/getting-started.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/start/getting-started.md)
- [docs/start/wizard.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/start/wizard.md)
- [extensions/memory-core/package.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/extensions/memory-core/package.json)
- [package.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json)
- [pnpm-lock.yaml](https://github.com/openclaw/openclaw/blob/bf6ec64f/pnpm-lock.yaml)
- [pnpm-workspace.yaml](https://github.com/openclaw/openclaw/blob/bf6ec64f/pnpm-workspace.yaml)
- [scripts/clawtributors-map.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/clawtributors-map.json)
- [scripts/protocol-gen-swift.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/protocol-gen-swift.ts)
- [scripts/update-clawtributors.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/update-clawtributors.ts)
- [scripts/update-clawtributors.types.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/update-clawtributors.types.ts)
- [src/agents/pi-embedded-runner-extraparams.live.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner-extraparams.live.test.ts)
- [src/agents/pi-embedded-runner-extraparams.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner-extraparams.test.ts)
- [src/cron/run-log.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cron/run-log.test.ts)
- [src/cron/run-log.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cron/run-log.ts)
- [src/cron/store.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cron/store.ts)
- [src/gateway/protocol/index.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/protocol/index.ts)
- [src/gateway/protocol/schema.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/protocol/schema.ts)
- [src/gateway/server.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/server.ts)
- [src/index.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/index.ts)
- [ui/package.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/ui/package.json)
- [ui/src/styles.css](https://github.com/openclaw/openclaw/blob/bf6ec64f/ui/src/styles.css)
- [ui/src/styles/layout.mobile.css](https://github.com/openclaw/openclaw/blob/bf6ec64f/ui/src/styles/layout.mobile.css)

## Purpose and Scope

The Gateway is OpenClaw's central control plane—a single long-running WebSocket server that orchestrates all system components. It owns channel connections (WhatsApp, Telegram, Discord, etc.), manages conversation sessions, routes messages to agents, and exposes a unified RPC interface for clients (CLI, Control UI, macOS/iOS/Android apps).

**Related pages:**

- For Gateway configuration options (port, bind modes, auth): see [Gateway Configuration](https://deepwiki.com/openclaw/openclaw/3.1-gateway-configuration)
- For the WebSocket protocol specification: see [Gateway Protocol](https://deepwiki.com/openclaw/openclaw/3.2-gateway-protocol)
- For service installation and management: see [Gateway Service Management](https://deepwiki.com/openclaw/openclaw/3.3-gateway-service-management)
- For remote access patterns: see [Remote Access](https://deepwiki.com/openclaw/openclaw/3.4-remote-access)

---

## Architecture Overview

The Gateway sits at the center of OpenClaw's network topology, serving as the sole entry point for all operations:

```
Agent RuntimeChannel AdaptersGateway Control Plane :18789Client Layerws://127.0.0.1:18789WebSocketWebSocketBridge ProtocolBonjour DiscoveryDNS-SDRoute MessagesRoute MessagesRoute MessagesRoute MessagesRoute Messagesopenclaw CLIControl UI
(Browser)Terminal UImacOS AppiOS NodeAndroid NodeWebSocket Server
startGatewayServer()Protocol Handler
validateRequestFrame
validateEventFrameSession Manager
loadSessionStore
saveSessionStoreConfig Manager
loadConfigCron Manager
DEFAULT_CRON_STORE_PATHPresence SystemWhatsApp
BaileysTelegram
grammYDiscord
discord.jsSignal
signal-cliSlack
BoltPi Agent Core
@mariozechner/pi-agent-coreTool RegistryMemory Search
```

**Sources:**[src/gateway/server.ts 1-4](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/server.ts#L1-L4) [src/index.ts 1-95](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/index.ts#L1-L95) [CHANGELOG.md 1-100](https://github.com/openclaw/openclaw/blob/bf6ec64f/CHANGELOG.md#L1-L100)

---

## Core Responsibilities

The Gateway manages six primary domains:

| Domain | Responsibility | Key Files |
| --- | --- | --- |
| **WebSocket Server** | Accept client connections, multiplex RPC | [src/gateway/server.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/server.ts) |
| **Message Routing** | Route inbound messages from channels to agents | [src/auto-reply/](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/) |
| **Session Management** | Track conversation state, history, compaction | [src/config/sessions.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/sessions.ts) |
| **Configuration** | Load/validate/hot-reload `openclaw.json` | [src/config/config.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/config.ts) |
| **Presence** | Monitor channel health, node connectivity | Gateway presence system |
| **Cron/Scheduling** | Execute scheduled tasks, manage job state | [src/cron/store.ts 1-37](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cron/store.ts#L1-L37) |

**Sources:**[README.md 1-100](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md#L1-L100) [docs/gateway/index.md 1-50](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/index.md#L1-L50)

---

## Network Architecture

### Binding Modes

The Gateway supports four binding modes:

```
CustomTailscaleLANLoopback (Default)loopbacklantailnetcustomSSH TunnelToken RequiredToken/Tailscale ID127.0.0.1:187890.0.0.0:18789
(All Interfaces)100.x.y.z:18789
(Tailnet Interface)Specific IP:18789gateway.bind
gateway.portRemote Clients
```

**Key configuration fields:**

- `gateway.port` (default: `18789`, env: `OPENCLAW_GATEWAY_PORT`)
- `gateway.bind` (values: `loopback`, `lan`, `tailnet`, `auto`, `custom`)
- `gateway.auth.mode` (values: `token`, `password`)
- `gateway.auth.token` (env: `OPENCLAW_GATEWAY_TOKEN`)

**Port allocation pattern:**

- Base port: `gateway.port` (e.g., 18789)
- Browser control: base + 2 (18791, loopback only)
- Canvas host: base + 4 (18793, configurable via `canvasHost.port`)

**Sources:**[docs/gateway/index.md 15-50](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/index.md#L15-L50) [docs/start/wizard.md 40-60](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/start/wizard.md#L40-L60)

---

## Protocol Architecture

### Frame Types

The Gateway protocol uses four frame types:

```
validateRequestFrame()validateResponseFrame()validateEventFrame()Client FrameRequestFrame
{id, method, params}EventFrame
{event, data}Server FrameResponseFrame
{id, result/error}EventFrame
{event, data}Protocol Validation
ajv.compile()Schema Registry
ProtocolSchemas
```

**Key protocol functions:**

- `validateRequestFrame()` - Validates inbound RPC requests
- `validateResponseFrame()` - Validates outbound responses
- `validateEventFrame()` - Validates bidirectional events
- `PROTOCOL_VERSION` - Current protocol version constant

**RPC method categories:**

| Category | Methods | Schema Files |
| --- | --- | --- |
| Agent | `agent.run`, `agent.wait`, `agent.identity` | [src/gateway/protocol/schema/agent.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/protocol/schema/agent.ts) |
| Sessions | `sessions.list`, `sessions.patch`, `sessions.reset` | [src/gateway/protocol/schema/sessions.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/protocol/schema/sessions.ts) |
| Channels | `channels.status`, `channels.logout` | [src/gateway/protocol/schema/channels.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/protocol/schema/channels.ts) |
| Config | `config.get`, `config.set`, `config.patch` | [src/gateway/protocol/schema/config.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/protocol/schema/config.ts) |
| Nodes | `node.list`, `node.invoke`, `node.pair` | [src/gateway/protocol/schema/nodes.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/protocol/schema/nodes.ts) |
| Cron | `cron.list`, `cron.add`, `cron.run` | [src/gateway/protocol/schema/cron.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/protocol/schema/cron.ts) |

**Sources:**[src/gateway/protocol/index.ts 1-50](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/protocol/index.ts#L1-L50) [src/gateway/protocol/schema.ts 1-17](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/protocol/schema.ts#L1-L17)

---

## Startup and Lifecycle

### Initialization Sequence

```
"WebSocket Server""Channel Adapters""loadSessionStore()""loadConfig()""startGatewayServer()""buildProgram()""main (openclaw)""WebSocket Server""Channel Adapters""loadSessionStore()""loadConfig()""startGatewayServer()""buildProgram()""main (openclaw)"alt[Config Missing or mode != local]"Gateway Running""loadDotEnv()""normalizeEnv()""assertSupportedRuntime()""buildProgram()""gateway command""loadConfig()""OpenClawConfig""Check gateway.mode=local""Exit with error""loadSessionStore()""Session State""Initialize adapters""Ready""Start WebSocketport=gateway.port""Listening""Watch config fileif gateway.reload.mode != off""SIGUSR1 → restart""SIGTERM → graceful shutdown"
```

**Startup validation:**

1. Runtime check: Node >= 22 (`assertSupportedRuntime()`)
2. Config validation: `gateway.mode` must be `local`
3. Port availability: Fails if `gateway.port` already bound (unless `--force`)
4. Auth validation: Non-loopback binds require `gateway.auth.token` or `gateway.auth.password`

**Sources:**[src/index.ts 37-95](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/index.ts#L37-L95) [docs/gateway/index.md 15-40](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/index.md#L15-L40)

---

## Configuration Hot Reload

The Gateway watches `openclaw.json` and can apply changes without full restart:

```
File ChangeoffhybridYesNomanual~/.openclaw/openclaw.jsonchokidar
File WatcherloadConfig()
Zod Validationgateway.reload.modeIgnore ChangesHybrid ReloadSafe to
Hot-Apply?Apply In-Place
(channels, skills, etc.)SIGUSR1
In-Process RestartRequire Manual Restart
```

**Hot-reloadable fields:**

- `channels.*` - Channel configuration (allowlists, bot tokens)
- `skills.*` - Skill settings
- `tools.*` - Tool policies (non-sandbox)
- `agents.defaults.model` - Default model selection

**Restart-required fields:**

- `gateway.port` - Port binding
- `gateway.bind` - Network interface
- `gateway.auth.*` - Authentication settings
- `agents.defaults.sandbox.*` - Docker sandbox configuration

**Sources:**[docs/gateway/index.md 15-35](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/index.md#L15-L35) [CHANGELOG.md 25-30](https://github.com/openclaw/openclaw/blob/bf6ec64f/CHANGELOG.md#L25-L30)

---

## Key Components

### WebSocket Server (startGatewayServer)

The Gateway's WebSocket server multiplexes HTTP and WebSocket traffic on a single port:

| Path | Protocol | Purpose |
| --- | --- | --- |
| `/` | WebSocket | RPC control plane |
| `/` | HTTP GET | Control UI static assets |
| `/__openclaw__/*` | HTTP | Internal hooks, health checks |
| `/v1/chat/completions` | HTTP POST | OpenAI-compatible API |
| `/v1/responses` | HTTP POST | OpenResponses API |
| `/tools/invoke` | HTTP POST | Direct tool invocation |

**Connection flow:**

1. Client sends `connect` frame with `auth.token` or `auth.password`
2. Server validates via `validateConnectParams()`
3. Server responds with `HelloOk` frame including protocol version
4. Bidirectional RPC and events enabled

**Sources:**[src/gateway/server.ts 1-4](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/server.ts#L1-L4) [docs/gateway/index.md 30-35](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/index.md#L30-L35)

---

### Session Manager

Sessions are identified by composite keys:

```
Session Keymain
(Default DM)dm:channel:id
(Per-DM)group:channel:id
(Per-Group)thread:channel:id:threadId
(Per-Thread)Session Store
~/.openclaw/sessions.json{ history, metadata,
thinkingLevel, verboseLevel,
model, sendPolicy }
```

**Session resolution functions:**

- `deriveSessionKey()` - Generate key from message context
- `resolveSessionKey()` - Normalize and validate keys
- `loadSessionStore()` - Read session state from disk
- `saveSessionStore()` - Persist session state

**Session metadata:**

- `history` - Message transcript (user/assistant turns)
- `thinkingLevel` - Reasoning verbosity (off/minimal/low/medium/high/xhigh)
- `verboseLevel` - Tool output verbosity
- `model` - Per-session model override
- `lastActiveAt` - Timestamp for pruning

**Sources:**[src/config/sessions.ts 12-18](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/sessions.ts#L12-L18) [src/index.ts 12-18](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/index.ts#L12-L18)

---

## Message Processing Pipeline

Inbound messages flow through multiple stages:

```
"Model Provider""Agent Runtime""Session Manager""Access Control""Channel Router""Channel Adapter""Model Provider""Agent Runtime""Session Manager""Access Control""Channel Router""Channel Adapter"alt[Not in allowlist]alt[DM Policy: pairing]alt[Tool Call]loop[Agent Turn]"Inbound Message Event""Check Access Policy""Check allowlist""Send Pairing Code""Drop Message""Resolve Session KeyderiveSessionKey()""Load HistoryloadSessionStore()""Queue Message(sequential/concurrent)""Build System Prompt""Memory Search""Stream Request""Text/Tool Call""Execute Tool""Stream Response""Save TranscriptsaveSessionStore()"
```

**Access control policies:**

- `dmPolicy="pairing"` - Unknown senders get pairing code (default)
- `dmPolicy="allowlist"` - Only allowlisted senders processed
- `dmPolicy="open"` - All DMs accepted (requires `"*"` in allowlist)
- `groupPolicy` - Separate rules for groups (mention gating, etc.)

**Sources:**[src/auto-reply/reply.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/reply.ts) [src/index.ts 52-73](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/index.ts#L52-L73) [README.md 100-120](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md#L100-L120)

---

## Cron and Scheduling

The Gateway includes a built-in cron system:

```
loadCronStore()TriggerappendCronRunLog()Auto-pruneCron Store
~/.openclaw/cron/jobs.jsonCron Managercroner
Cron LibraryJob ExecutionSend Message
(message tool)Invoke Agent
(agent.run)HTTP WebhookRun Log
~/.openclaw/cron/runs/.jsonlJSONL Append
```

**Cron job schema:**

- `id` - Unique job identifier
- `schedule` - Cron expression (e.g., `"0 9 * * *"`)
- `enabled` - Boolean toggle
- `action` - Job payload (message, agent invocation, webhook)
- `deliverTo` - Target channel/session for output

**Run log format:**Each job maintains a JSONL log at `~/.openclaw/cron/runs/<jobId>.jsonl`:

```
type CronRunLogEntry = {
  ts: number;           // Timestamp
  jobId: string;        // Job ID
  action: "finished";   // Event type
  status: "ok" | "error" | "skipped";
  error?: string;       // Error message if failed
  durationMs?: number;  // Execution time
  nextRunAtMs?: number; // Next scheduled run
};
```

**Sources:**[src/cron/store.ts 9-36](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cron/store.ts#L9-L36) [src/cron/run-log.ts 4-14](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cron/run-log.ts#L4-L14) [docs/cli/index.md 165-177](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/cli/index.md#L165-L177)

---

## Service Management

The Gateway can run as a supervised background service:

| Platform | Supervisor | Service Name Pattern | Config Location |
| --- | --- | --- | --- |
| macOS | launchd | `bot.molt.<profile>` | `~/Library/LaunchAgents/` |
| Linux | systemd | `openclaw-gateway[-<profile>].service` | `~/.config/systemd/user/` |
| Windows | schtasks | `OpenClaw Gateway (<profile>)` | Task Scheduler |

**Installation:**

```
openclaw gateway install [--force]
```

**Service commands:**

```
openclaw gateway status    # Check service state
openclaw gateway start     # Start service
openclaw gateway stop      # Stop service
openclaw gateway restart   # Restart service
openclaw gateway uninstall # Remove service
```

**Service metadata (embedded in config):**

- `OPENCLAW_SERVICE_MARKER=openclaw`
- `OPENCLAW_SERVICE_KIND=gateway`
- `OPENCLAW_SERVICE_VERSION=<version>`
- `OPENCLAW_SERVICE_PROFILE=<profile>` (if using profiles)

**Logging:**

- macOS: `$OPENCLAW_STATE_DIR/logs/gateway.log`, `gateway.err.log`
- Linux: `journalctl --user -u openclaw-gateway[-<profile>].service`
- Windows: `schtasks /Query /TN "OpenClaw Gateway (<profile>)" /V`

**Sources:**[docs/gateway/index.md 50-100](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/index.md#L50-L100) [docs/gateway/troubleshooting.md 90-125](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/troubleshooting.md#L90-L125)

---

## Health Monitoring

### Health Check Endpoints

| Endpoint | Purpose | Response |
| --- | --- | --- |
| `/__openclaw__/health` | Gateway liveness | `{"ok": true}` |
| `openclaw health` (CLI) | Full health probe | Service status, channel status, auth validation |
| `openclaw status --deep` | Deep inspection | Includes provider probes, channel tests |

### Presence System

The Gateway tracks presence for:

- **Channels** - Connection state, last message time
- **Nodes** - Connected iOS/Android/macOS nodes, capabilities
- **Agents** - Active sessions, queue depth

**Presence entry schema:**

```
type PresenceEntry = {
  id: string;              // Entity ID
  type: "channel" | "node" | "agent";
  status: "online" | "offline" | "error";
  lastSeenAt: number;      // Timestamp
  metadata?: Record<string, unknown>;
};
```

**Sources:**[docs/gateway/troubleshooting.md 14-30](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/troubleshooting.md#L14-L30) [src/gateway/protocol/schema/types.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/protocol/schema/types.ts)

---

The Gateway defines standardized error codes:

```
INVALID_PARAMS
Bad request parametersUNAUTHORIZED
Auth failureNOT_FOUND
Resource missingCONFLICT
State conflictINTERNAL_ERROR
Server errorTIMEOUT
Operation timeout
```

**Error response format:**

```
type ErrorShape = {
  code: ErrorCode;        // Enum value
  message: string;        // Human-readable description
  details?: unknown;      // Optional debug info
};
```

**Common error scenarios:**

- `INVALID_PARAMS` - Validation failure (Zod/Ajv)
- `UNAUTHORIZED` - Missing or invalid `auth.token`
- `NOT_FOUND` - Session, node, or job not found
- `GATEWAY_UNAVAILABLE` - Gateway not reachable
- `MODEL_UNAVAILABLE` - No auth configured for model

**Sources:**[src/gateway/protocol/schema/error-codes.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/protocol/schema/error-codes.ts) [src/gateway/protocol/schema/types.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/protocol/schema/types.ts)

---

## Multi-Gateway Support

While typically unnecessary, OpenClaw supports running multiple isolated Gateways on the same host:

**Isolation requirements:**

- Unique `gateway.port` per instance
- Unique `OPENCLAW_STATE_DIR` per instance
- Unique `OPENCLAW_CONFIG_PATH` per instance
- Unique `agents.defaults.workspace` per instance
- Separate WhatsApp sessions (one per Gateway)

**Common use cases:**

1. **Rescue bot** - Isolated backup agent with different auth
2. **Development/production** - Separate environments (`--dev` profile)
3. **Multi-tenant** - Per-user Gateway isolation

**Profile-based separation:**

```
# Development instance
openclaw --dev gateway --port 19001

# Production instance
openclaw gateway --port 18789

# Custom profile
openclaw --profile rescue gateway --port 20000
```

**Sources:**[docs/gateway/index.md 52-100](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/index.md#L52-L100) [docs/gateway/troubleshooting.md 1-50](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/troubleshooting.md#L1-L50)

<svg id="mermaid-fu8dstus3vp" width="100%" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 2412 512" style="max-width: 512px;" role="graphics-document document" aria-roledescription="error"><g></g><g><path class="error-icon" d="m411.313,123.313c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32-9.375,9.375-20.688-20.688c-12.484-12.5-32.766-12.5-45.25,0l-16,16c-1.261,1.261-2.304,2.648-3.31,4.051-21.739-8.561-45.324-13.426-70.065-13.426-105.867,0-192,86.133-192,192s86.133,192 192,192 192-86.133 192-192c0-24.741-4.864-48.327-13.426-70.065 1.402-1.007 2.79-2.049 4.051-3.31l16-16c12.5-12.492 12.5-32.758 0-45.25l-20.688-20.688 9.375-9.375 32.001-31.999zm-219.313,100.687c-52.938,0-96,43.063-96,96 0,8.836-7.164,16-16,16s-16-7.164-16-16c0-70.578 57.422-128 128-128 8.836,0 16,7.164 16,16s-7.164,16-16,16z"></path><path class="error-icon" d="m459.02,148.98c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l16,16c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16.001-16z"></path><path class="error-icon" d="m340.395,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16-16c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l15.999,16z"></path><path class="error-icon" d="m400,64c8.844,0 16-7.164 16-16v-32c0-8.836-7.156-16-16-16-8.844,0-16,7.164-16,16v32c0,8.836 7.156,16 16,16z"></path><path class="error-icon" d="m496,96.586h-32c-8.844,0-16,7.164-16,16 0,8.836 7.156,16 16,16h32c8.844,0 16-7.164 16-16 0-8.836-7.156-16-16-16z"></path><path class="error-icon" d="m436.98,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688l32-32c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32c-6.251,6.25-6.251,16.375-0.001,22.625z"></path><text class="error-text" x="1440" y="250" font-size="150px" style="text-anchor: middle;">Syntax error in text</text> <text class="error-text" x="1250" y="400" font-size="100px" style="text-anchor: middle;">mermaid version 11.12.2</text></g></svg>