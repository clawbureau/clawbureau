Menu

## CLI Reference

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
- [scripts/update-clawtributors.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/update-clawtributors.ts)
- [scripts/update-clawtributors.types.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/update-clawtributors.types.ts)
- [src/agents/pi-embedded-runner-extraparams.live.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner-extraparams.live.test.ts)
- [src/agents/pi-embedded-runner-extraparams.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner-extraparams.test.ts)
- [src/cli/nodes-cli.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cli/nodes-cli.ts)
- [src/cli/nodes-screen.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cli/nodes-screen.test.ts)
- [src/cli/nodes-screen.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cli/nodes-screen.ts)
- [src/cli/program.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cli/program.ts)
- [src/index.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/index.ts)
- [ui/package.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/ui/package.json)
- [ui/src/styles.css](https://github.com/openclaw/openclaw/blob/bf6ec64f/ui/src/styles.css)
- [ui/src/styles/layout.mobile.css](https://github.com/openclaw/openclaw/blob/bf6ec64f/ui/src/styles/layout.mobile.css)

## Purpose and Scope

This page provides an overview of OpenClaw's command-line interface, its architecture, and organizational structure. The `openclaw` CLI is the primary interface for managing the Gateway, agents, channels, models, and system configuration.

For detailed command references organized by category, see the sub-pages:

- Gateway operations: [Gateway Commands](https://deepwiki.com/openclaw/openclaw/12.1-gateway-commands)
- Agent management and messaging: [Agent Commands](https://deepwiki.com/openclaw/openclaw/12.2-agent-commands)
- Channel configuration and status: [Channel Commands](https://deepwiki.com/openclaw/openclaw/12.3-channel-commands)
- Model configuration and authentication: [Model Commands](https://deepwiki.com/openclaw/openclaw/12.4-model-commands)
- Configuration management: [Configuration Commands](https://deepwiki.com/openclaw/openclaw/12.5-configuration-commands)
- Diagnostics and troubleshooting: [Diagnostic Commands](https://deepwiki.com/openclaw/openclaw/12.6-diagnostic-commands)

For operational guidance on running the Gateway service, see [Gateway](https://deepwiki.com/openclaw/openclaw/3-gateway). For configuration file structure, see [Configuration File Structure](https://deepwiki.com/openclaw/openclaw/4.1-configuration-file-structure).

---

## CLI Architecture

The CLI is built using Commander.js and provides a unified interface to Gateway RPC methods, local operations, and system management.

```
Target SystemsExecution LayerCommand Categoriesopenclaw.mjs
(CLI Entry Point)buildProgram()
src/cli/program.tsCommander.js
Argument ParserGateway Commands
(gateway, status, health)Agent Commands
(agent, agents, sessions)Channel Commands
(channels, message, pairing)Model Commands
(models)Config Commands
(config, configure, setup)Diagnostic Commands
(doctor, logs, security)Local Operations
(config read/write, file I/O)Gateway RPC Client
(WebSocket to port 18789)Service Control
(launchd, systemd, schtasks)openclaw.json
(~/.openclaw/)Gateway Server
(ws://127.0.0.1:18789)System Services
(OS-level supervisors)
```

**Title**: CLI Command Flow Architecture

**Sources**: [openclaw.mjs](https://github.com/openclaw/openclaw/blob/bf6ec64f/openclaw.mjs) [src/index.ts 1-95](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/index.ts#L1-L95) [src/cli/program.ts 1-3](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cli/program.ts#L1-L3) [package.json 13-14](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json#L13-L14)

---

## Command Organization

OpenClaw commands are organized into six primary categories, each documented in detail on dedicated sub-pages:

| Category | Sub-Page | Primary Commands | Purpose |
| --- | --- | --- | --- |
| **Gateway** | [#12.1](https://deepwiki.com/openclaw/openclaw/12.1-gateway-commands) | `gateway`, `status`, `health` | Gateway lifecycle, service management, health checks |
| **Agent** | [#12.2](https://deepwiki.com/openclaw/openclaw/12.2-agent-commands) | `agent`, `agents`, `message`, `sessions` | Agent execution, multi-agent management, messaging |
| **Channel** | [#12.3](https://deepwiki.com/openclaw/openclaw/12.3-channel-commands) | `channels`, `pairing` | Channel configuration, login, status, pairing approvals |
| **Model** | [#12.4](https://deepwiki.com/openclaw/openclaw/12.4-model-commands) | `models` | Model selection, authentication, fallback chains |
| **Configuration** | [#12.5](https://deepwiki.com/openclaw/openclaw/12.5-configuration-commands) | `config`, `configure`, `onboard`, `setup`, `doctor` | Config management, onboarding, migrations |
| **Diagnostic** | [#12.6](https://deepwiki.com/openclaw/openclaw/12.6-diagnostic-commands) | `doctor`, `logs`, `security` | Troubleshooting, log access, security audits |

Additional command categories include: `memory`, `nodes`, `node`, `approvals`, `sandbox`, `browser`, `cron`, `hooks`, `webhooks`, `plugins`, `skills`, `tui`, `acp`, `dns`.

**Sources**: [docs/cli/index.md 53-238](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/cli/index.md#L53-L238) [CHANGELOG.md 1-270](https://github.com/openclaw/openclaw/blob/bf6ec64f/CHANGELOG.md#L1-L270)

---

## Global Options and Flags

Global options apply to all commands and control CLI behavior, output formatting, and profile isolation:

```
Output ControlProfile IsolationUpdates--update
Run updateVersion & Help--version, -V, -v
Print version--help
Command help--dev
~/.openclaw-dev--no-color
Disable ANSI--json
Machine output--verbose
Debug logsOPENCLAW_STATE_DIR
~/.openclaw-devOPENCLAW_STATE_DIR
~/.openclaw-{name}Terminal Output
```

**Title**: Global CLI Options and Environment Overrides

### Key Global Flags

- **`--dev`**: Isolate state under `~/.openclaw-dev` with shifted default ports (Gateway: 19001, Canvas: 19005)
- **`--profile <name>`**: Isolate state under `~/.openclaw-<name>` for multi-instance setups
- **`--no-color`**: Disable ANSI colors (also respects `NO_COLOR=1` environment variable)
- **`--json`**: Output structured JSON instead of human-readable text
- **`--verbose`**: Enable debug-level console output (does not affect file logs)
- **`--version`, `-V`, `-v`**: Print CLI version and exit
- **`--update`**: Shorthand for `openclaw update` (source installs only)

The `--dev` and `--profile` flags enable running multiple isolated OpenClaw instances on the same machine:

```
# Default instance
openclaw gateway

# Dev instance (port 19001, separate state)
openclaw --dev gateway

# Named profile (custom port, separate state)
openclaw --profile work gateway --port 20001
```

**Sources**: [docs/cli/index.md 54-61](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/cli/index.md#L54-L61) [docs/gateway/index.md 70-108](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/index.md#L70-L108)

---

## Configuration Precedence

CLI arguments, environment variables, and configuration files follow a strict precedence hierarchy:

```
Example OverridesHighest PriorityOverridesBase ConfigFallbackPriority 1Priority 2Priority 3CLI Arguments
(--port, --bind, etc.)Environment Variables
(OPENCLAW_*, CLAWDBOT_*)openclaw.json
(~/.openclaw/)Built-in DefaultsMerged ConfigurationloadConfig()
src/config/config.tsZod Schema Validation
OpenClawSchemaRuntime Configurationopenclaw gateway --port 19000OPENCLAW_GATEWAY_PORT=19000
openclaw gatewayconfig: gateway.port=19000
```

**Title**: Configuration Precedence and Resolution

### Precedence Rules

1. **CLI arguments** (highest): `--port 19000` overrides all other sources
2. **Environment variables**: `OPENCLAW_GATEWAY_PORT=19000` overrides config file
3. **Configuration file**: `gateway.port: 19000` in `openclaw.json`
4. **Built-in defaults** (lowest): Hardcoded fallbacks (e.g., port 18789)

### Environment Variable Mapping

Common environment variables that override config:

| Environment Variable | Config Path | Example |
| --- | --- | --- |
| `OPENCLAW_GATEWAY_PORT` | `gateway.port` | `18789` |
| `OPENCLAW_GATEWAY_TOKEN` | `gateway.auth.token` | `secret123` |
| `OPENCLAW_STATE_DIR` | N/A (runtime path) | `~/.openclaw` |
| `OPENCLAW_CONFIG_PATH` | N/A (config file path) | `~/.openclaw/openclaw.json` |
| `ANTHROPIC_API_KEY` | Stored in auth profiles | `sk-ant-...` |
| `OPENAI_API_KEY` | Stored in auth profiles | `sk-...` |

**Sources**: [src/index.ts 20-22](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/index.ts#L20-L22) [docs/gateway/index.md 42](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/index.md#L42-L42) [docs/cli/index.md 281-333](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/cli/index.md#L281-L333)

---

## Command Invocation Patterns

### Standard Command Pattern

Most commands follow the pattern: `openclaw <category> <action> [options]`

```
# Gateway operations
openclaw gateway status
openclaw gateway start
openclaw gateway install

# Agent operations
openclaw agent --message "Hello"
openclaw agents list
openclaw agents add work --workspace ~/.openclaw/workspace-work

# Channel operations
openclaw channels list
openclaw channels status --probe
openclaw channels login --channel whatsapp

# Model operations
openclaw models status
openclaw models auth setup-token --provider anthropic
```

### RPC vs Local Execution

Commands execute either **locally** (config manipulation, file I/O) or via **Gateway RPC** (runtime queries):

| Execution Type | Commands | Communication |
| --- | --- | --- |
| **Local** | `config`, `configure`, `setup`, `gateway install` | Direct file I/O to `~/.openclaw/` |
| **RPC** | `status`, `health`, `agent`, `sessions`, `channels status` | WebSocket to `ws://127.0.0.1:18789` |
| **Hybrid** | `doctor`, `gateway status`, `models status` | Mix of file checks + RPC probes |

### JSON Output Mode

Most commands support `--json` for machine-readable output:

```
# Human-readable table
openclaw models status

# JSON output (for scripts)
openclaw models status --json | jq '.profiles[] | select(.provider=="anthropic")'

# Status snapshot
openclaw status --json > status.json
```

**Sources**: [docs/cli/index.md 439-556](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/cli/index.md#L439-L556) [docs/gateway/index.md 15-51](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/index.md#L15-L51)

---

## Output Formatting

The CLI adapts output based on terminal capabilities and user preferences:

### Color Palette

OpenClaw uses a "lobster seam" color palette for CLI output:

| Color | Hex | Usage |
| --- | --- | --- |
| `accent` | `#FF5A2D` | Headings, labels, primary highlights |
| `accentBright` | `#FF7A3D` | Command names, emphasis |
| `accentDim` | `#D14A22` | Secondary highlights |
| `info` | `#FF8A5B` | Informational values |
| `success` | `#2FBF71` | Success states |
| `warn` | `#FFB020` | Warnings, attention |
| `error` | `#E23D2D` | Errors, failures |
| `muted` | `#8B7F77` | De-emphasis, metadata |

### Terminal Capabilities

- **ANSI colors**: Auto-detected based on TTY presence; disable with `--no-color` or `NO_COLOR=1`
- **OSC-8 hyperlinks**: Clickable links in supported terminals (iTerm2, WezTerm, etc.)
- **OSC 9;4 progress**: Progress indicators for long-running commands
- **Unicode**: Box-drawing characters for tables; fallback to ASCII if unsupported

### Output Modes

```
# Colored human output (default in TTY)
openclaw status

# Plain text (no colors, good for logs)
openclaw status --no-color

# JSON (machine-readable)
openclaw status --json

# Verbose (debug output to console)
openclaw gateway --verbose
```

**Sources**: [docs/cli/index.md 62-83](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/cli/index.md#L62-L83) [docs/gateway/index.md 19-20](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/index.md#L19-L20)

---

## Service Management Commands

Gateway service lifecycle is managed through OS-native supervisors:

```
openclaw gateway installopenclaw gateway uninstallopenclaw gateway startopenclaw gateway stopopenclaw gateway restartopenclaw gateway statusmacOS: LaunchAgent
~/Library/LaunchAgents/
bot.molt.gateway.plistLinux: systemd
~/.config/systemd/user/
openclaw-gateway.serviceWindows: Task Scheduler
OpenClaw GatewayCheck Runtime StatePID / Exit CodeListening PortsService ConfigLast Error from LogsWait for ExitWait for Port
```

**Title**: Gateway Service Management Flow

### Platform-Specific Service Names

| Platform | Service Name Pattern | Config Location |
| --- | --- | --- |
| macOS | `bot.molt.gateway` (or `bot.molt.<profile>`) | `~/Library/LaunchAgents/` |
| Linux | `openclaw-gateway.service` (or `openclaw-gateway-<profile>.service`) | `~/.config/systemd/user/` |
| Windows | `OpenClaw Gateway` (or `OpenClaw Gateway (<profile>)`) | Task Scheduler |

Service configs embed metadata for version tracking and management:

- `OPENCLAW_SERVICE_MARKER=openclaw`
- `OPENCLAW_SERVICE_KIND=gateway`
- `OPENCLAW_SERVICE_VERSION=<version>`

**Sources**: [docs/gateway/index.md 52-68](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/index.md#L52-L68) [docs/cli/index.md 130-185](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/cli/index.md#L130-L185)

---

The CLI uses standard exit codes for script compatibility:

| Exit Code | Meaning | Example |
| --- | --- | --- |
| `0` | Success | Command completed successfully |
| `1` | General error | Invalid arguments, missing config |
| `143` | SIGTERM (graceful shutdown) | Service stop via supervisor |
| Non-zero | Command-specific failure | RPC timeout, auth failure |

Errors are written to **stderr** with structured formatting:

```
# CLI error (local)
[openclaw] Config validation failed: gateway.mode must be "local" or "remote"

# RPC error (Gateway)
[openclaw] Gateway RPC failed: connect ECONNREFUSED 127.0.0.1:18789

# Uncaught exception (fatal)
[openclaw] Uncaught exception: Error: ENOENT: no such file or directory
```

Fatal errors trigger `process.exit(1)` after logging. Unhandled promise rejections are caught and logged to prevent silent failures.

**Sources**: [src/index.ts 80-94](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/index.ts#L80-L94) [docs/gateway/index.md 38](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/index.md#L38-L38)

---

## Command Discovery and Help

### Built-in Help System

Every command provides contextual help:

```
# Top-level help
openclaw --help

# Category help
openclaw gateway --help
openclaw channels --help

# Command help
openclaw channels login --help
openclaw models auth setup-token --help
```

### Command Tree

The full command tree is documented in [CLI reference (index)](https://deepwiki.com/openclaw/openclaw/12-cli-reference) and follows this structure:

```
openclaw [global-opts] <category> <action> [options]
├── gateway (run|status|health|probe|install|start|stop|restart|...)
├── agent (run agent turn)
├── agents (list|add|delete)
├── message (send|read|react|delete|...)
├── channels (list|status|login|logout|add|remove|...)
├── models (status|list|set|auth|aliases|fallbacks|scan)
├── config (get|set|unset)
├── configure (interactive wizard)
├── setup/onboard (initial setup)
├── doctor (health checks + migrations)
├── status/health/logs (diagnostics)
├── sessions/memory/nodes/... (additional categories)
└── plugins (list|install|enable|disable|...)
```

**Sources**: [docs/cli/index.md 86-238](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/cli/index.md#L86-L238) [CHANGELOG.md 1-124](https://github.com/openclaw/openclaw/blob/bf6ec64f/CHANGELOG.md#L1-L124)

---

## Sub-Page Index

For detailed command documentation, see:

- **[Gateway Commands](https://deepwiki.com/openclaw/openclaw/12.1-gateway-commands)**: Gateway lifecycle (`gateway run`, `status`, `health`, `probe`, `call`, service management)
- **[Agent Commands](https://deepwiki.com/openclaw/openclaw/12.2-agent-commands)**: Agent execution (`agent`, `agents list/add/delete`, `message send`, session management)
- **[Channel Commands](https://deepwiki.com/openclaw/openclaw/12.3-channel-commands)**: Channel operations (`channels list/status/add/remove/login/logout`, `pairing approve`)
- **[Model Commands](https://deepwiki.com/openclaw/openclaw/12.4-model-commands)**: Model configuration (`models status/list/set/set-image`, `auth add/setup-token`, aliases, fallbacks)
- **[Configuration Commands](https://deepwiki.com/openclaw/openclaw/12.5-configuration-commands)**: Config management (`config get/set/unset`, `configure`, `setup`, `onboard`, `reset`, `uninstall`)
- **[Diagnostic Commands](https://deepwiki.com/openclaw/openclaw/12.6-diagnostic-commands)**: Troubleshooting (`doctor`, `status`, `health`, `logs`, `security audit`, `system event`)

**Sources**: [docs/cli/index.md 1-73](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/cli/index.md#L1-L73)

<svg id="mermaid-fu8dstus3vp" width="100%" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 2412 512" style="max-width: 512px;" role="graphics-document document" aria-roledescription="error"><g></g><g><path class="error-icon" d="m411.313,123.313c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32-9.375,9.375-20.688-20.688c-12.484-12.5-32.766-12.5-45.25,0l-16,16c-1.261,1.261-2.304,2.648-3.31,4.051-21.739-8.561-45.324-13.426-70.065-13.426-105.867,0-192,86.133-192,192s86.133,192 192,192 192-86.133 192-192c0-24.741-4.864-48.327-13.426-70.065 1.402-1.007 2.79-2.049 4.051-3.31l16-16c12.5-12.492 12.5-32.758 0-45.25l-20.688-20.688 9.375-9.375 32.001-31.999zm-219.313,100.687c-52.938,0-96,43.063-96,96 0,8.836-7.164,16-16,16s-16-7.164-16-16c0-70.578 57.422-128 128-128 8.836,0 16,7.164 16,16s-7.164,16-16,16z"></path><path class="error-icon" d="m459.02,148.98c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l16,16c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16.001-16z"></path><path class="error-icon" d="m340.395,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16-16c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l15.999,16z"></path><path class="error-icon" d="m400,64c8.844,0 16-7.164 16-16v-32c0-8.836-7.156-16-16-16-8.844,0-16,7.164-16,16v32c0,8.836 7.156,16 16,16z"></path><path class="error-icon" d="m496,96.586h-32c-8.844,0-16,7.164-16,16 0,8.836 7.156,16 16,16h32c8.844,0 16-7.164 16-16 0-8.836-7.156-16-16-16z"></path><path class="error-icon" d="m436.98,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688l32-32c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32c-6.251,6.25-6.251,16.375-0.001,22.625z"></path><text class="error-text" x="1440" y="250" font-size="150px" style="text-anchor: middle;">Syntax error in text</text> <text class="error-text" x="1250" y="400" font-size="100px" style="text-anchor: middle;">mermaid version 11.12.2</text></g></svg> <svg id="mermaid-7khuxtjp8f" width="100%" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 2412 512" style="max-width: 512px;" role="graphics-document document" aria-roledescription="error"><g></g><g><path class="error-icon" d="m411.313,123.313c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32-9.375,9.375-20.688-20.688c-12.484-12.5-32.766-12.5-45.25,0l-16,16c-1.261,1.261-2.304,2.648-3.31,4.051-21.739-8.561-45.324-13.426-70.065-13.426-105.867,0-192,86.133-192,192s86.133,192 192,192 192-86.133 192-192c0-24.741-4.864-48.327-13.426-70.065 1.402-1.007 2.79-2.049 4.051-3.31l16-16c12.5-12.492 12.5-32.758 0-45.25l-20.688-20.688 9.375-9.375 32.001-31.999zm-219.313,100.687c-52.938,0-96,43.063-96,96 0,8.836-7.164,16-16,16s-16-7.164-16-16c0-70.578 57.422-128 128-128 8.836,0 16,7.164 16,16s-7.164,16-16,16z"></path><path class="error-icon" d="m459.02,148.98c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l16,16c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16.001-16z"></path><path class="error-icon" d="m340.395,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16-16c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l15.999,16z"></path><path class="error-icon" d="m400,64c8.844,0 16-7.164 16-16v-32c0-8.836-7.156-16-16-16-8.844,0-16,7.164-16,16v32c0,8.836 7.156,16 16,16z"></path><path class="error-icon" d="m496,96.586h-32c-8.844,0-16,7.164-16,16 0,8.836 7.156,16 16,16h32c8.844,0 16-7.164 16-16 0-8.836-7.156-16-16-16z"></path><path class="error-icon" d="m436.98,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688l32-32c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32c-6.251,6.25-6.251,16.375-0.001,22.625z"></path><text class="error-text" x="1440" y="250" font-size="150px" style="text-anchor: middle;">Syntax error in text</text> <text class="error-text" x="1250" y="400" font-size="100px" style="text-anchor: middle;">mermaid version 11.12.2</text></g></svg> <svg id="mermaid-5cnv3xfsc84" width="100%" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 2412 512" style="max-width: 512px;" role="graphics-document document" aria-roledescription="error"><g></g><g><path class="error-icon" d="m411.313,123.313c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32-9.375,9.375-20.688-20.688c-12.484-12.5-32.766-12.5-45.25,0l-16,16c-1.261,1.261-2.304,2.648-3.31,4.051-21.739-8.561-45.324-13.426-70.065-13.426-105.867,0-192,86.133-192,192s86.133,192 192,192 192-86.133 192-192c0-24.741-4.864-48.327-13.426-70.065 1.402-1.007 2.79-2.049 4.051-3.31l16-16c12.5-12.492 12.5-32.758 0-45.25l-20.688-20.688 9.375-9.375 32.001-31.999zm-219.313,100.687c-52.938,0-96,43.063-96,96 0,8.836-7.164,16-16,16s-16-7.164-16-16c0-70.578 57.422-128 128-128 8.836,0 16,7.164 16,16s-7.164,16-16,16z"></path><path class="error-icon" d="m459.02,148.98c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l16,16c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16.001-16z"></path><path class="error-icon" d="m340.395,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16-16c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l15.999,16z"></path><path class="error-icon" d="m400,64c8.844,0 16-7.164 16-16v-32c0-8.836-7.156-16-16-16-8.844,0-16,7.164-16,16v32c0,8.836 7.156,16 16,16z"></path><path class="error-icon" d="m496,96.586h-32c-8.844,0-16,7.164-16,16 0,8.836 7.156,16 16,16h32c8.844,0 16-7.164 16-16 0-8.836-7.156-16-16-16z"></path><path class="error-icon" d="m436.98,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688l32-32c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32c-6.251,6.25-6.251,16.375-0.001,22.625z"></path><text class="error-text" x="1440" y="250" font-size="150px" style="text-anchor: middle;">Syntax error in text</text> <text class="error-text" x="1250" y="400" font-size="100px" style="text-anchor: middle;">mermaid version 11.12.2</text></g></svg>