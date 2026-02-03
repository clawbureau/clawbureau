Menu

## Overview

Relevant source files
- [.npmrc](https://github.com/openclaw/openclaw/blob/bf6ec64f/.npmrc)
- [AGENTS.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/AGENTS.md)
- [CHANGELOG.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/CHANGELOG.md)
- [README.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md)
- [apps/android/app/build.gradle.kts](https://github.com/openclaw/openclaw/blob/bf6ec64f/apps/android/app/build.gradle.kts)
- [apps/ios/Sources/Info.plist](https://github.com/openclaw/openclaw/blob/bf6ec64f/apps/ios/Sources/Info.plist)
- [apps/ios/Tests/Info.plist](https://github.com/openclaw/openclaw/blob/bf6ec64f/apps/ios/Tests/Info.plist)
- [apps/ios/project.yml](https://github.com/openclaw/openclaw/blob/bf6ec64f/apps/ios/project.yml)
- [assets/avatar-placeholder.svg](https://github.com/openclaw/openclaw/blob/bf6ec64f/assets/avatar-placeholder.svg)
- [docs/docs.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/docs.json)
- [docs/help/faq.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/help/faq.md)
- [docs/help/index.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/help/index.md)
- [docs/help/troubleshooting.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/help/troubleshooting.md)
- [docs/install/index.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/install/index.md)
- [docs/install/installer.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/install/installer.md)
- [docs/install/migrating.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/install/migrating.md)
- [docs/northflank.mdx](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/northflank.mdx)
- [docs/platforms/digitalocean.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/platforms/digitalocean.md)
- [docs/platforms/exe-dev.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/platforms/exe-dev.md)
- [docs/platforms/fly.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/platforms/fly.md)
- [docs/platforms/gcp.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/platforms/gcp.md)
- [docs/platforms/index.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/platforms/index.md)
- [docs/platforms/linux.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/platforms/linux.md)
- [docs/platforms/mac/release.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/platforms/mac/release.md)
- [docs/platforms/oracle.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/platforms/oracle.md)
- [docs/platforms/windows.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/platforms/windows.md)
- [docs/reference/RELEASING.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/reference/RELEASING.md)
- [docs/start/hubs.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/start/hubs.md)
- [docs/vps.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/vps.md)
- [extensions/memory-core/package.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/extensions/memory-core/package.json)
- [fly.private.toml](https://github.com/openclaw/openclaw/blob/bf6ec64f/fly.private.toml)
- [fly.toml](https://github.com/openclaw/openclaw/blob/bf6ec64f/fly.toml)
- [package.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json)
- [pnpm-lock.yaml](https://github.com/openclaw/openclaw/blob/bf6ec64f/pnpm-lock.yaml)
- [pnpm-workspace.yaml](https://github.com/openclaw/openclaw/blob/bf6ec64f/pnpm-workspace.yaml)
- [scripts/clawtributors-map.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/clawtributors-map.json)
- [scripts/update-clawtributors.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/update-clawtributors.ts)
- [scripts/update-clawtributors.types.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/update-clawtributors.types.ts)
- [scripts/write-build-info.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/write-build-info.ts)
- [src/agents/pi-embedded-runner-extraparams.live.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner-extraparams.live.test.ts)
- [src/agents/pi-embedded-runner-extraparams.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner-extraparams.test.ts)
- [src/discord/monitor/presence-cache.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/discord/monitor/presence-cache.test.ts)
- [src/index.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/index.ts)
- [src/infra/git-commit.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/infra/git-commit.ts)
- [ui/package.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/ui/package.json)
- [ui/src/styles.css](https://github.com/openclaw/openclaw/blob/bf6ec64f/ui/src/styles.css)
- [ui/src/styles/layout.mobile.css](https://github.com/openclaw/openclaw/blob/bf6ec64f/ui/src/styles/layout.mobile.css)

## Purpose and Scope

This document provides a technical introduction to the OpenClaw codebase: its purpose, architecture, core components, and how they fit together. It explains what OpenClaw is, how it's structured at a high level, and where to find key subsystems in code.

For detailed installation steps, see [Quick Start](https://deepwiki.com/openclaw/openclaw/1.2-quick-start). For configuration reference, see [Configuration File Structure](https://deepwiki.com/openclaw/openclaw/4.1-configuration-file-structure). For deep dives into agent execution, see [Agent Execution Flow](https://deepwiki.com/openclaw/openclaw/5.1-agent-execution-flow).

---

## What is OpenClaw

OpenClaw is a **personal AI assistant platform** that runs on your own infrastructure. It connects AI models (Claude, GPT, Gemini, local models) to messaging channels you already use (WhatsApp, Telegram, Discord, Slack, Signal, iMessage, Microsoft Teams, and 15+ more via plugins). The system is designed for single-user or small-team deployment with local-first control, extensive tooling, and multi-agent routing.

**Sources:**[README.md 1-23](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md#L1-L23) [package.json 1-14](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json#L1-L14)

---

## Core Architecture

```
Extensions: extensions/*Messaging Channels: src/Agent Runtime: src/agents/Gateway Control Plane: src/gateway/User InterfacesRPCWebSocketWebSocketBridge ProtocolBonjour DiscoveryDNS-SDRoute MessagesRoute MessagesRoute MessagesRoute MessagesRoute MessagesRoute Messagesopenclaw CLI
bin: openclaw.mjsControl UI
ui/src/Terminal UI
src/tui/macOS App
apps/macos/iOS Node
apps/ios/Android Node
apps/android/server.ts
WebSocket Server
default port 18789src/config/sessions.ts
Session Storesrc/config/config.ts
loadConfig()src/cron/
Cron Schedulersrc/infra/presence.ts
Health Monitorpiembeddedrunner.ts
Pi Agent Core RPCprompt-builder.ts
Context Assemblysrc/memory/
Hybrid Searchsrc/agents/tools.ts
Tool Definitionssrc/agents/sandbox.ts
Docker Isolationprovider-web.ts
Baileystelegram/
grammYdiscord/
discord.jsslack/
Boltsignal/
signal-cliimessage/
imsgmsteams/
@microsoft/agents-hostingmatrix/
matrix-bot-sdknostr/
nostr-toolsvoice-call/memory-core/bluebubbles/
```

**Description:** OpenClaw's architecture centers on a **Gateway Control Plane** ([src/gateway/server.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/server.ts)) that orchestrates all system components. The Gateway exposes a WebSocket server (default port 18789) that accepts connections from CLI, Control UI, TUI, and companion apps. It routes messages between channels and the agent runtime, manages sessions, handles cron jobs, and monitors system health. The **Agent Runtime** ([src/agents/piembeddedrunner.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/piembeddedrunner.ts)) executes AI interactions using the Pi Agent Core library, builds dynamic system prompts, queries memory search, and invokes tools. The system is extensible via plugins loaded from [extensions/](https://github.com/openclaw/openclaw/blob/bf6ec64f/extensions/)

**Sources:**[src/gateway/server.ts 1-100](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/server.ts#L1-L100) [src/agents/piembeddedrunner.ts 1-50](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/piembeddedrunner.ts#L1-L50) [src/index.ts 1-95](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/index.ts#L1-L95) [README.md 132-167](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md#L132-L167)

---

## System Entry Points

```
Core ServicesCommand RoutingCLI Entry: openclaw.mjsopenclaw.mjs
Shebang wrappersrc/index.ts
Main modulesrc/cli/program.ts
buildProgram()src/commands/gateway.ts
gateway subcommandssrc/commands/agent.ts
agent subcommandssrc/commands/channels.ts
channels subcommandssrc/commands/configure.ts
config/configure/onboardsrc/commands/doctor.ts
doctor/setupsrc/gateway/server.ts
Gateway Servicesrc/agents/piembeddedrunner.ts
Agent Servicesrc/tui/
Terminal UI
```

**Description:** The `openclaw` command ([openclaw.mjs](https://github.com/openclaw/openclaw/blob/bf6ec64f/openclaw.mjs)) serves as the main entry point. It loads [src/index.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/index.ts) which sets up environment, installs error handlers, and builds the CLI program via [src/cli/program.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cli/program.ts) using Commander.js. The program registers command groups under [src/commands/](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/) (gateway, agent, channels, config, doctor, etc.), which route to their respective services. The Gateway and Agent services can run as background daemons (launchd/systemd) or interactively.

**Sources:**[openclaw.mjs 1-10](https://github.com/openclaw/openclaw/blob/bf6ec64f/openclaw.mjs#L1-L10) [src/index.ts 47-94](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/index.ts#L47-L94) [src/cli/program.ts 1-50](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cli/program.ts#L1-L50) [package.json 12-14](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json#L12-L14)

---

## Configuration and State

OpenClaw stores configuration in `~/.openclaw/openclaw.json` (JSON5 format) and state/sessions in `~/.openclaw/`. The configuration loader ([src/config/config.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/config.ts#LNaN-LNaN)) applies precedence: environment variables override config file values, which override system defaults. The [doctor command](https://deepwiki.com/openclaw/openclaw/12.6-diagnostic-commands) auto-migrates legacy paths and config schemas.

### Configuration File Location

| Setting | Default Path | Override |
| --- | --- | --- |
| Config | `~/.openclaw/openclaw.json` | `OPENCLAW_CONFIG_PATH` |
| State | `~/.openclaw/` | `OPENCLAW_STATE_DIR` |
| Workspace | `~/.openclaw/workspace/` | `agents.defaults.workspace` |

**Sources:**[src/config/config.ts 1-100](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/config.ts#L1-L100) [docs/gateway/configuration.md 1-50](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/configuration.md#L1-L50) [README.md 295-313](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md#L295-L313)

---

## Agent Execution Model

```
Inbound Message
from ChannelresolveSessionKey()
src/config/sessions.tsSession Lock
sequential/concurrentPiEmbeddedRunner
src/agents/piembeddedrunner.tsbuildSystemPrompt()
src/agents/prompt-builder.tssearchMemory()
src/memory/Model Provider
Anthropic/OpenAI/etcTool Execution
src/agents/tools.tsDocker Sandbox
src/agents/sandbox.tsStream Response
Block StreamingsaveSessionStore()
src/config/sessions.ts
```

**Description:** When a message arrives from a channel, [resolveSessionKey()](https://github.com/openclaw/openclaw/blob/bf6ec64f/resolveSessionKey\(\)) in [src/config/sessions.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/sessions.ts) determines the session ID (e.g., `main` for direct user chats, `dm:channel:id` for DMs, `group:channel:id` for groups). The [PiEmbeddedRunner](https://github.com/openclaw/openclaw/blob/bf6ec64f/PiEmbeddedRunner) in [src/agents/piembeddedrunner.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/piembeddedrunner.ts) loads session history, builds a system prompt via [src/agents/prompt-builder.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/prompt-builder.ts) queries memory search ([src/memory/](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/)), and streams the request to model providers. Tool calls are intercepted, executed (optionally in Docker sandboxes via [src/agents/sandbox.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/sandbox.ts)), and results are streamed back to the channel. Session state is persisted after each turn.

**Sources:**[src/agents/piembeddedrunner.ts 1-360](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/piembeddedrunner.ts#L1-L360) [src/config/sessions.ts 1-100](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/sessions.ts#L1-L100) [src/agents/prompt-builder.ts 1-50](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/prompt-builder.ts#L1-L50) [src/memory/ 1-50](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/#L1-L50)

---

## Message Routing and Channel Integration

OpenClaw routes messages through a unified auto-reply system ([src/auto-reply/reply.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/reply.ts#LNaN-LNaN)) that handles access control, session resolution, and agent dispatch. Each channel adapter ([src/telegram/](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/telegram/) [src/discord/](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/discord/) [src/slack/](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/slack/) etc.) implements:

1. **Authentication** (bot tokens, QR login, OAuth)
2. **Inbound parsing** (text, media, reactions, threads)
3. **Access control** (allowlists, pairing, DM policies)
4. **Outbound formatting** (markdown, chunking, media uploads)

Channels are enabled via configuration (e.g., `channels.discord.enabled: true`) and environment variables (e.g., `DISCORD_BOT_TOKEN`).

**Sources:**[src/auto-reply/reply.ts 1-100](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/reply.ts#L1-L100) [src/telegram/ 1-50](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/telegram/#L1-L50) [src/discord/ 1-50](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/discord/#L1-L50) [src/slack/ 1-50](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/slack/#L1-L50) [src/provider-web.ts 1-100](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/provider-web.ts#L1-L100)

---

## Plugin Architecture

```
Integration SlotsPlugin TypesPlugin Loader
src/plugins/loader.tspackage.json
openclaw.extensions fieldConfig Schema
TypeBox ValidationChannel Plugin
extensions/msteams/Tool Plugin
extensions/lobster/Memory Plugin
extensions/memory-core/Provider Plugin
Custom InferenceChannel Slot
Message RoutingTool Slot
Agent CapabilitiesMemory Slot
Search BackendProvider Slot
Model Inference
```

**Description:** Plugins live in [extensions/](https://github.com/openclaw/openclaw/blob/bf6ec64f/extensions/) as workspace packages. The [plugin loader](https://github.com/openclaw/openclaw/blob/bf6ec64f/plugin%20loader) in [src/plugins/loader.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/plugins/loader.ts) discovers plugins by scanning `package.json` files for the `openclaw.extensions` field. Each plugin declares its type (channel, tool, memory, provider), config schema (TypeBox), and entry point. The loader validates schemas, loads plugins via jiti, and registers them into the appropriate slot (channel router, tool registry, memory search, or model providers). Bundled plugins are auto-enabled when configuration is present.

**Sources:**[extensions/memory-core/package.json 1-18](https://github.com/openclaw/openclaw/blob/bf6ec64f/extensions/memory-core/package.json#L1-L18) [extensions/msteams/ 1-50](https://github.com/openclaw/openclaw/blob/bf6ec64f/extensions/msteams/#L1-L50) [extensions/matrix/ 1-50](https://github.com/openclaw/openclaw/blob/bf6ec64f/extensions/matrix/#L1-L50) [src/plugins/loader.ts 1-100](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/plugins/loader.ts#L1-L100)

---

## Deployment Models

OpenClaw supports four primary deployment patterns:

| Model | Environment | Gateway Host | State Storage | Access Method |
| --- | --- | --- | --- | --- |
| **Local Dev** | Developer machine | `pnpm dev` | `~/.openclaw/` | Loopback (`127.0.0.1:18789`) |
| **macOS Production** | macOS App | LaunchAgent | `~/.openclaw/` | Loopback + SSH/Tailscale |
| **Linux/VM** | VPS/VM | systemd service | `~/.openclaw/` | Loopback + SSH tunnel |
| **Cloud (Fly.io)** | Docker container | Fly.io machine | Persistent volume | HTTPS ingress |

All deployments support the same client interfaces (CLI, Web UI, mobile apps) with token/password authentication for non-loopback bindings.

**Sources:**[docs/platforms/fly.md 1-100](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/platforms/fly.md#L1-L100) [docs/platforms/linux.md 1-50](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/platforms/linux.md#L1-L50) [fly.toml 1-77](https://github.com/openclaw/openclaw/blob/bf6ec64f/fly.toml#L1-L77) [README.md 211-220](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md#L211-L220)

---

## Key Technologies

| Component | Technology | Location |
| --- | --- | --- |
| **Runtime** | Node.js ≥22 | Required |
| **Agent Core** | `@mariozechner/pi-agent-core` | [package.json 166](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json#L166-L166) |
| **CLI Framework** | Commander.js | [src/cli/program.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cli/program.ts) |
| **WebSocket Server** | `ws` library | [src/gateway/server.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/server.ts) |
| **Messaging** | Baileys, grammY, discord.js, Bolt | [src/](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/) |
| **UI** | Lit (web components) | [ui/](https://github.com/openclaw/openclaw/blob/bf6ec64f/ui/) |
| **Storage** | JSON5 files, SQLite (memory) | [src/config/](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/) [src/memory/](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/) |
| **Sandboxing** | Docker | [src/agents/sandbox.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/sandbox.ts) |
| **Schema Validation** | TypeBox, Zod | [src/config/schema.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/schema.ts) |

**Sources:**[package.json 155-210](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json#L155-L210) [src/gateway/server.ts 1-50](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/server.ts#L1-L50) [src/agents/piembeddedrunner.ts 1-50](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/piembeddedrunner.ts#L1-L50)

---

## Directory Structure

```
openclaw/
├── src/                    # TypeScript source
│   ├── agents/            # Agent runtime, tools, sandbox
│   ├── gateway/           # Gateway server, protocol
│   ├── config/            # Configuration, sessions
│   ├── cli/               # CLI commands
│   ├── commands/          # Command implementations
│   ├── telegram/          # Telegram channel
│   ├── discord/           # Discord channel
│   ├── slack/             # Slack channel
│   ├── signal/            # Signal channel
│   ├── imessage/          # iMessage channel
│   ├── memory/            # Memory search
│   ├── web/               # Control UI backend
│   └── ...
├── extensions/            # Plugin workspace packages
│   ├── msteams/          # Microsoft Teams plugin
│   ├── matrix/           # Matrix plugin
│   ├── memory-core/      # Core memory plugin
│   └── ...
├── apps/                  # Companion apps
│   ├── macos/            # macOS menu bar app (Swift)
│   ├── ios/              # iOS node app (Swift)
│   └── android/          # Android node app (Kotlin)
├── ui/                    # Control UI frontend (Lit)
├── docs/                  # Documentation (Mintlify)
├── skills/                # Bundled skills
├── dist/                  # Build output
├── openclaw.mjs          # CLI entry point
├── package.json          # npm package manifest
├── tsconfig.json         # TypeScript config
└── fly.toml              # Fly.io deployment config
```

**Sources:**[package.json 16-79](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json#L16-L79) [pnpm-workspace.yaml 1-15](https://github.com/openclaw/openclaw/blob/bf6ec64f/pnpm-workspace.yaml#L1-L15) [README.md 130-167](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md#L130-L167)