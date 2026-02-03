Menu

## Development

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
- [docs/platforms/fly.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/platforms/fly.md)
- [docs/platforms/mac/release.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/platforms/mac/release.md)
- [docs/reference/RELEASING.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/reference/RELEASING.md)
- [extensions/memory-core/package.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/extensions/memory-core/package.json)
- [fly.private.toml](https://github.com/openclaw/openclaw/blob/bf6ec64f/fly.private.toml)
- [fly.toml](https://github.com/openclaw/openclaw/blob/bf6ec64f/fly.toml)
- [package.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json)
- [pnpm-lock.yaml](https://github.com/openclaw/openclaw/blob/bf6ec64f/pnpm-lock.yaml)
- [pnpm-workspace.yaml](https://github.com/openclaw/openclaw/blob/bf6ec64f/pnpm-workspace.yaml)
- [scripts/clawtributors-map.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/clawtributors-map.json)
- [scripts/protocol-gen-swift.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/protocol-gen-swift.ts)
- [scripts/update-clawtributors.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/update-clawtributors.ts)
- [scripts/update-clawtributors.types.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/update-clawtributors.types.ts)
- [scripts/write-build-info.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/write-build-info.ts)
- [src/agents/pi-embedded-runner-extraparams.live.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner-extraparams.live.test.ts)
- [src/agents/pi-embedded-runner-extraparams.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner-extraparams.test.ts)
- [src/cron/run-log.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cron/run-log.test.ts)
- [src/cron/run-log.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cron/run-log.ts)
- [src/cron/store.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cron/store.ts)
- [src/gateway/protocol/index.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/protocol/index.ts)
- [src/gateway/protocol/schema.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/protocol/schema.ts)
- [src/gateway/server.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/server.ts)
- [src/index.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/index.ts)
- [src/infra/git-commit.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/infra/git-commit.ts)
- [ui/package.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/ui/package.json)
- [ui/src/styles.css](https://github.com/openclaw/openclaw/blob/bf6ec64f/ui/src/styles.css)
- [ui/src/styles/layout.mobile.css](https://github.com/openclaw/openclaw/blob/bf6ec64f/ui/src/styles/layout.mobile.css)

This section provides resources for developers working on OpenClaw: architecture documentation, development environment setup, build processes, protocol specifications, and release procedures. For operational guidance on running OpenClaw, see [Operations and Troubleshooting](https://deepwiki.com/openclaw/openclaw/14-operations-and-troubleshooting). For deployment instructions, see [Deployment](https://deepwiki.com/openclaw/openclaw/13-deployment).

## Repository Structure

OpenClaw is organized as a TypeScript monorepo with platform-specific applications and extensions.

### Directory Layout

```
extensions/ Pluginsapps/ Platformssrc/ ModulesRootsrc/
Core TypeScriptdist/
Build Outputapps/
Platform Appsextensions/
Plugin Systemui/
Control UIdocs/
Documentationscripts/
Build Toolsskills/
Bundled Skillssrc/cli/
CLI Commandssrc/gateway/
Gateway Serversrc/agents/
Agent Runtimesrc/channels/
Channel Integrationssrc/config/
Configurationsrc/infra/
Infrastructuresrc/media/
Media Pipelinesrc/memory/
Memory Searchapps/ios/
iOS Nodeapps/android/
Android Nodeapps/shared/
OpenClawKit Swiftextensions/memory-coreextensions/msteamsextensions/matrixextensions/nostrextensions/zaloextensions/... (20+)
```

**Sources:**[AGENTS.md 1-17](https://github.com/openclaw/openclaw/blob/bf6ec64f/AGENTS.md#L1-L17) [README.md 130-167](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md#L130-L167) [package.json 1-287](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json#L1-L287)

### Key Files

| File | Purpose |
| --- | --- |
| `package.json` | npm package metadata, scripts, dependencies |
| `pnpm-lock.yaml` | Locked dependency tree |
| `pnpm-workspace.yaml` | Monorepo workspace configuration |
| `tsconfig.json` | TypeScript compiler configuration |
| `vitest.config.ts` | Test framework configuration |
| `openclaw.mjs` | CLI entry point (bin target) |
| `AGENTS.md` | Repository guidelines and conventions |
| `CHANGELOG.md` | Release history |

**Sources:**[AGENTS.md 1-164](https://github.com/openclaw/openclaw/blob/bf6ec64f/AGENTS.md#L1-L164) [package.json 1-14](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json#L1-L14) [pnpm-workspace.yaml 1-15](https://github.com/openclaw/openclaw/blob/bf6ec64f/pnpm-workspace.yaml#L1-L15)

## Development Environment

### Requirements

- **Node.js**: ≥22.12.0 (specified in `package.json` engines)
- **Package Manager**: pnpm (recommended), npm, or Bun
- **TypeScript**: 5.9+ (dev dependency)
- **Build Tools**: Configured via package scripts

**Sources:**[package.json 152-154](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json#L152-L154) [README.md 42-56](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md#L42-L56)

### Initial Setup

```
# Clone repository
git clone https://github.com/openclaw/openclaw.git
cd openclaw

# Install dependencies
pnpm install

# Build UI assets
pnpm ui:build

# Compile TypeScript
pnpm build

# Run development gateway
pnpm gateway:watch
```

The development setup uses `tsx` for running TypeScript directly during development, while production uses compiled JavaScript from `dist/`.

**Sources:**[README.md 82-101](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md#L82-L101) [package.json 80-149](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json#L80-L149)

### Pre-commit Hooks

OpenClaw uses `prek` for pre-commit validation:

```
prek install
```

This runs the same checks as CI: linting and formatting verification.

**Sources:**[AGENTS.md 41](https://github.com/openclaw/openclaw/blob/bf6ec64f/AGENTS.md#L41-L41)

## Build System

### Build Pipeline

```
Build OutputsBuild StepsBuild Inputssrc/**/*.tsui/src/**src/canvas-host/a2ui/
A2UI Assetspnpm canvas:a2ui:bundle
scripts/bundle-a2ui.shtsc -p tsconfig.jsonscripts/canvas-a2ui-copy.tsscripts/copy-hook-metadata.tsscripts/write-build-info.tspnpm ui:build
vite builddist/**/*.js
Compiled TypeScriptdist/canvas-host/a2ui/
Bundled Assetsdist/control-ui/
Web UIdist/build-info.json
Version + Commit
```

**Sources:**[package.json 88](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json#L88-L88) [scripts/write-build-info.ts 1-50](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/write-build-info.ts#L1-L50) [AGENTS.md 46-49](https://github.com/openclaw/openclaw/blob/bf6ec64f/AGENTS.md#L46-L49)

### Build Scripts

| Command | Purpose |
| --- | --- |
| `pnpm build` | Full production build (TypeScript + assets) |
| `pnpm ui:build` | Build Control UI web assets |
| `pnpm canvas:a2ui:bundle` | Bundle A2UI host assets |
| `pnpm gateway:watch` | Development mode with auto-reload |
| `pnpm lint` | Run oxlint on TypeScript sources |
| `pnpm format` | Check formatting with oxfmt |
| `pnpm format:fix` | Auto-fix formatting issues |

**Sources:**[package.json 80-149](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json#L80-L149) [AGENTS.md 46-49](https://github.com/openclaw/openclaw/blob/bf6ec64f/AGENTS.md#L46-L49)

### Build Artifacts

The `dist/` directory contains compiled output organized by module:

```
dist/
├── agents/          # Agent execution system
├── channels/        # Channel integrations
├── cli/             # CLI command handlers
├── config/          # Configuration system
├── gateway/         # Gateway server
├── plugin-sdk/      # Plugin development SDK
├── control-ui/      # Built web UI
├── canvas-host/     # A2UI host
├── build-info.json  # Version and commit metadata
└── index.js         # Main entry point
```

The `files` field in `package.json` specifies which `dist/` subdirectories are included in npm packages.

**Sources:**[package.json 16-79](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json#L16-L79)

## Testing Strategy

### Test Hierarchy

```
Test TargetsTest CommandsTest TypesUnit Tests
*.test.ts
Colocated with sourceE2E Tests
*.e2e.test.ts
End-to-end flowsLive Tests
*.live.test.ts
Real API callsDocker Tests
scripts/test-*.sh
Clean environmentspnpm test
Vitest unit + e2epnpm test:live
CLAWDBOT_LIVE_TEST=1pnpm test:docker:all
Full Docker suitepnpm test:coverage
Coverage reportConfiguration SystemGateway ProtocolAgent RuntimeChannel RoutingModel Providers
```

**Sources:**[AGENTS.md 64-72](https://github.com/openclaw/openclaw/blob/bf6ec64f/AGENTS.md#L64-L72) [package.json 122-138](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json#L122-L138)

### Running Tests

```
# Unit and E2E tests
pnpm test

# With coverage report
pnpm test:coverage

# Watch mode (auto-rerun on changes)
pnpm test:watch

# Live tests (requires API keys)
CLAWDBOT_LIVE_TEST=1 pnpm test:live

# Docker smoke test (fast)
OPENCLAW_INSTALL_SMOKE_SKIP_NONROOT=1 pnpm test:install:smoke

# Docker E2E (requires API keys)
pnpm test:install:e2e:anthropic  # ANTHROPIC_API_KEY
pnpm test:install:e2e:openai     # OPENAI_API_KEY
```

**Sources:**[AGENTS.md 64-72](https://github.com/openclaw/openclaw/blob/bf6ec64f/AGENTS.md#L64-L72) [package.json 122-142](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json#L122-L142)

### Coverage Thresholds

Vitest enforces 70% coverage for lines, functions, branches, and statements. Configuration in `package.json`:

```
"vitest": {
  "coverage": {
    "thresholds": {
      "lines": 70,
      "functions": 70,
      "branches": 70,
      "statements": 70
    }
  }
}
```

**Sources:**[package.json 255-274](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json#L255-L274)

## Development Workflow

### Daily Development

```
CommitLocal TestingValidationEdit CodeEdit src/**/*.tsAdd *.test.tspnpm lintpnpm formatpnpm testpnpm gateway:watchpnpm tuiscripts/committer "msg" file...prek pre-commit hooks
```

**Sources:**[AGENTS.md 74-91](https://github.com/openclaw/openclaw/blob/bf6ec64f/AGENTS.md#L74-L91) [README.md 82-101](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md#L82-L101)

### Commit Standards

OpenClaw uses a custom commit script to enforce scoped changes:

```
# Group related changes
scripts/committer "CLI: add verbose flag to send" src/commands/send.ts src/cli/program.ts

# Avoid manual git add/commit
```

Commits should:

- Use action-oriented messages (e.g., "CLI: add verbose flag")
- Group related changes together
- Avoid bundling unrelated refactors

**Sources:**[AGENTS.md 74-91](https://github.com/openclaw/openclaw/blob/bf6ec64f/AGENTS.md#L74-L91)

### Code Style

- **Language**: TypeScript (ESM modules)
- **Formatting**: Oxfmt (run `pnpm format`)
- **Linting**: Oxlint (run `pnpm lint`)
- **File Size**: Target <700 LOC per file (guideline, not strict)
- **Comments**: Add brief explanations for tricky logic
- **Naming**: Use `OpenClaw` for product, `openclaw` for CLI/code

**Sources:**[AGENTS.md 51-58](https://github.com/openclaw/openclaw/blob/bf6ec64f/AGENTS.md#L51-L58) [package.json 114-121](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json#L114-L121)

## Contribution Guidelines

### Pull Request Workflow

```
MergeReviewValidationPR CreationFork RepositoryCreate Feature BranchImplement ChangesAdd/Update Testspnpm lintpnpm buildpnpm testpnpm test:install:smokeOpen Pull RequestCode ReviewRebase on MainSquash if MessyAdd Changelog EntryMerge to Main
```

**Sources:**[AGENTS.md 74-91](https://github.com/openclaw/openclaw/blob/bf6ec64f/AGENTS.md#L74-L91) [CHANGELOG.md 1-71](https://github.com/openclaw/openclaw/blob/bf6ec64f/CHANGELOG.md#L1-L71)

### PR Requirements

1. **Tests**: Add tests for new functionality
2. **Linting**: Pass `pnpm lint` and `pnpm format`
3. **Build**: Clean `pnpm build` output
4. **Smoke Test**: Pass installer smoke test (before major releases)
5. **Changelog**: Add entry for user-facing changes
6. **Documentation**: Update relevant docs

**Sources:**[AGENTS.md 74-91](https://github.com/openclaw/openclaw/blob/bf6ec64f/AGENTS.md#L74-L91) [docs/reference/RELEASING.md 39-50](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/reference/RELEASING.md#L39-L50)

### Changelog Format

Changelogs follow a strict format with sections:

- **Highlights**: Major features
- **Changes**: New functionality
- **Fixes**: Bug fixes
- **Breaking**: Breaking changes (if any)

Each entry includes:

- Component prefix (e.g., "CLI:", "Gateway:", "Agents:")
- Brief description
- Issue/PR number
- Contributor credit (e.g., "Thanks @username")

**Sources:**[CHANGELOG.md 1-71](https://github.com/openclaw/openclaw/blob/bf6ec64f/CHANGELOG.md#L1-L71) [AGENTS.md 78-79](https://github.com/openclaw/openclaw/blob/bf6ec64f/AGENTS.md#L78-L79)

### Merge Strategy

- **Prefer rebase** for clean commit history
- **Squash** when commit history is messy
- **Add co-author** when squashing contributor PRs
- Always include PR number and thanks in changelog

**Sources:**[AGENTS.md 84-91](https://github.com/openclaw/openclaw/blob/bf6ec64f/AGENTS.md#L84-L91)

## Architecture Overview

### Core Components

```
Config LayerChannel LayerAgent LayerGateway LayerEntry Pointsopenclaw.mjs
CLI Entrysrc/index.ts
Main Modulesrc/cli/program.ts
Commander Setupsrc/gateway/server.impl.ts
startGatewayServersrc/gateway/protocol/index.ts
Validation Functionssrc/gateway/protocol/schema/*.ts
TypeBox Schemassrc/agents/piembeddedrunner.ts
PiEmbeddedRunnersrc/agents/system-prompt.ts
buildSystemPromptsrc/memory/**
Memory Systemsrc/telegram/**
grammY Integrationsrc/discord/**
discord.js Integrationsrc/provider-web.ts
Baileys Integrationsrc/routing/**
Channel Routersrc/config/config.ts
loadConfigsrc/config/schema.ts
OpenClawSchemasrc/config/sessions.ts
Session Store
```

**Sources:**[src/index.ts 1-95](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/index.ts#L1-L95) [src/gateway/server.ts 1-4](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/server.ts#L1-L4) [src/gateway/protocol/index.ts 1-350](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/protocol/index.ts#L1-L350)

### Protocol Validation

OpenClaw uses Ajv for runtime schema validation with TypeBox schemas:

| Validator Function | Schema | Purpose |
| --- | --- | --- |
| `validateConnectParams` | `ConnectParamsSchema` | Client handshake |
| `validateRequestFrame` | `RequestFrameSchema` | RPC requests |
| `validateResponseFrame` | `ResponseFrameSchema` | RPC responses |
| `validateEventFrame` | `EventFrameSchema` | Server events |
| `validateAgentParams` | `AgentParamsSchema` | Agent invocation |
| `validateChatSendParams` | `ChatSendParamsSchema` | Chat messages |

**Sources:**[src/gateway/protocol/index.ts 194-322](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/protocol/index.ts#L194-L322) [src/gateway/protocol/schema.ts 1-17](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/protocol/schema.ts#L1-L17)

## Platform-Specific Development

### macOS App

The macOS menu bar app is built with Swift and SwiftUI:

```
# Generate Xcode project
pnpm ios:gen

# Open in Xcode
pnpm ios:open

# Package for distribution (dev)
scripts/package-mac-app.sh

# Package for release (signed + notarized)
scripts/package-mac-dist.sh
```

Packaging requires:

- Developer ID Application certificate
- Sparkle private key (`SPARKLE_PRIVATE_KEY_FILE`)
- App Store Connect API key (for notarization)

**Sources:**[README.md 267-279](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md#L267-L279) [docs/platforms/mac/release.md 1-78](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/platforms/mac/release.md#L1-L78) [package.json 111-113](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json#L111-L113)

### iOS Node

iOS app is generated via XcodeGen:

```
# Generate project
cd apps/ios && xcodegen generate

# Build for simulator
pnpm ios:build

# Run on simulator
pnpm ios:run
```

**Sources:**[package.json 103-106](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json#L103-L106) [apps/ios/project.yml 1-135](https://github.com/openclaw/openclaw/blob/bf6ec64f/apps/ios/project.yml#L1-L135)

### Android Node

Android app uses Gradle:

```
# Build debug APK
pnpm android:assemble

# Install on device
pnpm android:install

# Run on device
pnpm android:run
```

**Sources:**[package.json 107-110](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json#L107-L110) [apps/android/app/build.gradle.kts 1-129](https://github.com/openclaw/openclaw/blob/bf6ec64f/apps/android/app/build.gradle.kts#L1-L129)

## Protocol Generation

### Swift Code Generation

The Gateway protocol schemas are exported to Swift for iOS/macOS clients:

```
# Generate Swift models from TypeBox schemas
pnpm protocol:gen:swift
```

This generates `GatewayModels.swift` with Codable structs matching the TypeScript protocol definitions. Output locations:

- `apps/macos/Sources/OpenClawProtocol/GatewayModels.swift`
- `apps/shared/OpenClawKit/Sources/OpenClawProtocol/GatewayModels.swift`

**Sources:**[scripts/protocol-gen-swift.ts 1-150](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/protocol-gen-swift.ts#L1-L150) [package.json 144-145](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json#L144-L145)

### JSON Schema Export

Protocol schemas can be exported to JSON Schema:

```
pnpm protocol:gen
```

Generates `dist/protocol.schema.json` for external tooling.

**Sources:**[package.json 143](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json#L143-L143)

## Release Process Overview

Releases involve coordinated npm publishing and macOS app distribution. The full process is documented in child pages, but key files are:

| File | Purpose |
| --- | --- |
| `docs/reference/RELEASING.md` | npm release checklist |
| `docs/platforms/mac/release.md` | macOS app packaging |
| `scripts/make_appcast.sh` | Sparkle feed generation |
| `appcast.xml` | Sparkle update feed |

**Sources:**[docs/reference/RELEASING.md 1-108](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/reference/RELEASING.md#L1-L108) [docs/platforms/mac/release.md 1-78](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/platforms/mac/release.md#L1-L78)

### Version Synchronization

Versions must be updated in multiple locations:

| Location | Field | Format |
| --- | --- | --- |
| `package.json` | `version` | `2026.1.29` |
| `apps/android/app/build.gradle.kts` | `versionName`, `versionCode` | `2026.1.29`, `202601290` |
| `apps/ios/Sources/Info.plist` | `CFBundleShortVersionString`, `CFBundleVersion` | `2026.1.29`, `20260129` |
| `apps/macos/.../Info.plist` | `CFBundleShortVersionString`, `CFBundleVersion` | `2026.1.29`, `20260129` |

**Sources:**[AGENTS.md 125](https://github.com/openclaw/openclaw/blob/bf6ec64f/AGENTS.md#L125-L125) [package.json 2](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json#L2-L2) [apps/android/app/build.gradle.kts 24-25](https://github.com/openclaw/openclaw/blob/bf6ec64f/apps/android/app/build.gradle.kts#L24-L25) [apps/ios/Sources/Info.plist 21-24](https://github.com/openclaw/openclaw/blob/bf6ec64f/apps/ios/Sources/Info.plist#L21-L24)

## Plugin Development

OpenClaw supports four plugin types via the extension system:

1. **Channel Plugins**: New messaging platform integrations
2. **Tool Plugins**: New agent capabilities
3. **Provider Plugins**: Custom model inference backends
4. **Memory Plugins**: Alternative search providers

Plugins declare capabilities via `openclaw.extensions` in `package.json` and export a manifest matching the plugin SDK schema.

**Sources:**[AGENTS.md 9-10](https://github.com/openclaw/openclaw/blob/bf6ec64f/AGENTS.md#L9-L10) [extensions/memory-core/package.json 1-17](https://github.com/openclaw/openclaw/blob/bf6ec64f/extensions/memory-core/package.json#L1-L17)

### Plugin Workspace

Bundled plugins live in `extensions/`:

- `extensions/memory-core` - Core memory search
- `extensions/msteams` - Microsoft Teams
- `extensions/matrix` - Matrix protocol
- `extensions/nostr` - Nostr protocol
- `extensions/zalo` - Zalo messenger
- And 15+ more...

Plugin dependencies must be in `dependencies`, not `devDependencies`, as runtime loads them via `npm install --omit=dev`.

**Sources:**[AGENTS.md 9-10](https://github.com/openclaw/openclaw/blob/bf6ec64f/AGENTS.md#L9-L10) [pnpm-workspace.yaml 1-15](https://github.com/openclaw/openclaw/blob/bf6ec64f/pnpm-workspace.yaml#L1-L15)

## Cloud Deployment

### Fly.io Configuration

Two deployment templates are provided:

| File | Purpose | Public IP |
| --- | --- | --- |
| `fly.toml` | Standard deployment | Yes (HTTPS ingress) |
| `fly.private.toml` | Hardened deployment | No (proxy/tunnel only) |

Both mount a persistent volume at `/data` for state storage and require `OPENCLAW_STATE_DIR=/data`.

**Sources:**[fly.toml 1-35](https://github.com/openclaw/openclaw/blob/bf6ec64f/fly.toml#L1-L35) [fly.private.toml 1-40](https://github.com/openclaw/openclaw/blob/bf6ec64f/fly.private.toml#L1-L40) [docs/platforms/fly.md 1-400](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/platforms/fly.md#L1-L400)

### Docker Build

The repository includes a `Dockerfile` for containerized deployments. Key environment variables:

- `OPENCLAW_STATE_DIR` - State directory path (default: `~/.openclaw`)
- `OPENCLAW_GATEWAY_PORT` - Gateway port (default: `18789`)
- `NODE_OPTIONS` - Node.js flags (e.g., `--max-old-space-size=1536`)

**Sources:**[fly.toml 10-15](https://github.com/openclaw/openclaw/blob/bf6ec64f/fly.toml#L10-L15) [docs/platforms/fly.md 50-89](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/platforms/fly.md#L50-L89)

## Additional Resources

For detailed information on specific development topics, see:

- **[Architecture Deep Dive](https://deepwiki.com/openclaw/openclaw/15.1-architecture-deep-dive)** - Component interactions and design decisions
- **[Protocol Specification](https://deepwiki.com/openclaw/openclaw/15.2-protocol-specification)** - WebSocket protocol schemas and validation
- **[Building from Source](https://deepwiki.com/openclaw/openclaw/15.3-building-from-source)** - Detailed build setup and troubleshooting
- **[Release Process](https://deepwiki.com/openclaw/openclaw/15.4-release-process)** - Version management and distribution

<svg id="mermaid-fu8dstus3vp" width="100%" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 2412 512" style="max-width: 512px;" role="graphics-document document" aria-roledescription="error"><g></g><g><path class="error-icon" d="m411.313,123.313c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32-9.375,9.375-20.688-20.688c-12.484-12.5-32.766-12.5-45.25,0l-16,16c-1.261,1.261-2.304,2.648-3.31,4.051-21.739-8.561-45.324-13.426-70.065-13.426-105.867,0-192,86.133-192,192s86.133,192 192,192 192-86.133 192-192c0-24.741-4.864-48.327-13.426-70.065 1.402-1.007 2.79-2.049 4.051-3.31l16-16c12.5-12.492 12.5-32.758 0-45.25l-20.688-20.688 9.375-9.375 32.001-31.999zm-219.313,100.687c-52.938,0-96,43.063-96,96 0,8.836-7.164,16-16,16s-16-7.164-16-16c0-70.578 57.422-128 128-128 8.836,0 16,7.164 16,16s-7.164,16-16,16z"></path><path class="error-icon" d="m459.02,148.98c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l16,16c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16.001-16z"></path><path class="error-icon" d="m340.395,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16-16c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l15.999,16z"></path><path class="error-icon" d="m400,64c8.844,0 16-7.164 16-16v-32c0-8.836-7.156-16-16-16-8.844,0-16,7.164-16,16v32c0,8.836 7.156,16 16,16z"></path><path class="error-icon" d="m496,96.586h-32c-8.844,0-16,7.164-16,16 0,8.836 7.156,16 16,16h32c8.844,0 16-7.164 16-16 0-8.836-7.156-16-16-16z"></path><path class="error-icon" d="m436.98,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688l32-32c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32c-6.251,6.25-6.251,16.375-0.001,22.625z"></path><text class="error-text" x="1440" y="250" font-size="150px" style="text-anchor: middle;">Syntax error in text</text> <text class="error-text" x="1250" y="400" font-size="100px" style="text-anchor: middle;">mermaid version 11.12.2</text></g></svg> <svg id="mermaid-7khuxtjp8f" width="100%" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 2412 512" style="max-width: 512px;" role="graphics-document document" aria-roledescription="error"><g></g><g><path class="error-icon" d="m411.313,123.313c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32-9.375,9.375-20.688-20.688c-12.484-12.5-32.766-12.5-45.25,0l-16,16c-1.261,1.261-2.304,2.648-3.31,4.051-21.739-8.561-45.324-13.426-70.065-13.426-105.867,0-192,86.133-192,192s86.133,192 192,192 192-86.133 192-192c0-24.741-4.864-48.327-13.426-70.065 1.402-1.007 2.79-2.049 4.051-3.31l16-16c12.5-12.492 12.5-32.758 0-45.25l-20.688-20.688 9.375-9.375 32.001-31.999zm-219.313,100.687c-52.938,0-96,43.063-96,96 0,8.836-7.164,16-16,16s-16-7.164-16-16c0-70.578 57.422-128 128-128 8.836,0 16,7.164 16,16s-7.164,16-16,16z"></path><path class="error-icon" d="m459.02,148.98c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l16,16c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16.001-16z"></path><path class="error-icon" d="m340.395,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16-16c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l15.999,16z"></path><path class="error-icon" d="m400,64c8.844,0 16-7.164 16-16v-32c0-8.836-7.156-16-16-16-8.844,0-16,7.164-16,16v32c0,8.836 7.156,16 16,16z"></path><path class="error-icon" d="m496,96.586h-32c-8.844,0-16,7.164-16,16 0,8.836 7.156,16 16,16h32c8.844,0 16-7.164 16-16 0-8.836-7.156-16-16-16z"></path><path class="error-icon" d="m436.98,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688l32-32c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32c-6.251,6.25-6.251,16.375-0.001,22.625z"></path><text class="error-text" x="1440" y="250" font-size="150px" style="text-anchor: middle;">Syntax error in text</text> <text class="error-text" x="1250" y="400" font-size="100px" style="text-anchor: middle;">mermaid version 11.12.2</text></g></svg> <svg id="mermaid-5cnv3xfsc84" width="100%" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 2412 512" style="max-width: 512px;" role="graphics-document document" aria-roledescription="error"><g></g><g><path class="error-icon" d="m411.313,123.313c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32-9.375,9.375-20.688-20.688c-12.484-12.5-32.766-12.5-45.25,0l-16,16c-1.261,1.261-2.304,2.648-3.31,4.051-21.739-8.561-45.324-13.426-70.065-13.426-105.867,0-192,86.133-192,192s86.133,192 192,192 192-86.133 192-192c0-24.741-4.864-48.327-13.426-70.065 1.402-1.007 2.79-2.049 4.051-3.31l16-16c12.5-12.492 12.5-32.758 0-45.25l-20.688-20.688 9.375-9.375 32.001-31.999zm-219.313,100.687c-52.938,0-96,43.063-96,96 0,8.836-7.164,16-16,16s-16-7.164-16-16c0-70.578 57.422-128 128-128 8.836,0 16,7.164 16,16s-7.164,16-16,16z"></path><path class="error-icon" d="m459.02,148.98c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l16,16c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16.001-16z"></path><path class="error-icon" d="m340.395,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16-16c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l15.999,16z"></path><path class="error-icon" d="m400,64c8.844,0 16-7.164 16-16v-32c0-8.836-7.156-16-16-16-8.844,0-16,7.164-16,16v32c0,8.836 7.156,16 16,16z"></path><path class="error-icon" d="m496,96.586h-32c-8.844,0-16,7.164-16,16 0,8.836 7.156,16 16,16h32c8.844,0 16-7.164 16-16 0-8.836-7.156-16-16-16z"></path><path class="error-icon" d="m436.98,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688l32-32c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32c-6.251,6.25-6.251,16.375-0.001,22.625z"></path><text class="error-text" x="1440" y="250" font-size="150px" style="text-anchor: middle;">Syntax error in text</text> <text class="error-text" x="1250" y="400" font-size="100px" style="text-anchor: middle;">mermaid version 11.12.2</text></g></svg> <svg id="mermaid-hmbioix2qbm" width="100%" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 2412 512" style="max-width: 512px;" role="graphics-document document" aria-roledescription="error"><g></g><g><path class="error-icon" d="m411.313,123.313c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32-9.375,9.375-20.688-20.688c-12.484-12.5-32.766-12.5-45.25,0l-16,16c-1.261,1.261-2.304,2.648-3.31,4.051-21.739-8.561-45.324-13.426-70.065-13.426-105.867,0-192,86.133-192,192s86.133,192 192,192 192-86.133 192-192c0-24.741-4.864-48.327-13.426-70.065 1.402-1.007 2.79-2.049 4.051-3.31l16-16c12.5-12.492 12.5-32.758 0-45.25l-20.688-20.688 9.375-9.375 32.001-31.999zm-219.313,100.687c-52.938,0-96,43.063-96,96 0,8.836-7.164,16-16,16s-16-7.164-16-16c0-70.578 57.422-128 128-128 8.836,0 16,7.164 16,16s-7.164,16-16,16z"></path><path class="error-icon" d="m459.02,148.98c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l16,16c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16.001-16z"></path><path class="error-icon" d="m340.395,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16-16c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l15.999,16z"></path><path class="error-icon" d="m400,64c8.844,0 16-7.164 16-16v-32c0-8.836-7.156-16-16-16-8.844,0-16,7.164-16,16v32c0,8.836 7.156,16 16,16z"></path><path class="error-icon" d="m496,96.586h-32c-8.844,0-16,7.164-16,16 0,8.836 7.156,16 16,16h32c8.844,0 16-7.164 16-16 0-8.836-7.156-16-16-16z"></path><path class="error-icon" d="m436.98,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688l32-32c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32c-6.251,6.25-6.251,16.375-0.001,22.625z"></path><text class="error-text" x="1440" y="250" font-size="150px" style="text-anchor: middle;">Syntax error in text</text> <text class="error-text" x="1250" y="400" font-size="100px" style="text-anchor: middle;">mermaid version 11.12.2</text></g></svg> <svg id="mermaid-z5tp3lz1enf" width="100%" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 2412 512" style="max-width: 512px;" role="graphics-document document" aria-roledescription="error"><g></g><g><path class="error-icon" d="m411.313,123.313c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32-9.375,9.375-20.688-20.688c-12.484-12.5-32.766-12.5-45.25,0l-16,16c-1.261,1.261-2.304,2.648-3.31,4.051-21.739-8.561-45.324-13.426-70.065-13.426-105.867,0-192,86.133-192,192s86.133,192 192,192 192-86.133 192-192c0-24.741-4.864-48.327-13.426-70.065 1.402-1.007 2.79-2.049 4.051-3.31l16-16c12.5-12.492 12.5-32.758 0-45.25l-20.688-20.688 9.375-9.375 32.001-31.999zm-219.313,100.687c-52.938,0-96,43.063-96,96 0,8.836-7.164,16-16,16s-16-7.164-16-16c0-70.578 57.422-128 128-128 8.836,0 16,7.164 16,16s-7.164,16-16,16z"></path><path class="error-icon" d="m459.02,148.98c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l16,16c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16.001-16z"></path><path class="error-icon" d="m340.395,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16-16c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l15.999,16z"></path><path class="error-icon" d="m400,64c8.844,0 16-7.164 16-16v-32c0-8.836-7.156-16-16-16-8.844,0-16,7.164-16,16v32c0,8.836 7.156,16 16,16z"></path><path class="error-icon" d="m496,96.586h-32c-8.844,0-16,7.164-16,16 0,8.836 7.156,16 16,16h32c8.844,0 16-7.164 16-16 0-8.836-7.156-16-16-16z"></path><path class="error-icon" d="m436.98,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688l32-32c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32c-6.251,6.25-6.251,16.375-0.001,22.625z"></path><text class="error-text" x="1440" y="250" font-size="150px" style="text-anchor: middle;">Syntax error in text</text> <text class="error-text" x="1250" y="400" font-size="100px" style="text-anchor: middle;">mermaid version 11.12.2</text></g></svg>