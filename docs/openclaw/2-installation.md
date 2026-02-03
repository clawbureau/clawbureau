Menu

## Installation

Relevant source files
- [AGENTS.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/AGENTS.md)
- [apps/android/app/build.gradle.kts](https://github.com/openclaw/openclaw/blob/bf6ec64f/apps/android/app/build.gradle.kts)
- [apps/ios/Sources/Info.plist](https://github.com/openclaw/openclaw/blob/bf6ec64f/apps/ios/Sources/Info.plist)
- [apps/ios/Tests/Info.plist](https://github.com/openclaw/openclaw/blob/bf6ec64f/apps/ios/Tests/Info.plist)
- [apps/ios/project.yml](https://github.com/openclaw/openclaw/blob/bf6ec64f/apps/ios/project.yml)
- [docs/cli/index.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/cli/index.md)
- [docs/docs.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/docs.json)
- [docs/gateway/index.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/index.md)
- [docs/gateway/troubleshooting.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/troubleshooting.md)
- [docs/help/faq.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/help/faq.md)
- [docs/help/index.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/help/index.md)
- [docs/help/troubleshooting.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/help/troubleshooting.md)
- [docs/index.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/index.md)
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
- [docs/start/getting-started.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/start/getting-started.md)
- [docs/start/hubs.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/start/hubs.md)
- [docs/start/wizard.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/start/wizard.md)
- [docs/vps.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/vps.md)
- [fly.private.toml](https://github.com/openclaw/openclaw/blob/bf6ec64f/fly.private.toml)
- [fly.toml](https://github.com/openclaw/openclaw/blob/bf6ec64f/fly.toml)
- [scripts/write-build-info.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/write-build-info.ts)
- [src/discord/monitor/presence-cache.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/discord/monitor/presence-cache.test.ts)
- [src/infra/git-commit.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/infra/git-commit.ts)

This page provides a comprehensive guide to installing OpenClaw across all supported platforms and methods. It covers system requirements, installation approaches, and post-installation verification steps.

For a minimal quick-start path focused on getting your first message working, see [Quick Start](https://deepwiki.com/openclaw/openclaw/1.2-quick-start). For production deployment considerations (VPS, cloud platforms, networking), see [Deployment](https://deepwiki.com/openclaw/openclaw/13-deployment). For development setup from source with testing workflows, see [Building from Source](https://deepwiki.com/openclaw/openclaw/15.3-building-from-source).

---

## Purpose and Scope

This guide covers:

- System requirements and compatibility
- Three primary installation methods (installer script, npm global, from source)
- Platform-specific installation paths (macOS, Linux, Windows via WSL2)
- Service installation (LaunchAgent, systemd)
- Post-installation verification

After completing installation, you will have the `openclaw` CLI available and be ready to run the onboarding wizard (see [Onboarding Wizard](https://deepwiki.com/openclaw/openclaw/2.3-onboarding-wizard)).

---

## System Requirements

**Runtime baseline:**

- **Node.js ≥ 22** (required for all installations)
- Platform: macOS, Linux, or Windows via WSL2
- `pnpm` (only required for source builds)

**Runtime recommendations:**

- **Node** is the recommended runtime for the Gateway
- **Bun** is not recommended for Gateway execution (known issues with WhatsApp and Telegram channels)
- Bun is acceptable for CLI execution and development scripts

**Platform compatibility:**

| Platform | Gateway Support | Companion App | Service Supervisor |
| --- | --- | --- | --- |
| macOS | Full | Menu bar app | LaunchAgent |
| Linux | Full | Planned | systemd user unit |
| Windows (WSL2) | Full (recommended) | Planned | systemd user unit |
| Windows (native) | Untested | Planned | schtasks |
| iOS | Node runtime only | Node app | N/A |
| Android | Node runtime only | Node app | N/A |

**Disk space:**

- CLI + dependencies: ~500MB
- State directory (`~/.openclaw`): varies with usage (sessions, logs, memory)
- Workspace: varies with files created

**Memory recommendations:**

- Minimal: 512MB-1GB for personal use
- Recommended: 2GB for production deployments

Sources: [docs/help/faq.md 337-347](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/help/faq.md#L337-L347) [docs/index.md 101](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/index.md#L101-L101) [AGENTS.md 39](https://github.com/openclaw/openclaw/blob/bf6ec64f/AGENTS.md#L39-L39) [docs/platforms/index.md 9-10](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/platforms/index.md#L9-L10)

---

## Installation Methods Overview

```
Post-InstallConfiguration & StateInstallation OutputsInstallation MethodsUser on macOS/Linux/WSL2install.sh
(Recommended)npm install -g openclawGit Clone + BuildDocker
(see Docker guide)openclaw CLI
in PATHnode_modules/@openclawdist/
(compiled JS)openclaw.mjs
(entrypoint)~/.openclaw/
(OPENCLAW_STATE_DIR)openclaw.jsonworkspace/agents//sessions/credentials/openclaw onboard
--install-daemonService InstallationLaunchAgent
(macOS)systemd user unit
(Linux/WSL2)
```

**Key decision points:**

| Method | Best For | Trade-offs |
| --- | --- | --- |
| **Installer script** | Most users, quick setup | Requires internet, runs npm under the hood |
| **Global npm** | Users with existing Node setup | Manual steps, no automatic onboarding |
| **From source** | Contributors, customization | Requires `pnpm`, longer setup |
| **Docker** | Isolated environments, cloud deployments | Different workflow, see [Docker](https://deepwiki.com/openclaw/openclaw/2.2-installation-methods) |

Sources: [docs/install/index.md 36-98](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/install/index.md#L36-L98) [docs/start/getting-started.md 54-77](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/start/getting-started.md#L54-L77) [docs/index.md 100-131](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/index.md#L100-L131)

---

The installer script is the recommended path. It installs the CLI globally via npm, validates the installation, and optionally runs onboarding.

### Basic usage

**macOS / Linux / WSL2:**

```
curl -fsSL https://openclaw.bot/install.sh | bash
```

**Windows (PowerShell):**

```
iwr -useb https://openclaw.ai/install.ps1 | iex
```

The script will:

1. Check for Node.js ≥ 22
2. Install `openclaw` globally via npm (or pnpm if detected)
3. Verify the `openclaw` command is in PATH
4. Optionally launch the onboarding wizard

### Installer script flags

View all flags:

```
curl -fsSL https://openclaw.bot/install.sh | bash -s -- --help
```

**Common flags:**

| Flag | Purpose |
| --- | --- |
| `--verbose` | Show full npm output and trace |
| `--no-onboard` | Skip onboarding wizard |
| `--install-method git` | Install from GitHub checkout instead of npm |
| `--beta` | Install beta release (npm dist-tag `beta`) |
| `--accept-risk` | Non-interactive, accept all prompts |

### Install from GitHub checkout

To install from source with the installer:

```
curl -fsSL https://openclaw.bot/install.sh | bash -s -- --install-method git
```

This clones the repository to `~/.openclaw-src` and symlinks the CLI into your PATH.

### Non-interactive installation

For automation or CI:

```
curl -fsSL https://openclaw.bot/install.sh | bash -s -- --no-onboard --accept-risk
```

Then run onboarding separately:

```
openclaw onboard --non-interactive --mode local --auth-choice apiKey --anthropic-api-key "$ANTHROPIC_API_KEY"
```

Sources: [docs/install/index.md 40-51](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/install/index.md#L40-L51) [docs/install/installer.md 10-26](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/install/installer.md#L10-L26) [docs/help/faq.md 258-267](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/help/faq.md#L258-L267)

---

## Installation Method 2: Global npm Install

Manual installation via npm or pnpm.

### Standard global install

```
npm install -g openclaw@latest
```

or:

```
pnpm add -g openclaw@latest
```

### Sharp binary workaround (macOS)

If you have `libvips` installed globally (e.g., via Homebrew) and `sharp` fails to install:

```
SHARP_IGNORE_GLOBAL_LIBVIPS=1 npm install -g openclaw@latest
```

If you see `"sharp: Please add node-gyp to your dependencies"`, either:

- Install build tooling: `xcode-select --install` and `npm install -g node-gyp`
- Use the `SHARP_IGNORE_GLOBAL_LIBVIPS=1` workaround to skip native builds

### Beta release

```
npm install -g openclaw@beta
```

### Verify installation

```
openclaw --version
openclaw --help
```

### Post-install: Run onboarding

```
openclaw onboard --install-daemon
```

Sources: [docs/install/index.md 62-86](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/install/index.md#L62-L86) [docs/help/faq.md 294-301](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/help/faq.md#L294-L301)

---

## Installation Method 3: From Source

For contributors, development, or customization.

### Clone and build

```
# Clone repository
git clone https://github.com/openclaw/openclaw.git
cd openclaw

# Install dependencies
pnpm install

# Build Control UI assets (auto-installs UI deps on first run)
pnpm ui:build

# Build TypeScript to dist/
pnpm build

# Run onboarding
openclaw onboard --install-daemon
```

If you don't have a global `openclaw` command yet, run via `pnpm`:

```
pnpm openclaw onboard --install-daemon
```

### Build outputs

After `pnpm build`, key outputs:

- `dist/` - Compiled JavaScript
- `dist/build-info.json` - Commit hash and version metadata
- `openclaw.mjs` - CLI entrypoint (referenced by `package.json` `bin` field)
- `dist/node-host/**` - Headless node runtime
- `dist/acp/**` - ACP CLI (IDE integration)

### Development workflow

Run Gateway in watch mode:

```
pnpm gateway:watch
```

Run CLI commands in dev:

```
pnpm openclaw <command>
```

or:

```
bun openclaw.mjs <command>
```

Sources: [docs/install/index.md 88-99](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/install/index.md#L88-L99) [docs/index.md 120-131](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/index.md#L120-L131) [AGENTS.md 38-49](https://github.com/openclaw/openclaw/blob/bf6ec64f/AGENTS.md#L38-L49) [docs/reference/RELEASING.md 27-31](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/reference/RELEASING.md#L27-L31)

---

## Platform-Specific Installation

### macOS

**Requirements:**

- macOS 11+ (Big Sur or later)
- Node.js 22+ (install via Homebrew or nvm)

**Install Node via Homebrew:**

```
brew install node@22
```

**macOS companion app:**The OpenClaw menu bar app is available separately. It bundles the Gateway and provides:

- Menu bar status and controls
- Voice wake integration
- Local WebChat UI

To build the macOS app from source:

```
scripts/package-mac-app.sh
```

For releases, see [macOS release guide](https://deepwiki.com/openclaw/openclaw/15.4-release-process).

### Linux

**Requirements:**

- Ubuntu 20.04+, Debian 11+, or equivalent
- Node.js 22+

**Install Node via NodeSource:**

```
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs
```

**Service installation:**The Gateway installs as a systemd user unit:

```
openclaw gateway install
```

Service name: `openclaw-gateway.service` (or `openclaw-gateway-<profile>.service` for profiles)

**Lingering (keep service running after logout):**The installer attempts to enable lingering automatically:

```
loginctl enable-linger $USER
```

If this fails (requires sudo), run manually.

### Windows (WSL2)

**Recommended approach: WSL2 with Ubuntu**

1. Install WSL2:
```
wsl --install -d Ubuntu
```
1. Inside WSL2, follow the Linux installation steps above.

**Native Windows:**Native Windows installs are untested and not recommended. The PowerShell installer exists but compatibility is limited.

```
iwr -useb https://openclaw.ai/install.ps1 | iex
```

**Service installation (native Windows):**Uses Windows Task Scheduler (`schtasks`). Service name: `OpenClaw Gateway (<profile>)`.

Sources: [docs/platforms/index.md 16-29](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/platforms/index.md#L16-L29) [docs/platforms/windows.md 9-17](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/platforms/windows.md#L9-L17) [docs/platforms/linux.md 1-7](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/platforms/linux.md#L1-L7) [docs/start/getting-started.md 49-52](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/start/getting-started.md#L49-L52)

---

## Service Installation

The Gateway can run as a supervised background service. This is recommended for production use and after initial setup.

### Install service during onboarding

```
openclaw onboard --install-daemon
```

### Install service separately

```
openclaw gateway install
```

Options:

- `--runtime node` - Use Node.js (recommended)
- `--runtime bun` - Use Bun (not recommended for Gateway)
- `--port <port>` - Override default port (18789)
- `--force` - Overwrite existing service

### Service locations

**macOS:**

- Service file: `~/Library/LaunchAgents/bot.molt.gateway.plist`
- Legacy name: `com.openclaw.gateway.plist`
- Profile-specific: `bot.molt.<profile>.plist`

**Linux / WSL2:**

- Service file: `~/.config/systemd/user/openclaw-gateway.service`
- Profile-specific: `openclaw-gateway-<profile>.service`

**Windows (native):**

- Task name: `OpenClaw Gateway`
- Profile-specific: `OpenClaw Gateway (<profile>)`

### Service management

Start the service:

```
openclaw gateway start
```

Stop the service:

```
openclaw gateway stop
```

Restart the service:

```
openclaw gateway restart
```

Check status:

```
openclaw gateway status
```

Sources: [docs/gateway/index.md 7-40](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/index.md#L7-L40) [docs/start/wizard.md 131-136](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/start/wizard.md#L131-L136) [docs/platforms/index.md 40-50](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/platforms/index.md#L40-L50) [docs/cli/index.md 613-631](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/cli/index.md#L613-L631)

---

## Post-Installation Steps

### 1\. Verify CLI installation

```
openclaw --version
openclaw --help
```

Expected output:

```
openclaw <version>
```

If `openclaw: command not found`, verify Node/npm PATH configuration. See [Troubleshooting](https://deepwiki.com/openclaw/openclaw/14.3-common-issues).

### 2\. Run onboarding wizard

```
openclaw onboard --install-daemon
```

The wizard guides you through:

- Model/auth setup (Anthropic, OpenAI, local models)
- Workspace location
- Gateway configuration (port, bind, auth)
- Channel setup (WhatsApp, Telegram, Discord, etc.)
- Service installation

For details, see [Onboarding Wizard](https://deepwiki.com/openclaw/openclaw/2.3-onboarding-wizard).

### 3\. Verify Gateway is running

```
openclaw gateway status
```

Expected output should show:

- `Runtime: running`
- `RPC probe: ok`

### 4\. Quick health check

```
openclaw status
openclaw health
```

If the Gateway is not reachable, check:

```
openclaw logs --follow
```

### 5\. Open the dashboard

```
openclaw dashboard
```

This opens the Control UI in your browser at `http://127.0.0.1:18789/` (or the configured port).

If auth is required, paste the token from:

```
openclaw config get gateway.auth.token
```

Sources: [docs/install/index.md 109-125](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/install/index.md#L109-L125) [docs/start/getting-started.md 123-129](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/start/getting-started.md#L123-L129) [docs/start/wizard.md 48-150](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/start/wizard.md#L48-L150)

---

## Installation Directory Structure

After installation, key files and directories:

```
Workspace filesAgent stateCredentialsState directory: ~/.openclawGlobal npm installationsymlink//usr/local/lib/node_modules/openclaw/usr/local/bin/openclawpackage.jsonopenclaw.mjsdist/dist/index.jsdist/gateway/dist/cli/dist/node-host/dist/acp/OPENCLAW_STATE_DIRopenclaw.json.envcredentials/agents/workspace/logs/sandboxes/tools/credentials/oauth.jsoncredentials/whatsapp/agents/main/agents/main/sessions/agents/main/memory.dbworkspace/AGENTS.mdworkspace/SOUL.mdworkspace/USER.mdworkspace/MEMORY.mdworkspace/memory/
```

**Key paths:**

| Path | Purpose | Environment Variable |
| --- | --- | --- |
| `/usr/local/lib/node_modules/openclaw` | npm global install location | N/A |
| `/usr/local/bin/openclaw` | Symlink to CLI entrypoint | N/A |
| `openclaw.mjs` | CLI entrypoint (bin field) | N/A |
| `~/.openclaw/` | State directory | `OPENCLAW_STATE_DIR` |
| `~/.openclaw/openclaw.json` | Main configuration file | `OPENCLAW_CONFIG_PATH` |
| `~/.openclaw/.env` | Environment variables (loaded by Gateway) | N/A |
| `~/.openclaw/workspace/` | Default agent workspace | `agents.defaults.workspace` |
| `~/.openclaw/agents/<agentId>/` | Per-agent state | N/A |
| `~/.openclaw/credentials/` | OAuth tokens, channel creds | N/A |

Sources: [docs/help/faq.md 397-406](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/help/faq.md#L397-L406) [docs/start/wizard.md 293-312](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/start/wizard.md#L293-L312) [docs/install/index.md 149-181](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/install/index.md#L149-L181) [AGENTS.md 6-8](https://github.com/openclaw/openclaw/blob/bf6ec64f/AGENTS.md#L6-L8)

---

## Verification Commands

After installation, use these commands to verify setup:

```
# Check CLI version
openclaw --version

# Quick status (local summary)
openclaw status

# Full diagnosis (pasteable, safe to share)
openclaw status --all

# Gateway reachability and health
openclaw gateway status

# Deep probes (requires reachable Gateway)
openclaw status --deep

# Model provider status
openclaw models status

# Run health checks and repairs
openclaw doctor

# View live logs
openclaw logs --follow
```

**Expected outputs:**

1. `openclaw --version` should show the installed version
2. `openclaw status` should show Gateway as reachable
3. `openclaw gateway status` should show:
	- Runtime: running
	- RPC probe: ok
4. `openclaw models status` should show configured auth profiles

If any command fails, see [Troubleshooting](https://deepwiki.com/openclaw/openclaw/14-operations-and-troubleshooting).

Sources: [docs/help/faq.md 196-243](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/help/faq.md#L196-L243) [docs/gateway/troubleshooting.md 16-27](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/troubleshooting.md#L16-L27) [docs/start/getting-started.md 123-129](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/start/getting-started.md#L123-L129)

---

After installation and verification:

1. **Configure channels**: Add WhatsApp, Telegram, Discord, etc.
	```
	openclaw channels add
	```
	See [Channels](https://deepwiki.com/openclaw/openclaw/8-channels) for details.
2. **Customize workspace**: Edit bootstrap files in `~/.openclaw/workspace/`
	- `AGENTS.md` - Repository guidelines and coding style
	- `SOUL.md` - Agent personality and behavior
	- `USER.md` - User preferences and context
	- `MEMORY.md` - Persistent memory
3. **Set up skills**: Install optional dependencies for skills
	```
	openclaw skills list
	```
4. **Configure security**: Review access controls and sandboxing
	```
	openclaw security audit
	```
5. **Deploy remotely** (optional): See [Deployment](https://deepwiki.com/openclaw/openclaw/13-deployment) for VPS and cloud options.
6. **Pair devices** (optional): Connect iOS/Android nodes for camera, canvas, voice wake. See [Nodes](https://deepwiki.com/openclaw/openclaw/11-device-nodes).

Sources: [docs/start/getting-started.md 199-204](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/start/getting-started.md#L199-L204) [docs/index.md 166-213](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/index.md#L166-L213)

---

**Sources:**

- [docs/install/index.md 1-183](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/install/index.md#L1-L183)
- [docs/start/getting-started.md 1-205](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/start/getting-started.md#L1-L205)
- [docs/help/faq.md 294-608](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/help/faq.md#L294-L608)
- [docs/install/installer.md 1-116](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/install/installer.md#L1-L116)
- [docs/start/wizard.md 1-322](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/start/wizard.md#L1-L322)
- [AGENTS.md 1-164](https://github.com/openclaw/openclaw/blob/bf6ec64f/AGENTS.md#L1-L164)
- [docs/platforms/index.md 1-50](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/platforms/index.md#L1-L50)
- [docs/gateway/index.md 1-40](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/index.md#L1-L40)
- [docs/cli/index.md 1-240](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/cli/index.md#L1-L240)

<svg id="mermaid-fu8dstus3vp" width="100%" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 2412 512" style="max-width: 512px;" role="graphics-document document" aria-roledescription="error"><g></g><g><path class="error-icon" d="m411.313,123.313c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32-9.375,9.375-20.688-20.688c-12.484-12.5-32.766-12.5-45.25,0l-16,16c-1.261,1.261-2.304,2.648-3.31,4.051-21.739-8.561-45.324-13.426-70.065-13.426-105.867,0-192,86.133-192,192s86.133,192 192,192 192-86.133 192-192c0-24.741-4.864-48.327-13.426-70.065 1.402-1.007 2.79-2.049 4.051-3.31l16-16c12.5-12.492 12.5-32.758 0-45.25l-20.688-20.688 9.375-9.375 32.001-31.999zm-219.313,100.687c-52.938,0-96,43.063-96,96 0,8.836-7.164,16-16,16s-16-7.164-16-16c0-70.578 57.422-128 128-128 8.836,0 16,7.164 16,16s-7.164,16-16,16z"></path><path class="error-icon" d="m459.02,148.98c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l16,16c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16.001-16z"></path><path class="error-icon" d="m340.395,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16-16c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l15.999,16z"></path><path class="error-icon" d="m400,64c8.844,0 16-7.164 16-16v-32c0-8.836-7.156-16-16-16-8.844,0-16,7.164-16,16v32c0,8.836 7.156,16 16,16z"></path><path class="error-icon" d="m496,96.586h-32c-8.844,0-16,7.164-16,16 0,8.836 7.156,16 16,16h32c8.844,0 16-7.164 16-16 0-8.836-7.156-16-16-16z"></path><path class="error-icon" d="m436.98,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688l32-32c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32c-6.251,6.25-6.251,16.375-0.001,22.625z"></path><text class="error-text" x="1440" y="250" font-size="150px" style="text-anchor: middle;">Syntax error in text</text> <text class="error-text" x="1250" y="400" font-size="100px" style="text-anchor: middle;">mermaid version 11.12.2</text></g></svg>