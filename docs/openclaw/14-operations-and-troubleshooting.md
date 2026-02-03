Menu

## Operations and Troubleshooting

Relevant source files
- [docs/cli/index.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/cli/index.md)
- [docs/docs.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/docs.json)
- [docs/gateway/doctor.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/doctor.md)
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
- [docs/platforms/gcp.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/platforms/gcp.md)
- [docs/platforms/index.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/platforms/index.md)
- [docs/platforms/linux.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/platforms/linux.md)
- [docs/platforms/oracle.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/platforms/oracle.md)
- [docs/platforms/windows.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/platforms/windows.md)
- [docs/start/getting-started.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/start/getting-started.md)
- [docs/start/hubs.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/start/hubs.md)
- [docs/start/wizard.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/start/wizard.md)
- [docs/vps.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/vps.md)
- [src/agents/agent-scope.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/agent-scope.test.ts)
- [src/agents/agent-scope.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/agent-scope.ts)
- [src/agents/bash-tools.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/bash-tools.test.ts)
- [src/agents/model-auth.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/model-auth.ts)
- [src/agents/pi-tools-agent-config.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-tools-agent-config.test.ts)
- [src/agents/sandbox-skills.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/sandbox-skills.test.ts)
- [src/commands/auth-choice-options.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/auth-choice-options.test.ts)
- [src/commands/auth-choice-options.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/auth-choice-options.ts)
- [src/commands/auth-choice.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/auth-choice.test.ts)
- [src/commands/auth-choice.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/auth-choice.ts)
- [src/commands/configure.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/configure.ts)
- [src/commands/doctor.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/doctor.ts)
- [src/commands/onboard-auth.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/onboard-auth.test.ts)
- [src/commands/onboard-auth.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/onboard-auth.ts)
- [src/commands/onboard-non-interactive.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/onboard-non-interactive.ts)
- [src/commands/onboard-types.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/onboard-types.ts)
- [src/discord/monitor/presence-cache.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/discord/monitor/presence-cache.test.ts)
- [src/wizard/onboarding.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/wizard/onboarding.ts)

This page provides operational guidance for running and maintaining OpenClaw deployments. It covers diagnostic workflows, service lifecycle management, health monitoring, and common troubleshooting patterns. For deep dives into specific topics, see:

- Health monitoring and status commands: [Health Monitoring](https://deepwiki.com/openclaw/openclaw/14.1-health-monitoring)
- Doctor command usage and migrations: [Doctor Command Guide](https://deepwiki.com/openclaw/openclaw/14.2-doctor-command-guide)
- Specific error messages and fixes: [Common Issues](https://deepwiki.com/openclaw/openclaw/14.3-common-issues)
- Moving installations and backup strategies: [Migration and Backup](https://deepwiki.com/openclaw/openclaw/14.4-migration-and-backup)

For runtime failures and channel-specific issues, see [Troubleshooting](https://github.com/openclaw/openclaw/blob/bf6ec64f/Troubleshooting)

---

## Operational Context

OpenClaw runs as a long-lived Gateway process that owns messaging channel connections and the WebSocket control plane. Operational tasks center on:

1. **Monitoring**: Gateway health, channel connectivity, model auth status
2. **Diagnostics**: Identifying why messages fail or the Gateway won't start
3. **Lifecycle**: Starting, stopping, restarting, upgrading
4. **Recovery**: Repairing broken state, migrating legacy data
5. **Maintenance**: Config updates, log rotation, backup

The CLI provides a layered diagnostic surface: fast local checks (`openclaw status`), remote Gateway probes (`openclaw health`), and repair automation (`openclaw doctor`).

---

## Diagnostic Workflow: First 60 Seconds

When something breaks, run these commands in order. Each provides progressively deeper insight.

```
Need full context?Gateway issues?Need provider checks?Service running but unreachable?Want repairs?Need structured data?Issue Detectedopenclaw status
(local triage)openclaw status --all
(pasteable report)openclaw gateway status
(supervisor + RPC)openclaw status --deep
(live probes)openclaw logs --follow
(stream logs)openclaw doctor
(repair)openclaw health --json
(gateway snapshot)
```

**Quick reference:**

| Command | What it shows | When to use |
| --- | --- | --- |
| `openclaw status` | OS/update, gateway reachability, agents/sessions, provider config | First check; fast local summary |
| `openclaw status --all` | Full diagnosis + log tail (tokens redacted) | Safe to share for debugging |
| `openclaw gateway status` | Supervisor runtime, RPC probe, config path mismatch | Gateway "running" but nothing responds |
| `openclaw status --deep` | Gateway health + provider probes (requires reachable gateway) | Configured but not working |
| `openclaw logs --follow` | Live log stream | Need the actual failure reason |
| `openclaw doctor` | Config validation + repair automation | Fix stale config/state |
| `openclaw health --verbose` | Gateway snapshot with target URL + config path on errors | Debug auth or network issues |

**Sources:**[docs/help/faq.md 196-244](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/help/faq.md#L196-L244) [docs/gateway/troubleshooting.md 14-30](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/troubleshooting.md#L14-L30)

---

## Diagnostic Command Architecture

The CLI provides three layers of diagnostics: local checks, remote probes, and repair actions. Understanding which layer each command operates in helps choose the right tool.

```
Gateway WebSocket RPC :18789Repair ActionsRemote Probes (require Gateway RPC)Local Checks (no Gateway required)openclaw statusopenclaw gateway statusreadConfigFileSnapshot()Service supervisor check
(launchd/systemd/schtasks)openclaw status --deepopenclaw healthopenclaw logsopenclaw channels statusopenclaw system presenceopenclaw doctoropenclaw config setopenclaw gateway restartopenclaw sandbox recreateGateway RPC Handler
src/gateway/server.tshealth endpointlogs.tail RPCconfig.get/set/applypresence.list
```

**Key code entities:**

- Local checks: [src/commands/status.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/status.ts) [src/daemon/service.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/daemon/service.ts)
- RPC client: [src/gateway/call.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/call.ts) `buildGatewayConnectionDetails()`
- Gateway server: [src/gateway/server.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/server.ts) WebSocket RPC handler
- Doctor flow: [src/commands/doctor.ts 65-306](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/doctor.ts#L65-L306)

**Sources:**[src/gateway/server.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/server.ts) [src/commands/doctor.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/doctor.ts) [src/gateway/call.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/call.ts)

---

## Gateway Lifecycle Management

The Gateway runs as a supervised background service (launchd on macOS, systemd on Linux, schtasks on Windows). The CLI manages the service through a unified interface.

### Service States

```
openclaw gateway installopenclaw gateway startopenclaw gateway stopopenclaw gateway startopenclaw gateway restartopenclaw gateway uninstallconfig file changehybrid reloadcritical changein-process restartfatal errorsupervisor auto-restartUninstalledInstalledRunningStoppedConfigReloadRestartingFailed
```

### Service Management Commands

```
# Install service (creates supervisor config)
openclaw gateway install --runtime node

# Check status (supervisor + RPC probe)
openclaw gateway status

# Lifecycle controls
openclaw gateway start
openclaw gateway stop
openclaw gateway restart

# Manual run (foreground, for debugging)
openclaw gateway --port 18789 --verbose

# Force restart (kill existing listener first)
openclaw gateway --force
```

**Service configuration paths:**

- macOS: `~/Library/LaunchAgents/bot.molt.openclaw.plist` (or profile-specific)
- Linux: `~/.config/systemd/user/openclaw-gateway.service` (or profile-specific)
- Windows: Task Scheduler task `OpenClaw Gateway`

**Code references:**

- Service interface: [src/daemon/service.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/daemon/service.ts) `resolveGatewayService()`
- Install flow: [src/daemon/service.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/daemon/service.ts) `install()` method
- macOS launchd: [src/daemon/service.macos.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/daemon/service.macos.ts)
- Linux systemd: [src/daemon/service.linux.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/daemon/service.linux.ts)
- Windows schtasks: [src/daemon/service.windows.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/daemon/service.windows.ts)

**Sources:**[src/daemon/service.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/daemon/service.ts) [src/commands/gateway.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/gateway.ts) [docs/gateway/index.md 15-43](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/index.md#L15-L43)

---

## Configuration Hot Reload

The Gateway watches `openclaw.json` and applies changes without downtime when possible. The reload mode is controlled by `gateway.reload.mode`.

```
hybridoffsafe changecritical changeConfig file change detectedReload mode?gateway.reload.mode: hybridgateway.reload.mode: offAnalyze changed fieldsCritical
change?Hot-apply safe changes
(allowlists, tools)In-process restart
(SIGUSR1)Ignore change
(require manual restart)Config reloaded
```

**Critical changes (trigger restart):**

- Gateway bind/port changes
- Auth mode/token changes
- Channel credentials
- Model provider config
- Agent workspace paths

**Safe hot-apply changes:**

- Channel allowlists
- Tool allow/deny policies
- Sandbox configuration
- Cron job definitions

**Code reference:**[src/gateway/server.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/server.ts) config watcher implementation

**Sources:**[docs/gateway/index.md 25-29](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/index.md#L25-L29) [src/gateway/server.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/server.ts)

---

## Health Monitoring Surface

OpenClaw exposes health status through multiple surfaces. Each surface targets a different operational context.

```
Monitoring SurfacesGateway RPC EndpointsCLI Commandsopenclaw statusopenclaw status --deepopenclaw healthopenclaw channels statusopenclaw models statushealth RPC
(agents, channels, sessions)presence.list RPC
(system events)channels.status RPCmodels.status RPCControl UI
Status pageFile logs
~/.openclaw/logs/
```

**Key status fields:**

- Gateway reachability: `openclaw gateway status` checks RPC probe
- Channel health: `openclaw channels status --probe` (WhatsApp/Telegram/Discord state)
- Model auth: `openclaw models status --probe` (OAuth expiry, API key validity)
- Session count: `openclaw status` shows active sessions
- System events: `openclaw system presence` shows recent events

**Sources:**[docs/cli/index.md 515-541](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/cli/index.md#L515-L541) [docs/gateway/troubleshooting.md 14-30](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/troubleshooting.md#L14-L30)

---

## Doctor Command Workflow

The `openclaw doctor` command automates common repair tasks. It runs a series of checks and offers fixes for detected issues.

```
openclaw doctorCheck for updates
(git installs only)UI protocol freshness
(rebuild if stale)Load + validate config
loadAndMaybeMigrateDoctorConfig()Auth profile health
noteAuthProfileHealth()Detect legacy state
detectLegacyStateMigrations()State integrity checks
noteStateIntegrity()Sandbox images
maybeRepairSandboxImages()Gateway service config
maybeRepairGatewayServiceConfig()Security warnings
noteSecurityWarnings()Gateway health check
checkGatewayHealth()Gateway daemon repair
maybeRepairGatewayDaemon()Write repaired config
writeConfigFile()Workspace backup tip
noteWorkspaceBackupTip()Doctor complete
```

**Doctor modes:**

- Interactive (default): Prompts for each repair
- `--yes`: Accept all defaults (including restarts)
- `--non-interactive`: Only safe migrations (no prompts, no restarts)
- `--deep`: Scan system services for extra gateway installs

**Common repairs:**

- OAuth profile ID normalization: [src/commands/doctor-auth.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/doctor-auth.ts) `maybeRepairAnthropicOAuthProfileId()`
- Legacy state migration: [src/commands/doctor-state-migrations.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/doctor-state-migrations.ts) `runLegacyStateMigrations()`
- Service config updates: [src/commands/doctor-gateway-services.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/doctor-gateway-services.ts) `maybeRepairGatewayServiceConfig()`
- Sandbox image recreation: [src/commands/doctor-sandbox.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/doctor-sandbox.ts) `maybeRepairSandboxImages()`

**Sources:**[src/commands/doctor.ts 65-306](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/doctor.ts#L65-L306) [docs/gateway/doctor.md 1-223](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/doctor.md#L1-L223)

---

## Configuration Management

Configuration lives in `~/.openclaw/openclaw.json` (or `OPENCLAW_CONFIG_PATH`). The CLI provides helpers for safe config edits.

### Configuration Precedence

```
highest prioritymiddle prioritylowest priorityEnvironment Variables
(OPENCLAW_GATEWAY_TOKEN)~/.openclaw/openclaw.jsonSystem DefaultsMerged ConfigGateway startup
```

### Configuration Commands

```
# View current value
openclaw config get gateway.port

# Set value (JSON5 syntax)
openclaw config set agents.defaults.model "openai/gpt-4"
openclaw config set tools.allow '["read", "write", "exec"]'

# Remove value
openclaw config unset tools.exec.requireApproval

# Interactive wizard
openclaw configure

# Validate and apply via RPC (triggers reload)
openclaw gateway call config.apply --params '{"config": {...}, "baseHash": "..."}'
```

**Config validation:**

- Schema: [src/config/schema.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/schema.ts) Zod schemas
- Loader: [src/config/config.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/config.ts) `readConfigFileSnapshot()`
- Migration: [src/commands/doctor-config-flow.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/doctor-config-flow.ts) `loadAndMaybeMigrateDoctorConfig()`

**Sources:**[src/config/config.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/config.ts) [src/commands/configure.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/configure.ts) [docs/gateway/configuration.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/configuration.md)

---

## Log Access Patterns

OpenClaw logs to multiple destinations depending on how the Gateway runs. Understanding log locations is critical for troubleshooting.

```
Access MethodsService-Specific LogsLog DestinationsGateway Execution ModesForeground
(openclaw gateway)Background Service
(launchd/systemd)stdout/stderr
(console)File Log
~/.openclaw/logs/openclaw-YYYY-MM-DD.logService Log
(platform-specific)macOS LaunchAgent
~/.openclaw/logs/gateway.logLinux systemd
journalctl --user -u openclaw-gatewayWindows Task Scheduler
Event Vieweropenclaw logs --followtail -f ~/.openclaw/logs/*.logjournalctl --user -u openclaw-gateway -f
```

**Log commands:**

```
# Preferred (RPC-based, requires running Gateway)
openclaw logs --follow
openclaw logs --limit 200 --json

# Direct file access (always works)
tail -f "$(ls -t ~/.openclaw/logs/openclaw-*.log | head -1)"

# macOS LaunchAgent logs
tail -f ~/.openclaw/logs/gateway.log
tail -f ~/.openclaw/logs/gateway.err.log

# Linux systemd logs
journalctl --user -u openclaw-gateway.service -f -n 200

# Windows Task Scheduler
# Check Event Viewer → Task Scheduler History
```

**Log configuration:**

```
{
  "logging": {
    "level": "info",
    "file": "~/.openclaw/logs/openclaw-{date}.log",
    "consoleLevel": "warn",
    "consoleStyle": "pretty"
  }
}
```

**Sources:**[docs/gateway/troubleshooting.md 95-124](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/troubleshooting.md#L95-L124) [docs/gateway/index.md 35-36](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/index.md#L35-L36)

---

## Common Operational Patterns

### Pattern: Gateway Won't Start

**Symptom:**`openclaw gateway status` shows service loaded but RPC probe fails.

**Triage:**

```
# 1. Check supervisor state
openclaw gateway status

# 2. Check last gateway error in logs
openclaw logs --limit 50 | grep -i error

# 3. Run doctor
openclaw doctor
```

**Common causes:**

- `gateway.mode` not set to `"local"`: Fix with `openclaw config set gateway.mode local`
- Non-loopback bind without auth: Fix with `openclaw config set gateway.auth.token "..."`
- Port already in use: Fix with `openclaw gateway --force` or change port
- Invalid config: Fix with `openclaw doctor`

**Sources:**[docs/gateway/troubleshooting.md 122-215](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/troubleshooting.md#L122-L215)

---

### Pattern: Model Auth Expired

**Symptom:** Messages get no reply; logs show "No credentials found for profile".

**Triage:**

```
# Check auth status
openclaw models status

# Check for expiry
openclaw models status --probe
```

**Fix (Anthropic setup-token):**

```
# On gateway host
openclaw models auth setup-token --provider anthropic
openclaw models status
```

**Fix (OAuth refresh failed):**

```
# Re-run onboarding or paste new token
openclaw onboard
# or
openclaw models auth paste-token --provider anthropic
```

**Sources:**[docs/gateway/troubleshooting.md 39-73](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/troubleshooting.md#L39-L73)

---

### Pattern: Service Running But Config Mismatch

**Symptom:**`openclaw gateway status` shows different config paths for CLI vs service.

**Explanation:** The CLI and service use different config resolution. This happens when:

- Running CLI with `--profile` but service installed without it
- Running CLI with `OPENCLAW_STATE_DIR` set but service uses default
- Editing config after service install

**Fix:**

```
# Reinstall service from same profile/state-dir context
openclaw gateway install --force

# Or restart from correct context
OPENCLAW_STATE_DIR=~/.openclaw-prod openclaw gateway restart
```

**Sources:**[docs/gateway/troubleshooting.md 162-214](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/troubleshooting.md#L162-L214)

---

### Pattern: Control UI "Unauthorized" Over HTTP

**Symptom:** Opening `http://<lan-ip>:18789/` shows "device identity required" or connect fails.

**Explanation:** Non-HTTPS contexts block WebCrypto, so device identity can't be generated.

**Fix options:**

1. Use HTTPS via Tailscale Serve:
	```
	openclaw gateway --bind tailnet --tailscale serve
	# Open https://<magicdns>/
	```
2. Use loopback (always HTTP-safe):
	```
	# On gateway host
	open http://127.0.0.1:18789/
	```
3. Allow insecure auth (token-only):
	```
	{
	  "gateway": {
	    "controlUi": {
	      "allowInsecureAuth": true
	    }
	  }
	}
	```

**Sources:**[docs/gateway/troubleshooting.md 76-87](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/troubleshooting.md#L76-L87)

---

## Backup and State Management

OpenClaw state lives in `~/.openclaw/` (or `OPENCLAW_STATE_DIR`). Critical paths:

```
~/.openclaw/openclaw.json
(configuration)credentials/
(OAuth, WhatsApp)agents//
(per-agent state)logs/
(file logs)workspace/
(agent files)agents//agent/auth-profiles.json
(API keys + OAuth)agents//sessions/
(conversation history)credentials/whatsapp//
(Baileys state)
```

### Backup Strategy

**Minimal backup (config + auth only):**

```
tar czf openclaw-backup.tar.gz \
  ~/.openclaw/openclaw.json \
  ~/.openclaw/credentials/ \
  ~/.openclaw/agents/*/agent/auth-profiles.json
```

**Full backup (with sessions + workspace):**

```
tar czf openclaw-full-backup.tar.gz \
  ~/.openclaw/openclaw.json \
  ~/.openclaw/credentials/ \
  ~/.openclaw/agents/ \
  ~/.openclaw/workspace/
```

**Restore:**

```
tar xzf openclaw-backup.tar.gz -C ~/
openclaw doctor
openclaw gateway restart
```

**Sources:**[docs/help/faq.md 386-406](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/help/faq.md#L386-L406)

---

## Migration Between Machines

To move OpenClaw to a new machine (preserving sessions, auth, and memory):

1. Install OpenClaw on new machine
2. Copy state directory:
	```
	# On old machine
	tar czf openclaw-state.tar.gz ~/.openclaw/
	# On new machine
	tar xzf openclaw-state.tar.gz -C ~/
	```
3. Run doctor to validate:
	```
	openclaw doctor
	```
4. Restart service:
	```
	openclaw gateway restart
	```

**Important notes:**

- Workspace files contain memory; copy them to preserve agent memory
- Sessions are per-agent; copy `~/.openclaw/agents/<agentId>/sessions/`
- WhatsApp credentials are under `~/.openclaw/credentials/whatsapp/`
- OAuth tokens are in `auth-profiles.json` per agent

**Sources:**[docs/help/faq.md 386-406](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/help/faq.md#L386-L406)

---

## Multi-Gateway Operational Patterns

When running multiple isolated Gateways (rescue bot, dev/prod separation):

**Profile isolation:**

```
# Prod gateway (default profile)
openclaw gateway start

# Dev gateway (isolated profile)
openclaw --profile dev gateway --port 19789

# Service install per profile
openclaw --profile prod gateway install --port 18789
openclaw --profile dev gateway install --port 19789
```

**Service names by profile:**

- macOS: `bot.molt.<profile>`
- Linux: `openclaw-gateway-<profile>.service`
- Windows: `OpenClaw Gateway (<profile>)`

**State isolation:**

- Config: `~/.openclaw/openclaw.json` vs `~/.openclaw-<profile>/openclaw.json`
- State: `~/.openclaw/` vs `~/.openclaw-<profile>/`

**Sources:**[docs/gateway/multiple-gateways.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/multiple-gateways.md) [docs/gateway/index.md 52-72](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/index.md#L52-L72)

---

## Security Audit

The CLI provides a security audit command that checks for common misconfigurations:

```
# Local audit (config + state)
openclaw security audit

# Deep audit (probe running Gateway)
openclaw security audit --deep

# Auto-fix safe issues
openclaw security audit --fix
```

**Common findings:**

- Gateway exposed without auth
- Weak pairing policies (dm.policy: "open")
- Missing sandbox configuration
- World-readable config files
- Deprecated auth methods

**Sources:**[docs/gateway/security.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/security.md) [src/commands/security.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/security.ts)

---

## Operational Checklist for Production

**Pre-deployment:**

- Run `openclaw security audit --deep`
- Set `gateway.auth.token` (even for loopback)
- Configure channel allowlists or pairing
- Enable sandbox for untrusted sessions
- Set up log rotation
- Configure backup automation

**Post-deployment:**

- Verify `openclaw status --deep` shows healthy
- Test failover with `openclaw models status --probe`
- Confirm service auto-restart: `openclaw gateway stop && sleep 5 && openclaw gateway status`
- Test config hot-reload: edit `openclaw.json`, check logs
- Validate backup restore on a test machine

**Ongoing:**

- Weekly: `openclaw status --all` (check for expiring OAuth)
- Monthly: `openclaw doctor` (catch stale state)
- After updates: `openclaw doctor --deep` (validate service config)

**Sources:**[docs/gateway/security.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/security.md) [docs/gateway/troubleshooting.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/troubleshooting.md)

<svg id="mermaid-fu8dstus3vp" width="100%" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 2412 512" style="max-width: 512px;" role="graphics-document document" aria-roledescription="error"><g></g><g><path class="error-icon" d="m411.313,123.313c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32-9.375,9.375-20.688-20.688c-12.484-12.5-32.766-12.5-45.25,0l-16,16c-1.261,1.261-2.304,2.648-3.31,4.051-21.739-8.561-45.324-13.426-70.065-13.426-105.867,0-192,86.133-192,192s86.133,192 192,192 192-86.133 192-192c0-24.741-4.864-48.327-13.426-70.065 1.402-1.007 2.79-2.049 4.051-3.31l16-16c12.5-12.492 12.5-32.758 0-45.25l-20.688-20.688 9.375-9.375 32.001-31.999zm-219.313,100.687c-52.938,0-96,43.063-96,96 0,8.836-7.164,16-16,16s-16-7.164-16-16c0-70.578 57.422-128 128-128 8.836,0 16,7.164 16,16s-7.164,16-16,16z"></path><path class="error-icon" d="m459.02,148.98c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l16,16c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16.001-16z"></path><path class="error-icon" d="m340.395,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16-16c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l15.999,16z"></path><path class="error-icon" d="m400,64c8.844,0 16-7.164 16-16v-32c0-8.836-7.156-16-16-16-8.844,0-16,7.164-16,16v32c0,8.836 7.156,16 16,16z"></path><path class="error-icon" d="m496,96.586h-32c-8.844,0-16,7.164-16,16 0,8.836 7.156,16 16,16h32c8.844,0 16-7.164 16-16 0-8.836-7.156-16-16-16z"></path><path class="error-icon" d="m436.98,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688l32-32c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32c-6.251,6.25-6.251,16.375-0.001,22.625z"></path><text class="error-text" x="1440" y="250" font-size="150px" style="text-anchor: middle;">Syntax error in text</text> <text class="error-text" x="1250" y="400" font-size="100px" style="text-anchor: middle;">mermaid version 11.12.2</text></g></svg> <svg id="mermaid-7khuxtjp8f" width="100%" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 2412 512" style="max-width: 512px;" role="graphics-document document" aria-roledescription="error"><g></g><g><path class="error-icon" d="m411.313,123.313c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32-9.375,9.375-20.688-20.688c-12.484-12.5-32.766-12.5-45.25,0l-16,16c-1.261,1.261-2.304,2.648-3.31,4.051-21.739-8.561-45.324-13.426-70.065-13.426-105.867,0-192,86.133-192,192s86.133,192 192,192 192-86.133 192-192c0-24.741-4.864-48.327-13.426-70.065 1.402-1.007 2.79-2.049 4.051-3.31l16-16c12.5-12.492 12.5-32.758 0-45.25l-20.688-20.688 9.375-9.375 32.001-31.999zm-219.313,100.687c-52.938,0-96,43.063-96,96 0,8.836-7.164,16-16,16s-16-7.164-16-16c0-70.578 57.422-128 128-128 8.836,0 16,7.164 16,16s-7.164,16-16,16z"></path><path class="error-icon" d="m459.02,148.98c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l16,16c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16.001-16z"></path><path class="error-icon" d="m340.395,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16-16c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l15.999,16z"></path><path class="error-icon" d="m400,64c8.844,0 16-7.164 16-16v-32c0-8.836-7.156-16-16-16-8.844,0-16,7.164-16,16v32c0,8.836 7.156,16 16,16z"></path><path class="error-icon" d="m496,96.586h-32c-8.844,0-16,7.164-16,16 0,8.836 7.156,16 16,16h32c8.844,0 16-7.164 16-16 0-8.836-7.156-16-16-16z"></path><path class="error-icon" d="m436.98,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688l32-32c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32c-6.251,6.25-6.251,16.375-0.001,22.625z"></path><text class="error-text" x="1440" y="250" font-size="150px" style="text-anchor: middle;">Syntax error in text</text> <text class="error-text" x="1250" y="400" font-size="100px" style="text-anchor: middle;">mermaid version 11.12.2</text></g></svg> <svg id="mermaid-5cnv3xfsc84" width="100%" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 2412 512" style="max-width: 512px;" role="graphics-document document" aria-roledescription="error"><g></g><g><path class="error-icon" d="m411.313,123.313c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32-9.375,9.375-20.688-20.688c-12.484-12.5-32.766-12.5-45.25,0l-16,16c-1.261,1.261-2.304,2.648-3.31,4.051-21.739-8.561-45.324-13.426-70.065-13.426-105.867,0-192,86.133-192,192s86.133,192 192,192 192-86.133 192-192c0-24.741-4.864-48.327-13.426-70.065 1.402-1.007 2.79-2.049 4.051-3.31l16-16c12.5-12.492 12.5-32.758 0-45.25l-20.688-20.688 9.375-9.375 32.001-31.999zm-219.313,100.687c-52.938,0-96,43.063-96,96 0,8.836-7.164,16-16,16s-16-7.164-16-16c0-70.578 57.422-128 128-128 8.836,0 16,7.164 16,16s-7.164,16-16,16z"></path><path class="error-icon" d="m459.02,148.98c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l16,16c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16.001-16z"></path><path class="error-icon" d="m340.395,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16-16c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l15.999,16z"></path><path class="error-icon" d="m400,64c8.844,0 16-7.164 16-16v-32c0-8.836-7.156-16-16-16-8.844,0-16,7.164-16,16v32c0,8.836 7.156,16 16,16z"></path><path class="error-icon" d="m496,96.586h-32c-8.844,0-16,7.164-16,16 0,8.836 7.156,16 16,16h32c8.844,0 16-7.164 16-16 0-8.836-7.156-16-16-16z"></path><path class="error-icon" d="m436.98,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688l32-32c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32c-6.251,6.25-6.251,16.375-0.001,22.625z"></path><text class="error-text" x="1440" y="250" font-size="150px" style="text-anchor: middle;">Syntax error in text</text> <text class="error-text" x="1250" y="400" font-size="100px" style="text-anchor: middle;">mermaid version 11.12.2</text></g></svg> <svg id="mermaid-hmbioix2qbm" width="100%" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 2412 512" style="max-width: 512px;" role="graphics-document document" aria-roledescription="error"><g></g><g><path class="error-icon" d="m411.313,123.313c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32-9.375,9.375-20.688-20.688c-12.484-12.5-32.766-12.5-45.25,0l-16,16c-1.261,1.261-2.304,2.648-3.31,4.051-21.739-8.561-45.324-13.426-70.065-13.426-105.867,0-192,86.133-192,192s86.133,192 192,192 192-86.133 192-192c0-24.741-4.864-48.327-13.426-70.065 1.402-1.007 2.79-2.049 4.051-3.31l16-16c12.5-12.492 12.5-32.758 0-45.25l-20.688-20.688 9.375-9.375 32.001-31.999zm-219.313,100.687c-52.938,0-96,43.063-96,96 0,8.836-7.164,16-16,16s-16-7.164-16-16c0-70.578 57.422-128 128-128 8.836,0 16,7.164 16,16s-7.164,16-16,16z"></path><path class="error-icon" d="m459.02,148.98c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l16,16c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16.001-16z"></path><path class="error-icon" d="m340.395,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16-16c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l15.999,16z"></path><path class="error-icon" d="m400,64c8.844,0 16-7.164 16-16v-32c0-8.836-7.156-16-16-16-8.844,0-16,7.164-16,16v32c0,8.836 7.156,16 16,16z"></path><path class="error-icon" d="m496,96.586h-32c-8.844,0-16,7.164-16,16 0,8.836 7.156,16 16,16h32c8.844,0 16-7.164 16-16 0-8.836-7.156-16-16-16z"></path><path class="error-icon" d="m436.98,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688l32-32c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32c-6.251,6.25-6.251,16.375-0.001,22.625z"></path><text class="error-text" x="1440" y="250" font-size="150px" style="text-anchor: middle;">Syntax error in text</text> <text class="error-text" x="1250" y="400" font-size="100px" style="text-anchor: middle;">mermaid version 11.12.2</text></g></svg> <svg id="mermaid-z5tp3lz1enf" width="100%" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 2412 512" style="max-width: 512px;" role="graphics-document document" aria-roledescription="error"><g></g><g><path class="error-icon" d="m411.313,123.313c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32-9.375,9.375-20.688-20.688c-12.484-12.5-32.766-12.5-45.25,0l-16,16c-1.261,1.261-2.304,2.648-3.31,4.051-21.739-8.561-45.324-13.426-70.065-13.426-105.867,0-192,86.133-192,192s86.133,192 192,192 192-86.133 192-192c0-24.741-4.864-48.327-13.426-70.065 1.402-1.007 2.79-2.049 4.051-3.31l16-16c12.5-12.492 12.5-32.758 0-45.25l-20.688-20.688 9.375-9.375 32.001-31.999zm-219.313,100.687c-52.938,0-96,43.063-96,96 0,8.836-7.164,16-16,16s-16-7.164-16-16c0-70.578 57.422-128 128-128 8.836,0 16,7.164 16,16s-7.164,16-16,16z"></path><path class="error-icon" d="m459.02,148.98c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l16,16c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16.001-16z"></path><path class="error-icon" d="m340.395,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16-16c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l15.999,16z"></path><path class="error-icon" d="m400,64c8.844,0 16-7.164 16-16v-32c0-8.836-7.156-16-16-16-8.844,0-16,7.164-16,16v32c0,8.836 7.156,16 16,16z"></path><path class="error-icon" d="m496,96.586h-32c-8.844,0-16,7.164-16,16 0,8.836 7.156,16 16,16h32c8.844,0 16-7.164 16-16 0-8.836-7.156-16-16-16z"></path><path class="error-icon" d="m436.98,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688l32-32c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32c-6.251,6.25-6.251,16.375-0.001,22.625z"></path><text class="error-text" x="1440" y="250" font-size="150px" style="text-anchor: middle;">Syntax error in text</text> <text class="error-text" x="1250" y="400" font-size="100px" style="text-anchor: middle;">mermaid version 11.12.2</text></g></svg>