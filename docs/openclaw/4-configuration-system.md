Menu

## Configuration System

Relevant source files
- [.prettierignore](https://github.com/openclaw/openclaw/blob/bf6ec64f/.prettierignore)
- [docs/cli/memory.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/cli/memory.md)
- [docs/concepts/memory.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/concepts/memory.md)
- [docs/gateway/doctor.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/doctor.md)
- [src/agents/agent-scope.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/agent-scope.test.ts)
- [src/agents/agent-scope.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/agent-scope.ts)
- [src/agents/bash-tools.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/bash-tools.test.ts)
- [src/agents/memory-search.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/memory-search.test.ts)
- [src/agents/memory-search.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/memory-search.ts)
- [src/agents/model-auth.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/model-auth.ts)
- [src/agents/pi-tools-agent-config.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-tools-agent-config.test.ts)
- [src/agents/sandbox-skills.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/sandbox-skills.test.ts)
- [src/agents/tools/memory-tool.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/tools/memory-tool.ts)
- [src/auto-reply/reply/agent-runner.heartbeat-typing.runreplyagent-typing-heartbeat.retries-after-compaction-failure-by-resetting-session.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/reply/agent-runner.heartbeat-typing.runreplyagent-typing-heartbeat.retries-after-compaction-failure-by-resetting-session.test.ts)
- [src/cli/memory-cli.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cli/memory-cli.test.ts)
- [src/cli/memory-cli.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cli/memory-cli.ts)
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
- [src/config/config.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/config.ts)
- [src/config/schema.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/schema.ts)
- [src/config/types.tools.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/types.tools.ts)
- [src/config/zod-schema.agent-runtime.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/zod-schema.agent-runtime.ts)
- [src/memory/index.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/index.test.ts)
- [src/memory/internal.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/internal.test.ts)
- [src/memory/internal.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/internal.ts)
- [src/memory/manager-cache-key.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager-cache-key.ts)
- [src/memory/manager.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/manager.ts)
- [src/memory/sync-memory-files.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/memory/sync-memory-files.ts)
- [src/wizard/onboarding.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/wizard/onboarding.ts)

The Configuration System manages all persistent settings for OpenClaw through a hierarchical architecture with clear precedence rules, schema validation, and automated migrations. It provides both interactive wizards and CLI tools for configuration management, supports multi-agent setups with isolated settings, and handles runtime overrides through environment variables.

For managing agent-specific runtime settings like model selection and tool policies, see [Agent System](https://deepwiki.com/openclaw/openclaw/5-agent-system). For gateway network and authentication settings, see [Gateway Configuration](https://deepwiki.com/openclaw/openclaw/3.1-gateway-configuration).

---

## Architecture Overview

**Configuration Loading and Validation Flow**

```
.env Files
dotenv loadingopenclaw.json
~/.openclaw/Environment Variables
ANTHROPIC_API_KEY, etc.loadConfig()
src/config/io.tsparseConfigJson5()
JSON5.parsemigrateLegacyConfig()
src/config/legacy-migrate.tsvalidateConfigObject()
src/config/validation.tsOpenClawSchema
src/config/zod-schema.tsresolveRuntimeOverrides()
src/config/runtime-overrides.tswriteConfigFile()
src/config/io.tsOpenClawConfig
Type-Safe Object
```

**Sources**:

- [src/config/config.ts 1-15](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/config.ts#L1-L15)
- [src/config/io.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/io.ts)
- [src/config/validation.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/validation.ts)
- [src/config/zod-schema.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/zod-schema.ts)
- [src/config/runtime-overrides.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/runtime-overrides.ts)

---

## Configuration Sources and Precedence

OpenClaw loads configuration from multiple sources with a clear precedence hierarchy (highest to lowest):

| Priority | Source | Path/Location | Format |
| --- | --- | --- | --- |
| 1 | Environment Variables | `process.env.*` | Key-value pairs |
| 2 | Config File | `~/.openclaw/openclaw.json` | JSON5 |
| 3 | System Defaults | Hardcoded in source | TypeScript constants |

**Precedence Rules**:

- Environment variables always win (runtime overrides applied last)
- Config file values override system defaults
- Missing keys fall back to defaults
- Arrays and objects are replaced entirely (no deep merging except for specific domains)

**Environment Variable Resolution**:

The system resolves environment variables through `resolveRuntimeOverrides()` which applies the following patterns:

- `ANTHROPIC_API_KEY` → `models.providers.anthropic.apiKey`
- `OPENAI_API_KEY` → `models.providers.openai.apiKey`
- `GEMINI_API_KEY` → `models.providers.google.apiKey`
- `OPENCLAW_GATEWAY_TOKEN` → `gateway.auth.token`
- `OPENCLAW_GATEWAY_PASSWORD` → `gateway.auth.password`
- `OPENCLAW_STATE_DIR` → state directory location
- `OPENCLAW_AGENT_DIR` → agent directory location

**Sources**:

- [src/config/runtime-overrides.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/runtime-overrides.ts)
- [src/config/paths.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/paths.ts)

---

## Configuration File Structure

The primary configuration file is `~/.openclaw/openclaw.json`, parsed as JSON5 (supports comments and trailing commas).

**File Location and Discovery**:

```
// Default path
CONFIG_PATH = "~/.openclaw/openclaw.json"

// Alternative locations checked:
// 1. OPENCLAW_CONFIG_PATH environment variable
// 2. ~/.openclaw/openclaw.json
// 3. Current directory ./openclaw.json (development only)
```

**Top-Level Structure**:

```
{
  // Metadata (auto-managed)
  meta: {
    lastTouchedVersion: "0.1.0",
    lastTouchedAt: "2024-01-15T10:30:00Z"
  },

  // Gateway control plane
  gateway: { /* ... */ },

  // Agent runtime defaults and list
  agents: { /* ... */ },

  // Authentication profiles
  auth: { /* ... */ },

  // Model catalog and provider config
  models: { /* ... */ },

  // Tool policies and settings
  tools: { /* ... */ },

  // Messaging channel integrations
  channels: { /* ... */ },

  // Plugin system
  plugins: { /* ... */ },

  // Scheduled tasks
  cron: { /* ... */ },

  // Command system
  commands: { /* ... */ },

  // Session behavior
  session: { /* ... */ },

  // Skills loading
  skills: { /* ... */ },

  // UI settings
  ui: { /* ... */ },

  // Browser control
  browser: { /* ... */ },

  // Message handling
  messages: { /* ... */ },

  // Discovery (mDNS/Bonjour)
  discovery: { /* ... */ },

  // Diagnostics and telemetry
  diagnostics: { /* ... */ }
}
```

**Sources**:

- [src/config/types.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/types.ts)
- [src/config/config.ts 14](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/config.ts#L14-L14)
- [src/config/paths.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/paths.ts)

---

## Schema Validation

All configuration is validated against `OpenClawSchema`, a Zod schema that enforces type safety and structural correctness.

**Validation Flow**:

```
SuccessFailureRaw JSON5
Parsed ObjectvalidateConfigObject()
src/config/validation.tsOpenClawSchema.parse()
src/config/zod-schema.tsPlugin Schemas
validateConfigObjectWithPlugins()Valid OpenClawConfig
```

**Schema Organization**:

The Zod schema is split across multiple files for maintainability:

| File | Responsibility |
| --- | --- |
| `zod-schema.ts` | Root schema export, composition |
| `zod-schema.core.ts` | Gateway, UI, discovery schemas |
| `zod-schema.agent-runtime.ts` | Agent, tools, memory, sandbox schemas |
| `zod-schema.channels.ts` | Channel configuration schemas |
| `zod-schema.auth.ts` | Authentication profile schemas |
| `zod-schema.models.ts` | Model catalog schemas |

**Common Validation Patterns**:

```
// Tool policy validation with conflict detection
const ToolPolicySchema = z.object({
  allow: z.array(z.string()).optional(),
  alsoAllow: z.array(z.string()).optional(),
  deny: z.array(z.string()).optional(),
}).superRefine((value, ctx) => {
  if (value.allow && value.allow.length > 0 && 
      value.alsoAllow && value.alsoAllow.length > 0) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "cannot set both allow and alsoAllow"
    });
  }
});

// Memory search config with source validation
const MemorySearchSchema = z.object({
  enabled: z.boolean().optional(),
  sources: z.array(z.union([
    z.literal("memory"), 
    z.literal("sessions")
  ])).optional(),
  provider: z.union([
    z.literal("openai"), 
    z.literal("gemini"), 
    z.literal("local")
  ]).optional(),
  // ... more fields
});
```

**Sources**:

- [src/config/validation.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/validation.ts)
- [src/config/zod-schema.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/zod-schema.ts)
- [src/config/zod-schema.agent-runtime.ts 1-549](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/zod-schema.agent-runtime.ts#L1-L549)

---

## Configuration Domains

**Domain Hierarchy and Schema Types**:

```
Plugins DomainPluginsConfig
enabled, allow, denyPluginSlots
memory, etc.PluginEntries
per-plugin configAuth DomainAuthConfig
profiles, order, cooldownsChannels DomainChannelsConfig
telegram, discord, etc.TelegramChannelConfig
botToken, dmPolicyDiscordChannelConfig
token, intentsWhatsAppChannelConfig
selfChatMode, debounceTools DomainToolsConfig
profile, allow, denyExecToolConfig
host, security, askMediaToolsConfig
image, audio, videoToolsWebSchema
search, fetchAgent DomainAgentsConfig
defaults + listAgentDefaultsConfig
workspace, model, toolsAgentEntrySchema
per-agent overridesMemorySearchConfig
provider, chunking, syncAgentSandboxSchema
mode, docker, browserGateway DomainGatewayConfig
port, bind, auth, tailscaleGatewayAuthConfig
mode, token, passwordGatewayNodesConfig
browser mode, commands
```

**Key Domain Exports**:

| Domain | Type Definition | Schema | Location |
| --- | --- | --- | --- |
| Gateway | `GatewayConfig` | `GatewaySchema` | [src/config/types.gateway.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/types.gateway.ts) |
| Agents | `AgentsConfig` | `AgentsSchema` | [src/config/types.agents.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/types.agents.ts) |
| Tools | `ToolsConfig` | `ToolsSchema` | [src/config/types.tools.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/types.tools.ts) |
| Auth | `AuthConfig` | `AuthSchema` | [src/config/types.auth.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/types.auth.ts) |
| Channels | `ChannelsConfig` | `ChannelsSchema` | [src/config/types.channels.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/types.channels.ts) |
| Models | `ModelsConfig` | `ModelsSchema` | [src/config/types.models.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/types.models.ts) |
| Plugins | `PluginsConfig` | `PluginsSchema` | [src/config/types.plugins.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/types.plugins.ts) |
| Memory | `MemorySearchConfig` | `MemorySearchSchema` | [src/config/types.tools.ts 224-324](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/types.tools.ts#L224-L324) |

**Sources**:

- [src/config/types.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/types.ts)
- [src/config/types.tools.ts 1-451](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/types.tools.ts#L1-L451)
- [src/config/zod-schema.agent-runtime.ts 1-549](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/zod-schema.agent-runtime.ts#L1-L549)
- [src/config/schema.ts 1-365](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/schema.ts#L1-L365)

---

## Management Tools

OpenClaw provides four primary CLI tools for configuration management:

**Tool Responsibilities and Usage**:

```
Config OperationsActionsAutomated ToolsInteractive Wizardsopenclaw onboard
src/wizard/onboarding.tsopenclaw configure
src/commands/configure.wizard.tsopenclaw doctor
src/commands/doctor.tsopenclaw config
src/cli/config-cli.tsInitial Setup
auth, workspace, channelsSection Editor
guided field editingHealth Check
repairs, migrationsDirect Manipulation
get/set/unset keysreadConfigFileSnapshot()
src/config/io.tswriteConfigFile()
src/config/io.tsapplyWizardMetadata()
src/commands/onboard-helpers.ts
```

### openclaw onboard

Interactive wizard for first-time setup. Guides through:

1. Risk acknowledgement (security warning)
2. Flow selection (quickstart vs manual/advanced)
3. Gateway mode (local vs remote)
4. Workspace directory configuration
5. Authentication setup (OAuth, API keys, tokens)
6. Model selection and validation
7. Gateway networking (port, bind, auth, Tailscale)
8. Channel setup (Telegram, Discord, WhatsApp, etc.)
9. Skills initialization
10. Service installation (optional)

**Key Functions**:

- `runOnboardingWizard()` - Main orchestrator [src/wizard/onboarding.ts 87-451](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/wizard/onboarding.ts#L87-L451)
- `configureGatewayForOnboarding()` - Gateway setup [src/wizard/onboarding.gateway-config.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/wizard/onboarding.gateway-config.ts)
- `setupChannels()` - Channel configuration [src/commands/onboard-channels.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/onboard-channels.ts)
- `applyAuthChoice()` - Authentication handling [src/commands/auth-choice.apply.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/auth-choice.apply.ts)

**Sources**:

- [src/wizard/onboarding.ts 1-452](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/wizard/onboarding.ts#L1-L452)
- [src/commands/onboard-helpers.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/onboard-helpers.ts)
- [src/wizard/onboarding.gateway-config.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/wizard/onboarding.gateway-config.ts)

### openclaw configure

Section-by-section configuration editor with guided prompts:

**Available Sections**:

| Section ID | Label | Config Keys |
| --- | --- | --- |
| `gateway` | Gateway | `gateway.*` |
| `agent-defaults` | Agent Defaults | `agents.defaults.*` |
| `agents` | Multi-Agent | `agents.list` |
| `auth` | Authentication | `auth.*` |
| `models` | Model Catalog | `models.*` |
| `tools` | Tool Policies | `tools.*` |
| `channels` | Messaging Channels | `channels.*` |
| `memory` | Memory Search | `agents.defaults.memorySearch.*` |
| `sandbox` | Sandboxing | `agents.defaults.sandbox.*` |

**Implementation**:

- `runConfigureWizard()` - Section selector [src/commands/configure.wizard.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/configure.wizard.ts)
- `CONFIGURE_WIZARD_SECTIONS` - Section definitions [src/commands/configure.shared.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/configure.shared.ts)

**Sources**:

- [src/commands/configure.ts 1-5](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/configure.ts#L1-L5)
- [src/commands/configure.wizard.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/configure.wizard.ts)

### openclaw doctor

Automated health checks, migrations, and repairs. Performs:

- **Pre-flight**: Optional update check (git installs)
- **UI Protocol**: Freshness check for Control UI
- **Config Migration**: `migrateLegacyConfig()` for format changes
- **Auth Health**: OAuth expiry, profile cooldowns, keychain access
- **State Integrity**: Permissions, sessions, transcripts
- **Sandbox Images**: Pull/verify Docker images when enabled
- **Service Health**: systemd/launchd status and repair
- **Gateway Health**: Connection probe and restart prompts
- **Security Audit**: Open DM policies, missing auth tokens

**Modes**:

```
# Interactive (default)
openclaw doctor

# Auto-repair with confirmation
openclaw doctor --fix

# Non-interactive (safe migrations only)
openclaw doctor --non-interactive

# Deep scan (includes service detection)
openclaw doctor --deep
```

**Key Functions**:

- `doctorCommand()` - Main orchestrator [src/commands/doctor.ts 65-306](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/doctor.ts#L65-L306)
- `loadAndMaybeMigrateDoctorConfig()` - Config loading [src/commands/doctor-config-flow.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/doctor-config-flow.ts)
- `detectLegacyStateMigrations()` - State migration detection [src/commands/doctor-state-migrations.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/doctor-state-migrations.ts)
- `noteAuthProfileHealth()` - Auth validation [src/commands/doctor-auth.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/doctor-auth.ts)

**Sources**:

- [src/commands/doctor.ts 1-307](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/doctor.ts#L1-L307)
- [src/commands/doctor-config-flow.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/doctor-config-flow.ts)
- [src/commands/doctor-state-migrations.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/doctor-state-migrations.ts)

### openclaw config

Direct key manipulation for scripting and automation:

```
# Get a value
openclaw config get gateway.port

# Set a value
openclaw config set gateway.port 18790

# Unset a value (revert to default)
openclaw config unset gateway.bind

# List all keys
openclaw config list
```

**Implementation**:

- Directly modifies `openclaw.json` using lodash `_.get()` and `_.set()`
- Validates entire config after each write
- Preserves comments and formatting when possible (JSON5)

**Sources**:

- [src/cli/config-cli.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cli/config-cli.ts)

---

## Multi-Agent Configuration

OpenClaw supports multiple isolated agents with independent settings:

**Agent Isolation Layers**:

```
Personal AgentWork AgentMain Agent (default)Workspace
~/.openclaw/workspaceAgent Dir
~/.openclaw/agents/main/agentAuth Profiles
main/agent/auth-profiles.jsonTool Policy
agents.list[0].toolsModel Config
agents.list[0].modelWorkspace
~/work/openclawAgent Dir
~/.openclaw/agents/work/agentAuth Profiles
work/agent/auth-profiles.jsonTool Policy
agents.list[1].toolsModel Config
agents.list[1].modelWorkspace
~/personal/openclawAgent Dir
~/.openclaw/agents/personal/agentAuth Profiles
personal/agent/auth-profiles.jsonTool Policy
agents.list[2].toolsModel Config
agents.list[2].modelagents.defaults
Fallback SettingsChannel Bindings
channels.*.bindings
```

**Configuration Structure**:

```
{
  agents: {
    // Shared defaults (fallback for all agents)
    defaults: {
      workspace: "~/.openclaw/workspace",
      model: { primary: "anthropic/claude-opus-4" },
      tools: { profile: "full" },
      memorySearch: { enabled: true, provider: "openai" }
    },

    // Agent-specific overrides
    list: [
      {
        id: "main",
        default: true,  // Used when no binding matches
        workspace: "~/.openclaw/workspace",
        // Inherits from defaults
      },
      {
        id: "work",
        workspace: "~/work/openclaw",
        agentDir: "~/.openclaw/agents/work/agent",
        model: { primary: "openai-codex/gpt-5.2" },
        tools: {
          profile: "coding",
          deny: ["web_search"]  // Restrict for work context
        },
        sandbox: {
          mode: "all"  // Always sandbox for work agent
        }
      },
      {
        id: "personal",
        workspace: "~/personal/openclaw",
        model: { primary: "anthropic/claude-sonnet-4" },
        tools: {
          profile: "messaging",
          elevated: {
            enabled: false  // Disable elevated exec
          }
        }
      }
    ]
  }
}
```

**Agent Resolution**:

The system resolves which agent handles a message using:

1. **Channel Bindings**: Explicit mappings in `channels.<provider>.bindings`
	```
	channels: {
	  telegram: {
	    bindings: [
	      { account: "work_bot", agent: "work" },
	      { account: "personal_bot", agent: "personal" }
	    ]
	  }
	}
	```
2. **Default Agent**: Falls back to agent with `default: true` (usually `main`)

**Agent-Specific Settings**:

The `resolveAgentConfig()` function merges defaults with per-agent overrides:

| Setting | Override Behavior |
| --- | --- |
| `workspace` | Replaces default |
| `agentDir` | Replaces default |
| `model` | Merges `primary` and `fallbacks` |
| `tools` | Deep merges allow/deny lists |
| `memorySearch` | Deep merges all fields |
| `sandbox` | Deep merges docker/browser settings |
| `heartbeat` | Replaces default |
| `identity` | Replaces default |

**Sources**:

- [src/agents/agent-scope.ts 1-125](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/agent-scope.ts#L1-L125)
- [src/agents/agent-scope.ts 60-124](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/agent-scope.ts#L60-L124)
- [src/routing/session-key.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/routing/session-key.ts)

---

## Runtime Overrides

Environment variables provide runtime overrides without modifying `openclaw.json`:

**Override Resolution Flow**:

```
process.env.*resolveRuntimeOverrides()
src/config/runtime-overrides.tsBase Config
from openclaw.jsonMerged Config
env wins over file
```

**Common Override Patterns**:

| Environment Variable | Config Key | Example |
| --- | --- | --- |
| `OPENCLAW_GATEWAY_TOKEN` | `gateway.auth.token` | `secret123` |
| `OPENCLAW_GATEWAY_PORT` | `gateway.port` | `18790` |
| `OPENCLAW_STATE_DIR` | State directory | `~/custom-state` |
| `OPENCLAW_AGENT_DIR` | Agent directory | `~/custom-agent` |
| `ANTHROPIC_API_KEY` | `models.providers.anthropic.apiKey` | `sk-ant-...` |
| `OPENAI_API_KEY` | `models.providers.openai.apiKey` | `sk-...` |
| `GEMINI_API_KEY` | `models.providers.google.apiKey` | `AI...` |
| `OPENROUTER_API_KEY` | For openrouter provider | `sk-or-...` |

**Usage Example**:

```
# Override gateway token at runtime
OPENCLAW_GATEWAY_TOKEN=dev-token openclaw gateway run

# Use different state directory for testing
OPENCLAW_STATE_DIR=/tmp/openclaw-test openclaw gateway run

# Override model API key
ANTHROPIC_API_KEY=sk-test openclaw agent message "hello"
```

**Validation**:

Runtime overrides are applied *after* schema validation of the base config, then the merged result is validated again. This ensures environment variables cannot introduce invalid configurations.

**Sources**:

- [src/config/runtime-overrides.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/runtime-overrides.ts)
- [src/config/paths.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/paths.ts)

---

## Migration and Backwards Compatibility

The configuration system maintains backwards compatibility through automated migrations:

**Migration Architecture**:

```
Legacy Config
openclaw.json v0Detect Config Version
meta.lastTouchedVersionMigration 1
Rename FieldsMigration 2
Restructure DomainsMigration 3
New DefaultsValidate New Schema
OpenClawSchemaModern Config
openclaw.json v1Backup
openclaw.json.bak
```

**Migration Functions**:

- `migrateLegacyConfig()` - Config schema migrations [src/config/legacy-migrate.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/legacy-migrate.ts)
- `detectLegacyStateMigrations()` - State file relocations [src/commands/doctor-state-migrations.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/doctor-state-migrations.ts)
- `runLegacyStateMigrations()` - Execute state migrations [src/commands/doctor-state-migrations.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/doctor-state-migrations.ts)

**Types of Migrations**:

1. **Field Renames**: Old keys mapped to new locations
	```
	// Example: channels.whatsapp.policy → channels.whatsapp.dmPolicy
	if (config.channels?.whatsapp?.policy) {
	  config.channels.whatsapp.dmPolicy = config.channels.whatsapp.policy;
	  delete config.channels.whatsapp.policy;
	}
	```
2. **Structural Changes**: Domain reorganization
	```
	// Example: Move tools.elevated from global to agents.defaults
	if (config.tools?.elevated && !config.agents?.defaults?.tools?.elevated) {
	  config.agents = config.agents || {};
	  config.agents.defaults = config.agents.defaults || {};
	  config.agents.defaults.tools = config.agents.defaults.tools || {};
	  config.agents.defaults.tools.elevated = config.tools.elevated;
	}
	```
3. **Value Transformations**: Type or format changes
	```
	// Example: Convert string model to { primary: string } object
	if (typeof config.agents?.defaults?.model === 'string') {
	  config.agents.defaults.model = {
	    primary: config.agents.defaults.model
	  };
	}
	```
4. **State Relocations**: File path migrations
	```
	// Example: Move sessions from ~/.openclaw/sessions to 
	//          ~/.openclaw/agents/main/sessions
	await fs.rename(
	  '~/.openclaw/sessions',
	  '~/.openclaw/agents/main/sessions'
	);
	```

**Migration Guarantees**:

- **Non-destructive**: Original config backed up to `openclaw.json.bak`
- **Idempotent**: Running migrations multiple times is safe
- **Version-gated**: Only migrations newer than `meta.lastTouchedVersion` run
- **Validated**: Post-migration config must pass schema validation
- **Logged**: All migrations logged to console and `~/.openclaw/logs/gateway.log`

**Doctor Integration**:

The `doctor` command automatically detects and applies migrations:

```
# Detect migrations
openclaw doctor  # Prompts for confirmation

# Auto-apply migrations
openclaw doctor --fix

# Non-interactive (safe migrations only)
openclaw doctor --non-interactive
```

**Sources**:

- [src/config/legacy-migrate.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/legacy-migrate.ts)
- [src/commands/doctor-state-migrations.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/doctor-state-migrations.ts)
- [src/commands/doctor.ts 160-181](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/doctor.ts#L160-L181)

<svg id="mermaid-fu8dstus3vp" width="100%" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 2412 512" style="max-width: 512px;" role="graphics-document document" aria-roledescription="error"><g></g><g><path class="error-icon" d="m411.313,123.313c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32-9.375,9.375-20.688-20.688c-12.484-12.5-32.766-12.5-45.25,0l-16,16c-1.261,1.261-2.304,2.648-3.31,4.051-21.739-8.561-45.324-13.426-70.065-13.426-105.867,0-192,86.133-192,192s86.133,192 192,192 192-86.133 192-192c0-24.741-4.864-48.327-13.426-70.065 1.402-1.007 2.79-2.049 4.051-3.31l16-16c12.5-12.492 12.5-32.758 0-45.25l-20.688-20.688 9.375-9.375 32.001-31.999zm-219.313,100.687c-52.938,0-96,43.063-96,96 0,8.836-7.164,16-16,16s-16-7.164-16-16c0-70.578 57.422-128 128-128 8.836,0 16,7.164 16,16s-7.164,16-16,16z"></path><path class="error-icon" d="m459.02,148.98c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l16,16c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16.001-16z"></path><path class="error-icon" d="m340.395,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16-16c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l15.999,16z"></path><path class="error-icon" d="m400,64c8.844,0 16-7.164 16-16v-32c0-8.836-7.156-16-16-16-8.844,0-16,7.164-16,16v32c0,8.836 7.156,16 16,16z"></path><path class="error-icon" d="m496,96.586h-32c-8.844,0-16,7.164-16,16 0,8.836 7.156,16 16,16h32c8.844,0 16-7.164 16-16 0-8.836-7.156-16-16-16z"></path><path class="error-icon" d="m436.98,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688l32-32c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32c-6.251,6.25-6.251,16.375-0.001,22.625z"></path><text class="error-text" x="1440" y="250" font-size="150px" style="text-anchor: middle;">Syntax error in text</text> <text class="error-text" x="1250" y="400" font-size="100px" style="text-anchor: middle;">mermaid version 11.12.2</text></g></svg>