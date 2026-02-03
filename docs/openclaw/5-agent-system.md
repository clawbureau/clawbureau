Menu

## Agent System

Relevant source files
- [.npmrc](https://github.com/openclaw/openclaw/blob/bf6ec64f/.npmrc)
- [CHANGELOG.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/CHANGELOG.md)
- [README.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md)
- [assets/avatar-placeholder.svg](https://github.com/openclaw/openclaw/blob/bf6ec64f/assets/avatar-placeholder.svg)
- [docs/concepts/system-prompt.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/concepts/system-prompt.md)
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
- [src/agents/channel-tools.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/channel-tools.ts)
- [src/agents/cli-runner.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/cli-runner.test.ts)
- [src/agents/cli-runner/helpers.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/cli-runner/helpers.ts)
- [src/agents/pi-embedded-helpers.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-helpers.ts)
- [src/agents/pi-embedded-runner-extraparams.live.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner-extraparams.live.test.ts)
- [src/agents/pi-embedded-runner-extraparams.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner-extraparams.test.ts)
- [src/agents/pi-embedded-runner.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner.test.ts)
- [src/agents/pi-embedded-runner.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner.ts)
- [src/agents/pi-embedded-runner/compact.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner/compact.ts)
- [src/agents/pi-embedded-runner/run.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner/run.ts)
- [src/agents/pi-embedded-runner/run/attempt.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner/run/attempt.ts)
- [src/agents/pi-embedded-runner/run/params.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner/run/params.ts)
- [src/agents/pi-embedded-runner/run/types.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner/run/types.ts)
- [src/agents/pi-embedded-runner/system-prompt.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner/system-prompt.ts)
- [src/agents/pi-embedded-subscribe.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-subscribe.ts)
- [src/agents/pi-tools.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-tools.ts)
- [src/agents/sandbox.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/sandbox.ts)
- [src/agents/system-prompt-params.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/system-prompt-params.test.ts)
- [src/agents/system-prompt-params.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/system-prompt-params.ts)
- [src/agents/system-prompt-report.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/system-prompt-report.ts)
- [src/agents/system-prompt.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/system-prompt.test.ts)
- [src/agents/system-prompt.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/system-prompt.ts)
- [src/auto-reply/reply/commands-context-report.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/reply/commands-context-report.ts)
- [src/commands/agent/run-context.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/agent/run-context.ts)
- [src/commands/agent/types.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/commands/agent/types.ts)
- [src/config/types.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/types.ts)
- [src/config/zod-schema.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/zod-schema.ts)
- [src/gateway/protocol/schema/agent.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/gateway/protocol/schema/agent.ts)
- [src/index.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/index.ts)
- [src/telegram/group-migration.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/telegram/group-migration.test.ts)
- [src/telegram/group-migration.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/telegram/group-migration.ts)
- [ui/package.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/ui/package.json)
- [ui/src/styles.css](https://github.com/openclaw/openclaw/blob/bf6ec64f/ui/src/styles.css)
- [ui/src/styles/layout.mobile.css](https://github.com/openclaw/openclaw/blob/bf6ec64f/ui/src/styles/layout.mobile.css)

## Purpose and Scope

The Agent System is the core execution engine of OpenClaw. It orchestrates model inference, tool execution, and session management for all agent interactions. This page covers the architecture, execution flow, and configuration of agents.

For specific subsystems, see:

- **[Agent Execution Flow](https://deepwiki.com/openclaw/openclaw/5.1-agent-execution-flow)** for detailed message processing pipelines
- **[System Prompt](https://deepwiki.com/openclaw/openclaw/5.2-system-prompt)** for prompt construction and customization
- **[Session Management](https://deepwiki.com/openclaw/openclaw/5.3-session-management)** for session keys, history, and compaction
- **[Model Selection and Failover](https://deepwiki.com/openclaw/openclaw/5.4-model-selection-and-failover)** for model configuration and auth profile rotation

**Sources**: [CHANGELOG.md 1-850](https://github.com/openclaw/openclaw/blob/bf6ec64f/CHANGELOG.md#L1-L850) [README.md 1-500](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md#L1-L500)

---

## Architecture Overview

The Agent System wraps the Pi Agent Core library (`@mariozechner/pi-agent-core`) and provides OpenClaw-specific integrations for channels, tools, sandboxing, and configuration. The primary entry point is `runEmbeddedPiAgent`, which manages the full lifecycle of an agent turn.

```
Pi Agent CoreTool IntegrationContext AssemblyExecution OrchestrationAgent Entry PointsrunEmbeddedPiAgent
(pi-embedded-runner/run.ts)queueEmbeddedPiMessage
(queue management)compactEmbeddedPiSession
(history compaction)resolveModel
(model selection)ensureOpenClawModelsJson
(Pi models.json)buildEmbeddedRunPayloads
(prepare attempt)runEmbeddedAttempt
(single inference)buildAgentSystemPrompt
(system-prompt.ts)resolveBootstrapContextForRun
(AGENTS.md, SOUL.md, etc)resolveSkillsPromptForRun
(skills/*.md)SessionManager.load
(session history)createOpenClawCodingTools
(pi-tools.ts)resolveSandboxContext
(Docker isolation)filterToolsByPolicy
(allow/deny)createAgentSession
(Pi coding agent)streamSimple
(Pi AI)SessionManager
(JSONL storage)
```

**Key Abstractions**:

- **EmbeddedPiAgentMeta**: Configuration for an agent instance (workspace, model, tools, sandbox)
- **EmbeddedPiRunMeta**: Per-turn metadata (session key, message, channel context)
- **EmbeddedPiRunResult**: Execution outcome (success, error, usage, timing)
- **SubscribeEmbeddedPiSessionParams**: Streaming callbacks for real-time output

**Sources**: [src/agents/pi-embedded-runner.ts 1-28](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner.ts#L1-L28) [src/agents/pi-embedded-runner/run.ts 1-100](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner/run.ts#L1-L100) [README.md 130-200](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md#L130-L200)

---

## Agent Execution Flow

### Queue Management and Lanes

Agent execution supports two queue modes:

- **Sequential** (`session`): One turn at a time per session
- **Concurrent** (`global`): Parallel turns across all sessions

Queue modes are resolved via `resolveSessionLane` and `resolveGlobalLane` using configuration `agents.defaults.queue.mode`.

```
Tool ExecutorPi Agent CorerunEmbeddedAttemptrunEmbeddedPiAgentCommand QueueChannel AdapterTool ExecutorPi Agent CorerunEmbeddedAttemptrunEmbeddedPiAgentCommand QueueChannel AdapterResolve lane (sequential/concurrent)loop[Agent Turn]alt[Success][Auth Error][Context Overflow][Rate Limit]loop[Failover Attempts]queueEmbeddedPiMessageEnqueue in laneAcquire session lockLoad config & resolve agentBuild payloads (model, auth, sandbox)runEmbeddedAttemptLoad session historyBuild system promptLoad bootstrap filesCreate toolsstreamSimple (with tools)Text deltaTool callExecute toolTool resultDone (stop/error)Save sessionSuccess resultFailover (next auth profile)Auto-compactRetry with compacted historyMark profile cooldownFailover (next profile)Release session lockStream response chunks
```

**Key Functions**:

- `queueEmbeddedPiMessage` [src/agents/pi-embedded-runner/runs.ts 100-200](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner/runs.ts#L100-L200): Queue a message for execution
- `resolveSessionLane` [src/agents/pi-embedded-runner/lanes.ts 10-40](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner/lanes.ts#L10-L40): Determine if sequential or concurrent
- `acquireSessionWriteLock` [src/agents/session-write-lock.ts 10-60](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/session-write-lock.ts#L10-L60): Prevent concurrent modifications

**Sources**: [src/agents/pi-embedded-runner/run.ts 50-150](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner/run.ts#L50-L150) [src/agents/pi-embedded-runner/lanes.ts 1-80](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner/lanes.ts#L1-L80) [src/agents/pi-embedded-runner/runs.ts 1-300](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner/runs.ts#L1-L300)

---

### Attempt Execution Model

Each agent turn may involve multiple attempts due to failover. The `runEmbeddedAttempt` function handles a single inference attempt with full context assembly.

```
Streaming EventsInferenceTool CreationContext AssemblyAttempt PreparationLoad SessionManager
(session JSONL)limitHistoryTurns
(DM/group limits)resolveAuthProfileOrder
(OAuth + API keys)resolveSandboxContext
(Docker config)buildEmbeddedSystemPrompt
(sections + bootstrap)resolveBootstrapContextForRun
(AGENTS.md, SOUL.md, TOOLS.md)loadWorkspaceSkillEntries
(skills/*/SKILL.md)Memory context
(MEMORY.md if present)createOpenClawCodingTools
(read, write, edit, exec, process)createOpenClawTools
(browser, canvas, nodes, cron, sessions)filterToolsByPolicy
(allow/deny + sandbox)createAgentSession
(Pi coding agent)streamSimple
(model inference)subscribeEmbeddedPiSession
(streaming callbacks)text_delta
(incremental text)tool_use
(tool invocation)tool_result
(execution outcome)done
(stop/error/length)
```

**Key Files**:

- `runEmbeddedAttempt` [src/agents/pi-embedded-runner/run/attempt.ts 80-500](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner/run/attempt.ts#L80-L500): Single inference attempt orchestration
- `subscribeEmbeddedPiSession` [src/agents/pi-embedded-subscribe.ts 30-200](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-subscribe.ts#L30-L200): Event streaming and callbacks
- `createOpenClawCodingTools` [src/agents/pi-tools.ts 100-400](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-tools.ts#L100-L400): Tool registry construction

**Sources**: [src/agents/pi-embedded-runner/run/attempt.ts 1-600](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner/run/attempt.ts#L1-L600) [src/agents/pi-embedded-subscribe.ts 1-300](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-subscribe.ts#L1-L300) [src/agents/pi-tools.ts 1-500](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-tools.ts#L1-L500)

---

## System Prompt Construction

The system prompt is assembled from multiple sources with configurable sections. The `buildAgentSystemPrompt` function coordinates all prompt sections.

### Prompt Modes

Three modes control which sections are included:

- **full**: All sections (default for main agent)
- **minimal**: Reduced sections (Tooling, Workspace, Runtime) - used for subagents
- **none**: Just basic identity line, no sections
```
OutputBootstrap FilesPrompt Sections (Full Mode)Configuration Inputsagents.defaults / agents.list[]agents.list[].identitytools.allow / tools.denyagents.defaults.sandbox## User Identity
(owner numbers)## Current Date & Time
(timezone only)## Skills (mandatory)
(skills/*/SKILL.md)## Memory Recall
(memory_search/memory_get)## Messaging
(message tool, SILENT_REPLY_TOKEN)## Voice (TTS)
(TTS hints)## Reply Tags
([[reply_to_current]])## Documentation
(local docs path)## Reasoning Format
(/)## OpenClaw CLI Quick Reference
(gateway restart, etc)## Runtime Environment
(host, OS, arch, model)## Tooling
(available tool list)## Workspace
(workspace dir, notes)## Sandbox
(browser bridge, elevated mode)AGENTS.md
(core identity)SOUL.md
(personality)TOOLS.md
(custom tools)IDENTITY.md
(per-agent identity)USER.md
(user context)MEMORY.md
(memory context)System Prompt
(buildAgentSystemPrompt)
```

**Key Functions**:

- `buildAgentSystemPrompt` [src/agents/system-prompt.ts 129-400](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/system-prompt.ts#L129-L400): Assemble all prompt sections
- `resolveBootstrapContextForRun` [src/agents/bootstrap-files.ts 50-200](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/bootstrap-files.ts#L50-L200): Load bootstrap files
- `resolveSkillsPromptForRun` [src/agents/skills.ts 100-300](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/skills.ts#L100-L300): Build skills XML

**Prompt Section Summary**:

| Section | Condition | Purpose |
| --- | --- | --- |
| User Identity | `ownerNumbers` set | Identify authorized users |
| Current Date & Time | `userTimezone` set | Time zone for scheduling |
| Skills (mandatory) | `skillsPrompt` present | Skill discovery and loading |
| Memory Recall | `memory_search` tool available | Memory integration guidance |
| Messaging | Not minimal mode | Cross-channel messaging rules |
| Voice (TTS) | `ttsHint` set | TTS tag usage |
| Reply Tags | Not minimal mode | Native reply/quote syntax |
| Documentation | `docsPath` set | OpenClaw docs reference |
| Reasoning Format | `reasoningTagHint` true | `<think>/<final>` tag usage |
| CLI Quick Reference | Always (full mode) | Gateway commands |
| Runtime Environment | `runtimeInfo` present | Host/OS/model context |
| Tooling | `toolNames` present | Available tool list |
| Workspace | Always | Workspace directory |
| Sandbox | Sandbox enabled | Browser bridge, elevated mode |

**Sources**: [src/agents/system-prompt.ts 1-500](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/system-prompt.ts#L1-L500) [docs/concepts/system-prompt.md 1-200](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/concepts/system-prompt.md#L1-L200) [src/agents/bootstrap-files.ts 1-300](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/bootstrap-files.ts#L1-L300)

---

## Session Management

Sessions are identified by session keys and stored as JSONL files via the Pi Agent Core `SessionManager`.

### Session Key Format

Session keys follow a hierarchical pattern:

```
agent:{agentId}:{channel}:{scope}:{identifier}
```

Examples:

- `agent:main:whatsapp:dm:+15555550123` (DM)
- `agent:main:telegram:group:123456789` (group)
- `agent:work:slack:dm:U0123ABC` (multi-agent DM)

**Key Resolution**:

- `deriveSessionKey` [src/config/sessions.ts 50-150](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/sessions.ts#L50-L150): Generate session key from channel/message context
- `resolveSessionKey` [src/config/sessions.ts 150-250](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/sessions.ts#L150-L250): Normalize and validate session key format

### Session Storage

Sessions are stored as JSONL files:

- **Location**: `~/.openclaw/sessions/{sessionKey}.jsonl`
- **Format**: One JSON object per line (messages, metadata, events)
- **Management**: `SessionManager` from `@mariozechner/pi-coding-agent`
```
Session OperationsSession ManagerSession Stores~/.openclaw/sessions/
(default)Custom path
(session.store override)SessionManager.load
(read JSONL)SessionManager.append
(write message)SessionManager.truncate
(compact history)limitHistoryTurns
(DM/group limits)compactEmbeddedPiSession
(summarize old turns)Session reset
(delete or truncate)
```

**History Limits**:

- **DM sessions**: `session.dmHistoryLimit` (default: no limit)
- **Group sessions**: `session.historyLimit` (default: 100 turns)
- Per-channel overrides: `session.dmHistoryLimitByChannel`, `session.historyLimitByChannel`

**Compaction**:

- Triggered when context overflow occurs
- Summarizes old conversation turns
- Preserves recent messages
- See `compactEmbeddedPiSession` [src/agents/pi-embedded-runner/compact.ts 50-300](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner/compact.ts#L50-L300)

**Sources**: [src/config/sessions.ts 1-400](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/sessions.ts#L1-L400) [src/agents/pi-embedded-runner/compact.ts 1-400](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner/compact.ts#L1-L400) [docs/gateway/configuration.md 1800-2000](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/configuration.md#L1800-L2000)

---

## Model Selection and Failover

Model selection involves resolving the primary model, loading auth profiles, and handling failover on errors.

### Model Resolution Pipeline

```
Recovery ActionsFailover LogicAuth Profile ResolutionModel ValidationModel SelectionAuthBillingRate LimitOverflowSuccessOtherUser /model directiveSession-pinned modelagents.list[].model.primaryagents.defaults.model.primarymodels.defaults.model
(anthropic/claude-sonnet-4-5)ensureOpenClawModelsJson
(write Pi models.json)resolveModel
(validate + normalize)auth-profiles.json
(OAuth + API keys)resolveAuthProfileOrder
(per-provider rotation)isProfileInCooldown
(billing/failure backoff)getApiKeyForModel
(first available)runEmbeddedAttempt
(inference)markAuthProfileFailure
(cooldown)markAuthProfileGood
(clear cooldown)Next auth profileAuto-compact sessionTry fallback model
```

**Key Functions**:

- `resolveDefaultModelForAgent` [src/agents/model-selection.ts 50-150](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/model-selection.ts#L50-L150): Resolve model with fallbacks
- `resolveAuthProfileOrder` [src/agents/model-auth.ts 200-300](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/model-auth.ts#L200-L300): Auth profile rotation order
- `isProfileInCooldown` [src/agents/auth-profiles.ts 50-100](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/auth-profiles.ts#L50-L100): Check billing/failure cooldown
- `classifyFailoverReason` [src/agents/pi-embedded-helpers/errors.ts 200-350](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-helpers/errors.ts#L200-L350): Classify error type

**Failover Reasons**:

| Reason | Detection | Action |
| --- | --- | --- |
| `auth_error` | 401, invalid\_api\_key | Mark profile bad, rotate auth |
| `billing_error` | 402, insufficient\_quota | Mark profile bad (long cooldown), rotate |
| `rate_limit` | 429, rate\_limit\_exceeded | Mark profile cooldown, rotate |
| `context_overflow` | context\_length\_exceeded | Auto-compact, retry same model |
| `timeout` | Network timeout | Retry with next auth profile |
| `overloaded` | 529, overloaded\_error | Retry with exponential backoff |
| `unknown` | Other errors | Try fallback model |

**Cooldown Configuration**:

- `auth.cooldowns.billingBackoffHours` (default: 24 hours)
- `auth.cooldowns.failureWindowHours` (default: 1 hour)
- `auth.cooldowns.billingMaxHours` (default: 168 hours = 7 days)

**Sources**: [src/agents/pi-embedded-runner/run.ts 200-600](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner/run.ts#L200-L600) [src/agents/model-auth.ts 1-500](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/model-auth.ts#L1-L500) [src/agents/auth-profiles.ts 1-300](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/auth-profiles.ts#L1-L300) [src/agents/failover-error.ts 1-200](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/failover-error.ts#L1-L200)

---

## Tool System Integration

Tools are created via `createOpenClawCodingTools`, which combines Pi coding tools (read, write, edit, exec, process) with OpenClaw-specific tools (browser, canvas, nodes, cron, sessions, message).

### Tool Creation Pipeline

```
Tool FilteringOpenClaw ToolsTool CreationTool Policy Resolutiontools.allow / tools.denyagents.list[].toolstools.byProviderchannels..groups..toolPolicySubagent tool restrictionsagents.defaults.sandbox.toolsPi coding tools
(read, write, edit)createExecTool
(bash-tools.exec.ts)createProcessTool
(bash-tools.process.ts)createApplyPatchTool
(apply-patch.ts)createOpenClawTools
(openclaw-tools.ts)browser
(CDP control)canvas
(A2UI host)nodes
(device actions)cron
(scheduled tasks)message
(channel actions)sessions_*
(cross-session)gateway
(restart, config)filterToolsByPolicy
(merge all policies)Sandbox tool restrictionsAvailable Tools
(sent to model)
```

**Tool Policy Precedence** (most to least restrictive):

1. Subagent restrictions (if subagent)
2. Sandbox tool policy (if sandbox enabled)
3. Group tool policy (if group message)
4. Provider-specific policy (`tools.byProvider`)
5. Tool profile (`tools.profile`)
6. Global allow/deny (`tools.allow`, `tools.deny`)

**Tool Groups**:

- `group:fs`: read, write, edit, apply\_patch, grep, find, ls
- `group:runtime`: exec, process
- `group:sessions`: sessions\_list, sessions\_history, sessions\_send, sessions\_spawn
- `group:memory`: memory\_search, memory\_get
- `group:messaging`: message (all actions)

**Sandbox Tool Restrictions**:

- Default sandbox tool policy: `{ allow: ["group:fs", "group:runtime", "group:sessions", "group:memory"], deny: ["browser", "canvas", "nodes", "cron", "gateway"] }`
- Per-agent override: `agents.list[].sandbox.tools`
- See [Sandboxing](https://deepwiki.com/openclaw/openclaw/13.3-cloud-deployment) for detailed sandbox configuration

**Sources**: [src/agents/pi-tools.ts 1-700](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-tools.ts#L1-L700) [src/agents/pi-tools.policy.ts 1-400](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-tools.policy.ts#L1-L400) [src/agents/tool-policy.ts 1-300](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/tool-policy.ts#L1-L300) [docs/tools/index.md 1-400](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/tools/index.md#L1-L400)

---

## Configuration

The Agent System is configured via `agents.defaults` and `agents.list[]` in `openclaw.json`.

### Configuration Schema

```
Runtime ResolutionPer-Agent Config (agents.list[])Agent Defaults (agents.defaults)workspace
(workspace directory)model.primary
(default model)sandbox
(Docker isolation)queue.mode
(sequential/concurrent)tools
(allow/deny)groupChat
(mention patterns)id
(agent identifier)workspace
(override)model
(override)sandbox
(override)tools
(override)identity
(name, emoji, avatar)groupChat
(override)resolveSessionAgentIds
(session → agent)resolveSandboxConfigForAgent
(merge defaults)resolveDefaultModelForAgent
(merge defaults)
```

**Key Configuration Fields**:

| Field | Type | Purpose |
| --- | --- | --- |
| `agents.defaults.workspace` | string | Default workspace directory |
| `agents.defaults.model.primary` | string | Default model (e.g. `anthropic/claude-sonnet-4-5`) |
| `agents.defaults.sandbox.mode` | string | Sandbox mode (`off`, `non-main`, `all`) |
| `agents.defaults.queue.mode` | string | Queue mode (`sequential`, `concurrent`) |
| `agents.defaults.tools` | object | Global tool policy |
| `agents.list[].id` | string | Agent identifier (unique) |
| `agents.list[].workspace` | string | Per-agent workspace override |
| `agents.list[].model` | object | Per-agent model override |
| `agents.list[].sandbox` | object | Per-agent sandbox override |
| `agents.list[].tools` | object | Per-agent tool policy override |
| `agents.list[].identity` | object | Agent identity (name, emoji, avatar) |

**Configuration Examples**:

Minimal configuration (single agent):

```
{
  agents: {
    defaults: {
      workspace: "~/.openclaw/workspace",
      model: { primary: "anthropic/claude-sonnet-4-5" }
    }
  }
}
```

Multi-agent configuration:

```
{
  agents: {
    defaults: {
      workspace: "~/.openclaw/workspace",
      model: { primary: "anthropic/claude-sonnet-4-5" },
      sandbox: { mode: "non-main", scope: "session" }
    },
    list: [
      {
        id: "main",
        identity: { name: "Clawd", emoji: "🦞" }
      },
      {
        id: "work",
        workspace: "~/work/workspace",
        sandbox: { mode: "all" },
        tools: { profile: "coding" }
      },
      {
        id: "support",
        tools: { profile: "messaging", allow: ["slack", "discord"] }
      }
    ]
  }
}
```

**Agent Resolution**:

- `resolveSessionAgentIds` [src/agents/agent-scope.ts 50-150](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/agent-scope.ts#L50-L150): Map session key to agent ID
- `resolveSandboxConfigForAgent` [src/agents/sandbox/config.ts 50-200](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/sandbox/config.ts#L50-L200): Merge sandbox config
- `resolveDefaultModelForAgent` [src/agents/model-selection.ts 50-150](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/model-selection.ts#L50-L150): Merge model config

**Sources**: [docs/gateway/configuration.md 400-800](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/configuration.md#L400-L800) [docs/gateway/configuration-examples.md 1-300](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/configuration-examples.md#L1-L300) [docs/multi-agent-sandbox-tools.md 1-250](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/multi-agent-sandbox-tools.md#L1-L250) [src/config/types.agents.ts 1-200](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/types.agents.ts#L1-L200)

---

## Multi-Agent Architecture

OpenClaw supports multiple isolated agents with dedicated workspaces, auth profiles, and tool policies. Agents are routed via channel bindings.

### Agent Routing

```
Agent IsolationAgent SelectionRouting ResolutionInbound MessageChannel
(whatsapp/telegram/etc)Account ID
(multi-account)Chat Type
(dm/group)Chat IDBinding Key
(channel:account)bindings.agents
(channel:account → agentId)broadcast
(groupId → [agentIds])Default Agent
(agents.list[0] or 'main')Bound Agent
(from bindings)Broadcast Agents
(from broadcast)Agent Workspace
(agents.list[].workspace)Agent Auth
(auth-profiles.json)Agent Sessions
(session keys)Agent Tools
(agents.list[].tools)
```

**Binding Configuration**:

```
{
  bindings: {
    agents: {
      "whatsapp:default": "main",
      "telegram:work_bot": "work",
      "slack:support_bot": "support"
    }
  }
}
```

**Broadcast Configuration** (group → multiple agents):

```
{
  broadcast: {
    "120363403215116621@g.us": ["main", "work"],
    "telegram:-1001234567890": ["support", "sales"]
  }
}
```

**Agent Isolation**:

- **Workspace**: Each agent has a dedicated workspace directory
- **Auth**: Each agent has its own `auth-profiles.json`
- **Sessions**: Session keys include agent ID: `agent:{agentId}:...`
- **Tools**: Each agent can have distinct tool policies

**Sources**: [src/config/types.agents.ts 1-300](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/types.agents.ts#L1-L300) [docs/gateway/configuration.md 1200-1500](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/gateway/configuration.md#L1200-L1500) [docs/multi-agent-sandbox-tools.md 1-250](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/multi-agent-sandbox-tools.md#L1-L250)

<svg id="mermaid-fu8dstus3vp" width="100%" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 2412 512" style="max-width: 512px;" role="graphics-document document" aria-roledescription="error"><g></g><g><path class="error-icon" d="m411.313,123.313c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32-9.375,9.375-20.688-20.688c-12.484-12.5-32.766-12.5-45.25,0l-16,16c-1.261,1.261-2.304,2.648-3.31,4.051-21.739-8.561-45.324-13.426-70.065-13.426-105.867,0-192,86.133-192,192s86.133,192 192,192 192-86.133 192-192c0-24.741-4.864-48.327-13.426-70.065 1.402-1.007 2.79-2.049 4.051-3.31l16-16c12.5-12.492 12.5-32.758 0-45.25l-20.688-20.688 9.375-9.375 32.001-31.999zm-219.313,100.687c-52.938,0-96,43.063-96,96 0,8.836-7.164,16-16,16s-16-7.164-16-16c0-70.578 57.422-128 128-128 8.836,0 16,7.164 16,16s-7.164,16-16,16z"></path><path class="error-icon" d="m459.02,148.98c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l16,16c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16.001-16z"></path><path class="error-icon" d="m340.395,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16-16c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l15.999,16z"></path><path class="error-icon" d="m400,64c8.844,0 16-7.164 16-16v-32c0-8.836-7.156-16-16-16-8.844,0-16,7.164-16,16v32c0,8.836 7.156,16 16,16z"></path><path class="error-icon" d="m496,96.586h-32c-8.844,0-16,7.164-16,16 0,8.836 7.156,16 16,16h32c8.844,0 16-7.164 16-16 0-8.836-7.156-16-16-16z"></path><path class="error-icon" d="m436.98,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688l32-32c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32c-6.251,6.25-6.251,16.375-0.001,22.625z"></path><text class="error-text" x="1440" y="250" font-size="150px" style="text-anchor: middle;">Syntax error in text</text> <text class="error-text" x="1250" y="400" font-size="100px" style="text-anchor: middle;">mermaid version 11.12.2</text></g></svg>