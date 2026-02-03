Menu

## Commands and Directives

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
- [docs/tools/slash-commands.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/tools/slash-commands.md)
- [extensions/memory-core/package.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/extensions/memory-core/package.json)
- [package.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json)
- [pnpm-lock.yaml](https://github.com/openclaw/openclaw/blob/bf6ec64f/pnpm-lock.yaml)
- [pnpm-workspace.yaml](https://github.com/openclaw/openclaw/blob/bf6ec64f/pnpm-workspace.yaml)
- [scripts/clawtributors-map.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/clawtributors-map.json)
- [scripts/update-clawtributors.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/update-clawtributors.ts)
- [scripts/update-clawtributors.types.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/update-clawtributors.types.ts)
- [src/agents/pi-embedded-runner-extraparams.live.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner-extraparams.live.test.ts)
- [src/agents/pi-embedded-runner-extraparams.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner-extraparams.test.ts)
- [src/auto-reply/command-detection.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/command-detection.ts)
- [src/auto-reply/commands-args.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/commands-args.ts)
- [src/auto-reply/commands-registry.data.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/commands-registry.data.ts)
- [src/auto-reply/commands-registry.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/commands-registry.test.ts)
- [src/auto-reply/commands-registry.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/commands-registry.ts)
- [src/auto-reply/commands-registry.types.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/commands-registry.types.ts)
- [src/auto-reply/group-activation.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/group-activation.ts)
- [src/auto-reply/reply.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/reply.ts)
- [src/auto-reply/reply/commands-info.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/reply/commands-info.test.ts)
- [src/auto-reply/reply/commands-info.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/reply/commands-info.ts)
- [src/auto-reply/reply/commands.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/reply/commands.ts)
- [src/auto-reply/reply/directive-handling.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/reply/directive-handling.ts)
- [src/auto-reply/send-policy.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/send-policy.ts)
- [src/auto-reply/status.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/status.test.ts)
- [src/auto-reply/status.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/status.ts)
- [src/auto-reply/templating.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/templating.ts)
- [src/discord/monitor/native-command.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/discord/monitor/native-command.ts)
- [src/index.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/index.ts)
- [src/slack/monitor/slash.command-arg-menus.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/slack/monitor/slash.command-arg-menus.test.ts)
- [src/slack/monitor/slash.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/slack/monitor/slash.ts)
- [src/telegram/bot-handlers.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/telegram/bot-handlers.ts)
- [src/telegram/bot/types.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/telegram/bot/types.ts)
- [ui/package.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/ui/package.json)
- [ui/src/styles.css](https://github.com/openclaw/openclaw/blob/bf6ec64f/ui/src/styles.css)
- [ui/src/styles/layout.mobile.css](https://github.com/openclaw/openclaw/blob/bf6ec64f/ui/src/styles/layout.mobile.css)

This page documents the command and directive system in OpenClaw. Commands are user-facing interactions (like `/status`, `/help`, `/model`) that trigger specific actions. Directives are special modifiers (like `/think`, `/verbose`, `/reasoning`) that control agent behavior and can be either inline hints or persistent session settings.

For detailed command reference and usage examples, see [Command Reference](https://deepwiki.com/openclaw/openclaw/9.1-command-reference). For platform-specific command implementations, see [Platform-Specific Commands](https://deepwiki.com/openclaw/openclaw/9.2-platform-specific-commands). For directive behavior details, see [Directives](https://deepwiki.com/openclaw/openclaw/9.3-directives).

## Command vs Directive Concepts

OpenClaw distinguishes between **commands** and **directives**:

### Commands

Standalone `/...` messages that trigger specific actions:

- `/status` - Show session and model status
- `/help` - Display help information
- `/reset` - Reset the current session
- `/compact` - Compact session history
- `/model` - Change model selection

Commands must generally be sent as standalone messages (the message starts with `/`). Some commands like `/help`, `/status`, `/commands`, and `/whoami` can also work as **inline shortcuts** when embedded in regular messages.

### Directives

Modifiers that control agent behavior, stripped from messages before the model sees them:

- `/think <level>` - Set thinking level
- `/verbose on|off` - Control verbosity
- `/reasoning on|off` - Control reasoning output
- `/elevated on|off` - Control elevated access
- `/exec host=... security=...` - Configure exec tool behavior
- `/model <name>` - Change model
- `/queue <mode>` - Configure queue behavior

Directives behave differently based on message content:

- **Inline hints** (when mixed with regular text): Applied for that turn only, not persisted
- **Directive-only messages** (message contains only directives): Persisted to session, acknowledged with confirmation

Sources: [docs/tools/slash-commands.md 1-20](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/tools/slash-commands.md#L1-L20) [src/auto-reply/reply/directives.ts 1-12](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/reply/directives.ts#L1-L12)

## Command Processing Architecture

```
YesNoNoYesInbound Message
(from channel)getCommandDetection()
commands-registry.ts:174Command
detected?Access Control Check
useAccessGroups configAuthorized?extractDirectives()
directives.tsnormalizeCommandBody()
commands-registry.ts:332parseCommandArgs()
commands-registry.ts:400Normal agent flowSilent drop or
treat as textRoute to handlerhandleCommands()
commands.tsExecute specific
command handlerFormat and send reply
```

**Command Detection Flow**

The command detection flow determines whether an inbound message is a command and routes it accordingly:

1. **Detection**: `getCommandDetection()` checks if the message starts with `/` and matches a registered command alias
2. **Access Control**: If `commands.useAccessGroups` is enabled, verifies the sender is authorized (allowlist/pairing)
3. **Directive Extraction**: Strips directives from the message text before further processing
4. **Normalization**: `normalizeCommandBody()` parses the command text and extracts the command name
5. **Argument Parsing**: `parseCommandArgs()` extracts command arguments based on the command definition
6. **Routing**: Matched command is routed to `handleCommands()` for execution

Sources: [src/auto-reply/commands-registry.ts 174-226](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/commands-registry.ts#L174-L226) [src/auto-reply/reply/commands.ts 1-9](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/reply/commands.ts#L1-L9) [src/auto-reply/command-detection.ts 1-6](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/command-detection.ts#L1-L6)

## Command Registry System

```
Command DiscoveryCommand MetadataCommand RegistryCommand Definition SourcesgetChatCommands()
commands-registry.data.ts:10listPluginCommands()
plugins/commands.tslistSkillCommandsForAgents()
skill-commands.tsCommand Registry Cache
commands-registry.ts:40-65Text Alias Map
/{command} → specNative Command Specs
Discord/Telegram/SlackChatCommandDefinition
- key: string
- description: string
- textAliases: string[]
- nativeName: string
- args: ArgDefinition[]
- acceptsArgs: boolean
- category: CommandCategory
- scope: CommandScopelistChatCommands()listNativeCommandSpecs()findCommandByNativeName()
```

**Command Registry Components**

The command registry aggregates commands from multiple sources and provides lookup interfaces:

- **`getChatCommands()`**: Returns all built-in command definitions with metadata (key, description, aliases, arguments)
- **`listPluginCommands()`**: Dynamically discovers commands contributed by loaded plugins
- **`listSkillCommandsForAgents()`**: Generates commands for user-invocable skills
- **Text Alias Map**: Caches command text aliases (e.g., `/status`, `/s`) for fast lookup
- **Native Command Specs**: Platform-specific command definitions for Discord/Telegram/Slack registration
- **`ChatCommandDefinition`**: Command metadata structure including key, description, text aliases, native name, arguments, category, and scope

Command keys are internal identifiers (e.g., `dock:telegram`) while text aliases are user-facing (e.g., `/dock-telegram`). Commands are categorized (status, configuration, agent, session, system) and scoped (owner-only, sender-gated).

Sources: [src/auto-reply/commands-registry.ts 40-65](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/commands-registry.ts#L40-L65) [src/auto-reply/commands-registry.data.ts 10-30](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/commands-registry.data.ts#L10-L30) [src/auto-reply/skill-commands.ts 9](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/skill-commands.ts#L9-L9)

## Directive Processing Flow

```
NoYesYes - Directive-only msgNo - Mixed with textInbound MessageSender
authorized?parseInlineDirectives()
directive-handling.parse.tsisDirectiveOnly()?Treat directives as
plain textpersistInlineDirectives()
directive-handling.persist.tsApply as inline hints
(not persisted)Update session store
thinkingLevel, verboseLevel, etc.formatDirectiveAck()
Send acknowledgementStrip directives from textApply for this turn onlyPass cleaned text
to agentapplyInlineDirectivesFastLane()
Bypass queue/model
```

**Directive Processing Behavior**

Directive processing varies based on message content and sender authorization:

1. **Authorization Check**: Directives are only processed for authorized senders (allowlist/pairing). Unauthorized senders see directives as plain text
2. **Extraction**: `parseInlineDirectives()` identifies and extracts directive tokens from the message
3. **Directive-Only Messages**: When the message contains only directives, they are persisted to the session and an acknowledgement is sent
4. **Mixed Messages**: When directives are mixed with regular text, they are applied as temporary hints for that turn only (not persisted)
5. **Fast Lane**: Directive-only messages use `applyInlineDirectivesFastLane()` to bypass the queue and model, executing immediately

Directives supported:

- `/think <level>` - Set thinking level (off, minimal, low, medium, high, xhigh)
- `/verbose on|off|full` - Control verbose logging
- `/reasoning on|off|stream` - Control reasoning output
- `/elevated on|off|ask|full` - Control elevated exec access
- `/exec host=... security=... ask=... node=...` - Configure exec tool
- `/model <name>` - Change active model
- `/queue <mode> [options]` - Configure queue behavior

Sources: [src/auto-reply/reply/directive-handling.ts 1-7](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/reply/directive-handling.ts#L1-L7) [src/auto-reply/reply/directive-handling.parse.ts 4](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/reply/directive-handling.parse.ts#L4-L4) [src/auto-reply/reply/directive-handling.persist.ts 5](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/reply/directive-handling.persist.ts#L5-L5)

## Platform-Specific Command Implementations

```
Text Command FallbackSlack (Bolt)Telegram (grammY)Discord (Carbon)registerNativeCommands()
discord/native-commands.tsDiscordCommand class
monitor/native-command.ts:23Autocomplete handler
native-command.ts:300registerTelegramHandlers()
telegram/bot-handlers.ts:26bot.command() handlersInline keyboard buttons
inline-buttons.tsregisterSlackHandlers()
slack/monitor.tsapp.command() handlers
slack/monitor/slash.ts:9Block action handlers
slack/monitor/slash.ts:150Text command parser
commands-registry.ts:332WhatsApp, Signal,
iMessage, WebChat,
Google Chat, MS TeamsCommand Registry
```

**Native Command Registration**

Native commands are platform-specific slash commands that provide enhanced UX:

### Discord Commands

- Uses `@buape/carbon` library for command registration
- `DiscordCommand` class extends `Command` base class
- Autocomplete for dynamic option values (models, thinking levels, etc.)
- Button menus when required arguments are omitted
- Registration happens in `registerNativeCommands()` when `commands.native` is enabled

### Telegram Commands

- Uses `grammY` bot framework
- Commands registered via `bot.command()` handlers
- Inline keyboard buttons for option selection
- Forum thread support (topic IDs preserved in commands)
- Registration in `registerTelegramHandlers()`

### Slack Commands

- Uses `@slack/bolt` framework
- Commands registered via `app.command()` handlers
- Block action handlers for button interactions
- Requires manual slash command creation in Slack app settings
- Command list at `/slack-commands` endpoint for easy setup

### Text Command Fallback

All platforms support text commands as fallback. Channels without native command support (WhatsApp, Signal, iMessage, WebChat, Google Chat, MS Teams) rely exclusively on text command parsing.

Configuration:

- `commands.native: "auto"` - Auto-enable for Discord/Telegram, off for Slack
- `commands.text: true` - Enable text command parsing (default)
- Per-channel overrides: `channels.discord.commands.native`, etc.

Sources: [src/discord/monitor/native-command.ts 1-10](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/discord/monitor/native-command.ts#L1-L10) [src/telegram/bot-handlers.ts 26-35](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/telegram/bot-handlers.ts#L26-L35) [src/slack/monitor/slash.ts 1-15](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/slack/monitor/slash.ts#L1-L15)

## Command Argument System

```
Dynamic ChoicesArgument FormattersArgument ParsingArgument DefinitionCommandArgDefinition
- name: string
- type: 'string' | 'choice' | 'boolean'
- required: boolean
- choices: string[] | function
- description: stringparseCommandArgs()
Text command parsing
commands-registry.ts:400Native command parsing
Platform-specificserializeCommandArgs()
commands-registry.ts:502COMMAND_ARG_FORMATTERS
commands-args.ts:1formatThinkingLevel()formatModelRef()formatQueueMode()resolveCommandArgChoices()
commands-registry.ts:570CommandArgChoiceContext
- config
- sessionKey
- accountId
- agentId
```

**Argument Processing**

Command arguments are defined, parsed, and validated through a structured system:

1. **Argument Definition**: Each command declares its arguments via `CommandArgDefinition`:
	- `name`: Argument identifier
	- `type`: string, choice (enum), or boolean
	- `required`: Whether the argument is mandatory
	- `choices`: Static array or dynamic function returning available values
	- `description`: Help text for the argument
2. **Text Parsing**: `parseCommandArgs()` extracts arguments from text commands:
	- Simple space-separated values: `/model gpt-5`
	- Key-value pairs: `/exec host=gateway security=full`
	- Quoted values: `/message send --message "Hello world"`
3. **Native Parsing**: Platform-specific parsing from native command interactions:
	- Discord: Autocomplete options and select menus
	- Telegram: Inline keyboard buttons
	- Slack: Block kit select menus
4. **Serialization**: `serializeCommandArgs()` converts parsed arguments back to canonical text format for storage/display
5. **Dynamic Choices**: `resolveCommandArgChoices()` provides context-aware option lists:
	- Available models based on configured providers
	- Thinking levels filtered by model/provider support
	- Queue modes and their parameters
6. **Formatters**: `COMMAND_ARG_FORMATTERS` provide domain-specific argument formatting for display

Sources: [src/auto-reply/commands-registry.ts 400-502](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/commands-registry.ts#L400-L502) [src/auto-reply/commands-registry.types.ts 1-20](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/commands-registry.types.ts#L1-L20) [src/auto-reply/commands-args.ts 1-15](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/commands-args.ts#L1-L15)

## Command Execution Flow

```
Command HandlersCommand ContextRoute to handlerbuildCommandContext()
commands-context.tsCommandContext
- config
- sessionEntry
- sessionKey
- commandArgs
- channel
- accountId
- senderId
- isOwner
- msgContexthandleCommands()
commands-core.tsbuildStatusReply()
commands-status.tsbuildHelpMessage()
status.tsbuildCommandsMessage()
status.tshandleModelCommand()handleResetCommand()handleCompactCommand()handleConfigCommand()Format replySend to channel
```

**Command Handler Execution**

Command handlers execute in a structured context with access to configuration and session state:

1. **Context Building**: `buildCommandContext()` assembles:
	- Current configuration
	- Session entry (history, model, tokens)
	- Session key for routing
	- Parsed command arguments
	- Channel and account information
	- Sender identity and owner status
	- Message metadata
2. **Handler Dispatch**: `handleCommands()` routes to specific handlers:
	- **Status**: `buildStatusReply()` generates session status with model, tokens, cost, runtime
	- **Help**: `buildHelpMessage()` returns command help text
	- **Commands**: `buildCommandsMessage()` lists available commands (paginated for Telegram)
	- **Model**: Changes active model and persists to session
	- **Reset**: Clears session history and reinitializes
	- **Compact**: Triggers history compaction/summarization
	- **Config**: Read/write configuration (requires `commands.config: true`)
3. **Response Formatting**: Handlers return structured responses with:
	- Reply text (markdown formatted)
	- Target routing (original channel or explicit override)
	- Metadata (suppress typing indicators, etc.)
4. **Delivery**: Response is sent through the originating channel adapter

Sources: [src/auto-reply/reply/commands.ts 1-9](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/reply/commands.ts#L1-L9) [src/auto-reply/reply/commands-context.ts 1](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/reply/commands-context.ts#L1-L1) [src/auto-reply/reply/commands-status.ts 1](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/reply/commands-status.ts#L1-L1)

## Configuration

Commands and directives are configured via the `commands` section of `openclaw.json`:

| Config Key | Type | Default | Description |
| --- | --- | --- | --- |
| `commands.native` | `boolean \| "auto"` | `"auto"` | Enable native slash commands (auto: on for Discord/Telegram, off for Slack) |
| `commands.nativeSkills` | `boolean \| "auto"` | `"auto"` | Register skill commands as native slash commands |
| `commands.text` | `boolean` | `true` | Enable text command parsing (`/...` in messages) |
| `commands.bash` | `boolean` | `false` | Enable `! <cmd>` host bash commands (requires `tools.elevated` allowlists) |
| `commands.bashForegroundMs` | `number` | `2000` | Bash foreground timeout before backgrounding |
| `commands.config` | `boolean` | `false` | Enable `/config` command for disk writes |
| `commands.debug` | `boolean` | `false` | Enable `/debug` command for runtime overrides |
| `commands.restart` | `boolean` | `false` | Enable `/restart` command |
| `commands.useAccessGroups` | `boolean` | `true` | Enforce allowlist/pairing for commands and directives |

### Per-Channel Overrides

Channel-specific command settings override global defaults:

```
{
  channels: {
    discord: {
      commands: {
        native: true,          // Override global commands.native
        nativeSkills: false    // Disable skill commands on Discord
      }
    },
    telegram: {
      commands: {
        native: true,
        nativeSkills: true
      }
    },
    slack: {
      commands: {
        native: false          // Slack requires manual slash command setup
      }
    }
  }
}
```

### Access Control

When `commands.useAccessGroups: true` (default), commands and directives are only processed for authorized senders:

- Allowlisted users (`channels.*.allowFrom`, `channels.*.dm.allowFrom`)
- Paired users (approved via `openclaw pairing approve`)
- Owner (first allowlist entry)

Unauthorized senders:

- Command-only messages are silently ignored
- Inline `/...` tokens are treated as plain text
- Directives are not extracted or applied

Sources: [docs/tools/slash-commands.md 26-57](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/tools/slash-commands.md#L26-L57) [src/auto-reply/commands-registry.ts 140-173](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/commands-registry.ts#L140-L173)

## Security and Authorization

```
NoYesNoYesowner-onlysender-gatedNoYesInbound Messagecommands.useAccessGroups
enabled?Sender in
allowlist or
paired?Is sender
owner?Command
scope?Allow all senders
(insecure)Deny access
Directives → plain text
Commands → silent dropAllow commandDeny: owner-onlyProcess command
or directive
```

**Command Authorization Model**

Command and directive authorization follows a multi-layer access control model:

1. **Global Toggle**: `commands.useAccessGroups` enables/disables all authorization checks
	- When `false`: All senders can use commands (insecure, not recommended)
	- When `true` (default): Enforces allowlist/pairing checks
2. **Sender Authorization**:
	- **Allowlisted**: User appears in `channels.*.allowFrom` or `channels.*.dm.allowFrom`
	- **Paired**: User completed pairing flow via `openclaw pairing approve`
	- **Owner**: First entry in allowlist (additional privileges)
3. **Command Scope**:
	- **owner-only**: Requires sender is owner (e.g., `/config`, `/debug`, `/restart`, `/send`)
	- **sender-gated**: Any authorized sender can use
4. **Unauthorized Behavior**:
	- Command-only messages: Silently dropped (no error sent)
	- Inline commands: Treated as plain text, passed to model
	- Directives: Not extracted, treated as regular message content
5. **Group Command Gating**:
	- Command-only messages from allowlisted senders bypass mention requirements
	- Ensures authorized users can always run commands even in mention-gated groups
6. **Special Cases**:
	- Inline shortcuts (`/help`, `/status`, `/commands`, `/whoami`) work in mixed messages
	- Fast-path: Command-only messages bypass queue and model for instant response

Sources: [docs/tools/slash-commands.md 19-20](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/tools/slash-commands.md#L19-L20) [src/auto-reply/commands-registry.ts 140-173](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/commands-registry.ts#L140-L173) [src/auto-reply/reply/directive-handling.parse.ts 54-85](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/reply/directive-handling.parse.ts#L54-L85)

## Command Categories and Scopes

Commands are organized by category and scope for access control and organization:

| Category | Commands | Description |
| --- | --- | --- |
| **status** | `/status`, `/health`, `/context`, `/whoami` | System and session status queries |
| **configuration** | `/config`, `/debug`, `/allowlist` | Configuration management (requires elevated access) |
| **agent** | `/model`, `/think`, `/verbose`, `/reasoning`, `/elevated` | Agent behavior controls |
| **session** | `/reset`, `/new`, `/compact`, `/usage`, `/tts` | Session lifecycle management |
| **system** | `/restart`, `/stop`, `/send` | Gateway control (owner-only) |
| **help** | `/help`, `/commands`, `/skill` | Documentation and command discovery |

| Scope | Description | Example Commands |
| --- | --- | --- |
| **sender-gated** | Any authorized sender | `/status`, `/help`, `/model` |
| **owner-only** | Only the owner (first allowlist entry) | `/config`, `/debug`, `/restart`, `/send` |

Skill commands (user-invocable skills) are dynamically registered and treated as sender-gated by default. Skills can override this with `command-dispatch: tool` to route directly to a tool without model invocation.

Sources: [src/auto-reply/commands-registry.data.ts 10-50](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/commands-registry.data.ts#L10-L50) [src/auto-reply/commands-registry.types.ts 1-10](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/commands-registry.types.ts#L1-L10)

<svg id="mermaid-fu8dstus3vp" width="100%" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 2412 512" style="max-width: 512px;" role="graphics-document document" aria-roledescription="error"><g></g><g><path class="error-icon" d="m411.313,123.313c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32-9.375,9.375-20.688-20.688c-12.484-12.5-32.766-12.5-45.25,0l-16,16c-1.261,1.261-2.304,2.648-3.31,4.051-21.739-8.561-45.324-13.426-70.065-13.426-105.867,0-192,86.133-192,192s86.133,192 192,192 192-86.133 192-192c0-24.741-4.864-48.327-13.426-70.065 1.402-1.007 2.79-2.049 4.051-3.31l16-16c12.5-12.492 12.5-32.758 0-45.25l-20.688-20.688 9.375-9.375 32.001-31.999zm-219.313,100.687c-52.938,0-96,43.063-96,96 0,8.836-7.164,16-16,16s-16-7.164-16-16c0-70.578 57.422-128 128-128 8.836,0 16,7.164 16,16s-7.164,16-16,16z"></path><path class="error-icon" d="m459.02,148.98c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l16,16c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16.001-16z"></path><path class="error-icon" d="m340.395,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16-16c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l15.999,16z"></path><path class="error-icon" d="m400,64c8.844,0 16-7.164 16-16v-32c0-8.836-7.156-16-16-16-8.844,0-16,7.164-16,16v32c0,8.836 7.156,16 16,16z"></path><path class="error-icon" d="m496,96.586h-32c-8.844,0-16,7.164-16,16 0,8.836 7.156,16 16,16h32c8.844,0 16-7.164 16-16 0-8.836-7.156-16-16-16z"></path><path class="error-icon" d="m436.98,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688l32-32c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32c-6.251,6.25-6.251,16.375-0.001,22.625z"></path><text class="error-text" x="1440" y="250" font-size="150px" style="text-anchor: middle;">Syntax error in text</text> <text class="error-text" x="1250" y="400" font-size="100px" style="text-anchor: middle;">mermaid version 11.12.2</text></g></svg> <svg id="mermaid-7khuxtjp8f" width="100%" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 2412 512" style="max-width: 512px;" role="graphics-document document" aria-roledescription="error"><g></g><g><path class="error-icon" d="m411.313,123.313c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32-9.375,9.375-20.688-20.688c-12.484-12.5-32.766-12.5-45.25,0l-16,16c-1.261,1.261-2.304,2.648-3.31,4.051-21.739-8.561-45.324-13.426-70.065-13.426-105.867,0-192,86.133-192,192s86.133,192 192,192 192-86.133 192-192c0-24.741-4.864-48.327-13.426-70.065 1.402-1.007 2.79-2.049 4.051-3.31l16-16c12.5-12.492 12.5-32.758 0-45.25l-20.688-20.688 9.375-9.375 32.001-31.999zm-219.313,100.687c-52.938,0-96,43.063-96,96 0,8.836-7.164,16-16,16s-16-7.164-16-16c0-70.578 57.422-128 128-128 8.836,0 16,7.164 16,16s-7.164,16-16,16z"></path><path class="error-icon" d="m459.02,148.98c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l16,16c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16.001-16z"></path><path class="error-icon" d="m340.395,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16-16c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l15.999,16z"></path><path class="error-icon" d="m400,64c8.844,0 16-7.164 16-16v-32c0-8.836-7.156-16-16-16-8.844,0-16,7.164-16,16v32c0,8.836 7.156,16 16,16z"></path><path class="error-icon" d="m496,96.586h-32c-8.844,0-16,7.164-16,16 0,8.836 7.156,16 16,16h32c8.844,0 16-7.164 16-16 0-8.836-7.156-16-16-16z"></path><path class="error-icon" d="m436.98,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688l32-32c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32c-6.251,6.25-6.251,16.375-0.001,22.625z"></path><text class="error-text" x="1440" y="250" font-size="150px" style="text-anchor: middle;">Syntax error in text</text> <text class="error-text" x="1250" y="400" font-size="100px" style="text-anchor: middle;">mermaid version 11.12.2</text></g></svg>