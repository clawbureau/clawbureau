Menu

## Channels

Relevant source files
- [.npmrc](https://github.com/openclaw/openclaw/blob/bf6ec64f/.npmrc)
- [CHANGELOG.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/CHANGELOG.md)
- [README.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md)
- [assets/avatar-placeholder.svg](https://github.com/openclaw/openclaw/blob/bf6ec64f/assets/avatar-placeholder.svg)
- [extensions/memory-core/package.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/extensions/memory-core/package.json)
- [package.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json)
- [pnpm-lock.yaml](https://github.com/openclaw/openclaw/blob/bf6ec64f/pnpm-lock.yaml)
- [pnpm-workspace.yaml](https://github.com/openclaw/openclaw/blob/bf6ec64f/pnpm-workspace.yaml)
- [scripts/clawtributors-map.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/clawtributors-map.json)
- [scripts/update-clawtributors.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/update-clawtributors.ts)
- [scripts/update-clawtributors.types.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/update-clawtributors.types.ts)
- [src/agents/pi-embedded-runner-extraparams.live.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner-extraparams.live.test.ts)
- [src/agents/pi-embedded-runner-extraparams.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner-extraparams.test.ts)
- [src/config/config.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/config.ts)
- [src/discord/monitor.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/discord/monitor.ts)
- [src/imessage/monitor.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/imessage/monitor.ts)
- [src/index.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/index.ts)
- [src/signal/monitor.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/signal/monitor.ts)
- [src/slack/monitor.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/slack/monitor.ts)
- [src/telegram/bot.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/telegram/bot.test.ts)
- [src/telegram/bot.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/telegram/bot.ts)
- [src/web/auto-reply.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/web/auto-reply.ts)
- [src/web/inbound.media.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/web/inbound.media.test.ts)
- [src/web/inbound.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/web/inbound.test.ts)
- [src/web/inbound.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/web/inbound.ts)
- [src/web/test-helpers.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/web/test-helpers.ts)
- [src/web/vcard.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/web/vcard.ts)
- [ui/package.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/ui/package.json)
- [ui/src/styles.css](https://github.com/openclaw/openclaw/blob/bf6ec64f/ui/src/styles.css)
- [ui/src/styles/layout.mobile.css](https://github.com/openclaw/openclaw/blob/bf6ec64f/ui/src/styles/layout.mobile.css)

## Purpose and Scope

This document covers OpenClaw's channel integration architecture: how messaging platforms connect to the Gateway, how messages are routed, and how access control is enforced. Channels are the inbound/outbound adapters that connect OpenClaw to messaging platforms like WhatsApp, Telegram, Discord, Slack, Signal, and iMessage.

For details on how messages are processed after routing (agent execution, tools, etc.), see [Agent System](https://deepwiki.com/openclaw/openclaw/5-agent-system). For configuration of individual channels, see the channel-specific pages ([WhatsApp](https://deepwiki.com/openclaw/openclaw/8.2-whatsapp-integration), [Telegram](https://deepwiki.com/openclaw/openclaw/8.3-telegram-integration), [Discord](https://deepwiki.com/openclaw/openclaw/8.4-discord-integration), [Signal](https://deepwiki.com/openclaw/openclaw/8.5-signal-integration), [Other Channels](https://deepwiki.com/openclaw/openclaw/8.6-other-channels)).

---

## Channel Architecture Overview

Channels in OpenClaw are bidirectional adapters that:

1. Monitor messaging platforms for inbound messages
2. Route authorized messages through the Gateway to agents
3. Deliver agent responses back to the originating platform

Each channel implements platform-specific protocol handling (e.g., grammY for Telegram, discord.js for Discord, Baileys for WhatsApp) while exposing a common interface to the Gateway's auto-reply system.

### High-Level Channel Flow

```
Outbound DeliveryGateway Routing :18789Channel AdaptersMessaging PlatformsWhatsAppTelegramDiscordSlackSignaliMessageWhatsApp Monitor
monitorWebChannel()Telegram Bot
createTelegramBot()Discord Monitor
monitorDiscordProvider()Slack Monitor
monitorSlackProvider()Signal Monitor
monitorSignalProvider()iMessage Monitor
monitorIMessageProvider()Auto-Reply System
getReplyFromConfig()Session Key Resolution
resolveAgentRoute()Access Control
DM/Group Policy ChecksText Chunking
chunkTextWithMode()Media Handling
saveMediaBuffer()Platform-Specific Send
(sendMessage, etc.)
```

**Sources:**

- [src/web/auto-reply.ts 1](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/web/auto-reply.ts#L1-L1)
- [src/telegram/bot.ts 109-148](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/telegram/bot.ts#L109-L148)
- [src/discord/monitor.ts 1-29](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/discord/monitor.ts#L1-L29)
- [src/slack/monitor.ts 1-6](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/slack/monitor.ts#L1-L6)
- [src/signal/monitor.ts 1-18](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/signal/monitor.ts#L1-L18)
- [src/imessage/monitor.ts 1-3](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/imessage/monitor.ts#L1-L3)

---

## Core Channel Components

All channels share a common set of responsibilities, implemented through channel-specific code but following consistent patterns.

### Message Monitoring

Each channel implements a monitoring loop that:

- Connects to the platform's API/protocol
- Listens for inbound message events
- Extracts message metadata (sender, chat type, content, media)
- Passes normalized messages to the Gateway routing layer

| Platform | Monitor Function | Protocol Library |
| --- | --- | --- |
| WhatsApp | `monitorWebInbox()` | `@whiskeysockets/baileys` |
| Telegram | `createTelegramBot()` | `grammy` |
| Discord | `monitorDiscordProvider()` | `discord.js` via `@buape/carbon` |
| Slack | `monitorSlackProvider()` | `@slack/bolt` |
| Signal | `monitorSignalProvider()` | `signal-cli` (external daemon) |
| iMessage | `monitorIMessageProvider()` | `imsg` (macOS-only) |

**Sources:**

- [src/web/inbound.ts 3](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/web/inbound.ts#L3-L3)
- [src/telegram/bot.ts 109](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/telegram/bot.ts#L109-L109)
- [src/discord/monitor.ts 26](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/discord/monitor.ts#L26-L26)
- [src/slack/monitor.ts 3](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/slack/monitor.ts#L3-L3)
- [src/signal/monitor.ts 253](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/signal/monitor.ts#L253-L253)
- [src/imessage/monitor.ts 1](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/imessage/monitor.ts#L1-L1)

### Session Key Resolution

When a message arrives, the channel adapter determines which agent session should handle it by constructing a **session key**. Session keys follow a hierarchical pattern:

```
agent:{agentId}:{channel}:{scope}:{identifier}
```

**Examples:**

- `agent:main:telegram:dm:123456789` (DM on Telegram)
- `agent:main:telegram:group:987654321` (Group chat on Telegram)
- `agent:main:discord:dm:user123` (DM on Discord)
- `agent:main:discord:group:guild456:channel789` (Discord channel)
- `agent:work:whatsapp:dm:15551234567` (WhatsApp DM on "work" agent)

The routing logic is centralized in `resolveAgentRoute()`, which considers:

1. **Channel bindings** (`channels.{platform}.bindings`) to route specific accounts to specific agents
2. **Multi-agent routing** (`channels.{platform}.accountId` to agent mapping)
3. **Peer-based routing** (DM vs. group, with group ID suffixes for isolation)

**Sources:**

- [src/routing/resolve-route.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/routing/resolve-route.ts) (referenced by imports)
- [src/telegram/bot.ts 29](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/telegram/bot.ts#L29-L29)
- [src/routing/session-key.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/routing/session-key.ts) (referenced by imports)

### Access Control Checks

Before processing a message, channels enforce **access policies**:

#### DM Policies

The `dmPolicy` setting controls how DMs from unknown senders are handled:

| Policy | Behavior |
| --- | --- |
| `"pairing"` | Unknown senders receive a pairing code; admin must approve with `openclaw pairing approve <channel> <code>` |
| `"allowlist"` | Only senders in `allowFrom` list are processed |
| `"open"` | All DMs are processed (requires `allowFrom: ["*"]`) |

#### Group Policies

The `groupPolicy` setting controls group/channel access:

| Policy | Behavior |
| --- | --- |
| `"allowlist"` | Only groups in `groupAllowFrom` or `groups` config are processed |
| `"open"` | All groups are processed |

**Mention Gating:** In groups, channels can require explicit mentions (via `requireMention` or per-group `requireMention` config) to activate the agent.

**Sources:**

- [src/telegram/bot.ts 228-236](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/telegram/bot.ts#L228-L236)
- [src/discord/monitor.ts 7-18](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/discord/monitor.ts#L7-L18)
- [src/config/group-policy.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/group-policy.ts) (referenced by imports)

---

## Built-in Channel Support

OpenClaw includes native support for six messaging platforms:

### Core Channels

```
Protocol LibrariesCore Channels (src/)WhatsApp
src/web/Telegram
src/telegram/Discord
src/discord/Slack
src/slack/Signal
src/signal/iMessage
src/imessage/@whiskeysockets/baileysgrammy + @grammyjs/runner@buape/carbon (discord.js)@slack/boltsignal-cli (external)imsg (macOS)
```

### Platform-Specific Features

| Platform | DMs | Groups | Media | Voice | Reactions | Native Commands |
| --- | --- | --- | --- | --- | --- | --- |
| WhatsApp | ✓ | ✓ | ✓ | ✓ | \- | \- |
| Telegram | ✓ | ✓ (+ Topics) | ✓ | ✓ | ✓ | ✓ |
| Discord | ✓ | ✓ (+ Threads) | ✓ | \- | ✓ | ✓ (Slash) |
| Slack | ✓ | ✓ (+ Threads) | ✓ | \- | ✓ | ✓ (Slash) |
| Signal | ✓ | ✓ | ✓ | ✓ | ✓ | \- |
| iMessage | ✓ | ✓ | ✓ | ✓ | \- | \- |

**Sources:**

- [package.json 67-78](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json#L67-L78) (dependencies)
- [README.md 18-19](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md#L18-L19)
- [src/telegram/bot.ts 369-452](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/telegram/bot.ts#L369-L452) (reaction handling)
- [src/discord/monitor.ts 1-29](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/discord/monitor.ts#L1-L29)

---

## Channel Configuration Patterns

All channels follow a consistent configuration structure under `channels.<platform>` in `openclaw.json`:

### Common Configuration Fields

```
{
  "channels": {
    "<platform>": {
      // Authentication
      "token": string,              // Bot token (Telegram, Discord, etc.)
      "account": string,            // Account identifier (Signal, iMessage)
      "accountId": string,          // Multi-account identifier
      
      // Access Control
      "dmPolicy": "pairing" | "allowlist" | "open",
      "groupPolicy": "allowlist" | "open",
      "allowFrom": string[],        // Allowed DM senders
      "groupAllowFrom": string[],   // Allowed groups
      
      // Behavior
      "mediaMaxMb": number,         // Max media size (default varies)
      "replyToMode": "first" | "last" | "all",
      "historyLimit": number,       // Group history retention
      
      // Platform-Specific
      "groups": {                   // Group-level overrides
        "<groupId>": { ... }
      }
    }
  }
}
```

### Multi-Account Support

Channels support multiple accounts through the `accountId` field:

```
{
  "channels": {
    "telegram": {
      "accounts": {
        "personal": {
          "botToken": "123:ABC",
          "allowFrom": ["alice", "bob"]
        },
        "work": {
          "botToken": "456:DEF",
          "allowFrom": ["manager"]
        }
      }
    }
  }
}
```

**Sources:**

- [src/config/config.ts 1-15](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/config.ts#L1-L15)
- [src/config/types.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/config/types.ts) (referenced by imports)
- [src/telegram/bot.ts 50-65](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/telegram/bot.ts#L50-L65)

---

## Message Flow and Processing

### Inbound Message Pipeline

```
"Agent Runtime""getReplyFromConfig()""Session Router""Access Policy Check""Update Dedupe""Channel Monitor""Messaging Platform""Agent Runtime""getReplyFromConfig()""Session Router""Access Policy Check""Update Dedupe""Channel Monitor""Messaging Platform"alt[Access Denied][Access Granted]alt[Already Processed][New Update]Message EventCheck Update KeySkip (duplicate)Validate AccessDrop / Send Pairing CodeResolve Session KeyRoute to SessionProcess MessageResponse PayloadDeliver ResponseSend Message
```

**Key Functions:**

1. **Update Deduplication:** Prevents duplicate processing of the same message
	- Telegram: `createTelegramUpdateDedupe()` checks `update_id` + message hash
	- Discord: Similar pattern in `monitorDiscordProvider()`
	- WhatsApp: `resetWebInboundDedupe()` for message key tracking
2. **Access Policy Validation:**
	- `isDiscordGroupAllowedByPolicy()` (Discord)
	- `isSlackChannelAllowedByPolicy()` (Slack)
	- Inline checks in Telegram/WhatsApp monitors
3. **Session Routing:**
	- `resolveAgentRoute()` determines agent + session key
	- `resolveThreadSessionKeys()` for threaded conversations
	- Multi-agent bindings via `channels.<platform>.bindings`
4. **Auto-Reply Processing:**
	- `getReplyFromConfig()` orchestrates agent execution
	- Handles typing indicators, reaction acks, streaming
	- Returns `ReplyPayload[]` for delivery

**Sources:**

- [src/telegram/bot.ts 155-178](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/telegram/bot.ts#L155-L178) (dedupe logic)
- [src/discord/monitor.ts 7-18](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/discord/monitor.ts#L7-L18) (policy checks)
- [src/web/auto-reply.ts 1](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/web/auto-reply.ts#L1-L1) (auto-reply system)
- [src/web/inbound.ts 1-5](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/web/inbound.ts#L1-L5) (inbound message types)

### Outbound Delivery

When delivering responses, channels handle:

#### Text Chunking

Messages exceeding platform limits are split:

- `chunkTextWithMode()` supports `"length"` (character-based) or `"newline"` (paragraph-aware) modes
- `resolveTextChunkLimit()` returns platform-specific limits:
	- Telegram: 4096 chars (or config override)
	- Discord: 2000 chars
	- WhatsApp: 4096 chars
	- Signal: 4096 chars

#### Media Handling

- `saveMediaBuffer()` stores inbound media with extension detection
- Outbound media sent via platform-specific methods:
	- Telegram: `sendPhoto()`, `sendAnimation()`, `sendDocument()`
	- Discord: attachments in message payload
	- WhatsApp: `sendMessage()` with media message types

#### Platform-Specific Features

- **Telegram:** Inline keyboards via `reply_markup`, edit via `editMessageText()`
- **Discord:** Embeds, buttons, slash command responses
- **Slack:** Block Kit formatting, threading via `thread_ts`
- **Signal:** Attachments via `signalRpcRequest("sendMessage")`

**Sources:**

- [src/auto-reply/chunk.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/auto-reply/chunk.ts) (referenced by imports)
- [src/telegram/bot.ts 256-259](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/telegram/bot.ts#L256-L259) (text limit resolution)
- [src/media/store.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/media/store.ts) (referenced by imports)
- [src/signal/monitor.ts 196-207](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/signal/monitor.ts#L196-L207) (attachment fetching)

---

## Group and Thread Handling

Channels support group conversations with various threading models:

### Threading Models by Platform

| Platform | Threading Support | Session Key Pattern |
| --- | --- | --- |
| Telegram | Topics (forums only) | `telegram:group:{chatId}` or `telegram:group:{chatId}:topic:{topicId}` |
| Discord | Native threads | `discord:group:{guildId}:{channelId}` or `discord:thread:{threadId}` |
| Slack | Reply threads | `slack:group:{channelId}` + `thread_ts` tracking |
| WhatsApp | No native threads | `whatsapp:group:{groupId}` |
| Signal | No native threads | `signal:group:{groupId}` |

### Group History Management

Channels maintain in-memory group history for context:

- `historyLimit` config controls retention (default: 20 messages)
- Stored in `Map<string, HistoryEntry[]>` per group
- Cleared on bot restart

**Example (Telegram):**

```
const groupHistories = new Map<string, HistoryEntry[]>();
const historyLimit = telegramCfg.historyLimit ?? 
                     cfg.messages?.groupChat?.historyLimit ?? 
                     DEFAULT_GROUP_HISTORY_LIMIT;
```

### Mention Detection

Channels extract explicit mentions from messages:

- Telegram: `@username` or user IDs in `entities`
- Discord: `<@userId>` mentions
- Slack: `<@userId>` mentions
- WhatsApp: `mentionedJid` array in message

**Sources:**

- [src/telegram/bot.ts 220-226](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/telegram/bot.ts#L220-L226) (history limit resolution)
- [src/telegram/bot.ts 99-102](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/telegram/bot.ts#L99-L102) (forum topic handling)
- [src/discord/monitor.ts 28](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/discord/monitor.ts#L28-L28) (threading resolution)
- [src/slack/monitor.ts 4](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/slack/monitor.ts#L4-L4) (thread ts resolution)

---

## DM and Pairing Flow

For DM conversations, channels implement a pairing mechanism when `dmPolicy: "pairing"`:

### Pairing Sequence

```
"Allow Store~/.openclaw/allow/""openclaw CLI""Pairing Store~/.openclaw/pairing/""Channel Monitor""Unknown User""Allow Store~/.openclaw/allow/""openclaw CLI""Pairing Store~/.openclaw/pairing/""Channel Monitor""Unknown User"alt[Not Yet Paired][Already Paired]Send DMCheck Existing PairingGenerate 6-char CodeReturn Code"Use code ABCDEF with 'openclaw pairing approve'"openclaw pairing approve telegram ABCDEFAdd user to allowlistConfirmed"Pairing approved"Verify AllowlistAllowed(Process message normally)
```

**Key Components:**

1. **Pairing Request Storage:**`upsertTelegramPairingRequest()`, etc.
	- Generates random 6-character codes
	- Stores in `~/.openclaw/pairing/<channel>-pairing.json`
	- 5-minute expiration
2. **Allowlist Management:**`readTelegramAllowFromStore()`, etc.
	- Persistent storage in `~/.openclaw/allow/<channel>-allow.json`
	- Merged with config `allowFrom` at runtime
3. **CLI Commands:**
	- `openclaw pairing list <channel>` - Show pending requests
	- `openclaw pairing approve <channel> <code>` - Approve a request
	- `openclaw pairing deny <channel> <code>` - Reject a request

**Sources:**

- [src/telegram/bot.ts 229](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/telegram/bot.ts#L229-L229) (dmPolicy usage)
- [src/telegram/bot.test.ts 59-70](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/telegram/bot.test.ts#L59-L70) (pairing store mocks)
- [src/pairing/pairing-store.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/pairing/pairing-store.ts) (referenced by mocks)

---

## Plugin Channels

OpenClaw supports additional channels through the plugin system:

### Bundled Plugin Channels

The following channels are implemented as plugins in `extensions/`:

| Channel | Extension Path | Description |
| --- | --- | --- |
| BlueBubbles | `extensions/bluebubbles/` | iMessage via BlueBubbles bridge |
| Google Chat | `extensions/googlechat/` | Google Chat via Chat API |
| LINE | `extensions/line/` | LINE Messaging API |
| Mattermost | `extensions/mattermost/` | Mattermost teams |
| Matrix | `extensions/matrix/` | Matrix protocol (via matrix-bot-sdk) |
| MS Teams | `extensions/msteams/` | Microsoft Teams |
| Nextcloud Talk | `extensions/nextcloud-talk/` | Nextcloud Talk |
| Nostr | `extensions/nostr/` | Nostr protocol |
| Tlon/Urbit | `extensions/tlon/` | Urbit messaging |
| Twitch | `extensions/twitch/` | Twitch chat |
| Voice Call | `extensions/voice-call/` | Twilio voice calls |
| Zalo | `extensions/zalo/` | Zalo (Vietnam) |
| Zalo Personal | `extensions/zalouser/` | Zalo personal accounts |

### Plugin Channel Architecture

Plugin channels expose the same interface as core channels:

```
{
  "openclaw": {
    "extensions": [{
      "type": "channel",
      "id": "custom-platform",
      "config": { /* TypeBox schema */ },
      "monitor": async (opts) => { /* monitor implementation */ }
    }]
  }
}
```

**Auto-Enablement:** Plugin channels are automatically enabled when their configuration is present in `channels.<pluginId>`.

**Sources:**

- [pnpm-workspace.yaml 1-15](https://github.com/openclaw/openclaw/blob/bf6ec64f/pnpm-workspace.yaml#L1-L15)
- [extensions/line/package.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/extensions/line/package.json) (example plugin structure)
- [extensions/matrix/package.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/extensions/matrix/package.json) (example plugin structure)
- [CHANGELOG.md 19](https://github.com/openclaw/openclaw/blob/bf6ec64f/CHANGELOG.md#L19-L19) (Matrix SDK switch)

---

## Reaction Notifications

Some channels support reaction events as system notifications:

### Supported Platforms

- **Telegram:**`message_reaction` events
- **Discord:** Reaction add/remove events
- **Signal:** Reaction messages

### Configuration

Reaction notification modes:

| Mode | Behavior |
| --- | --- |
| `"off"` | Ignore all reactions |
| `"own"` | Only reactions on bot's own messages (default) |
| `"allowlist"` | Only reactions from users in `reactionAllowlist` |
| `"all"` | All reactions generate system events |

**Example (Telegram):**

```
{
  "channels": {
    "telegram": {
      "reactionNotifications": "own"
    }
  }
}
```

When a reaction is detected, the channel enqueues a system event:

```
Telegram reaction added: 👍 by Alice (@alice) on msg 12345
```

**Sources:**

- [src/telegram/bot.ts 369-452](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/telegram/bot.ts#L369-L452) (reaction handler)
- [src/signal/monitor.ts 19-29](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/signal/monitor.ts#L19-L29) (reaction message type)
- [src/discord/monitor.ts 17](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/discord/monitor.ts#L17-L17) (reaction notification check)

---

## Channel-Specific Details

For implementation details of individual channels, see:

- **[WhatsApp Integration](https://deepwiki.com/openclaw/openclaw/8.2-whatsapp-integration):** Baileys setup, QR login, media handling
- **[Telegram Integration](https://deepwiki.com/openclaw/openclaw/8.3-telegram-integration):** Bot setup, native commands, topics, forums
- **[Discord Integration](https://deepwiki.com/openclaw/openclaw/8.4-discord-integration):** Slash commands, autocomplete, button interactions
- **[Signal Integration](https://deepwiki.com/openclaw/openclaw/8.5-signal-integration):** signal-cli daemon, SSE event stream, attachments
- **[Other Channels](https://deepwiki.com/openclaw/openclaw/8.6-other-channels):** Slack, iMessage, and plugin channel guides

---

## Summary

Channels in OpenClaw provide a unified interface between messaging platforms and the Gateway's agent runtime. Key responsibilities include:

1. **Protocol Adaptation:** Platform-specific APIs → common message format
2. **Access Control:** DM/group policies, allowlists, pairing flows
3. **Session Routing:** Multi-agent routing via session keys
4. **Bidirectional Delivery:** Inbound message normalization, outbound text/media handling
5. **Platform Features:** Reactions, threads, native commands, media support

All channels follow consistent configuration patterns while exposing platform-specific features through their respective config sections.

**Sources:**

- [src/index.ts 1-95](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/index.ts#L1-L95) (main entry and exports)
- [README.md 118-119](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md#L118-L119) (channel list)
- [CHANGELOG.md 1-430](https://github.com/openclaw/openclaw/blob/bf6ec64f/CHANGELOG.md#L1-L430) (channel feature history)

<svg id="mermaid-fu8dstus3vp" width="100%" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 2412 512" style="max-width: 512px;" role="graphics-document document" aria-roledescription="error"><g></g><g><path class="error-icon" d="m411.313,123.313c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32-9.375,9.375-20.688-20.688c-12.484-12.5-32.766-12.5-45.25,0l-16,16c-1.261,1.261-2.304,2.648-3.31,4.051-21.739-8.561-45.324-13.426-70.065-13.426-105.867,0-192,86.133-192,192s86.133,192 192,192 192-86.133 192-192c0-24.741-4.864-48.327-13.426-70.065 1.402-1.007 2.79-2.049 4.051-3.31l16-16c12.5-12.492 12.5-32.758 0-45.25l-20.688-20.688 9.375-9.375 32.001-31.999zm-219.313,100.687c-52.938,0-96,43.063-96,96 0,8.836-7.164,16-16,16s-16-7.164-16-16c0-70.578 57.422-128 128-128 8.836,0 16,7.164 16,16s-7.164,16-16,16z"></path><path class="error-icon" d="m459.02,148.98c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l16,16c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16.001-16z"></path><path class="error-icon" d="m340.395,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16-16c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l15.999,16z"></path><path class="error-icon" d="m400,64c8.844,0 16-7.164 16-16v-32c0-8.836-7.156-16-16-16-8.844,0-16,7.164-16,16v32c0,8.836 7.156,16 16,16z"></path><path class="error-icon" d="m496,96.586h-32c-8.844,0-16,7.164-16,16 0,8.836 7.156,16 16,16h32c8.844,0 16-7.164 16-16 0-8.836-7.156-16-16-16z"></path><path class="error-icon" d="m436.98,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688l32-32c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32c-6.251,6.25-6.251,16.375-0.001,22.625z"></path><text class="error-text" x="1440" y="250" font-size="150px" style="text-anchor: middle;">Syntax error in text</text> <text class="error-text" x="1250" y="400" font-size="100px" style="text-anchor: middle;">mermaid version 11.12.2</text></g></svg> <svg id="mermaid-7khuxtjp8f" width="100%" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 2412 512" style="max-width: 512px;" role="graphics-document document" aria-roledescription="error"><g></g><g><path class="error-icon" d="m411.313,123.313c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32-9.375,9.375-20.688-20.688c-12.484-12.5-32.766-12.5-45.25,0l-16,16c-1.261,1.261-2.304,2.648-3.31,4.051-21.739-8.561-45.324-13.426-70.065-13.426-105.867,0-192,86.133-192,192s86.133,192 192,192 192-86.133 192-192c0-24.741-4.864-48.327-13.426-70.065 1.402-1.007 2.79-2.049 4.051-3.31l16-16c12.5-12.492 12.5-32.758 0-45.25l-20.688-20.688 9.375-9.375 32.001-31.999zm-219.313,100.687c-52.938,0-96,43.063-96,96 0,8.836-7.164,16-16,16s-16-7.164-16-16c0-70.578 57.422-128 128-128 8.836,0 16,7.164 16,16s-7.164,16-16,16z"></path><path class="error-icon" d="m459.02,148.98c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l16,16c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16.001-16z"></path><path class="error-icon" d="m340.395,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16-16c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l15.999,16z"></path><path class="error-icon" d="m400,64c8.844,0 16-7.164 16-16v-32c0-8.836-7.156-16-16-16-8.844,0-16,7.164-16,16v32c0,8.836 7.156,16 16,16z"></path><path class="error-icon" d="m496,96.586h-32c-8.844,0-16,7.164-16,16 0,8.836 7.156,16 16,16h32c8.844,0 16-7.164 16-16 0-8.836-7.156-16-16-16z"></path><path class="error-icon" d="m436.98,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688l32-32c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32c-6.251,6.25-6.251,16.375-0.001,22.625z"></path><text class="error-text" x="1440" y="250" font-size="150px" style="text-anchor: middle;">Syntax error in text</text> <text class="error-text" x="1250" y="400" font-size="100px" style="text-anchor: middle;">mermaid version 11.12.2</text></g></svg>