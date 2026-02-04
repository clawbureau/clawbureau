# ClawProviders.com — Programmatic SEO Strategy

**Domain:** clawproviders.com  
**Goal:** Definitive guide for running OpenClaw securely, optimized for both humans and agents  
**Status:** Planning  
**Date:** 2026-02-02  

---

## Executive Summary

Turn `clawproviders.com` into a **programmatic SEO powerhouse** targeting the growing market of developers setting up AI assistants. The content is already written (OpenClaw docs) — we just need to repackage it with:

1. **Provider-centric landing pages** (per-provider setup guides)
2. **Agent-first endpoints** (`/llms.txt`, `/skill.md`, markdown everywhere)
3. **Beautiful, simple UX** (not documentation-dense, action-oriented)
4. **Fast MVP** (static site, no backend initially)

---

## 🎯 SEO Opportunity Analysis

### High-Value Keywords (from OpenClaw docs)

| Topic Cluster | Search Intent | Competition | Our Content Source |
|---------------|---------------|-------------|-------------------|
| "Claude API setup" | Transactional | Medium | `5.4-model-selection-and-failover.md` |
| "OpenAI personal assistant" | Informational | High | `1-overview.md`, `5-agent-system.md` |
| "WhatsApp bot self-hosted" | Transactional | Low | `8.2-whatsapp-integration.md` |
| "Telegram AI bot setup" | Transactional | Low | `8.3-telegram-integration.md` |
| "Discord AI assistant" | Transactional | Medium | `8.4-discord-integration.md` |
| "Signal bot privacy" | Informational | Very Low | `8.5-signal-integration.md` |
| "Ollama local LLM setup" | Transactional | Low | `5.4-model-selection-and-failover.md` |
| "Run AI assistant VPS" | Transactional | Low | `13.2-vps-deployment.md` |
| "Fly.io AI deployment" | Transactional | Very Low | `13.3-cloud-deployment.md` |
| "Multi-model failover" | Technical | Very Low | `5.4-model-selection-and-failover.md` |
| "AI agent skills" | Informational | Low | `6.3-skills-system.md` |
| "AI assistant memory" | Informational | Medium | `7-memory-system.md` |

### Competitive Gap

**Nobody is doing this well:**
- OpenClaw docs are technical, not SEO-optimized
- LangChain/LlamaIndex focus on developers, not operators
- Existing "AI assistant" guides are either too basic or too vendor-locked
- **No llms.txt/agent-first content exists**

---

## 🏗️ Site Architecture

```
clawproviders.com/
├── /                           # Landing: "Set Up Your AI Assistant"
├── /llms.txt                   # Agent-readable site index
├── /skill.md                   # Pi/OpenClaw skill for integration
├── /robots.txt
├── /sitemap.xml
│
├── /providers/                 # Per-provider setup guides
│   ├── anthropic/              # Claude (API, OAuth, Claude Max)
│   ├── openai/                 # GPT (API, ChatGPT subscription)
│   ├── google/                 # Gemini (API, Vertex)
│   ├── openrouter/             # OpenRouter unified API
│   ├── ollama/                 # Local Ollama setup
│   ├── bedrock/                # AWS Bedrock
│   └── local/                  # LM Studio, llama.cpp
│
├── /channels/                  # Per-channel setup guides
│   ├── whatsapp/               # WhatsApp (Baileys, QR)
│   ├── telegram/               # Telegram bot
│   ├── discord/                # Discord bot
│   ├── slack/                  # Slack app
│   ├── signal/                 # Signal (signal-cli)
│   ├── imessage/               # iMessage (macOS only)
│   ├── matrix/                 # Matrix protocol
│   ├── msteams/                # MS Teams
│   └── nostr/                  # Nostr protocol
│
├── /deploy/                    # Deployment guides
│   ├── local/                  # macOS, Linux, WSL
│   ├── vps/                    # DigitalOcean, Oracle, Hetzner
│   ├── cloud/                  # Fly.io, Railway, Northflank
│   └── security/               # Token auth, Tailscale, SSH
│
├── /skills/                    # Skill library
│   ├── [skill-slug]/           # Individual skill pages
│   └── create/                 # How to create skills
│
├── /compare/                   # Comparison pages (SEO gold)
│   ├── claude-vs-gpt/
│   ├── whatsapp-vs-telegram/
│   ├── local-vs-cloud/
│   └── free-vs-paid-models/
│
├── /guides/                    # Long-form tutorials
│   ├── first-setup/            # "Your First OpenClaw in 5 Minutes"
│   ├── multi-model-failover/   # Reliability guide
│   ├── privacy-setup/          # Signal + local models
│   └── team-deployment/        # Multi-agent for teams
│
└── /api/                       # API docs (optional, later)
    └── v1/providers.json       # Machine-readable provider list
```

---

## 📄 Agent-First Endpoints

### `/llms.txt`

```txt
# clawproviders.com
> Definitive guides for setting up AI assistants with OpenClaw

## Providers
- /providers/anthropic: Claude API and OAuth setup
- /providers/openai: GPT models and ChatGPT subscriptions
- /providers/google: Gemini API and Vertex AI
- /providers/ollama: Local models with Ollama

## Channels
- /channels/whatsapp: WhatsApp bot integration
- /channels/telegram: Telegram bot setup
- /channels/discord: Discord bot configuration
- /channels/signal: Privacy-focused Signal integration

## Deployment
- /deploy/local: Local machine setup
- /deploy/vps: VPS deployment guides
- /deploy/cloud: Cloud platform deployment

## Skill
- /skill.md: OpenClaw skill for clawproviders integration
```

### `/skill.md`

```markdown
# ClawProviders Skill

When to use: User asks about setting up OpenClaw, configuring providers, or deploying to production.

## Steps

1. Identify the user's goal:
   - New setup → /guides/first-setup
   - Specific provider → /providers/{provider}
   - Specific channel → /channels/{channel}
   - Deployment → /deploy/{target}

2. Fetch the relevant guide:
   ```bash
   curl -s https://clawproviders.com/providers/anthropic/skill.md
   ```

3. Follow the provider-specific instructions

## Provider Skills

Each provider has its own skill at `/providers/{provider}/skill.md`:
- anthropic: Claude API key or Claude Max OAuth
- openai: OpenAI API or ChatGPT subscription
- google: Gemini API key
- ollama: Local installation

## Quick Commands

```bash
# Check provider status
openclaw models status

# Add Anthropic auth
openclaw models auth add --provider anthropic

# Set primary model
openclaw models set anthropic/claude-sonnet-4-20250514
```
```

---

## 📊 Content Generation Strategy

### Source Material Mapping

| OpenClaw Doc | ClawProviders Page | Treatment |
|--------------|-------------------|-----------|
| `1-overview.md` | `/` (landing) | Simplify, add CTAs |
| `1.2-quick-start.md` | `/guides/first-setup` | Step-by-step tutorial |
| `5.4-model-selection-and-failover.md` | `/providers/*`, `/guides/multi-model-failover` | Split by provider |
| `8.2-whatsapp-integration.md` | `/channels/whatsapp` | Simplify, add screenshots |
| `8.3-telegram-integration.md` | `/channels/telegram` | Simplify, add video |
| `8.4-discord-integration.md` | `/channels/discord` | Simplify, add bot setup |
| `8.5-signal-integration.md` | `/channels/signal` | Privacy-focused angle |
| `13.1-local-deployment.md` | `/deploy/local` | Platform-specific tabs |
| `13.2-vps-deployment.md` | `/deploy/vps` | Provider-specific guides |
| `13.3-cloud-deployment.md` | `/deploy/cloud` | Fly.io focus |
| `6.3-skills-system.md` | `/skills/create` | Developer tutorial |
| `10-extensions-and-plugins.md` | `/providers/*/` (plugin model) | Technical reference |

### Programmatic Content Templates

Each provider page uses a template:

```markdown
# {Provider} Setup for OpenClaw

> Set up {Provider} as your AI provider in under 5 minutes.

## Quick Start

\`\`\`bash
# Add {Provider} credentials
openclaw models auth add --provider {provider}

# Set as primary model
openclaw models set {provider}/{default_model}
\`\`\`

## Authentication Options

{auth_options_table}

## Configuration

{config_json_example}

## Failover Setup

{failover_config}

## Troubleshooting

{common_issues}

## Next Steps

- [Add a messaging channel](/channels/)
- [Deploy to production](/deploy/)
- [Set up multi-model failover](/guides/multi-model-failover)
```

---

## 🚀 MVP Scope (Week 1)

### Phase 1: Static Site Foundation

1. **Tech Stack**
   - Astro or plain HTML + Markdown
   - Deployed to Cloudflare Pages (free, fast, global CDN)
   - No backend needed

2. **Core Pages (10 pages)**
   - `/` — Landing
   - `/llms.txt` — Agent index
   - `/skill.md` — OpenClaw skill
   - `/providers/anthropic` — Claude guide
   - `/providers/openai` — OpenAI guide
   - `/providers/ollama` — Local models
   - `/channels/whatsapp` — WhatsApp setup
   - `/channels/telegram` — Telegram setup
   - `/deploy/local` — Local deployment
   - `/guides/first-setup` — 5-minute quickstart

3. **Design Requirements**
   - Dark mode default
   - Monospace code blocks
   - Copy-to-clipboard on all commands
   - Minimal, fast-loading
   - Mobile-first

### Phase 2: Expand Content (Week 2-3)

- All remaining providers (OpenRouter, Bedrock, Gemini, local)
- All remaining channels (Discord, Slack, Signal, iMessage)
- All deployment guides (VPS, Cloud)
- Comparison pages for SEO

### Phase 3: Dynamic Features (Week 4+)

- Provider status dashboard (are APIs up?)
- User-submitted skills directory
- Community provider ratings
- Integration with clawproviders.com registry (from PRD)

---

## 🔗 Integration with Claw Bureau

### How clawproviders.com feeds the ecosystem:

1. **SEO funnel** → Users discover via Google
2. **Content educates** → "Here's how to set up Claude"
3. **joinclaw.com CTA** → "Join the Claw community"
4. **clawbureau.com integration** → "Register as a verified provider"
5. **clawbounties.com** → "Earn credits by completing tasks"

### Registry API (Future)

```json
GET /api/v1/providers.json

{
  "providers": [
    {
      "id": "anthropic",
      "name": "Anthropic",
      "models": ["claude-sonnet-4-20250514", "claude-haiku-20250107"],
      "auth_modes": ["api_key", "oauth", "token"],
      "status": "operational",
      "docs_url": "/providers/anthropic"
    }
  ]
}
```

---

## 📈 Success Metrics

| Metric | Week 1 Target | Month 1 Target |
|--------|---------------|----------------|
| Pages indexed | 10 | 50+ |
| Organic traffic | 100 | 1,000+ |
| Time on page | 2min | 3min |
| `/llms.txt` requests | 50 | 500+ |
| Skill installs | 10 | 100+ |
| Newsletter signups | 25 | 250+ |

---

## 🛠️ Implementation Checklist

### Day 1
- [ ] Set up Astro project
- [ ] Create base layout with dark theme
- [ ] Implement `/llms.txt` and `/skill.md`
- [ ] Create landing page

### Day 2-3
- [ ] Create provider template
- [ ] Generate Anthropic, OpenAI, Ollama pages
- [ ] Create channel template
- [ ] Generate WhatsApp, Telegram pages

### Day 4-5
- [ ] Create deployment guides
- [ ] Create first-setup quickstart
- [ ] Add sitemap.xml, robots.txt
- [ ] Deploy to Cloudflare Pages

### Day 6-7
- [ ] SEO audit (meta tags, OG images)
- [ ] Test agent endpoints
- [ ] Create OpenClaw skill for clawproviders
- [ ] Announce in community

---

## Notes

- This PRD supersedes the registry-focused `clawproviders.md` PRD for MVP
- Provider registry functionality can layer on top later
- All content is CC-BY licensed (OpenClaw is MIT)
- Target audience: developers who want personal AI assistants, not enterprises
