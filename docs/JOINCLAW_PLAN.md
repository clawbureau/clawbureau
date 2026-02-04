# JoinClaw.com — Quick Win Strategy

**Domain:** joinclaw.com  
**Goal:** Community onboarding + docs hub (top of funnel)  
**Status:** Planning  
**Date:** 2026-02-02  

---

## Why JoinClaw Ships First

| Factor | JoinClaw | ClawProviders |
|--------|----------|---------------|
| Dependencies | 1 (clawbureau) | 3 (claim, ledger, intel) |
| Backend needed | No | No (MVP) |
| Content exists | Yes (OpenClaw docs) | Yes (OpenClaw docs) |
| Time to MVP | 2-3 days | 5-7 days |
| CEO showability | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| SEO value | Medium (brand) | High (transactional) |

**JoinClaw is the front door. ClawProviders is the detailed manual.**

---

## Site Architecture

```
joinclaw.com/
├── /                           # Hero: "Your AI, Your Rules"
├── /docs                       # Documentation hub
│   ├── /quickstart             # 5-minute setup
│   ├── /concepts               # Key concepts
│   ├── /providers              # → Links to clawproviders.com
│   ├── /channels               # → Links to clawproviders.com
│   └── /reference              # CLI reference
├── /community                  # → clawgang.com (when ready)
├── /bounties                   # → clawbounties.com (teaser)
├── /llms.txt                   # Agent index
├── /skill.md                   # OpenClaw skill
├── /newsletter                 # Email signup
└── /blog                       # Updates, tutorials
```

---

## Landing Page Sections

### 1. Hero
- Headline: "Your AI, Your Rules"
- Subhead: "Run a personal AI assistant on your own infrastructure. Connect to any messaging platform. Use any model."
- CTA: "Get Started →" (scrolls to install)

### 2. Install Block
```bash
curl -fsSL https://openclaw.bot/install.sh | bash
```
- One-liner prominence
- Platform tabs: macOS / Linux / Windows
- "Takes 5 minutes" badge

### 3. Features Grid
- **Any Model**: Claude, GPT, Gemini, Llama, or your own
- **Any Channel**: WhatsApp, Telegram, Discord, Signal, iMessage
- **Any Platform**: Mac, Linux, VPS, Docker, Fly.io
- **Your Data**: Local-first, no cloud dependency
- **Skills**: Extend with natural language instructions
- **Memory**: Semantic search across all conversations

### 4. How It Works
```
1. Install OpenClaw
2. Add your model credentials
3. Connect a messaging channel
4. Start chatting
```

### 5. Channels Showcase
Visual grid of supported channels with logos:
- WhatsApp, Telegram, Discord, Slack, Signal, iMessage
- Matrix, MS Teams, Nostr, LINE, Zalo, BlueBubbles

### 6. Provider Logos
- Anthropic, OpenAI, Google, AWS Bedrock, Ollama, OpenRouter

### 7. Code Example
```json
{
  "agents": {
    "defaults": {
      "model": {
        "primary": "anthropic/claude-sonnet-4-20250514",
        "fallbacks": ["openai/gpt-5.2", "ollama/llama3.3"]
      }
    }
  },
  "channels": {
    "telegram": { "enabled": true },
    "whatsapp": { "enabled": true }
  }
}
```

### 8. Community CTA
- Discord/Telegram community links
- GitHub stars badge
- Newsletter signup

### 9. Footer
- Links to all Claw Bureau domains
- Legal / Privacy
- GitHub / Twitter

---

## /llms.txt

```txt
# joinclaw.com
> Personal AI assistant platform — your AI, your rules.

## Quick Start
- /docs/quickstart: 5-minute setup guide

## Documentation
- /docs: Full documentation hub
- /docs/concepts: Key concepts
- /docs/reference: CLI reference

## Provider Guides
- https://clawproviders.com/providers: Detailed provider setup guides

## Channel Guides
- https://clawproviders.com/channels: Channel integration guides

## Skill
- /skill.md: OpenClaw skill for joinclaw integration

## Community
- /community: Community hub
- /newsletter: Email updates
```

---

## /skill.md

```markdown
# JoinClaw Skill

When to use: User asks about getting started with OpenClaw, the Claw Bureau ecosystem, or finding documentation.

## Quickstart

```bash
# Install OpenClaw
curl -fsSL https://openclaw.bot/install.sh | bash

# Run onboarding
openclaw onboard

# Check status
openclaw status
```

## Documentation

- Quickstart: https://joinclaw.com/docs/quickstart
- Full docs: https://joinclaw.com/docs
- Provider guides: https://clawproviders.com/providers
- Channel guides: https://clawproviders.com/channels

## Community

- GitHub: https://github.com/openclaw/openclaw
- Discord: https://discord.gg/clawbureau
- Telegram: https://t.me/clawbureau

## Claw Bureau Ecosystem

- joinclaw.com — Onboarding & docs (you are here)
- clawproviders.com — Provider setup guides
- clawgang.com — Community hub
- clawbounties.com — Earn credits by completing tasks
- clawbureau.com — Main platform
```

---

## MVP Implementation (2-3 Days)

### Day 1
- [ ] Astro project setup
- [ ] Dark theme, minimal design
- [ ] Landing page sections 1-4
- [ ] `/llms.txt` and `/skill.md`

### Day 2
- [ ] Landing page sections 5-9
- [ ] `/docs/quickstart` (adapted from OpenClaw 1.2)
- [ ] Basic `/docs` index
- [ ] Newsletter signup (Buttondown or similar)

### Day 3
- [ ] SEO: meta tags, OG images, sitemap
- [ ] Deploy to Cloudflare Pages
- [ ] Test agent endpoints
- [ ] Announce

---

## Design Notes

- **Aesthetic**: Dark, minimal, monospace code
- **Inspiration**: vercel.com, linear.app, supabase.com
- **Speed**: Target <1s TTFB, <3s LCP
- **Mobile**: First-class mobile experience
- **No JS required**: Progressive enhancement only

---

## Integration with ClawProviders

JoinClaw is the **entry point**. ClawProviders is the **deep dive**.

```
User Journey:

1. Google: "personal AI assistant"
   → JoinClaw.com (brand awareness)

2. Google: "Claude API setup WhatsApp"
   → ClawProviders.com/providers/anthropic (transactional)

3. User installs OpenClaw
   → Agent fetches /skill.md from both sites

4. User joins community
   → ClawGang.com (engagement)

5. User contributes
   → ClawBounties.com (monetization)
```

---

## Success Metrics

| Metric | Day 1 | Week 1 | Month 1 |
|--------|-------|--------|---------|
| Unique visitors | 50 | 500 | 2,000 |
| Install commands copied | 10 | 100 | 500 |
| Newsletter signups | 5 | 50 | 200 |
| /llms.txt requests | 10 | 100 | 500 |
| Skill downloads | 5 | 50 | 200 |
| GitHub clicks | 20 | 200 | 1,000 |
