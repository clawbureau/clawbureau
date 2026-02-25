> **Type:** Index
> **Status:** ACTIVE
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-25

# Agent Skills

Reusable skill files for AI coding agent harnesses (Pi, Claude Code, etc.).

## Available skills

| Skill | Description | Source |
|-------|-------------|--------|
| [clawsig](clawsig/SKILL.md) | Clawsig Protocol CLI — identity, wrap, verify, explain, compliance | `docs/skills/clawsig/SKILL.md` |

## Installation

Skills are installed by copying the `SKILL.md` file into the harness skill directory.

### Pi

```bash
# One-time setup
mkdir -p ~/.pi/agent/skills/clawsig
cp docs/skills/clawsig/SKILL.md ~/.pi/agent/skills/clawsig/SKILL.md
```

To sync after pulling updates:

```bash
cp docs/skills/clawsig/SKILL.md ~/.pi/agent/skills/clawsig/SKILL.md
```

### Claude Code

Place the skill content in your `.claude/skills/` directory or reference it via AGENTS.md.
