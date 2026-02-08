> **Type:** Index
> **Status:** REFERENCE
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-07
> **Source of truth:** oracle outputs in this folder
>
> **Scope:**
> - Index of oracle runs used as inputs to PoH/Trust planning.

# PoH Oracle Runs — 2026-02-07

This folder contains prompts + outputs from Oracle research runs.

## Completed

- `poh-harness-playbook` (gpt-5.2-pro)
  - Output: `poh-harness-playbook` was run via `oracle session poh-harness-playbook` (stored session; see terminal logs)
  - Focus: per-harness best practices + shim gaps (streaming, header forwarding)

- `poh-first-principles` (gpt-5.2-pro)
  - Output: `first-principles.gpt-5.2-pro.md`
  - Focus: PoH evidence model + threat model + roadmap

- `poh-subscription-auth` (gpt-5.2-pro)
  - Output: `subscription-auth.gpt-5.2-pro.md`
  - Focus: subscription auth (ChatGPT/Gemini/Claude web) vs verifiable receipts

- `poh-redteam-threats` (gpt-5.2-pro)
  - Output: `redteam.gpt-5.2-pro.md`
  - Focus: anti-gaming red-team list + verifier hardening

- `poh-harness-enforcement` (google/gemini-3-pro-preview)
  - Output: `harness-enforcement.google-gemini-3-pro-preview.md`
  - Focus: harness enforcement points (plugins/extensions vs wrappers) + compatibility matrix

- `poh-confidenti-consulting` (gpt-5.2-pro)
  - Output: `confidential-consulting.gpt-5.2-pro.md`
  - Focus: sensitive agent-to-agent consulting architecture + contract/policy objects + tiers

## Completed (continued)

- `poh-replay-nondetermi` (gpt-5.2-pro)
  - Output: `replay-nondeterminism.gpt-5.2-pro.md`

- `poh-replay-nondet-gemini` (google/gemini-3-pro-preview)
  - Output: `replay-nondeterminism.google-gemini-3-pro-preview.md`

- `poh-openclaw-prompt-integrity` (gpt-5.2-pro)
  - Output: `openclaw-system-prompt-integrity.gpt-5.2-pro.md`

- `poh-openclaw-prompt-integrity-gemini` (google/gemini-3-pro-preview)
  - Output: `openclaw-system-prompt-integrity.google-gemini-3-pro-preview.md`

## Completed (continued)

- `poh-prompt-injection` (gpt-5.2-pro)
  - Output: `prompt-injection-redteam.gpt-5.2-pro.md`

- `poh-prompt-injection-gemini` (google/gemini-3-pro-preview)
  - Output: `prompt-injection-redteam.google-gemini-3-pro-preview.md`

- `poh-next-building-blocks` (gpt-5.2-pro)
  - Output: `next-building-blocks-plan.gpt-5.2-pro.md`

## Running

(none)

## Prompts

- `PROMPT_first-principles.md`
- `PROMPT_subscription-auth.md`
- `PROMPT_redteam.md`
- `PROMPT_harness-enforcement.md`
- `PROMPT_sensitive-agent-to-agent.md`
- `PROMPT_replay-nondeterminism.md`
- `PROMPT_openclaw-system-prompt-integrity.md`
- `PROMPT_prompt-injection-redteam.md`
- `PROMPT_next-building-blocks-plan.md`
