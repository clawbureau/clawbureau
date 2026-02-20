# AGP-US-073 UI Duel Judge Report

Contract: `contract_clawbounties_ui_duel_v1`  
Fingerprint: `frontend:clawbounties:ux-redesign`  
Method: fail-closed hard gates first, weighted score second.

## Side-by-side result

| Contender | Story | PR | Hard gates | Final score | Decision |
|---|---:|---:|---|---:|---|
| Gemini 3.1 Pro Preview (Pi) | AGP-US-071 | #399 | **FAIL** (`ARENA_UI_DUEL_GATE_CORE_FLOWS_FAIL`, `ARENA_UI_DUEL_GATE_RUNTIME_ERRORS`) | 0.0 | Lose |
| GPT-5.3 Codex xhigh (Pi) | AGP-US-072 | #400 | **PASS** | 99.4 | **Winner** |

## Evidence pointers

- Contender A summary: `contender-a.summary.json`
- Contender A evaluator: `contender-a.evaluator-summary.json`
- Contender B summary: `contender-b.summary.json`
- Contender B evaluator: `contender-b.evaluator-summary.json`

All stored in:
`artifacts/ops/arena-productization/2026-02-20T14-40-00Z-agp-us-073-ui-duel-judge/`

## Ruling

Winner is **AGP-US-072 / contender_gpt_5_3_codex_xhigh_pi** because it is the only contender that passed all hard gates under real-data evaluator execution.

Action:
1. Merge winner PR #400 with merge commit.
2. Close loser PR #399 with fail-closed reason.
3. Proceed to AGP-US-074 routing policy update and rollback-code capture.
