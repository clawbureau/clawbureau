/**
 * Human approval example: two-phase execution with capability minting
 *
 * Demonstrates Coverage MTS — the agent proposes a plan, a human approves
 * or denies, and the approval receipt is recorded in the proof bundle.
 * Approved plans mint a capability (CST) that authorizes side-effects.
 *
 * This models the Clawsig Protocol's two-phase execution posture:
 *   Phase 1: Plan (always allowed — LLM calls + tool reads)
 *   Phase 2: Execute (requires human approval for side-effects)
 *
 * Usage:
 *   CLAWSIG_PROXY_URL=https://proxy.clawbureau.com \
 *   node --loader tsx examples/human-approval.ts
 */

import { createHash } from 'node:crypto';
import { createClawsigRun } from '../src/index.js';

function sha256(data: string): string {
  return 'sha256:' + createHash('sha256').update(data).digest('hex');
}

async function main() {
  const run = await createClawsigRun({
    agentDid: process.env.AGENT_DID || 'did:key:z6MkExample...',
    proxyUrl: process.env.CLAWSIG_PROXY_URL || 'https://proxy.clawbureau.com',
    keyFile: process.env.CLAWSIG_KEY_FILE || '.clawsig-key.json',
  });

  // ── Phase 1: Plan ──────────────────────────────────────────────
  // Agent reads code, analyzes the problem, proposes a fix

  const planResponse = await run.callLLM({
    model: 'claude-sonnet-4-20250514',
    messages: [
      { role: 'user', content: 'Fix the bug in src/auth.ts where tokens expire too early' },
    ],
  });

  // Agent reads files (read-only tools are always allowed)
  run.recordToolCall({
    tool_name: 'file_read',
    args_digest: sha256(JSON.stringify({ path: 'src/auth.ts' })),
    result_digest: sha256('const TOKEN_EXPIRY = 60; // 1 minute — too short!'),
    duration_ms: 5,
  });

  // Agent formulates a plan
  const plan = {
    description: 'Change TOKEN_EXPIRY from 60 to 3600 (1 hour)',
    files_to_modify: ['src/auth.ts'],
    risk: 'low',
  };
  const planHash = sha256(JSON.stringify(plan));

  // ── Human approval gate ────────────────────────────────────────
  // In a real system, this would be a Slack message, GitHub review,
  // or UI prompt. The human sees the plan and approves/denies.

  const humanApproved = true; // Simulated approval

  run.recordHumanApproval({
    approval_type: humanApproved ? 'explicit_approve' : 'explicit_deny',
    scope_hash_b64u: Buffer.from('write:src/auth.ts').toString('base64url'),
    plan_hash_b64u: planHash,
    approver_subject: 'user@example.com', // OIDC subject, email, or DID
    capability_minted: humanApproved,
  });

  // ── Phase 2: Execute (only if approved) ────────────────────────
  if (humanApproved) {
    // Now the agent can write files — the approval receipt proves authorization
    run.recordSideEffect({
      effect_class: 'filesystem_write',
      target_digest: sha256('src/auth.ts'),
      request_digest: sha256('const TOKEN_EXPIRY = 3600;'),
      response_digest: sha256('write_ok'),
      bytes_written: 28,
    });

    console.log('Plan approved — file written');
  } else {
    console.log('Plan denied — no side-effects executed');
  }

  // ── Finalize ───────────────────────────────────────────────────
  const result = await run.finalize();

  console.log(`Proof bundle: ${result.path}`);
  console.log(`Events: ${result.eventCount}`);
  console.log('Coverage level: MTS (model + tools + side-effects + human approval)');
}

main().catch(console.error);
