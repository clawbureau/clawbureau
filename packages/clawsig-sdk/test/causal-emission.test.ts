import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { createRun, generateKeyPair } from '../dist/index.js';

describe('clawsig-sdk causal emission (CAV-US-003)', () => {
  it('emits deterministic causal bindings on tool / side-effect / human approval receipts', async () => {
    const keyPair = await generateKeyPair();

    const run = await createRun({
      proxyBaseUrl: 'https://example.invalid',
      keyPair,
      harness: {
        id: 'causal-emission-test',
        version: '1.0.0',
        runtime: 'node',
      },
    });

    await run.recordEvent({
      eventType: 'run_start',
      payload: { story: 'CAV-US-003' },
    });

    const tool = await run.recordToolCall({
      toolName: 'bash',
      args: { command: 'echo hello' },
      result: { stdout: 'hello\n' },
      resultStatus: 'success',
      latencyMs: 5,
    });

    const toolBinding = tool.receipt.binding;
    assert.ok(toolBinding?.span_id, 'tool receipt should emit span_id');
    assert.equal(toolBinding?.tool_span_id, toolBinding?.span_id);
    assert.equal(toolBinding?.phase, 'execution');
    assert.equal(toolBinding?.attribution_confidence, 1.0);

    const side = await run.recordSideEffect({
      effectClass: 'filesystem_write',
      target: '/tmp/causal-emission.txt',
      request: { op: 'write' },
      response: { ok: true },
      responseStatus: 'success',
      latencyMs: 2,
      bytesWritten: 12,
    });

    const sideBinding = side.receipt.binding;
    assert.ok(sideBinding?.span_id, 'side-effect receipt should emit span_id');
    assert.equal(sideBinding?.parent_span_id, toolBinding?.span_id);
    assert.equal(sideBinding?.tool_span_id, toolBinding?.span_id);
    assert.equal(sideBinding?.phase, 'observation');
    assert.equal(sideBinding?.attribution_confidence, 1.0);

    const approval = await run.recordHumanApproval({
      approvalType: 'explicit_approve',
      approverSubject: 'did:key:z6MktestApprover',
      approverMethod: 'cli_confirm',
      scopeClaims: { action: 'deploy:staging' },
      scopeSummary: 'approve staging deploy',
      mintedCapabilityId: 'cap_123',
      mintedCapabilityTtlSeconds: 60,
    });

    const approvalBinding = approval.receipt.binding;
    assert.ok(approvalBinding?.span_id, 'human approval should emit span_id');
    assert.equal(approvalBinding?.parent_span_id, toolBinding?.span_id);
    assert.equal(approvalBinding?.tool_span_id, toolBinding?.span_id);
    assert.equal(approvalBinding?.phase, 'reflection');
    assert.equal(approvalBinding?.attribution_confidence, 1.0);
  });

  it('emits deterministic unattributed fallback for side-effects without tool lineage', async () => {
    const keyPair = await generateKeyPair();

    const run = await createRun({
      proxyBaseUrl: 'https://example.invalid',
      keyPair,
      harness: {
        id: 'causal-emission-test',
        version: '1.0.0',
        runtime: 'node',
      },
    });

    await run.recordEvent({
      eventType: 'run_start',
      payload: { story: 'CAV-US-003-fallback' },
    });

    const side = await run.recordSideEffect({
      effectClass: 'network_egress',
      target: 'https://example.com',
      request: { method: 'GET' },
      response: { status: 200 },
      responseStatus: 'success',
      latencyMs: 1,
    });

    const binding = side.receipt.binding;
    assert.ok(binding?.span_id, 'fallback side-effect should still emit span_id');
    assert.equal(binding?.tool_span_id, undefined);
    assert.equal(binding?.parent_span_id, undefined);
    assert.equal(binding?.phase, 'execution');
    assert.equal(binding?.attribution_confidence, 0.0);
  });
});
