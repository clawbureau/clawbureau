import { describe, expect, it } from 'vitest';
import { runDetailPage, type RunData } from '../src/pages/run.js';

function buildRun(overrides: Partial<RunData> = {}): RunData {
  return {
    run_id: 'run_1234567890abcdef',
    bundle_hash_b64u: 'bundle_hash',
    agent_did: 'did:key:z6MkTestAgentDid123456',
    proof_tier: 'gateway',
    status: 'FAIL',
    reason_code: 'VERIFIER_MALFORMED_RESPONSE',
    failure_class: 'upstream_malformed',
    verification_source: 'clawverify_api',
    auth_mode: 'pow',
    wpc_hash_b64u: null,
    rt_leaf_index: null,
    created_at: '2026-02-19T00:00:00.000Z',
    models: [],
    ...overrides,
  };
}

describe('runDetailPage', () => {
  it('renders severity tone and copyable next-step snippet for known reasons', () => {
    const html = runDetailPage(buildRun());

    expect(html).toContain('Upstream Response Malformed');
    expect(html).toContain('Next Step Snippet');
    expect(html).toContain('Copy next step');
    expect(html).toContain('View similar failures');
  });

  it('renders fallback triage card for unknown reason codes', () => {
    const html = runDetailPage(
      buildRun({
        reason_code: null,
        failure_class: 'none',
      })
    );

    expect(html).toContain('Unclassified Verification Failure');
    expect(html).toContain('UNKNOWN_REASON');
    expect(html).toContain('Verification Failure');
  });
});
