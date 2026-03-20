import { describe, expect, it } from 'vitest';

import { buildProofReport, renderProofReportHtml } from '../src/prove-cmd.js';

function makeBundle(): Record<string, unknown> {
  return {
    envelope_version: '1',
    envelope_type: 'proof_bundle',
    signer_did: 'did:key:zSigner',
    issued_at: '2026-03-20T19:16:58.121Z',
    payload: {
      bundle_version: '1',
      bundle_id: 'bundle_test_report',
      agent_did: 'did:key:zAgent',
      event_chain: [
        {
          event_id: 'evt_1',
          run_id: 'run_1',
          event_type: 'llm_call',
          timestamp: '2026-03-20T19:16:56.576Z',
          payload_hash_b64u: 'abc',
          prev_hash_b64u: null,
          event_hash_b64u: 'def',
        },
      ],
      receipts: [
        {
          envelope_version: '1',
          envelope_type: 'gateway_receipt',
          signer_did: 'did:key:zGatewaySigner',
          payload: {
            receipt_version: '1',
            receipt_id: 'rcpt_1',
            gateway_id: 'did:web:clawproxy.com',
            provider: 'google',
            model: 'gemini-2.5-flash',
            latency_ms: 1234,
            timestamp: '2026-03-20T19:16:58.121Z',
          },
        },
      ],
      network_receipts: [
        { classification: 'infrastructure', process_name: 'Google Chrome Helper' },
        { classification: 'expected', process_name: 'node' },
        { classification: 'expected', process_name: 'node' },
      ],
      metadata: {
        sentinels: {
          shell_events: 0,
          fs_events: 1,
          net_events: 3,
          net_suspicious: 2,
          preload_llm_events: 1,
          interpose_active: true,
          interpose_state: {
            cldd: {
              unmediated_connections: 4,
              unmonitored_spawns: 1,
              escapes_suspected: true,
            },
          },
          runtime_profile: {
            profile_id: 'prv.run.v1.proofed-minimal',
            profile_version: '1',
            mode: 'privacy_assurance',
            activation: {
              status: 'fallback',
              reasons: ['interpose_not_active'],
            },
            baseline: {
              process_count: 42,
              process_hash_b64u: 'base_hash_123',
            },
          },
          runtime_hygiene: {
            verdict: 'action',
            reviewer_action_required: true,
            buckets: {
              background_noise: [
                '2 network receipts matched baseline/background classifications.',
              ],
              caution: [
                'Runtime profile is in fallback mode (interpose_not_active).',
              ],
              action_required: [
                'CLDD unmediated connections (4) exceeded the action threshold (3).',
              ],
            },
          },
        },
      },
    },
  };
}

function makeCleanBundle(): Record<string, unknown> {
  return {
    envelope_version: '1',
    envelope_type: 'proof_bundle',
    signer_did: 'did:key:zSigner',
    issued_at: '2026-03-20T19:16:58.121Z',
    payload: {
      bundle_version: '1',
      bundle_id: 'bundle_clean_report',
      agent_did: 'did:key:zAgent',
      event_chain: [
        {
          event_id: 'evt_1',
          run_id: 'run_1',
          event_type: 'llm_call',
          timestamp: '2026-03-20T19:16:56.576Z',
          payload_hash_b64u: 'abc',
          prev_hash_b64u: null,
          event_hash_b64u: 'def',
        },
      ],
      receipts: [
        {
          envelope_version: '1',
          envelope_type: 'gateway_receipt',
          signer_did: 'did:key:zGatewaySigner',
          payload: {
            receipt_version: '1',
            receipt_id: 'rcpt_1',
            gateway_id: 'did:web:clawproxy.com',
            provider: 'google',
            model: 'gemini-2.5-flash',
            latency_ms: 1234,
            timestamp: '2026-03-20T19:16:58.121Z',
          },
        },
      ],
      network_receipts: [
        { classification: 'llm_api', process_name: 'node' },
      ],
      metadata: {
        sentinels: {
          shell_events: 0,
          fs_events: 1,
          net_events: 1,
          net_suspicious: 0,
          preload_llm_events: 1,
          interpose_active: true,
          interpose_state: {
            cldd: {
              unmediated_connections: 0,
              unmonitored_spawns: 0,
              escapes_suspected: false,
            },
          },
          runtime_profile: {
            profile_id: 'prv.run.v1.proofed-minimal',
            profile_version: '1',
            mode: 'privacy_assurance',
            activation: {
              status: 'active',
              reasons: [],
            },
            baseline: {
              process_count: 42,
              process_hash_b64u: 'base_hash_123',
            },
          },
          runtime_hygiene: {
            verdict: 'good',
            reviewer_action_required: false,
            buckets: {
              background_noise: [
                'No baseline/background network noise receipts were classified.',
              ],
              caution: [],
              action_required: [],
            },
          },
        },
      },
    },
  };
}

describe('buildProofReport', () => {
  it('summarizes gateway, sentinel, and network evidence for reviewer-facing output', () => {
    const report = buildProofReport({
      inputPath: '/tmp/proof_bundle.json',
      bundle: makeBundle(),
      runSummary: {
        status: 'PASS',
        tier: 'gateway',
        duration_seconds: 3,
        timestamp: '2026-03-20T19:16:58.381Z',
        did: 'did:key:zAgent',
        tools_used: [],
        files_modified: [],
      },
    });

    expect(report.public_layer.bundle_id).toBe('bundle_test_report');
    expect(report.harness.status).toBe('PASS');
    expect(report.harness.tier).toBe('gateway');
    expect(report.gateway.signed_count).toBe(1);
    expect(report.gateway.provider).toBe('google');
    expect(report.gateway.model).toBe('gemini-2.5-flash');
    expect(report.network.classification_counts.expected).toBe(2);
    expect(report.network.top_processes[0]).toEqual({ process_name: 'node', count: 2 });
    expect(report.review_buckets.map((bucket) => bucket.label)).toEqual([
      'Gateway proof',
      'Execution hygiene',
      'Background noise / ignorable infra',
      'Reviewer action needed',
    ]);
    expect(report.review_buckets[0]).toMatchObject({
      key: 'gateway_proof',
      tone: 'good',
    });
    expect(report.review_buckets[1]).toMatchObject({
      key: 'execution_hygiene',
      tone: 'action',
    });
    expect(report.sentinels.runtime_profile.profile_id).toBe('prv.run.v1.proofed-minimal');
    expect(report.sentinels.runtime_hygiene.verdict).toBe('action');
    expect(report.review_buckets[2].summary).toContain('baseline/background classifications');
    expect(report.review_buckets[3].items).toContain(
      'Review 2 suspicious network receipts in the raw bundle before external sharing.',
    );
    expect(report.review_buckets[3].items).toContain(
      'Decide whether the CLDD unmediated-connection signal is expected for this runtime or should be suppressed/tuned for cleaner reports.',
    );
    expect(report.warnings).toContain('2 suspicious network events were recorded.');
    expect(report.warnings).toContain('4 unmediated connections were observed by CLDD.');
    expect(report.warnings).toContain('1 unmonitored spawns were detected.');
    expect(report.warnings).toContain('CLDD marked the run as escape-suspected.');
    expect(report.warnings).toContain('Runtime profile fallback is active (interpose_not_active).');
    expect(report.warnings).toContain('Runtime hygiene verdict is ACTION; reviewer follow-up is required.');
  });

  it('keeps clean agent traffic out of the background-noise bucket', () => {
    const report = buildProofReport({
      inputPath: '/tmp/proof_bundle.json',
      bundle: makeCleanBundle(),
      runSummary: {
        status: 'PASS',
        tier: 'gateway',
      },
    });

    expect(report.network.classification_counts.llm_api).toBe(1);
    expect(report.review_buckets[1].items).toContain('No unmonitored spawns or escape flags were recorded.');
    expect(report.review_buckets[2]).toMatchObject({
      key: 'background_noise',
      tone: 'good',
      summary: 'No notable background or infrastructure traffic was recorded.',
    });
    expect(report.review_buckets[3].items).toEqual(['No extra reviewer action is required.']);
  });
});

describe('renderProofReportHtml', () => {
  it('renders a readable HTML report with escaped content', () => {
    const report = buildProofReport({
      inputPath: '/tmp/proof_bundle.json',
      bundle: makeBundle(),
      runSummary: {
        status: 'PASS',
        tier: 'gateway',
      },
    });

    const html = renderProofReportHtml({
      ...report,
      warnings: [...report.warnings, 'needs <review> & confirmation'],
      next_steps: ['Run clawverify verify proof-bundle --input /tmp/proof_bundle.json'],
    });

    expect(html).toContain('Human-readable proof bundle view');
    expect(html).toContain('bundle_test_report');
    expect(html).toContain('gemini-2.5-flash');
    expect(html).toContain('did:web:clawproxy.com');
    expect(html).toContain('Background noise / ignorable infra');
    expect(html).toContain('Reviewer action needed');
    expect(html).toContain('needs &lt;review&gt; &amp; confirmation');
    expect(html).toContain('clawverify verify proof-bundle --input /tmp/proof_bundle.json');
  });
});
