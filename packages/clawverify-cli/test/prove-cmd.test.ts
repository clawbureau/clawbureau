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
    expect(report.warnings).toContain('2 suspicious network events were recorded.');
    expect(report.warnings).toContain('4 unmediated connections were observed by CLDD.');
    expect(report.warnings).toContain('1 unmonitored spawns were detected.');
    expect(report.warnings).toContain('CLDD marked the run as escape-suspected.');
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
    expect(html).toContain('needs &lt;review&gt; &amp; confirmation');
    expect(html).toContain('clawverify verify proof-bundle --input /tmp/proof_bundle.json');
  });
});
