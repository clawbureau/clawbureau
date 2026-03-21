import { describe, expect, it } from 'vitest';

import { generateComplianceReport } from '../src/stubs';

describe('ledger compliance stubs wave1 integration', () => {
  it('uses authoritative compiler output instead of placeholder PENDING results', () => {
    const report = generateComplianceReport(
      'soc2',
      {
        agent_did: 'did:key:ledger-agent',
        event_chain: [{ event_id: 'evt-1' }],
        receipts: [{ payload: { receipt_id: 'gw-1', model: 'model-approved' } }],
        tool_receipts: [{ receipt_id: 'tool-1', tool_name: 'edit' }],
        side_effect_receipts: [{ receipt_id: 'se-1', effect_class: 'network_egress' }],
        human_approval_receipts: [
          { receipt_id: 'ha-1', approval_type: 'explicit_approve' },
        ],
      },
      {
        policy_hash_b64u: 'policy-hash',
        allowed_models: ['model-approved'],
      },
      {
        bundle_hash_b64u: 'bundle-hash',
        verification_fact: {
          status: 'VALID',
          reason_code: 'OK',
          reason: 'Proof bundle verified successfully',
          verified_at: '2026-01-01T00:00:00.000Z',
          agent_did: 'did:key:ledger-agent',
        },
      },
    ) as {
      runtime?: { state?: string; global_status?: string };
      report?: { framework?: string };
      status?: string;
    };

    expect(report.status).toBeUndefined();
    expect(report.runtime?.state).toBe('COMPILED_PASS');
    expect(report.runtime?.global_status).toBe('PASS');
    expect(report.report?.framework).toBe('SOC2_Type2');
  });

  it('returns honest fail-closed output when verification context is missing', () => {
    const report = generateComplianceReport(
      'soc2',
      {
        agent_did: 'did:key:ledger-agent',
      },
      undefined,
      {
        bundle_hash_b64u: 'bundle-hash',
      },
    ) as {
      runtime?: { state?: string; global_reason_code?: string };
      failure?: { reason_code?: string };
    };

    expect(report.runtime?.state).toBe('INPUT_REJECTED');
    expect(report.runtime?.global_reason_code).toBe(
      'COMPILER_INPUT_MISSING_VERIFICATION_FACT',
    );
    expect(report.failure?.reason_code).toBe(
      'COMPILER_INPUT_MISSING_VERIFICATION_FACT',
    );
  });

  it('fails closed when the authoritative bundle hash context is missing', () => {
    const report = generateComplianceReport(
      'soc2',
      {
        agent_did: 'did:key:ledger-agent',
      },
      undefined,
      {
        verification_fact: {
          status: 'VALID',
          reason_code: 'OK',
          reason: 'Proof bundle verified successfully',
          verified_at: '2026-01-01T00:00:00.000Z',
          agent_did: 'did:key:ledger-agent',
        },
      },
    ) as {
      runtime?: { state?: string; global_reason_code?: string };
      failure?: { reason_code?: string };
    };

    expect(report.runtime?.state).toBe('INPUT_REJECTED');
    expect(report.runtime?.global_reason_code).toBe(
      'COMPILER_INPUT_MISSING_BUNDLE_HASH',
    );
    expect(report.failure?.reason_code).toBe('COMPILER_INPUT_MISSING_BUNDLE_HASH');
  });
});
