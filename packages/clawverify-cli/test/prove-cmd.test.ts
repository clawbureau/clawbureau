import { describe, expect, it } from 'vitest';

import { buildProofReport, renderProofReportHtml, renderProofReportText } from '../src/prove-cmd.js';
import { renderProofReportText as renderProofReportTextFromIndex } from '../src/index.js';

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
          event_hash_b64u: 'event_hash_def123',
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
          egress_policy_receipt: {
            envelope_version: '1',
            envelope_type: 'egress_policy_receipt',
            payload_hash_b64u: 'egress_payload_hash_1234',
            hash_algorithm: 'SHA-256',
            signature_b64u: 'egress_signature_1234',
            algorithm: 'Ed25519',
            signer_did: 'did:key:zAgent',
            issued_at: '2026-03-20T19:16:57.351Z',
            payload: {
              receipt_version: '1',
              receipt_id: 'egr_1',
              policy_version: '1',
              policy_hash_b64u: 'policy_hash_1234',
              proofed_mode: true,
              clawproxy_url: 'https://clawproxy.example',
              allowed_proxy_destinations: ['api.openai.com', 'generativelanguage.googleapis.com'],
              allowed_child_destinations: ['api.clawbureau.internal'],
              direct_provider_access_blocked: true,
              blocked_attempt_count: 2,
              blocked_attempts_observed: true,
              hash_algorithm: 'SHA-256',
              agent_did: 'did:key:zAgent',
              timestamp: '2026-03-20T19:16:57.321Z',
              binding: {
                run_id: 'run_1',
                event_hash_b64u: 'event_hash_def123',
              },
            },
          },
        },
        processor_policy: {
          receipt_version: '1',
          receipt_type: 'processor_policy',
          policy_version: 'prv.proc.v1',
          profile_id: 'processor-profile-1',
          policy_hash_b64u: 'processor_policy_hash_123',
          enforce: true,
          binding: {
            run_id: 'run_1',
          },
          constraints: {
            allowed_providers: ['google'],
            allowed_models: ['gemini-2.5-flash'],
            allowed_regions: ['eu'],
            allowed_retention_profiles: ['no-store'],
            default_region: 'eu',
            default_retention_profile: 'no-store',
          },
          counters: {
            allowed_routes: 3,
            denied_routes: 1,
          },
          used_processors: [
            {
              provider: 'google',
              model: 'gemini-2.5-flash',
              region: 'eu',
              retention_profile: 'no-store',
              count: 3,
            },
          ],
          blocked_attempts: [
            {
              route: {
                provider: 'openai',
                model: 'gpt-5',
                region: 'us',
                retention_profile: 'default',
              },
              reason_code: 'PRV_POL_ROUTE_DENIED',
              timestamp: '2026-03-20T19:16:57.401Z',
            },
          ],
        },
        data_handling: {
          policy_version: 'prv.dlp.v1',
          receipts: [
            {
              envelope_version: '1',
              envelope_type: 'data_handling_receipt',
              payload_hash_b64u: 'dlp_payload_hash_1',
              hash_algorithm: 'SHA-256',
              signature_b64u: 'dlp_signature_1',
              algorithm: 'Ed25519',
              signer_did: 'did:key:zAgent',
              issued_at: '2026-03-20T19:16:56.951Z',
              payload: {
                receipt_version: '1',
                receipt_id: 'dlp_1',
                policy_version: 'prv.dlp.v1',
                run_id: 'run_1',
                provider: 'google',
                action: 'redact',
                reason_code: 'PRV_DLP_REDACTED',
                classes: [
                  { class_id: 'pii.email', rule_id: 'pii_email', action: 'redact', match_count: 2 },
                ],
                approval: {
                  required: false,
                  satisfied: false,
                  mechanism: 'header_token',
                  token_hash_b64u: null,
                },
                redaction: {
                  applied: true,
                  original_payload_hash_b64u: 'orig_hash_1',
                  outbound_payload_hash_b64u: 'redacted_hash_1',
                },
                timestamp: '2026-03-20T19:16:56.921Z',
              },
            },
            {
              envelope_version: '1',
              envelope_type: 'data_handling_receipt',
              payload_hash_b64u: 'dlp_payload_hash_2',
              hash_algorithm: 'SHA-256',
              signature_b64u: 'dlp_signature_2',
              algorithm: 'Ed25519',
              signer_did: 'did:key:zAgent',
              issued_at: '2026-03-20T19:16:57.041Z',
              payload: {
                receipt_version: '1',
                receipt_id: 'dlp_2',
                policy_version: 'prv.dlp.v1',
                run_id: 'run_1',
                provider: 'google',
                action: 'require_approval',
                reason_code: 'PRV_DLP_APPROVAL_REQUIRED',
                classes: [
                  { class_id: 'secret.api_key', rule_id: 'secret_key', action: 'require_approval', match_count: 1 },
                ],
                approval: {
                  required: true,
                  satisfied: false,
                  mechanism: 'header_token',
                  token_hash_b64u: null,
                },
                redaction: {
                  applied: false,
                  original_payload_hash_b64u: 'orig_hash_2',
                  outbound_payload_hash_b64u: null,
                },
                timestamp: '2026-03-20T19:16:57.011Z',
              },
            },
          ],
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
          event_hash_b64u: 'event_hash_def123',
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
          egress_policy_receipt: {
            envelope_version: '1',
            envelope_type: 'egress_policy_receipt',
            payload_hash_b64u: 'egress_payload_hash_clean_1234',
            hash_algorithm: 'SHA-256',
            signature_b64u: 'egress_signature_clean_1234',
            algorithm: 'Ed25519',
            signer_did: 'did:key:zAgent',
            issued_at: '2026-03-20T19:16:57.351Z',
            payload: {
              receipt_version: '1',
              receipt_id: 'egr_clean',
              policy_version: '1',
              policy_hash_b64u: 'policy_hash_clean_1234',
              proofed_mode: true,
              clawproxy_url: 'https://clawproxy.example',
              allowed_proxy_destinations: ['generativelanguage.googleapis.com'],
              allowed_child_destinations: [],
              direct_provider_access_blocked: true,
              blocked_attempt_count: 0,
              blocked_attempts_observed: false,
              hash_algorithm: 'SHA-256',
              agent_did: 'did:key:zAgent',
              timestamp: '2026-03-20T19:16:57.321Z',
              binding: {
                run_id: 'run_1',
                event_hash_b64u: 'event_hash_def123',
              },
            },
          },
        },
        processor_policy: {
          receipt_version: '1',
          receipt_type: 'processor_policy',
          policy_version: 'prv.proc.v1',
          profile_id: 'processor-profile-clean',
          policy_hash_b64u: 'processor_policy_hash_clean_123',
          enforce: true,
          binding: {
            run_id: 'run_1',
          },
          constraints: {
            allowed_providers: ['google'],
            allowed_models: ['gemini-2.5-flash'],
            allowed_regions: ['eu'],
            allowed_retention_profiles: ['no-store'],
            default_region: 'eu',
            default_retention_profile: 'no-store',
          },
          counters: {
            allowed_routes: 1,
            denied_routes: 0,
          },
          used_processors: [
            {
              provider: 'google',
              model: 'gemini-2.5-flash',
              region: 'eu',
              retention_profile: 'no-store',
              count: 1,
            },
          ],
          blocked_attempts: [],
        },
        data_handling: {
          policy_version: 'prv.dlp.v1',
          receipts: [
            {
              envelope_version: '1',
              envelope_type: 'data_handling_receipt',
              payload_hash_b64u: 'dlp_payload_hash_clean_1',
              hash_algorithm: 'SHA-256',
              signature_b64u: 'dlp_signature_clean_1',
              algorithm: 'Ed25519',
              signer_did: 'did:key:zAgent',
              issued_at: '2026-03-20T19:16:56.951Z',
              payload: {
                receipt_version: '1',
                receipt_id: 'dlp_clean_1',
                policy_version: 'prv.dlp.v1',
                run_id: 'run_1',
                provider: 'google',
                action: 'allow',
                reason_code: 'PRV_DLP_ALLOW',
                classes: [],
                approval: {
                  required: false,
                  satisfied: false,
                  mechanism: 'header_token',
                  token_hash_b64u: null,
                },
                redaction: {
                  applied: false,
                  original_payload_hash_b64u: 'allow_hash_1',
                  outbound_payload_hash_b64u: 'allow_hash_1',
                },
                timestamp: '2026-03-20T19:16:56.921Z',
              },
            },
          ],
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
    expect(report.privacy_posture.overall_verdict).toBe('action');
    expect(report.privacy_posture.evidence.egress_policy_receipt_present).toBe(true);
    expect(report.privacy_posture.evidence.processor_policy_evidence_present).toBe(true);
    expect(report.privacy_posture.evidence.data_handling_receipts_present).toBe(true);
    expect(report.privacy_posture.egress.blocked_attempt_count).toBe(2);
    expect(report.privacy_posture.processor_policy.used_processors[0]).toMatchObject({
      provider: 'google',
      model: 'gemini-2.5-flash',
      count: 3,
    });
    expect(report.privacy_posture.processor_policy.blocked_attempts[0]).toMatchObject({
      reason_code: 'PRV_POL_ROUTE_DENIED',
    });
    expect(report.privacy_posture.data_handling.actions).toEqual([
      { action: 'redact', count: 1 },
      { action: 'require_approval', count: 1 },
    ]);
    expect(report.privacy_posture.data_handling.sensitive_classes).toEqual([
      { class_id: 'pii.email', match_count: 2, actions: ['redact'] },
      { class_id: 'secret.api_key', match_count: 1, actions: ['require_approval'] },
    ]);
    expect(report.privacy_posture.signal_buckets.reviewer_action_required).toContain(
      '1 data-handling receipt required approval and did not satisfy it.',
    );
    expect(report.privacy_posture.proven_claims.join(' ')).toContain('signed egress policy receipt');
    expect(report.privacy_posture.not_proven_claims).toContain(
      'This report does not by itself prove legal or regulatory compliance.',
    );
    expect(report.privacy_posture.not_proven_claims).toContain(
      'This report does not independently verify every privacy receipt signature or processor-policy hash; use clawverify verify proof-bundle for canonical validation.',
    );
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
    expect(report.warnings).toContain('Privacy posture verdict is ACTION; reviewer follow-up is required.');
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
    expect(report.privacy_posture.overall_verdict).toBe('good');
    expect(report.privacy_posture.reviewer_action_required).toBe(false);
    expect(report.privacy_posture.data_handling.actions).toEqual([{ action: 'allow', count: 1 }]);
    expect(report.privacy_posture.data_handling.approval_unsatisfied_count).toBe(0);
    expect(report.privacy_posture.signal_buckets.reviewer_action_required).toEqual([]);
    expect(report.review_buckets[3].items).toEqual(['No extra reviewer action is required.']);
  });

  it('does not treat malformed privacy metadata as proof evidence', () => {
    const bundle = makeBundle();
    const payload = bundle.payload as {
      metadata?: {
        sentinels?: {
          egress_policy_receipt?: Record<string, unknown>;
        };
        data_handling?: {
          receipts?: Array<Record<string, unknown>>;
        };
        processor_policy?: Record<string, unknown>;
      };
    };

    if (payload.metadata?.sentinels?.egress_policy_receipt) {
      delete payload.metadata.sentinels.egress_policy_receipt.signature_b64u;
    }
    if (payload.metadata?.data_handling?.receipts?.[0]) {
      delete payload.metadata.data_handling.receipts[0].signature_b64u;
    }
    if (payload.metadata?.processor_policy) {
      delete payload.metadata.processor_policy.binding;
    }

    const report = buildProofReport({
      inputPath: '/tmp/proof_bundle.json',
      bundle,
      runSummary: {
        status: 'PASS',
        tier: 'gateway',
      },
    });

    expect(report.privacy_posture.evidence.egress_policy_receipt_present).toBe(false);
    expect(report.privacy_posture.evidence.processor_policy_evidence_present).toBe(false);
    expect(report.privacy_posture.evidence.data_handling_receipts_present).toBe(true);
    expect(report.privacy_posture.signal_buckets.caution).toContain(
      'An egress policy object is present, but it is not a structurally complete signed receipt envelope.',
    );
    expect(report.privacy_posture.signal_buckets.caution).toContain(
      'A processor policy object is present, but it is missing required evidence fields.',
    );
    expect(report.privacy_posture.signal_buckets.caution).toContain(
      'Some data-handling entries are present, but not all of them are structurally complete signed receipt envelopes.',
    );
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
    expect(html).toContain('Privacy posture');
    expect(html).toContain('Allowed processors and blocked routes');
    expect(html).toContain('Sensitive classes and actions');
    expect(html).toContain('What Is Not Proven');
    expect(html).toContain('needs &lt;review&gt; &amp; confirmation');
    expect(html).toContain('clawverify verify proof-bundle --input /tmp/proof_bundle.json');
  });
});

describe('renderProofReportText', () => {
  it('prints a privacy posture section with proven and not-proven boundaries', () => {
    const report = buildProofReport({
      inputPath: '/tmp/proof_bundle.json',
      bundle: makeBundle(),
      runSummary: {
        status: 'PASS',
        tier: 'gateway',
      },
    });

    const text = renderProofReportText(report);
    expect(text).toContain('Privacy posture:');
    expect(text).toContain('Allowed egress destinations:');
    expect(text).toContain('Allowed processors used:');
    expect(text).toContain('Blocked processor attempts:');
    expect(text).toContain('Sensitive classes/actions:');
    expect(text).toContain('Caution privacy signals:');
    expect(text).toContain('What is proven:');
    expect(text).toContain('Not proven / claim limits:');
    expect(text).toContain('Runtime hygiene posture');
  });

  it('is exported from the package entrypoint', () => {
    const report = buildProofReport({
      inputPath: '/tmp/proof_bundle.json',
      bundle: makeCleanBundle(),
      runSummary: {
        status: 'PASS',
        tier: 'gateway',
      },
    });

    expect(renderProofReportTextFromIndex(report)).toContain('=== Clawsig proof report ===');
  });
});
