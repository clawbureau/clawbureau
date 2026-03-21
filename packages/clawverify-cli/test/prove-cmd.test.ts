import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import crypto from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it, vi } from 'vitest';

import {
  buildProofReport,
  renderProofReportHtml,
  renderProofReportText,
  runProveReport,
} from '../src/prove-cmd.js';
import { renderProofReportText as renderProofReportTextFromIndex } from '../src/index.js';

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const REVIEWER_TEST_KEYPAIR = crypto.generateKeyPairSync('ed25519');
const REVIEWER_TEST_DID = (() => {
  const publicJwk = REVIEWER_TEST_KEYPAIR.publicKey.export({ format: 'jwk' }) as JsonWebKey & {
    x?: string;
  };
  if (!publicJwk.x) {
    throw new Error('failed to export reviewer test public key as JWK');
  }

  const multicodec = Buffer.concat([
    Buffer.from([0xed, 0x01]),
    Buffer.from(publicJwk.x, 'base64url'),
  ]);
  return `did:key:z${base58Encode(multicodec)}`;
})();

function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) {
    return '';
  }

  const digits: number[] = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let index = 0; index < digits.length; index++) {
      const value = digits[index]! * 256 + carry;
      digits[index] = value % 58;
      carry = Math.floor(value / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }

  for (let index = 0; index < bytes.length && bytes[index] === 0; index++) {
    digits.push(0);
  }

  return digits
    .reverse()
    .map((digit) => BASE58_ALPHABET[digit]!)
    .join('');
}

function sha256B64uJson(value: unknown): string {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('base64url');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function syncReviewerSignoffReceiptHashes(bundle: Record<string, unknown>): void {
  const payload = bundle.payload as {
    metadata?: {
      reviewer_signoff_receipts?: Array<Record<string, unknown>>;
    };
  };

  for (const receipt of payload.metadata?.reviewer_signoff_receipts ?? []) {
    if (typeof receipt.payload === 'object' && receipt.payload !== null && !Array.isArray(receipt.payload)) {
      const payloadHash = sha256B64uJson(receipt.payload);
      receipt.payload_hash_b64u = payloadHash;
      if (receipt.signer_did === REVIEWER_TEST_DID) {
        receipt.signature_b64u = crypto
          .sign(null, Buffer.from(payloadHash), REVIEWER_TEST_KEYPAIR.privateKey)
          .toString('base64url');
      }
    }
  }
}

function makeBundle(): Record<string, unknown> {
  const bundle: Record<string, unknown> = {
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
        reviewer_signoff_receipts: [
          {
            envelope_version: '1',
            envelope_type: 'reviewer_signoff_receipt',
            payload_hash_b64u: 'reviewer_signoff_payload_hash_1',
            hash_algorithm: 'SHA-256',
            signature_b64u: 'reviewer_signoff_signature_1',
            algorithm: 'Ed25519',
            signer_did: REVIEWER_TEST_DID,
            issued_at: '2026-03-20T19:17:10.000Z',
            payload: {
              receipt_version: '1',
              receipt_id: 'rsr_1',
              reviewer_did: REVIEWER_TEST_DID,
              decision: 'approve',
              timestamp: '2026-03-20T19:17:10.000Z',
              binding: {
                run_id: 'run_1',
                bundle_id: 'bundle_test_report',
                proof_bundle_hash_b64u: 'bundle_hash_12345678',
                event_hash_b64u: 'event_hash_def123',
                target_kind: 'run',
              },
              dispute: {
                status: 'none',
              },
            },
          },
        ],
      },
    },
  };
  syncReviewerSignoffReceiptHashes(bundle);
  return bundle;
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

function makeAttestedBundle(): Record<string, unknown> {
  const bundle = makeCleanBundle();
  const payload = bundle.payload as {
    event_chain?: Array<{ run_id?: string; event_hash_b64u?: string }>;
    metadata?: Record<string, unknown>;
    agent_did?: string;
  };
  if (!payload.metadata) {
    payload.metadata = {};
  }

  const runId = payload.event_chain?.[0]?.run_id ?? 'run_1';
  const eventHash = payload.event_chain?.[0]?.event_hash_b64u ?? 'event_hash_def123';
  const policyHash = 'policy_hash_attested_123456';
  const artifacts = {
    preload_hash_b64u: 'preload_hash_attested_123456',
    node_preload_sentinel_hash_b64u: 'node_preload_hash_attested_123456',
    sentinel_shell_hash_b64u: null,
    sentinel_shell_policy_hash_b64u: null,
    interpose_library_hash_b64u: null,
  };
  const manifest = {
    manifest_version: '1',
    runtime: {
      platform: 'linux',
      arch: 'x64',
      node_version: 'v22.0.0',
    },
    proofed: {
      proofed_mode: true,
      clawproxy_url: 'https://clawproxy.example',
      allowed_proxy_destinations: ['generativelanguage.googleapis.com'],
      allowed_child_destinations: [],
      sentinels: {
        shell_enabled: false,
        interpose_enabled: false,
        preload_enabled: true,
        fs_enabled: true,
        net_enabled: true,
      },
    },
    policy: {
      effective_policy_hash_b64u: policyHash,
    },
    artifacts,
  };
  const manifestHash = sha256B64uJson(manifest);
  const runtimeHash = sha256B64uJson(manifest.runtime);
  const receiptPayload = {
    receipt_version: '1',
    receipt_id: 'rar_1',
    hash_algorithm: 'SHA-256',
    agent_did: payload.agent_did ?? 'did:key:zAgent',
    timestamp: '2026-03-20T19:16:57.701Z',
    binding: {
      run_id: runId,
      event_hash_b64u: eventHash,
    },
    runner_measurement: {
      manifest_hash_b64u: manifestHash,
      runtime_hash_b64u: runtimeHash,
      artifacts,
    },
    policy: {
      effective_policy_hash_b64u: policyHash,
    },
  };

  payload.metadata.policy_binding = {
    binding_version: '1',
    effective_policy_hash_b64u: policyHash,
  };
  payload.metadata.runner_measurement = {
    binding_version: '1',
    hash_algorithm: 'SHA-256',
    manifest_hash_b64u: manifestHash,
    manifest,
  };
  payload.metadata.runner_attestation_receipt = {
    envelope_version: '1',
    envelope_type: 'runner_attestation_receipt',
    payload_hash_b64u: sha256B64uJson(receiptPayload),
    hash_algorithm: 'SHA-256',
    signature_b64u: 'runner_attestation_signature_123456',
    algorithm: 'Ed25519',
    signer_did: payload.agent_did ?? 'did:key:zAgent',
    issued_at: '2026-03-20T19:16:57.701Z',
    payload: receiptPayload,
  };

  return bundle;
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
    expect(report.reviewer_signoff.present).toBe(true);
    expect(report.reviewer_signoff.receipt_count).toBe(1);
    expect(report.reviewer_signoff.structured_receipt_count).toBe(1);
    expect(report.reviewer_signoff.decision_counts).toEqual({
      approve: 1,
      reject: 0,
      needs_changes: 0,
    });
    expect(report.reviewer_signoff.target_counts).toEqual({
      run: 1,
      export_pack: 0,
    });
    expect(report.reviewer_signoff.dispute_present).toBe(false);
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
    expect(report.privacy_posture.runner_attestation.posture).toBe('non_attested');
    expect(report.privacy_posture.runner_attestation.reason_code).toBe(
      'ATTESTED_TIER_NOT_GRANTED_NO_RUNNER_ATTESTATION',
    );
  });

  it('surfaces attested posture only when attested tier is claimed and runner evidence is structurally bound', () => {
    const report = buildProofReport({
      inputPath: '/tmp/proof_bundle.json',
      bundle: makeAttestedBundle(),
      runSummary: {
        status: 'PASS',
        tier: 'attested',
        trust_tier: 'attested',
      },
    });

    expect(report.harness.tier).toBe('attested');
    expect(report.harness.trust_tier).toBe('attested');
    expect(report.privacy_posture.runner_attestation.posture).toBe('attested');
    expect(report.privacy_posture.runner_attestation.reason_code).toBe('ATTESTED_TIER_GRANTED');
    expect(report.privacy_posture.runner_attestation.evidence.runner_measurement_present).toBe(true);
    expect(report.privacy_posture.runner_attestation.evidence.runner_attestation_receipt_present).toBe(true);
    expect(report.privacy_posture.runner_attestation.evidence.binding_consistent).toBe(true);
    expect(report.privacy_posture.proven_claims).toContain(
      'Run summary claims attested tier and bundle metadata carries runner measurement + runner attestation receipt evidence with matching run/event/policy/manifest bindings.',
    );
  });

  it('keeps posture non-attested when runner evidence exists but attested tier is not claimed', () => {
    const report = buildProofReport({
      inputPath: '/tmp/proof_bundle.json',
      bundle: makeAttestedBundle(),
      runSummary: {
        status: 'PASS',
        tier: 'gateway',
      },
    });

    expect(report.privacy_posture.runner_attestation.posture).toBe('non_attested');
    expect(report.privacy_posture.runner_attestation.reason_code).toBe(
      'ATTESTED_TIER_NOT_GRANTED_TRUST_CONSTRAINED',
    );
    expect(report.privacy_posture.not_proven_claims).toContain(
      'Cannot claim attested runner posture because run summary does not claim attested trust tier, even though runner attestation evidence is present.',
    );
  });

  it('treats malformed runner attestation evidence as invalid and renders it conservatively', () => {
    const bundle = makeAttestedBundle();
    const payload = bundle.payload as {
      metadata?: {
        runner_measurement?: {
          manifest?: Record<string, unknown>;
        };
      };
    };

    if (payload.metadata?.runner_measurement?.manifest) {
      delete payload.metadata.runner_measurement.manifest.proofed;
    }

    const report = buildProofReport({
      inputPath: '/tmp/proof_bundle.json',
      bundle,
      runSummary: {
        status: 'PASS',
        tier: 'attested',
        trust_tier: 'attested',
      },
    });

    expect(report.privacy_posture.overall_verdict).toBe('action');
    expect(report.privacy_posture.runner_attestation.posture).toBe('non_attested');
    expect(report.privacy_posture.runner_attestation.reason_code).toBe(
      'ATTESTED_TIER_NOT_GRANTED_INVALID_RUNNER_ATTESTATION',
    );
    expect(report.privacy_posture.runner_attestation.evidence.runner_measurement_present).toBe(true);
    expect(report.privacy_posture.runner_attestation.evidence.runner_measurement_structured).toBe(false);
    expect(report.privacy_posture.signal_buckets.reviewer_action_required).toContain(
      'Run summary claims attested posture, but runner attestation evidence is missing required structure/binding consistency.',
    );

    const text = renderProofReportText(report);
    expect(text).toContain('Runner measurement evidence : present but invalid');
    expect(text).toContain('Runner attestation receipt  : present');
  });

  it('surfaces policy/runner trust-root revocation as explicit attestation failure reasons', () => {
    const bundle = makeAttestedBundle();
    const payload = bundle.payload as {
      agent_did?: string;
      metadata?: {
        policy_binding?: {
          signed_policy_bundle_envelope?: {
            signer_did?: string;
            payload?: {
              metadata?: Record<string, unknown>;
            };
          };
        };
        runner_attestation_receipt?: {
          signer_did?: string;
          payload?: Record<string, unknown>;
          payload_hash_b64u?: string;
        };
      };
    };

    if (!payload.metadata) {
      payload.metadata = {};
    }
    if (!payload.metadata.policy_binding) {
      payload.metadata.policy_binding = {};
    }
    if (!payload.metadata.policy_binding.signed_policy_bundle_envelope) {
      payload.metadata.policy_binding.signed_policy_bundle_envelope = {
        signer_did: payload.agent_did ?? 'did:key:zAgent',
        payload: {},
      };
    }

    const policySignerDid =
      payload.metadata.policy_binding.signed_policy_bundle_envelope.signer_did ??
      'did:key:zAgent';
    const runnerSignerDid =
      payload.metadata?.runner_attestation_receipt?.signer_did ?? 'did:key:zAgent';

    const signedPolicyEnvelope = payload.metadata.policy_binding.signed_policy_bundle_envelope;
    if (signedPolicyEnvelope?.payload) {
      const policyMetadata = isRecord(signedPolicyEnvelope.payload.metadata)
        ? signedPolicyEnvelope.payload.metadata
        : {};
      policyMetadata.revoked_policy_issuer_keys = [
        {
          revocation_version: '1',
          revoked_signer_did: policySignerDid,
          effective_at: '2026-03-20T19:16:57.000Z',
          reason: 'Policy issuer trust root revoked',
        },
      ];
      signedPolicyEnvelope.payload.metadata = policyMetadata;
    }

    const runnerEnvelope = payload.metadata?.runner_attestation_receipt;
    if (runnerEnvelope?.payload) {
      runnerEnvelope.payload.revoked_runner_keys = [
        {
          revocation_version: '1',
          revoked_signer_did: runnerSignerDid,
          effective_at: '2026-03-20T19:16:57.000Z',
          reason: 'Runner signer trust root revoked',
        },
      ];
      runnerEnvelope.payload_hash_b64u = sha256B64uJson(runnerEnvelope.payload);
    }

    const report = buildProofReport({
      inputPath: '/tmp/proof_bundle.json',
      bundle,
      runSummary: {
        status: 'PASS',
        tier: 'attested',
        trust_tier: 'attested',
      },
    });

    expect(report.privacy_posture.runner_attestation.posture).toBe('non_attested');
    expect(report.privacy_posture.runner_attestation.reason_code).toBe(
      'ATTESTED_TIER_NOT_GRANTED_REVOKED_POLICY_ISSUER',
    );
    expect(report.privacy_posture.signal_buckets.reviewer_action_required.join(' ')).toContain(
      'Policy issuer signer DID',
    );
    expect(report.privacy_posture.not_proven_claims).toContain(
      'Cannot prove attested runner posture because the signed policy issuer trust-root key is revoked.',
    );
    expect(report.warnings).toContain(
      'Policy issuer trust-root key is revoked in signed policy metadata.',
    );
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

  it('summarizes reviewer signoff receipts and dispute references coherently', () => {
    const bundle = makeBundle();
    const payload = bundle.payload as {
      metadata?: {
        reviewer_signoff_receipts?: Array<{
          payload?: {
            decision?: string;
            binding?: Record<string, unknown>;
            dispute?: Record<string, unknown>;
          };
        }>;
      };
    };

    const first = payload.metadata?.reviewer_signoff_receipts?.[0]?.payload;
    if (first) {
      first.decision = 'reject';
      if (first.binding) {
        first.binding.target_kind = 'export_pack';
        first.binding.export_pack_root_hash_b64u = 'export_pack_root_hash_abcdef12';
      }
      first.dispute = {
        status: 'raised',
        notes: [
          {
            note_id: 'dn_1',
            note: 'Gateway receipt timestamp appears inconsistent with reviewer evidence.',
            evidence_refs: [
              {
                ref_id: 'ev_1',
                uri: 'https://example.invalid/review/ev_1',
              },
            ],
          },
        ],
      };
    }
    syncReviewerSignoffReceiptHashes(bundle);

    const report = buildProofReport({
      inputPath: '/tmp/proof_bundle.json',
      bundle,
      runSummary: {
        status: 'PASS',
        tier: 'gateway',
      },
    });

    expect(report.reviewer_signoff.decision_counts.reject).toBe(1);
    expect(report.reviewer_signoff.target_counts.export_pack).toBe(1);
    expect(report.reviewer_signoff.dispute_present).toBe(true);
    expect(report.reviewer_signoff.dispute_note_count).toBe(1);
    expect(report.reviewer_signoff.dispute_evidence_refs_count).toBe(1);
    expect(report.warnings).toContain(
      '1 reviewer signoff receipt recorded decision=reject.',
    );
    expect(report.warnings).toContain(
      'Reviewer dispute notes are present (1 notes, 1 evidence refs).',
    );
  });

  it('does not treat malformed reviewer signoff bindings as structured reviewer evidence', () => {
    const bundle = makeBundle();
    const payload = bundle.payload as {
      metadata?: {
        reviewer_signoff_receipts?: Array<{
          payload?: {
            decision?: string;
            binding?: Record<string, unknown>;
            dispute?: Record<string, unknown>;
          };
        }>;
      };
    };

    const first = payload.metadata?.reviewer_signoff_receipts?.[0]?.payload;
    if (first?.binding) {
      first.decision = 'reject';
      first.binding.target_kind = 'export_pack';
      delete first.binding.export_pack_root_hash_b64u;
      first.dispute = {
        status: 'raised',
        notes: [
          {
            note_id: 'dn_invalid_1',
            note: 'Export pack root hash was omitted.',
            evidence_refs: [
              {
                uri: 'https://example.invalid/review/ev_invalid_1',
              },
            ],
          },
        ],
      };
    }
    syncReviewerSignoffReceiptHashes(bundle);

    const report = buildProofReport({
      inputPath: '/tmp/proof_bundle.json',
      bundle,
      runSummary: {
        status: 'PASS',
        tier: 'gateway',
      },
    });

    expect(report.reviewer_signoff.receipt_count).toBe(1);
    expect(report.reviewer_signoff.structured_receipt_count).toBe(0);
    expect(report.reviewer_signoff.decision_counts).toEqual({
      approve: 0,
      reject: 0,
      needs_changes: 0,
    });
    expect(report.reviewer_signoff.target_counts).toEqual({
      run: 0,
      export_pack: 0,
    });
    expect(report.reviewer_signoff.dispute_present).toBe(false);
    expect(report.warnings).toContain(
      '1 reviewer signoff receipt failed local integrity or binding checks in the report summary.',
    );
    expect(report.warnings).not.toContain(
      '1 reviewer signoff receipt recorded decision=reject.',
    );
  });

  it('does not surface reviewer disputes from receipts with invalid reviewer signatures', () => {
    const bundle = makeBundle();
    const payload = bundle.payload as {
      metadata?: {
        reviewer_signoff_receipts?: Array<Record<string, unknown>>;
      };
    };

    const first = payload.metadata?.reviewer_signoff_receipts?.[0];
    if (first) {
      first.signature_b64u = 'a'.repeat(86);
    }

    const report = buildProofReport({
      inputPath: '/tmp/proof_bundle.json',
      bundle,
      runSummary: {
        status: 'PASS',
        tier: 'gateway',
      },
    });

    expect(report.reviewer_signoff.receipt_count).toBe(1);
    expect(report.reviewer_signoff.structured_receipt_count).toBe(0);
    expect(report.reviewer_signoff.dispute_present).toBe(false);
    expect(report.warnings).toContain(
      '1 reviewer signoff receipt failed local integrity or binding checks in the report summary.',
    );
  });

  it('marks reviewer signoff receipts as revoked when reviewer trust-root metadata revokes the signer', () => {
    const bundle = makeBundle();
    const payload = bundle.payload as {
      metadata?: {
        reviewer_signoff_receipts?: Array<Record<string, unknown>>;
      };
    };

    const first = payload.metadata?.reviewer_signoff_receipts?.[0];
    if (first && isRecord(first.payload)) {
      first.payload.revoked_reviewer_keys = [
        {
          revocation_version: '1',
          revoked_signer_did: REVIEWER_TEST_DID,
          effective_at: '2026-03-20T19:17:11.000Z',
          reason: 'Reviewer key revoked',
        },
      ];
    }
    syncReviewerSignoffReceiptHashes(bundle);

    const report = buildProofReport({
      inputPath: '/tmp/proof_bundle.json',
      bundle,
      runSummary: {
        status: 'PASS',
        tier: 'gateway',
      },
    });

    expect(report.reviewer_signoff.receipt_count).toBe(1);
    expect(report.reviewer_signoff.structured_receipt_count).toBe(0);
    expect(report.reviewer_signoff.revoked_receipt_count).toBe(1);
    expect(report.reviewer_signoff.revoked_reviewer_dids).toEqual([REVIEWER_TEST_DID]);
    expect(report.warnings).toContain(
      '1 reviewer signoff receipt was marked revoked by reviewer trust-root metadata.',
    );
    expect(report.review_buckets[3].items).toContain(
      '1 reviewer signoff receipt was marked revoked by reviewer trust-root metadata.',
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
    expect(html).toContain('Runner attestation posture');
    expect(html).toContain('Attested-tier reason code');
    expect(html).toContain('Reviewer signoff/dispute');
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
    expect(text).toContain('Runner attestation posture');
    expect(text).toContain('Attested-tier reason code');
    expect(text).toContain('Reviewer signoff receipts');
    expect(text).toContain('Reviewer decisions');
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

describe('runProveReport export pack', () => {
  it('writes a structured privacy/compliance export pack with manifest and claim boundaries', async () => {
    const tempDir = await mkdtemp(join(tmpdir(), 'clawsig-prove-export-pack-'));
    const bundlePath = join(tempDir, 'proof_bundle.json');
    const exportPackPath = join(tempDir, 'privacy-pack-a');
    const exportPackPathSecond = join(tempDir, 'privacy-pack-b');

    await writeFile(bundlePath, JSON.stringify(makeBundle(), null, 2) + '\n', 'utf-8');

    const stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    try {
      const report = await runProveReport({
        inputPath: bundlePath,
        exportPackPath,
        decrypt: false,
        json: false,
      });

      expect(report.export_pack_path).toBe(exportPackPath);

      await runProveReport({
        inputPath: bundlePath,
        exportPackPath: exportPackPathSecond,
        decrypt: false,
        json: false,
      });
    } finally {
      stdoutSpy.mockRestore();
    }

    try {
      const manifestRaw = await readFile(join(exportPackPath, 'manifest.json'), 'utf-8');
      const manifest = JSON.parse(manifestRaw) as {
        pack_type: string;
        generated_at: string;
        source: {
          bundle_path: string;
          verify_command: string;
        };
        entries: Array<{
          path: string;
          content_type: string;
          size_bytes: number;
          sha256_b64u: string;
        }>;
      };

      expect(manifest.pack_type).toBe('privacy_compliance_export_pack');
      expect(manifest.generated_at).toBe('2026-03-20T19:16:58.121Z');
      expect(manifest.source.bundle_path).toBe('proof-bundle/proof_bundle.json');
      expect(manifest.source.verify_command).toBe(
        'clawverify verify proof-bundle --input proof-bundle/proof_bundle.json',
      );
      expect(manifest.entries.map((entry) => entry.path)).toEqual(
        [...manifest.entries.map((entry) => entry.path)].sort((a, b) => a.localeCompare(b)),
      );
      expect(manifest.entries.map((entry) => entry.path)).toEqual(
        expect.arrayContaining([
          'README.md',
          'proof-bundle/proof_bundle.json',
          'privacy-evidence/egress_policy_receipt.json',
          'privacy-evidence/runtime_profile.json',
          'privacy-evidence/runtime_hygiene.json',
          'privacy-evidence/data_handling.json',
          'privacy-evidence/processor_policy.json',
          'privacy-evidence/reviewer_signoff_receipts.json',
          'reports/proof-report.html',
          'reports/proof-report.json',
          'reports/proof-report.txt',
          'reports/claims-boundary.md',
          'viewer/index.html',
        ]),
      );
      for (const entry of manifest.entries) {
        expect(entry.size_bytes).toBeGreaterThan(0);
        expect(entry.sha256_b64u).toMatch(/^[A-Za-z0-9_-]+$/);
      }

      const reportJsonRaw = await readFile(join(exportPackPath, 'reports/proof-report.json'), 'utf-8');
      expect(reportJsonRaw).toContain('"input_path": "proof-bundle/proof_bundle.json"');
      expect(reportJsonRaw).toContain(
        '"verify_command": "clawverify verify proof-bundle --input proof-bundle/proof_bundle.json"',
      );
      expect(reportJsonRaw).not.toContain('"export_pack_path"');
      expect(reportJsonRaw).not.toContain(bundlePath);

      const claimsBoundary = await readFile(join(exportPackPath, 'reports/claims-boundary.md'), 'utf-8');
      expect(claimsBoundary).toContain('## What This Pack Proves');
      expect(claimsBoundary).toContain('## What This Pack Does Not Prove');
      expect(claimsBoundary).toContain('Runner attestation posture:');
      expect(claimsBoundary).toContain(
        'Run canonical verification first: `clawverify verify proof-bundle --input proof-bundle/proof_bundle.json`.',
      );
      expect(claimsBoundary).toContain(
        'This report does not by itself prove legal or regulatory compliance.',
      );

      const reportText = await readFile(join(exportPackPath, 'reports/proof-report.txt'), 'utf-8');
      expect(reportText).not.toContain('Export pack      :');

      const reportHtml = await readFile(join(exportPackPath, 'reports/proof-report.html'), 'utf-8');
      expect(reportHtml).toContain('Privacy posture');
      expect(reportHtml).toContain('Runner attestation posture');
      expect(reportHtml).not.toContain(bundlePath);

      const viewerHtml = await readFile(join(exportPackPath, 'viewer/index.html'), 'utf-8');
      expect(viewerHtml).toContain('Export-pack viewer');
      expect(viewerHtml).toContain('Privacy posture');
      expect(viewerHtml).toContain('Runner attestation posture');
      expect(viewerHtml).toContain('Reviewer signoff receipts');
      expect(viewerHtml).toContain('../reports/proof-report.json');
      expect(viewerHtml).toContain('../proof-bundle/proof_bundle.json');
      expect(viewerHtml).not.toContain(bundlePath);

      const filesToMatch = [
        'README.md',
        'manifest.json',
        'proof-bundle/proof_bundle.json',
        'privacy-evidence/data_handling.json',
        'privacy-evidence/egress_policy_receipt.json',
        'privacy-evidence/processor_policy.json',
        'privacy-evidence/reviewer_signoff_receipts.json',
        'privacy-evidence/runtime_hygiene.json',
        'privacy-evidence/runtime_profile.json',
        'reports/claims-boundary.md',
        'reports/proof-report.html',
        'reports/proof-report.json',
        'reports/proof-report.txt',
        'viewer/index.html',
      ];
      for (const relativePath of filesToMatch) {
        const first = await readFile(join(exportPackPath, relativePath), 'utf-8');
        const second = await readFile(join(exportPackPathSecond, relativePath), 'utf-8');
        expect(first).toBe(second);
      }
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it('exports runner attestation evidence alongside the report when present', async () => {
    const tempDir = await mkdtemp(join(tmpdir(), 'clawsig-prove-export-pack-attested-'));
    const bundlePath = join(tempDir, 'proof_bundle.json');
    const exportPackPath = join(tempDir, 'privacy-pack');

    await writeFile(bundlePath, JSON.stringify(makeAttestedBundle(), null, 2) + '\n', 'utf-8');

    const stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    try {
      await runProveReport({
        inputPath: bundlePath,
        exportPackPath,
        decrypt: false,
        json: false,
      });

      const runnerMeasurement = await readFile(
        join(exportPackPath, 'privacy-evidence/runner_measurement.json'),
        'utf-8',
      );
      const runnerAttestationReceipt = await readFile(
        join(exportPackPath, 'privacy-evidence/runner_attestation_receipt.json'),
        'utf-8',
      );

      expect(runnerMeasurement).toContain('"manifest_hash_b64u"');
      expect(runnerAttestationReceipt).toContain('"envelope_type": "runner_attestation_receipt"');
    } finally {
      stdoutSpy.mockRestore();
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it('emits pack-local side-by-side comparison artifacts for reviewer deltas', async () => {
    const tempDir = await mkdtemp(join(tmpdir(), 'clawsig-prove-export-pack-compare-'));
    const baselineBundlePath = join(tempDir, 'baseline_bundle.json');
    const candidateBundlePath = join(tempDir, 'candidate_bundle.json');
    const baselineSummaryPath = join(tempDir, 'baseline_run_summary.json');
    const candidateSummaryPath = join(tempDir, 'candidate_run_summary.json');
    const baselinePackPath = join(tempDir, 'baseline-pack');
    const comparedPackPath = join(tempDir, 'compared-pack');

    await writeFile(baselineBundlePath, JSON.stringify(makeCleanBundle(), null, 2) + '\n', 'utf-8');
    await writeFile(candidateBundlePath, JSON.stringify(makeBundle(), null, 2) + '\n', 'utf-8');
    await writeFile(
      baselineSummaryPath,
      JSON.stringify({ status: 'PASS', tier: 'gateway', trust_tier: 'gateway' }, null, 2) + '\n',
      'utf-8',
    );
    await writeFile(
      candidateSummaryPath,
      JSON.stringify({ status: 'PASS', tier: 'attested', trust_tier: 'attested' }, null, 2) + '\n',
      'utf-8',
    );

    const stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    try {
      await runProveReport({
        inputPath: baselineBundlePath,
        runSummaryPath: baselineSummaryPath,
        exportPackPath: baselinePackPath,
        decrypt: false,
        json: false,
      });

      await runProveReport({
        inputPath: candidateBundlePath,
        runSummaryPath: candidateSummaryPath,
        exportPackPath: comparedPackPath,
        compareWithPath: baselinePackPath,
        decrypt: false,
        json: false,
      });

      const comparisonJsonRaw = await readFile(
        join(comparedPackPath, 'reports/run-comparison.json'),
        'utf-8',
      );
      const comparisonMarkdown = await readFile(
        join(comparedPackPath, 'reports/run-comparison.md'),
        'utf-8',
      );
      const viewerHtml = await readFile(join(comparedPackPath, 'viewer/index.html'), 'utf-8');
      const manifestRaw = await readFile(join(comparedPackPath, 'manifest.json'), 'utf-8');
      const manifest = JSON.parse(manifestRaw) as {
        entries: Array<{ path: string }>;
      };
      const comparison = JSON.parse(comparisonJsonRaw) as {
        generated_at: string;
        baseline_source: { type: string };
        deltas: {
          assurance: { rows: Array<{ label: string; baseline: unknown; candidate: unknown; changed: boolean }> };
          evidence: { rows: Array<{ label: string; baseline: unknown; candidate: unknown; changed: boolean }> };
          policy: { rows: Array<{ label: string; baseline: unknown; candidate: unknown; changed: boolean }> };
          processor: {
            blocked_attempts: { added: string[]; removed: string[] };
            used_processor_count_deltas: Array<{ key: string; baseline_count: number; candidate_count: number }>;
          };
          privacy: {
            rows: Array<{ label: string; changed: boolean }>;
            claim_deltas: { proven_claims: { added: string[]; removed: string[] } };
          };
        };
        reviewer_highlights: string[];
      };

      expect(comparison.baseline_source.type).toBe('export_pack');
      expect(comparison.generated_at).toBe('2026-03-20T19:16:58.121Z');
      expect(comparison.reviewer_highlights.join(' ')).toContain('Assurance tier changed');
      expect(comparison.deltas.assurance.rows).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            label: 'Harness tier',
            baseline: 'gateway',
            candidate: 'attested',
            changed: true,
          }),
        ]),
      );
      expect(comparison.deltas.evidence.rows).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            label: 'Blocked egress attempts',
            baseline: 0,
            candidate: 2,
            changed: true,
          }),
        ]),
      );
      expect(comparison.deltas.policy.rows).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            label: 'Processor denied routes',
            baseline: 0,
            candidate: 1,
            changed: true,
          }),
        ]),
      );
      expect(comparison.deltas.processor.blocked_attempts.added.length).toBeGreaterThan(0);
      expect(comparison.deltas.processor.used_processor_count_deltas).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            key: 'google / gemini-2.5-flash (eu, no-store)',
            baseline_count: 1,
            candidate_count: 3,
          }),
        ]),
      );
      expect(comparison.deltas.privacy.rows).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            label: 'Privacy verdict',
            changed: true,
          }),
        ]),
      );
      expect(comparison.deltas.privacy.claim_deltas.proven_claims.added.length).toBeGreaterThan(0);

      expect(comparisonMarkdown).toContain('# Side-by-side Run Comparison');
      expect(comparisonMarkdown).toContain('## Evidence Deltas');
      expect(comparisonMarkdown).toContain('## Privacy Deltas');
      expect(comparisonMarkdown).toContain('Blocked egress attempts');

      expect(viewerHtml).toContain('../reports/run-comparison.json');
      expect(viewerHtml).toContain('../reports/run-comparison.md');
      expect(viewerHtml).toContain('Side-by-side run comparison');

      expect(manifest.entries.map((entry) => entry.path)).toEqual(
        expect.arrayContaining([
          'reports/run-comparison.json',
          'reports/run-comparison.md',
        ]),
      );

      expect(comparisonJsonRaw).not.toContain(tempDir);
      expect(comparisonJsonRaw).not.toContain(candidateBundlePath);
      expect(comparisonJsonRaw).not.toContain(baselinePackPath);
      expect(comparisonMarkdown).not.toContain(tempDir);
      expect(comparisonMarkdown).not.toContain(candidateBundlePath);
      expect(comparisonMarkdown).not.toContain(baselinePackPath);
      expect(viewerHtml).not.toContain(tempDir);
      expect(viewerHtml).not.toContain(candidateBundlePath);
      expect(viewerHtml).not.toContain(baselinePackPath);
    } finally {
      stdoutSpy.mockRestore();
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it('summarizes evidence-only comparisons without a misleading no-delta fallback', async () => {
    const tempDir = await mkdtemp(join(tmpdir(), 'clawsig-prove-export-pack-evidence-compare-'));
    const baselineBundlePath = join(tempDir, 'baseline_bundle.json');
    const candidateBundlePath = join(tempDir, 'candidate_bundle.json');
    const baselinePackPath = join(tempDir, 'baseline-pack');
    const comparedPackPath = join(tempDir, 'compared-pack');
    const candidateBundle = JSON.parse(JSON.stringify(makeCleanBundle())) as Record<string, unknown>;
    const candidatePayload = candidateBundle.payload as { tool_receipts?: unknown[] };
    candidatePayload.tool_receipts = [{ tool_name: 'scanner', receipt_id: 'tool_1' }];

    await writeFile(baselineBundlePath, JSON.stringify(makeCleanBundle(), null, 2) + '\n', 'utf-8');
    await writeFile(candidateBundlePath, JSON.stringify(candidateBundle, null, 2) + '\n', 'utf-8');

    const stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    try {
      await runProveReport({
        inputPath: baselineBundlePath,
        exportPackPath: baselinePackPath,
        decrypt: false,
        json: false,
      });

      await runProveReport({
        inputPath: candidateBundlePath,
        exportPackPath: comparedPackPath,
        compareWithPath: baselinePackPath,
        decrypt: false,
        json: false,
      });

      const comparison = JSON.parse(
        await readFile(join(comparedPackPath, 'reports/run-comparison.json'), 'utf-8'),
      ) as {
        reviewer_highlights: string[];
        deltas: {
          evidence: { rows: Array<{ label: string; baseline: unknown; candidate: unknown; changed: boolean }> };
        };
      };

      expect(comparison.deltas.evidence.rows).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            label: 'Tool receipts',
            baseline: 0,
            candidate: 1,
            changed: true,
          }),
        ]),
      );
      expect(comparison.reviewer_highlights).toContain('Evidence delta summary: 1 evidence field changed.');
      expect(comparison.reviewer_highlights.join(' ')).not.toContain('No assurance, evidence, policy, processor, or privacy deltas were detected');
    } finally {
      stdoutSpy.mockRestore();
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it('fails closed when the export-pack directory is not empty', async () => {
    const tempDir = await mkdtemp(join(tmpdir(), 'clawsig-prove-export-pack-stale-'));
    const bundlePath = join(tempDir, 'proof_bundle.json');
    const exportPackPath = join(tempDir, 'privacy-pack');

    await writeFile(bundlePath, JSON.stringify(makeBundle(), null, 2) + '\n', 'utf-8');

    const stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    try {
      await runProveReport({
        inputPath: bundlePath,
        exportPackPath,
        decrypt: false,
        json: false,
      });

      await mkdir(join(exportPackPath, 'stale-dir'), { recursive: true });
      await writeFile(join(exportPackPath, 'stale.txt'), 'stale\n', 'utf-8');

      await expect(
        runProveReport({
          inputPath: bundlePath,
          exportPackPath,
          decrypt: false,
          json: false,
        }),
      ).rejects.toThrow(/must be empty to avoid stale artifacts/);
    } finally {
      stdoutSpy.mockRestore();
      await rm(tempDir, { recursive: true, force: true });
    }
  });
});
