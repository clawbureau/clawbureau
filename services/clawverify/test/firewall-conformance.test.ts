import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, describe, expect, it } from 'vitest';

import { base64UrlEncode, computeHash } from '../src/crypto';
import { computeExpectedTeeNonceBinding } from '../src/verify-execution-attestation';
import { verifyProofBundle as verifyProofBundleService } from '../src/verify-proof-bundle';

const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

type FixtureExpected = {
  status: 'VALID' | 'INVALID';
  proof_tier?: string;
  error_code?: string;
  model_identity_tier?: string;
  risk_flags?: string[];
};

type FixtureCase = {
  id: string;
  scenario:
    | 'valid_self'
    | 'valid_witnessed_web'
    | 'valid_witnessed_web_quorum_pass'
    | 'valid_witnessed_web_quorum_fail_warn'
    | 'valid_witnessed_web_transparency_pass'
    | 'valid_gateway'
    | 'valid_gateway_coverage'
    | 'valid_causal_linkage'
    | 'valid_cldd_discrepancy_warn'
    | 'valid_sandbox_tee'
    | 'valid_vir_uncorroborated_high_claim'
    | 'valid_vir_corroborated_high_claim'
    | 'invalid_coverage_chain_root_enforce'
    | 'invalid_cldd_discrepancy_enforce'
    | 'invalid_witnessed_web_quorum_fail_enforce'
    | 'invalid_witnessed_web_split_view_enforce'
    | 'invalid_witnessed_web_transparency_enforce_missing'
    | 'invalid_vir_merkle_mismatch'
    | 'invalid_vir_conflict_unreported'
    | 'invalid_vir_precedence_violation'
    | 'invalid_vir_event_contradiction'
    | 'invalid_causal_dangling'
    | 'invalid_causal_cycle'
    | 'invalid_causal_phase'
    | 'invalid_causal_confidence'
    | 'valid_causal_binding_snake_only'
    | 'valid_causal_binding_camel_only'
    | 'invalid_causal_binding_field_conflict'
    | 'invalid_causal_binding_normalization_failed'
    | 'invalid_causal_unicode_confusable_dangling'
    | 'valid_causal_confidence_authoritative'
    | 'valid_causal_confidence_inferred'
    | 'valid_causal_confidence_unattributed'
    | 'invalid_causal_confidence_overclaim'
    | 'invalid_causal_receipt_replay_detected'
    | 'invalid_causal_span_reuse_conflict'
    | 'valid_causal_no_replay_no_conflict'
    | 'valid_causal_connected'
    | 'invalid_causal_graph_disconnected'
    | 'invalid_causal_side_effect_orphaned'
    | 'invalid_causal_human_approval_orphaned'
    | 'valid_causal_clock_monotonic'
    | 'invalid_causal_clock_parent_after_child'
    | 'invalid_causal_phase_transition'
    | 'invalid_causal_clock_envelope_regression'
    | 'invalid_tee_nonce_binding_mismatch'
    | 'invalid_tee_revoked';
  expected: FixtureExpected;
};

const verifierImplPromise: Promise<typeof verifyProofBundleService> = (async () => {
  const mode = process.env.CLAWVERIFY_FIREWALL_VERIFIER_IMPL?.trim() || 'service';
  if (mode !== 'core') {
    return verifyProofBundleService;
  }

  const coreDistPath = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    '../../../packages/clawverify-core/dist/index.js'
  );

  const coreModule = (await import(coreDistPath)) as {
    verifyProofBundle?: typeof verifyProofBundleService;
  };

  if (typeof coreModule.verifyProofBundle !== 'function') {
    throw new Error(
      `CLAWVERIFY_FIREWALL_VERIFIER_IMPL=core requires built core dist at ${coreDistPath}`
    );
  }

  return coreModule.verifyProofBundle;
})();

function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';

  const digits: number[] = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      const x = digits[i] * 256 + carry;
      digits[i] = x % 58;
      carry = Math.floor(x / 58);
    }
    while (carry) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }

  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
    digits.push(0);
  }

  return digits
    .reverse()
    .map((d) => BASE58_ALPHABET[d])
    .join('');
}

async function makeDidKeyEd25519(): Promise<{ did: string; privateKey: CryptoKey }> {
  const keypair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);

  const publicKeyBytes = new Uint8Array(
    await crypto.subtle.exportKey('raw', keypair.publicKey)
  );

  const prefixed = new Uint8Array(2 + publicKeyBytes.length);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(publicKeyBytes, 2);

  return {
    did: `did:key:z${base58Encode(prefixed)}`,
    privateKey: keypair.privateKey,
  };
}

async function signEnvelope<T extends Record<string, unknown>>(args: {
  payload: T;
  envelopeType: string;
  signerDid: string;
  privateKey: CryptoKey;
  issuedAt: string;
}) {
  const payloadHash = await computeHash(args.payload, 'SHA-256');
  const signature = new Uint8Array(
    await crypto.subtle.sign('Ed25519', args.privateKey, new TextEncoder().encode(payloadHash))
  );

  return {
    envelope_version: '1' as const,
    envelope_type: args.envelopeType,
    payload: args.payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256' as const,
    signature_b64u: base64UrlEncode(signature),
    algorithm: 'Ed25519' as const,
    signer_did: args.signerDid,
    issued_at: args.issuedAt,
  };
}

async function sha256Utf8B64u(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return base64UrlEncode(new Uint8Array(digest));
}

function stringifyLeafValue(type: string, value: unknown): string {
  if (type === 'string') return String(value);
  if (type === 'number') return `${value}`;
  if (type === 'boolean') return value ? 'true' : 'false';
  return 'null';
}

async function makeBaseBundleParts(agentDid: string, runId: string) {
  const eventPayloadHash = await computeHash({ type: 'llm_call' }, 'SHA-256');
  const eventHeader = {
    event_id: `evt_${runId}`,
    run_id: runId,
    event_type: 'llm_call',
    timestamp: '2026-02-17T00:00:00Z',
    payload_hash_b64u: eventPayloadHash,
    prev_hash_b64u: null as string | null,
  };

  const eventHash = await computeHash(eventHeader, 'SHA-256');

  const bundlePayload: Record<string, unknown> = {
    bundle_version: '1',
    bundle_id: `bundle_${runId}`,
    agent_did: agentDid,
    event_chain: [
      {
        ...eventHeader,
        event_hash_b64u: eventHash,
      },
    ],
  };

  return { eventHash, bundlePayload };
}

async function makeVirV2Envelope(args: {
  agentDid: string;
  agentKey: CryptoKey;
  runId: string;
  eventHash: string;
  receiptId?: string;
  source?: 'tls_decrypt' | 'gateway' | 'interpose' | 'preload' | 'sni';
  modelClaimed?: string;
  modelObserved?: string;
  evidenceConflicts?: unknown[];
  tamperLeafValue?: boolean;
}) {
  const modelClaimed = args.modelClaimed ?? 'gpt-4';
  const modelObserved = args.modelObserved ?? 'gpt-4';

  const disclosedLeaves: Record<
    string,
    { type: 'string' | 'number' | 'boolean' | 'null'; value: unknown; salt_b64u: string }
  > = {
    model_claimed: {
      type: 'string',
      value: modelClaimed,
      salt_b64u: 'salt_model_claimed_firewall_001',
    },
    model_observed: {
      type: 'string',
      value: modelObserved,
      salt_b64u: 'salt_model_observed_firewall_001',
    },
    tokens_input: {
      type: 'number',
      value: 100,
      salt_b64u: 'salt_tokens_input_firewall_001',
    },
    tokens_output: {
      type: 'number',
      value: 200,
      salt_b64u: 'salt_tokens_output_firewall_001',
    },
  };

  const disclosedLeafHashes: string[] = [];
  for (const key of Object.keys(disclosedLeaves).sort((a, b) => a.localeCompare(b))) {
    const leaf = disclosedLeaves[key]!;
    const value = args.tamperLeafValue && key === 'tokens_input' ? 101 : leaf.value;
    disclosedLeafHashes.push(
      await sha256Utf8B64u(
        `vir_v2_leaf|${key}|${leaf.type}|${leaf.salt_b64u}|${stringifyLeafValue(leaf.type, value)}`
      )
    );
  }

  const merkleRoot = await sha256Utf8B64u(
    `vir_v2_root|${[...disclosedLeafHashes].sort((a, b) => a.localeCompare(b)).join('|')}`
  );

  const virPayload: Record<string, unknown> = {
    receipt_version: '2',
    receipt_id: args.receiptId ?? `vir_${args.runId}`,
    source: args.source ?? 'gateway',
    provider: 'openai',
    model: modelObserved,
    model_claimed: modelClaimed,
    model_observed: modelObserved,
    request_hash_b64u: 'req_hash_firewall_001',
    response_hash_b64u: 'res_hash_firewall_001',
    tokens_input: 100,
    tokens_output: 200,
    latency_ms: 250,
    agent_did: args.agentDid,
    timestamp: '2026-02-17T00:00:00Z',
    binding: {
      run_id: args.runId,
      event_hash_b64u: args.eventHash,
      nonce: 'nonce_firewall_001',
      subject_did: 'did:key:zSubjectFirewall001',
      scope_hash_b64u: 'scope_hash_firewall_001',
    },
    legal_binding: {
      nonce: 'nonce_firewall_001',
      subject_did: 'did:key:zSubjectFirewall001',
      scope_hash_b64u: 'scope_hash_firewall_001',
    },
    evidence_conflicts: args.evidenceConflicts,
    selective_disclosure: {
      disclosure_algorithm: 'vir_v2_typed_lexicographical',
      merkle_root_b64u: merkleRoot,
      redacted_leaf_hashes_b64u: [],
      disclosed_leaves: disclosedLeaves,
    },
  };

  return signEnvelope({
    payload: virPayload,
    envelopeType: 'vir_receipt',
    signerDid: args.agentDid,
    privateKey: args.agentKey,
    issuedAt: '2026-02-17T00:00:00Z',
  });
}

async function computeWebReceiptLeafHash(
  payload: Record<string, unknown>
): Promise<string> {
  const bindingRecord =
    typeof payload.binding === 'object' && payload.binding !== null
      ? (payload.binding as Record<string, unknown>)
      : null;

  return computeHash(
    {
      leaf_version: 'web_receipt_v1',
      receipt_version: payload.receipt_version,
      receipt_id: payload.receipt_id,
      witness_id: payload.witness_id,
      source: payload.source,
      request_hash_b64u: payload.request_hash_b64u,
      response_hash_b64u: payload.response_hash_b64u,
      session_hash_b64u: payload.session_hash_b64u ?? null,
      timestamp: payload.timestamp,
      binding: bindingRecord
        ? {
            run_id: bindingRecord.run_id ?? null,
            event_hash_b64u: bindingRecord.event_hash_b64u ?? null,
            nonce: bindingRecord.nonce ?? null,
            subject: bindingRecord.subject ?? bindingRecord.subject_did ?? null,
            scope: bindingRecord.scope ?? bindingRecord.scope_hash_b64u ?? null,
            job_id: bindingRecord.job_id ?? null,
            contract_id: bindingRecord.contract_id ?? null,
            jurisdiction: bindingRecord.jurisdiction ?? null,
            policy_hash: bindingRecord.policy_hash ?? null,
            token_scope_hash_b64u: bindingRecord.token_scope_hash_b64u ?? null,
          }
        : null,
    },
    'SHA-256'
  );
}

async function makeSingleLeafInclusionProof(args: {
  leafHashB64u: string;
  signerDid: string;
  signerKey: CryptoKey;
  corruptLeaf?: boolean;
}) {
  const leafHash = args.corruptLeaf ? `${args.leafHashB64u}x` : args.leafHashB64u;

  const sigBytes = new Uint8Array(
    await crypto.subtle.sign('Ed25519', args.signerKey, new TextEncoder().encode(leafHash))
  );

  return {
    proof_version: '1',
    log_id: 'clawlogs-firewall-web',
    tree_size: 1,
    leaf_hash_b64u: leafHash,
    root_hash_b64u: leafHash,
    audit_path: [],
    root_published_at: '2026-02-17T00:00:00Z',
    root_signature: {
      signer_did: args.signerDid,
      sig_b64u: base64UrlEncode(sigBytes),
    },
    metadata: {
      leaf_index: 0,
    },
  };
}

async function makeWebReceiptEnvelope(args: {
  runId: string;
  eventHash: string;
  witnessDid: string;
  witnessKey: CryptoKey;
  receiptId: string;
  responseHash: string;
  includeTransparencyProof?: boolean;
  corruptTransparencyProof?: boolean;
}) {
  const payload: Record<string, unknown> = {
    receipt_version: '1',
    receipt_id: args.receiptId,
    witness_id: `witness_${args.receiptId}`,
    source: 'chatgpt_web',
    request_hash_b64u: 'req_web_firewall_001',
    response_hash_b64u: args.responseHash,
    timestamp: '2026-02-17T00:00:00Z',
    binding: {
      run_id: args.runId,
      event_hash_b64u: args.eventHash,
    },
  };

  if (args.includeTransparencyProof) {
    const logSigner = await makeDidKeyEd25519();
    const leafHash = await computeWebReceiptLeafHash(payload);

    payload.transparency = {
      inclusion_proof: await makeSingleLeafInclusionProof({
        leafHashB64u: leafHash,
        signerDid: logSigner.did,
        signerKey: logSigner.privateKey,
        corruptLeaf: args.corruptTransparencyProof,
      }),
    };
  }

  return signEnvelope({
    payload,
    envelopeType: 'web_receipt',
    signerDid: args.witnessDid,
    privateKey: args.witnessKey,
    issuedAt: '2026-02-17T00:00:00Z',
  });
}

async function buildFixtureScenario(spec: FixtureCase) {
  const runId = `run_firewall_${spec.id.replace(/[^a-z0-9]+/gi, '_')}`;
  const agent = await makeDidKeyEd25519();
  const { eventHash, bundlePayload } = await makeBaseBundleParts(agent.did, runId);

  if (spec.scenario === 'valid_self') {
    const bundleEnvelope = await signEnvelope({
      payload: bundlePayload,
      envelopeType: 'proof_bundle',
      signerDid: agent.did,
      privateKey: agent.privateKey,
      issuedAt: '2026-02-17T00:00:01Z',
    });

    return { envelope: bundleEnvelope, options: {} };
  }

  if (
    spec.scenario === 'valid_witnessed_web' ||
    spec.scenario === 'valid_witnessed_web_quorum_pass' ||
    spec.scenario === 'valid_witnessed_web_quorum_fail_warn' ||
    spec.scenario === 'valid_witnessed_web_transparency_pass' ||
    spec.scenario === 'invalid_witnessed_web_quorum_fail_enforce' ||
    spec.scenario === 'invalid_witnessed_web_split_view_enforce' ||
    spec.scenario === 'invalid_witnessed_web_transparency_enforce_missing'
  ) {
    const witnessA = await makeDidKeyEd25519();
    const witnessB = await makeDidKeyEd25519();

    const webReceipts: unknown[] = [];

    if (spec.scenario === 'invalid_witnessed_web_split_view_enforce') {
      webReceipts.push(
        await makeWebReceiptEnvelope({
          runId,
          eventHash,
          witnessDid: witnessA.did,
          witnessKey: witnessA.privateKey,
          receiptId: `${runId}_a`,
          responseHash: 'res_web_firewall_split_a',
        })
      );
      webReceipts.push(
        await makeWebReceiptEnvelope({
          runId,
          eventHash,
          witnessDid: witnessB.did,
          witnessKey: witnessB.privateKey,
          receiptId: `${runId}_b`,
          responseHash: 'res_web_firewall_split_b',
        })
      );
    } else if (spec.scenario === 'valid_witnessed_web_quorum_pass') {
      webReceipts.push(
        await makeWebReceiptEnvelope({
          runId,
          eventHash,
          witnessDid: witnessA.did,
          witnessKey: witnessA.privateKey,
          receiptId: `${runId}_a`,
          responseHash: 'res_web_firewall_quorum_pass',
        })
      );
      webReceipts.push(
        await makeWebReceiptEnvelope({
          runId,
          eventHash,
          witnessDid: witnessB.did,
          witnessKey: witnessB.privateKey,
          receiptId: `${runId}_b`,
          responseHash: 'res_web_firewall_quorum_pass',
        })
      );
    } else if (spec.scenario === 'valid_witnessed_web_transparency_pass') {
      webReceipts.push(
        await makeWebReceiptEnvelope({
          runId,
          eventHash,
          witnessDid: witnessA.did,
          witnessKey: witnessA.privateKey,
          receiptId: `${runId}_a`,
          responseHash: 'res_web_firewall_transparency_pass',
          includeTransparencyProof: true,
        })
      );
    } else {
      webReceipts.push(
        await makeWebReceiptEnvelope({
          runId,
          eventHash,
          witnessDid: witnessA.did,
          witnessKey: witnessA.privateKey,
          receiptId: `${runId}_a`,
          responseHash: 'res_web_firewall_001',
        })
      );
    }

    const bundleEnvelope = await signEnvelope({
      payload: {
        ...bundlePayload,
        web_receipts: webReceipts,
      },
      envelopeType: 'proof_bundle',
      signerDid: agent.did,
      privateKey: agent.privateKey,
      issuedAt: '2026-02-17T00:00:01Z',
    });

    const options: Record<string, unknown> = {
      allowlistedWitnessSignerDids: [witnessA.did, witnessB.did],
    };

    if (
      spec.scenario === 'valid_witnessed_web_quorum_pass' ||
      spec.scenario === 'valid_witnessed_web_quorum_fail_warn' ||
      spec.scenario === 'invalid_witnessed_web_quorum_fail_enforce'
    ) {
      options.witnessed_web_quorum_m = 2;
      options.witnessed_web_quorum_n = 2;
      options.witnessed_web_policy_mode =
        spec.scenario === 'invalid_witnessed_web_quorum_fail_enforce'
          ? 'enforce'
          : 'warn';
    }

    if (spec.scenario === 'invalid_witnessed_web_split_view_enforce') {
      options.witnessed_web_policy_mode = 'enforce';
    }

    if (
      spec.scenario === 'valid_witnessed_web_transparency_pass' ||
      spec.scenario === 'invalid_witnessed_web_transparency_enforce_missing'
    ) {
      options.witnessed_web_transparency_mode = 'enforce';
    }

    return {
      envelope: bundleEnvelope,
      options,
    };
  }

  if (
    spec.scenario === 'valid_gateway' ||
    spec.scenario === 'valid_gateway_coverage' ||
    spec.scenario === 'valid_causal_linkage' ||
    spec.scenario === 'valid_cldd_discrepancy_warn' ||
    spec.scenario === 'invalid_causal_dangling' ||
    spec.scenario === 'invalid_causal_cycle' ||
    spec.scenario === 'invalid_causal_phase' ||
    spec.scenario === 'invalid_causal_confidence' ||
    spec.scenario === 'valid_causal_binding_snake_only' ||
    spec.scenario === 'valid_causal_binding_camel_only' ||
    spec.scenario === 'invalid_causal_binding_field_conflict' ||
    spec.scenario === 'invalid_causal_binding_normalization_failed' ||
    spec.scenario === 'invalid_causal_unicode_confusable_dangling' ||
    spec.scenario === 'valid_causal_confidence_authoritative' ||
    spec.scenario === 'valid_causal_confidence_inferred' ||
    spec.scenario === 'valid_causal_confidence_unattributed' ||
    spec.scenario === 'invalid_causal_confidence_overclaim' ||
    spec.scenario === 'invalid_causal_receipt_replay_detected' ||
    spec.scenario === 'invalid_causal_span_reuse_conflict' ||
    spec.scenario === 'valid_causal_no_replay_no_conflict' ||
    spec.scenario === 'valid_causal_connected' ||
    spec.scenario === 'invalid_causal_graph_disconnected' ||
    spec.scenario === 'invalid_causal_side_effect_orphaned' ||
    spec.scenario === 'invalid_causal_human_approval_orphaned' ||
    spec.scenario === 'valid_causal_clock_monotonic' ||
    spec.scenario === 'invalid_causal_clock_parent_after_child' ||
    spec.scenario === 'invalid_causal_phase_transition' ||
    spec.scenario === 'invalid_causal_clock_envelope_regression' ||
    spec.scenario === 'invalid_coverage_chain_root_enforce' ||
    spec.scenario === 'invalid_cldd_discrepancy_enforce'
  ) {
    const gateway = await makeDidKeyEd25519();

    const makeGatewayReceiptEnvelope = async (args: {
      receiptSuffix: string;
      receiptId?: string;
      responseHashB64u?: string;
      bindingExtras?: Record<string, unknown>;
      timestamp?: string;
      issuedAt?: string;
    }) => {
      const receiptPayload: Record<string, unknown> = {
        receipt_version: '1',
        receipt_id: args.receiptId ?? `rcpt_${runId}_${args.receiptSuffix}`,
        gateway_id: 'gw_firewall_001',
        provider: 'openai',
        model: 'gpt-4',
        request_hash_b64u: 'req_gateway_firewall_001',
        response_hash_b64u:
          args.responseHashB64u ?? 'res_gateway_firewall_001',
        tokens_input: 10,
        tokens_output: 20,
        latency_ms: 50,
        timestamp: args.timestamp ?? '2026-02-17T00:00:00Z',
        binding: {
          run_id: runId,
          event_hash_b64u: eventHash,
          ...(args.bindingExtras ?? {}),
        },
      };

      return signEnvelope({
        payload: receiptPayload,
        envelopeType: 'gateway_receipt',
        signerDid: gateway.did,
        privateKey: gateway.privateKey,
        issuedAt: args.issuedAt ?? '2026-02-17T00:00:00Z',
      });
    };

    let receiptEnvelopes: unknown[] = [
      await makeGatewayReceiptEnvelope({ receiptSuffix: 'base' }),
    ];

    if (spec.scenario === 'valid_causal_linkage') {
      receiptEnvelopes = [
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'root',
          bindingExtras: {
            span_id: 'span_root_firewall_001',
            phase: 'execution',
            attribution_confidence: 1,
          },
        }),
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'child',
          bindingExtras: {
            span_id: 'span_child_firewall_001',
            parent_span_id: 'span_root_firewall_001',
            tool_span_id: 'span_root_firewall_001',
            phase: 'execution',
            attribution_confidence: 0.5,
          },
        }),
      ];
    } else if (spec.scenario === 'invalid_causal_dangling') {
      receiptEnvelopes = [
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'dangling',
          bindingExtras: {
            span_id: 'span_child_firewall_002',
            parent_span_id: 'span_missing_firewall_002',
            tool_span_id: 'span_missing_firewall_002',
            phase: 'execution',
            attribution_confidence: 1,
          },
        }),
      ];
    } else if (spec.scenario === 'invalid_causal_cycle') {
      receiptEnvelopes = [
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'cycle_a',
          bindingExtras: {
            span_id: 'span_cycle_a_firewall_003',
            parent_span_id: 'span_cycle_b_firewall_003',
            phase: 'execution',
            attribution_confidence: 1,
          },
        }),
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'cycle_b',
          bindingExtras: {
            span_id: 'span_cycle_b_firewall_003',
            parent_span_id: 'span_cycle_a_firewall_003',
            phase: 'execution',
            attribution_confidence: 1,
          },
        }),
      ];
    } else if (spec.scenario === 'invalid_causal_phase') {
      receiptEnvelopes = [
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'phase',
          bindingExtras: {
            span_id: 'span_phase_firewall_004',
            phase: 'invalid-phase',
            attribution_confidence: 0.5,
          },
        }),
      ];
    } else if (spec.scenario === 'invalid_causal_confidence') {
      receiptEnvelopes = [
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'confidence',
          bindingExtras: {
            span_id: 'span_confidence_firewall_005',
            phase: 'execution',
            attribution_confidence: 1.5,
          },
        }),
      ];
    } else if (spec.scenario === 'valid_causal_binding_snake_only') {
      receiptEnvelopes = [
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'snake_only',
          bindingExtras: {
            span_id: 'span_snake_only_firewall_006',
            phase: 'execution',
            attribution_confidence: 0.5,
          },
        }),
      ];
    } else if (spec.scenario === 'valid_causal_binding_camel_only') {
      receiptEnvelopes = [
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'camel_only',
          bindingExtras: {
            spanId: 'span_camel_only_firewall_007',
            phase: 'execution',
            attributionConfidence: 0.5,
          },
        }),
      ];
    } else if (spec.scenario === 'invalid_causal_binding_field_conflict') {
      receiptEnvelopes = [
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'field_conflict',
          bindingExtras: {
            span_id: 'span_conflict_snake_firewall_008',
            spanId: 'span_conflict_camel_firewall_008',
            phase: 'execution',
            attribution_confidence: 0.5,
          },
        }),
      ];
    } else if (spec.scenario === 'invalid_causal_binding_normalization_failed') {
      receiptEnvelopes = [
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'normalization_failed',
          bindingExtras: {
            spanId: '   ',
            phase: 'execution',
            attributionConfidence: 0.5,
          },
        }),
      ];
    } else if (spec.scenario === 'invalid_causal_unicode_confusable_dangling') {
      receiptEnvelopes = [
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'unicode_confusable_root',
          bindingExtras: {
            span_id: 'span_root_firewall_\u200B019',
            phase: 'execution',
            attribution_confidence: 0.5,
          },
        }),
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'unicode_confusable_child',
          bindingExtras: {
            span_id: 'span_child_firewall_019',
            parent_span_id: 'span_root_firewall_019',
            phase: 'execution',
            attribution_confidence: 0.5,
          },
        }),
      ];
    } else if (spec.scenario === 'valid_causal_confidence_authoritative') {
      receiptEnvelopes = [
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'confidence_auth_root',
          bindingExtras: {
            span_id: 'span_confidence_auth_root_firewall_009',
            phase: 'execution',
            attribution_confidence: 1.0,
          },
        }),
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'confidence_auth_child',
          bindingExtras: {
            span_id: 'span_confidence_auth_child_firewall_009',
            parent_span_id: 'span_confidence_auth_root_firewall_009',
            phase: 'execution',
            attribution_confidence: 1.0,
          },
        }),
      ];
    } else if (spec.scenario === 'valid_causal_confidence_inferred') {
      receiptEnvelopes = [
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'confidence_inferred',
          bindingExtras: {
            span_id: 'span_confidence_inferred_firewall_010',
            phase: 'execution',
            attribution_confidence: 0.5,
          },
        }),
      ];
    } else if (spec.scenario === 'valid_causal_confidence_unattributed') {
      receiptEnvelopes = [
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'confidence_unattributed',
          bindingExtras: {
            phase: 'execution',
            attribution_confidence: 0.0,
          },
        }),
      ];
    } else if (spec.scenario === 'invalid_causal_confidence_overclaim') {
      receiptEnvelopes = [
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'confidence_overclaim',
          bindingExtras: {
            span_id: 'span_confidence_overclaim_firewall_011',
            phase: 'execution',
            attribution_confidence: 1.0,
          },
        }),
      ];
    } else if (spec.scenario === 'invalid_causal_receipt_replay_detected') {
      const replayReceiptId = `rcpt_${runId}_replay_target`;
      receiptEnvelopes = [
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'replay_a',
          receiptId: replayReceiptId,
          responseHashB64u: 'res_gateway_replay_firewall_011a',
          bindingExtras: {
            span_id: 'span_replay_firewall_012',
            phase: 'execution',
            attribution_confidence: 0.5,
          },
        }),
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'replay_b',
          receiptId: replayReceiptId,
          responseHashB64u: 'res_gateway_replay_firewall_011b',
          bindingExtras: {
            span_id: 'span_replay_firewall_012',
            phase: 'execution',
            attribution_confidence: 0.5,
          },
        }),
      ];
    } else if (spec.scenario === 'invalid_causal_span_reuse_conflict') {
      receiptEnvelopes = [
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'span_reuse_root',
          bindingExtras: {
            span_id: 'span_reuse_conflict_firewall_013',
            phase: 'execution',
            attribution_confidence: 0.5,
          },
        }),
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'span_reuse_conflict',
          bindingExtras: {
            span_id: 'span_reuse_conflict_firewall_013',
            parent_span_id: 'span_parent_conflict_firewall_013',
            phase: 'planning',
            attribution_confidence: 0.5,
          },
        }),
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'span_parent_anchor',
          bindingExtras: {
            span_id: 'span_parent_conflict_firewall_013',
            phase: 'execution',
            attribution_confidence: 0.5,
          },
        }),
      ];
    } else if (spec.scenario === 'valid_causal_no_replay_no_conflict') {
      receiptEnvelopes = [
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'no_replay_root',
          bindingExtras: {
            span_id: 'span_no_replay_root_firewall_014',
            phase: 'execution',
            attribution_confidence: 1.0,
          },
        }),
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'no_replay_child',
          bindingExtras: {
            span_id: 'span_no_replay_child_firewall_014',
            parent_span_id: 'span_no_replay_root_firewall_014',
            phase: 'execution',
            attribution_confidence: 1.0,
          },
        }),
      ];
    } else if (spec.scenario === 'valid_causal_connected') {
      receiptEnvelopes = [
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'connected_root',
          bindingExtras: {
            span_id: 'span_connected_root_firewall_015',
            phase: 'execution',
            attribution_confidence: 1.0,
          },
        }),
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'connected_child',
          bindingExtras: {
            span_id: 'span_connected_child_firewall_015',
            parent_span_id: 'span_connected_root_firewall_015',
            phase: 'execution',
            attribution_confidence: 1.0,
          },
        }),
      ];
    } else if (spec.scenario === 'invalid_causal_graph_disconnected') {
      receiptEnvelopes = [
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'disc_root_a',
          bindingExtras: {
            span_id: 'span_disconnected_root_a_firewall_016',
            phase: 'execution',
            attribution_confidence: 0.5,
          },
        }),
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'disc_root_b',
          bindingExtras: {
            span_id: 'span_disconnected_root_b_firewall_016',
            phase: 'execution',
            attribution_confidence: 0.5,
          },
        }),
      ];
    } else if (spec.scenario === 'invalid_causal_side_effect_orphaned') {
      receiptEnvelopes = [
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'side_effect_root',
          bindingExtras: {
            span_id: 'span_side_effect_root_firewall_017',
            phase: 'execution',
            attribution_confidence: 0.5,
          },
        }),
      ];
    } else if (spec.scenario === 'invalid_causal_human_approval_orphaned') {
      receiptEnvelopes = [
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'human_approval_root',
          bindingExtras: {
            span_id: 'span_human_approval_root_firewall_018',
            phase: 'execution',
            attribution_confidence: 0.5,
          },
        }),
      ];
    } else if (spec.scenario === 'valid_causal_clock_monotonic') {
      receiptEnvelopes = [
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'clock_root',
          timestamp: '2026-02-17T00:00:00.000Z',
          issuedAt: '2026-02-17T00:00:00.500Z',
          bindingExtras: {
            span_id: 'span_clock_root_firewall_020',
            phase: 'setup',
            attribution_confidence: 1.0,
          },
        }),
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'clock_child',
          timestamp: '2026-02-17T00:00:01.000Z',
          issuedAt: '2026-02-17T00:00:01.500Z',
          bindingExtras: {
            span_id: 'span_clock_child_firewall_020',
            parent_span_id: 'span_clock_root_firewall_020',
            phase: 'planning',
            attribution_confidence: 1.0,
          },
        }),
      ];
    } else if (spec.scenario === 'invalid_causal_clock_parent_after_child') {
      receiptEnvelopes = [
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'clock_parent_late',
          timestamp: '2026-02-17T00:00:03.000Z',
          issuedAt: '2026-02-17T00:00:03.500Z',
          bindingExtras: {
            span_id: 'span_clock_parent_late_firewall_021',
            phase: 'setup',
            attribution_confidence: 1.0,
          },
        }),
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'clock_child_early',
          timestamp: '2026-02-17T00:00:02.000Z',
          issuedAt: '2026-02-17T00:00:02.500Z',
          bindingExtras: {
            span_id: 'span_clock_child_early_firewall_021',
            parent_span_id: 'span_clock_parent_late_firewall_021',
            phase: 'planning',
            attribution_confidence: 1.0,
          },
        }),
      ];
    } else if (spec.scenario === 'invalid_causal_phase_transition') {
      receiptEnvelopes = [
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'phase_transition_parent',
          timestamp: '2026-02-17T00:00:00.000Z',
          issuedAt: '2026-02-17T00:00:00.500Z',
          bindingExtras: {
            span_id: 'span_phase_transition_parent_firewall_022',
            phase: 'teardown',
            attribution_confidence: 1.0,
          },
        }),
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'phase_transition_child',
          timestamp: '2026-02-17T00:00:01.000Z',
          issuedAt: '2026-02-17T00:00:01.500Z',
          bindingExtras: {
            span_id: 'span_phase_transition_child_firewall_022',
            parent_span_id: 'span_phase_transition_parent_firewall_022',
            phase: 'planning',
            attribution_confidence: 1.0,
          },
        }),
      ];
    } else if (spec.scenario === 'invalid_causal_clock_envelope_regression') {
      receiptEnvelopes = [
        await makeGatewayReceiptEnvelope({
          receiptSuffix: 'clock_envelope_regression',
          timestamp: '2026-02-17T00:00:05.000Z',
          issuedAt: '2026-02-17T00:00:04.000Z',
          bindingExtras: {
            span_id: 'span_clock_envelope_regression_firewall_023',
            phase: 'execution',
            attribution_confidence: 0.5,
          },
        }),
      ];
    }

    const bundlePayloadWithGateway: Record<string, unknown> = {
      ...bundlePayload,
      receipts: receiptEnvelopes,
    };

    const options: Record<string, unknown> = {
      allowlistedReceiptSignerDids: [gateway.did],
    };

    if (spec.scenario === 'invalid_causal_side_effect_orphaned') {
      bundlePayloadWithGateway.side_effect_receipts = [
        {
          receipt_version: '1',
          receipt_id: `se_${runId}`,
          effect_class: 'external_api_write',
          hash_algorithm: 'SHA-256',
          agent_did: agent.did,
          timestamp: '2026-02-17T00:00:00Z',
          binding: {
            tool_span_id: 'span_missing_side_effect_firewall_017',
          },
        },
      ];
    }

    if (spec.scenario === 'invalid_causal_human_approval_orphaned') {
      bundlePayloadWithGateway.human_approval_receipts = [
        {
          receipt_version: '1',
          receipt_id: `ha_${runId}`,
          approval_type: 'explicit_approve',
          agent_did: agent.did,
          timestamp: '2026-02-17T00:00:00Z',
          binding: {
            parent_span_id: 'span_missing_human_approval_firewall_018',
          },
        },
      ];
    }

    if (
      spec.scenario === 'valid_gateway_coverage' ||
      spec.scenario === 'invalid_coverage_chain_root_enforce' ||
      spec.scenario === 'valid_cldd_discrepancy_warn' ||
      spec.scenario === 'invalid_cldd_discrepancy_enforce'
    ) {
      const sentinel = await makeDidKeyEd25519();
      const coveragePayload: Record<string, unknown> = {
        attestation_version: '1',
        attestation_id: `cov_${runId}`,
        run_id: runId,
        agent_did: agent.did,
        sentinel_did: sentinel.did,
        issued_at: '2026-02-17T00:00:00Z',
        binding: {
          event_chain_root_hash_b64u:
            spec.scenario === 'invalid_coverage_chain_root_enforce'
              ? 'chain_root_mismatch_firewall_001'
              : eventHash,
        },
        metrics: {
          lineage: {
            root_pid: 1000,
            processes_tracked: 10,
            unmonitored_spawns: 0,
            escapes_suspected: false,
          },
          egress: {
            connections_total: 2,
            unmediated_connections: 0,
          },
          liveness: {
            status: 'continuous',
            uptime_ms: 12_000,
            heartbeat_interval_ms: 500,
            max_gap_ms: 200,
          },
        },
      };

      const coverageEnvelope = await signEnvelope({
        payload: coveragePayload,
        envelopeType: 'coverage_attestation',
        signerDid: sentinel.did,
        privateKey: sentinel.privateKey,
        issuedAt: '2026-02-17T00:00:00Z',
      });

      bundlePayloadWithGateway.coverage_attestations = [coverageEnvelope];
      options.allowlistedCoverageAttestationSignerDids = [sentinel.did];

      if (spec.scenario === 'valid_cldd_discrepancy_warn' || spec.scenario === 'invalid_cldd_discrepancy_enforce') {
        bundlePayloadWithGateway.metadata = {
          sentinels: {
            interpose_active: true,
            interpose_state: {
              cldd: {
                unmediated_connections: 2,
                unmonitored_spawns: 1,
                escapes_suspected: true,
              },
            },
          },
        };
      }

      options.coverage_enforcement_phase =
        spec.scenario === 'valid_cldd_discrepancy_warn'
          ? 'warn'
          : 'enforce';
    }

    const bundleEnvelope = await signEnvelope({
      payload: bundlePayloadWithGateway,
      envelopeType: 'proof_bundle',
      signerDid: agent.did,
      privateKey: agent.privateKey,
      issuedAt: '2026-02-17T00:00:01Z',
    });

    return {
      envelope: bundleEnvelope,
      options,
    };
  }

  if (
    spec.scenario === 'valid_sandbox_tee' ||
    spec.scenario === 'invalid_tee_nonce_binding_mismatch' ||
    spec.scenario === 'invalid_tee_revoked'
  ) {
    const attester = await makeDidKeyEd25519();
    const tcbVersion = spec.scenario === 'invalid_tee_revoked' ? 'tdx-firewall-revoked' : 'tdx-firewall-good';

    const bundlePayloadHash = await computeHash(bundlePayload, 'SHA-256');
    const expectedNonceBinding = await computeExpectedTeeNonceBinding({
      agentDid: agent.did,
      runId,
      proofBundleHashB64u: bundlePayloadHash,
    });
    const nonceBinding =
      spec.scenario === 'invalid_tee_nonce_binding_mismatch'
        ? 'tee_nonce_binding_mismatch_firewall_001'
        : expectedNonceBinding;

    const executionAttestationPayload: Record<string, unknown> = {
      attestation_version: '1',
      attestation_id: `ea_${runId}`,
      execution_type: 'tee_execution',
      agent_did: agent.did,
      attester_did: attester.did,
      run_id: runId,
      proof_bundle_hash_b64u: bundlePayloadHash,
      runtime_metadata: {
        tee: {
          attestation_type: 'tdx_quote',
          root_id: 'intel-tdx-root-firewall',
          tcb_version: tcbVersion,
          nonce_binding_b64u: nonceBinding,
          evidence_ref: {
            resource_type: 'tee_quote',
            resource_hash_b64u: 'tee_quote_hash_firewall_001',
          },
          measurements: {
            measurement_hash_b64u: 'tee_measurement_hash_firewall_001',
            model_weights_digest_b64u: 'tee_model_weights_hash_firewall_001',
          },
        },
      },
      issued_at: '2026-02-17T00:00:00Z',
    };

    const executionEnvelope = await signEnvelope({
      payload: executionAttestationPayload,
      envelopeType: 'execution_attestation',
      signerDid: attester.did,
      privateKey: attester.privateKey,
      issuedAt: '2026-02-17T00:00:00Z',
    });

    const bundleEnvelope = await signEnvelope({
      payload: bundlePayload,
      envelopeType: 'proof_bundle',
      signerDid: agent.did,
      privateKey: agent.privateKey,
      issuedAt: '2026-02-17T00:00:01Z',
    });

    return {
      envelope: bundleEnvelope,
      options: {
        execution_attestations: [executionEnvelope],
        allowlistedExecutionAttestationSignerDids: [attester.did],
        teeRootAllowlist: ['intel-tdx-root-firewall'],
        teeTcbAllowlist: [tcbVersion],
        teeRootRevoked: [],
        teeTcbRevoked: spec.scenario === 'invalid_tee_revoked' ? [tcbVersion] : [],
      },
    };
  }

  const virEnvelope = await makeVirV2Envelope({
    agentDid: agent.did,
    agentKey: agent.privateKey,
    runId,
    eventHash,
    ...(spec.scenario === 'valid_vir_uncorroborated_high_claim'
      ? { source: 'gateway' as const }
      : {}),
    ...(spec.scenario === 'valid_vir_corroborated_high_claim'
      ? { source: 'gateway' as const }
      : {}),
    ...(spec.scenario === 'invalid_vir_merkle_mismatch'
      ? { tamperLeafValue: true }
      : {}),
    ...(spec.scenario === 'invalid_vir_conflict_unreported'
      ? {
          modelClaimed: 'gpt-4',
          modelObserved: 'gpt-3.5',
          evidenceConflicts: [],
        }
      : {}),
    ...(spec.scenario === 'invalid_vir_precedence_violation'
      ? {
          evidenceConflicts: [
            {
              field: 'model',
              authoritative_source: 'interpose',
              divergent_source: 'tls_decrypt',
              authoritative_value: 'gpt-4',
              divergent_value: 'gpt-3.5',
            },
          ],
        }
      : {}),
  });

  if (spec.scenario === 'invalid_vir_event_contradiction') {
    const secondVirEnvelope = await makeVirV2Envelope({
      agentDid: agent.did,
      agentKey: agent.privateKey,
      runId,
      eventHash,
      receiptId: `vir_${runId}_second`,
      source: 'gateway',
    });

    const bundleEnvelope = await signEnvelope({
      payload: {
        ...bundlePayload,
        vir_receipts: [virEnvelope, secondVirEnvelope],
      },
      envelopeType: 'proof_bundle',
      signerDid: agent.did,
      privateKey: agent.privateKey,
      issuedAt: '2026-02-17T00:00:01Z',
    });

    return {
      envelope: bundleEnvelope,
      options: {},
    };
  }

  if (spec.scenario === 'valid_vir_corroborated_high_claim') {
    const gatewaySigner = await makeDidKeyEd25519();

    const receiptEnvelope = await signEnvelope({
      payload: {
        receipt_version: '1',
        receipt_id: `rcpt_${runId}`,
        gateway_id: 'gw_firewall_vir_001',
        provider: 'openai',
        model: 'gpt-4',
        request_hash_b64u: 'req_hash_firewall_001',
        response_hash_b64u: 'res_hash_firewall_001',
        tokens_input: 100,
        tokens_output: 200,
        latency_ms: 250,
        timestamp: '2026-02-17T00:00:00Z',
        binding: {
          run_id: runId,
          event_hash_b64u: eventHash,
        },
      },
      envelopeType: 'gateway_receipt',
      signerDid: gatewaySigner.did,
      privateKey: gatewaySigner.privateKey,
      issuedAt: '2026-02-17T00:00:00Z',
    });

    const bundleEnvelope = await signEnvelope({
      payload: {
        ...bundlePayload,
        vir_receipts: [virEnvelope],
        receipts: [receiptEnvelope],
      },
      envelopeType: 'proof_bundle',
      signerDid: agent.did,
      privateKey: agent.privateKey,
      issuedAt: '2026-02-17T00:00:01Z',
    });

    return {
      envelope: bundleEnvelope,
      options: {
        allowlistedReceiptSignerDids: [gatewaySigner.did],
      },
    };
  }

  const bundleEnvelope = await signEnvelope({
    payload: {
      ...bundlePayload,
      vir_receipts: [virEnvelope],
    },
    envelopeType: 'proof_bundle',
    signerDid: agent.did,
    privateKey: agent.privateKey,
    issuedAt: '2026-02-17T00:00:01Z',
  });

  return {
    envelope: bundleEnvelope,
    options: {},
  };
}

const fixtureSuite = process.env.CLAWVERIFY_FIREWALL_FIXTURE_SUITE?.trim() || 'clawverify-firewall';

const FIXTURE_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  `../../../packages/schema/fixtures/protocol-conformance/${fixtureSuite}`
);

const manifest = JSON.parse(
  fs.readFileSync(path.join(FIXTURE_DIR, 'manifest.v1.json'), 'utf8')
) as {
  manifest_version: string;
  suite: string;
  cases: string[];
};

const fixtures: FixtureCase[] = manifest.cases.map((name) =>
  JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, name), 'utf8'))
);

const summaryPath = process.env.CLAWVERIFY_FIREWALL_CONFORMANCE_SUMMARY_PATH?.trim();
const summaryRows: Array<{
  id: string;
  scenario: FixtureCase['scenario'];
  status: 'VALID' | 'INVALID';
  error_code: string;
  expected_status: 'VALID' | 'INVALID';
  expected_error_code: string;
}> = [];

afterAll(() => {
  if (!summaryPath) return;

  fs.mkdirSync(path.dirname(summaryPath), { recursive: true });
  fs.writeFileSync(
    summaryPath,
    `${JSON.stringify(
      {
        suite: manifest.suite,
        generated_at: new Date().toISOString(),
        fixtures: [...summaryRows].sort((a, b) => a.id.localeCompare(b.id)),
      },
      null,
      2
    )}\n`,
    'utf8'
  );
});

describe(`clawverify conformance fixtures (${manifest.suite})`, () => {
  it.each(fixtures)('validates fixture: $id', async (spec) => {
    const scenario = await buildFixtureScenario(spec);
    const verifyProofBundleImpl = await verifierImplPromise;
    const out = await verifyProofBundleImpl(scenario.envelope, scenario.options as any);

    summaryRows.push({
      id: spec.id,
      scenario: spec.scenario,
      status: out.result.status,
      error_code: out.error?.code ?? 'OK',
      expected_status: spec.expected.status,
      expected_error_code: spec.expected.error_code ?? 'OK',
    });

    expect(out.result.status).toBe(spec.expected.status);

    if (spec.expected.proof_tier) {
      expect(out.result.proof_tier).toBe(spec.expected.proof_tier);
    }

    if (spec.expected.error_code) {
      expect(out.error?.code).toBe(spec.expected.error_code);
    }

    if (spec.expected.model_identity_tier) {
      expect(out.result.model_identity_tier).toBe(spec.expected.model_identity_tier);
    }

    if (spec.expected.risk_flags && spec.expected.risk_flags.length > 0) {
      const outRiskFlags = out.result.risk_flags ?? [];
      for (const riskFlag of spec.expected.risk_flags) {
        expect(outRiskFlags).toContain(riskFlag);
      }
    }
  });
});
