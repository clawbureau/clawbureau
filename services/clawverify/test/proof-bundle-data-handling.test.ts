import { describe, expect, it } from 'vitest';

import { base64UrlEncode, computeHash } from '../src/crypto';
import { verifyProofBundle } from '../src/verify-proof-bundle';
import {
  computeSignedPolicyBundlePayloadHashB64u,
  computeSignedPolicyLayerHashB64u,
} from '../../../packages/clawsig-sdk/src/policy-resolution.js';

const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

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
    await crypto.subtle.exportKey('raw', keypair.publicKey),
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
  envelopeType: string;
  signerDid: string;
  privateKey: CryptoKey;
  payload: T;
  issuedAt?: string;
}) {
  const payloadHash = await computeHash(args.payload, 'SHA-256');
  const signature = new Uint8Array(
    await crypto.subtle.sign('Ed25519', args.privateKey, new TextEncoder().encode(payloadHash)),
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
    issued_at: args.issuedAt ?? '2026-03-20T00:00:00Z',
  };
}

async function makeEventChain(runId: string) {
  const payloadHash = await computeHash({ prompt: 'hello' }, 'SHA-256');
  const eventHeader = {
    event_id: 'evt_dlp_001',
    run_id: runId,
    event_type: 'llm_call',
    timestamp: '2026-03-20T00:00:01Z',
    payload_hash_b64u: payloadHash,
    prev_hash_b64u: null,
  };

  const eventHash = await computeHash(eventHeader, 'SHA-256');

  return [
    {
      ...eventHeader,
      event_hash_b64u: eventHash,
    },
  ];
}

async function makeDataHandlingPolicyEvidence(seed: string) {
  return {
    taxonomy_version: 'prv.dlp.taxonomy.v2' as const,
    ruleset_hash_b64u: await computeHash({ seed }, 'SHA-256'),
    built_in_rule_count: 8,
    custom_rule_count: 0,
  };
}


function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map((entry) => canonicalize(entry));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort((a, b) => a.localeCompare(b))) {
      out[key] = canonicalize((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

async function makePolicyBinding(args: {
  signerDid: string;
  privateKey: CryptoKey;
}) {
  const policy = {
    statements: [
      {
        sid: 'org.allow',
        effect: 'Allow',
        actions: ['model:invoke'],
        resources: ['*'],
      },
    ],
  };

  const policyHashB64u = await computeSignedPolicyLayerHashB64u(
    policy as { statements: Array<Record<string, unknown>> },
  );
  const signedBundlePayload = {
    policy_bundle_version: '1' as const,
    bundle_id: 'bundle_signed_policy_dlp_001',
    issuer_did: args.signerDid,
    issued_at: '2026-03-20T00:00:00Z',
    hash_algorithm: 'SHA-256' as const,
    layers: [
      {
        layer_id: 'org',
        scope: { scope_type: 'org' as const, org_id: 'acme' },
        apply_mode: 'merge' as const,
        policy,
        policy_hash_b64u: policyHashB64u,
      },
    ],
  };
  const signedBundlePayloadHash = await computeSignedPolicyBundlePayloadHashB64u(signedBundlePayload);
  const signedBundleSignature = new Uint8Array(
    await crypto.subtle.sign(
      'Ed25519',
      args.privateKey,
      new TextEncoder().encode(signedBundlePayloadHash),
    ),
  );
  const signedPolicyBundleEnvelope = {
    envelope_version: '1' as const,
    envelope_type: 'policy_bundle' as const,
    payload: signedBundlePayload,
    payload_hash_b64u: signedBundlePayloadHash,
    hash_algorithm: 'SHA-256' as const,
    signature_b64u: base64UrlEncode(signedBundleSignature),
    algorithm: 'Ed25519' as const,
    signer_did: args.signerDid,
    issued_at: '2026-03-20T00:00:00Z',
  };

  const effectivePolicySnapshot = {
    snapshot_version: '1' as const,
    resolver_version: 'org_project_task_exception.v1' as const,
    context: { org_id: 'acme' },
    source_bundle: {
      bundle_id: signedBundlePayload.bundle_id,
      issuer_did: args.signerDid,
      issued_at: signedBundlePayload.issued_at,
    },
    applied_layers: [
      {
        layer_id: 'org',
        scope_type: 'org' as const,
        org_id: 'acme',
        priority: 0,
        apply_mode: 'merge' as const,
        policy_hash_b64u: policyHashB64u,
      },
    ],
    effective_policy: policy,
  };

  const effectivePolicyHashB64u = await computeHash(
    canonicalize(effectivePolicySnapshot),
    'SHA-256',
  );

  return {
    effectivePolicyHashB64u,
    policyBinding: {
      binding_version: '1' as const,
      effective_policy_hash_b64u: effectivePolicyHashB64u,
      effective_policy_snapshot: effectivePolicySnapshot,
      signed_policy_bundle_envelope: signedPolicyBundleEnvelope,
    },
  };
}

async function makeEgressPolicyReceipt(args: {
  signerDid: string;
  privateKey: CryptoKey;
  runId: string;
  eventHashB64u: string;
  effectivePolicyHashB64u: string;
}) {
  const canonicalPolicy = {
    policy_version: '1',
    proofed_mode: true,
    clawproxy_url: 'https://clawproxy.example',
    allowed_proxy_destinations: ['clawproxy.example'],
    allowed_child_destinations: ['127.0.0.1', 'localhost'],
    direct_provider_access_blocked: true,
  };
  const policyHashB64u = await computeHash(canonicalPolicy, 'SHA-256');
  const payload = {
    receipt_version: '1' as const,
    receipt_id: `epr_${args.runId}`,
    policy_version: '1' as const,
    policy_hash_b64u: policyHashB64u,
    effective_policy_hash_b64u: args.effectivePolicyHashB64u,
    proofed_mode: true as const,
    clawproxy_url: canonicalPolicy.clawproxy_url,
    allowed_proxy_destinations: canonicalPolicy.allowed_proxy_destinations,
    allowed_child_destinations: canonicalPolicy.allowed_child_destinations,
    direct_provider_access_blocked: true as const,
    blocked_attempt_count: 0,
    blocked_attempts_observed: false,
    hash_algorithm: 'SHA-256' as const,
    agent_did: args.signerDid,
    timestamp: '2026-03-20T00:00:02Z',
    binding: {
      run_id: args.runId,
      event_hash_b64u: args.eventHashB64u,
    },
  };

  return await signEnvelope({
    envelopeType: 'egress_policy_receipt',
    signerDid: args.signerDid,
    privateKey: args.privateKey,
    payload,
    issuedAt: payload.timestamp,
  });
}

async function makeApprovalReceipt(args: {
  signerDid: string;
  privateKey: CryptoKey;
  agentDid: string;
  runId: string;
  eventHashB64u: string;
  effectivePolicyHashB64u: string;
  approvalScopeHashB64u: string;
}) {
  const payload = {
    receipt_version: '1' as const,
    receipt_id: 'har_001',
    approval_type: 'explicit_approve' as const,
    approver_subject: 'test-approver',
    approver_method: 'cli_confirm' as const,
    agent_did: args.agentDid,
    scope_hash_b64u: args.approvalScopeHashB64u,
    scope_summary: 'approve credential forwarding',
    policy_hash_b64u: args.effectivePolicyHashB64u,
    minted_capability_ttl_seconds: 600,
    hash_algorithm: 'SHA-256' as const,
    timestamp: '2026-03-20T00:00:02Z',
    binding: {
      run_id: args.runId,
      event_hash_b64u: args.eventHashB64u,
      policy_hash: args.effectivePolicyHashB64u,
    },
  };

  return await signEnvelope({
    envelopeType: 'human_approval_receipt',
    signerDid: args.signerDid,
    privateKey: args.privateKey,
    payload,
    issuedAt: payload.timestamp,
  });
}

async function makeDataHandlingReceipt(args: {
  signerDid: string;
  privateKey: CryptoKey;
  runId: string;
  effectivePolicyHashB64u: string;
  overrides?: Partial<{
    action: 'allow' | 'redact' | 'block' | 'require_approval';
    reason_code: string;
    classes: Array<{
      class_id: 'secret' | 'credential' | 'pii_email' | 'customer_restricted';
      rule_id: string;
      action: 'allow' | 'redact' | 'block' | 'require_approval';
      match_count: number;
    }>;
    approval: {
      required: boolean;
      satisfied: boolean;
      mechanism: string;
      scope_hash_b64u: string | null;
      receipt_hash_b64u: string | null;
      receipt_signer_did: string | null;
      receipt_envelope: Record<string, unknown> | null;
    };
    redaction: {
      applied: boolean;
      original_payload_hash_b64u: string;
      outbound_payload_hash_b64u: string | null;
    };
    classes: Array<{
      class_id: string;
      rule_id: string;
      action: 'allow' | 'redact' | 'block' | 'require_approval';
      match_count: number;
    }>;
    policy: {
      taxonomy_version: 'prv.dlp.taxonomy.v2';
      ruleset_hash_b64u: string;
      built_in_rule_count: number;
      custom_rule_count: number;
    };
  }>;
}) {
  const originalPayloadHash = await computeHash({ raw: 'secret' }, 'SHA-256');
  const redactedPayloadHash = await computeHash({ raw: '[REDACTED_SECRET]' }, 'SHA-256');
  const policy = args.overrides?.policy ?? (await makeDataHandlingPolicyEvidence('default'));
  const payload = {
    receipt_version: '1' as const,
    receipt_id: 'dhr_001',
    policy_version: 'prv.dlp.v1' as const,
    effective_policy_hash_b64u: args.effectivePolicyHashB64u,
    policy,
    run_id: args.runId,
    provider: 'openai',
    action: args.overrides?.action ?? ('redact' as const),
    reason_code: args.overrides?.reason_code ?? 'PRV_DLP_REDACTED',
    classes: args.overrides?.classes ?? [
      {
        class_id: 'secret.api_key',
        rule_id: 'prv.dlp.secret.api_key.v1',
        action: 'redact' as const,
        match_count: 1,
      },
    ],
    approval: args.overrides?.approval ?? {
      required: false,
      satisfied: false,
      mechanism: 'signed_receipt',
      scope_hash_b64u: null,
      receipt_hash_b64u: null,
      receipt_signer_did: null,
      receipt_envelope: null,
    },
    redaction: args.overrides?.redaction ?? {
      applied: true,
      original_payload_hash_b64u: originalPayloadHash,
      outbound_payload_hash_b64u: redactedPayloadHash,
    },
    timestamp: '2026-03-20T00:00:02Z',
  };

  return await signEnvelope({
    envelopeType: 'data_handling_receipt',
    signerDid: args.signerDid,
    privateKey: args.privateKey,
    payload,
    issuedAt: payload.timestamp,
  });
}

describe('proof bundle data handling evidence verification', () => {
  it('accepts valid signed data handling receipts in metadata', async () => {
    const signer = await makeDidKeyEd25519();
    const policy = await makePolicyBinding({
      signerDid: signer.did,
      privateKey: signer.privateKey,
    });
    const runId = 'run_dlp_valid_001';
    const eventChain = await makeEventChain(runId);
    const egressPolicyReceipt = await makeEgressPolicyReceipt({
      signerDid: signer.did,
      privateKey: signer.privateKey,
      runId,
      eventHashB64u: eventChain[0]!.event_hash_b64u,
      effectivePolicyHashB64u: policy.effectivePolicyHashB64u,
    });
    const dataHandlingReceipt = await makeDataHandlingReceipt({
      signerDid: signer.did,
      privateKey: signer.privateKey,
      runId,
      effectivePolicyHashB64u: policy.effectivePolicyHashB64u,
    });

    const payload = {
      bundle_version: '1' as const,
      bundle_id: 'bundle_dlp_valid_001',
      agent_did: signer.did,
      event_chain: eventChain,
      metadata: {
        policy_binding: policy.policyBinding,
        sentinels: {
          interpose_active: true,
          egress_policy_receipt: egressPolicyReceipt,
        },
        data_handling: {
          policy_version: 'prv.dlp.v1',
          taxonomy_version: dataHandlingReceipt.payload.policy.taxonomy_version,
          ruleset_hash_b64u: dataHandlingReceipt.payload.policy.ruleset_hash_b64u,
          built_in_rule_count: dataHandlingReceipt.payload.policy.built_in_rule_count,
          custom_rule_count: dataHandlingReceipt.payload.policy.custom_rule_count,
          effective_policy_hash_b64u: policy.effectivePolicyHashB64u,
          receipts: [dataHandlingReceipt],
        },
      },
    };

    const bundleEnvelope = await signEnvelope({
      envelopeType: 'proof_bundle',
      signerDid: signer.did,
      privateKey: signer.privateKey,
      payload,
      issuedAt: '2026-03-20T00:00:03Z',
    });

    const out = await verifyProofBundle(bundleEnvelope);
    expect(out.result.status).toBe('VALID');
  });

  it('fails closed when data handling receipt signature is tampered', async () => {
    const signer = await makeDidKeyEd25519();
    const policy = await makePolicyBinding({
      signerDid: signer.did,
      privateKey: signer.privateKey,
    });
    const runId = 'run_dlp_invalid_sig_001';
    const eventChain = await makeEventChain(runId);
    const egressPolicyReceipt = await makeEgressPolicyReceipt({
      signerDid: signer.did,
      privateKey: signer.privateKey,
      runId,
      eventHashB64u: eventChain[0]!.event_hash_b64u,
      effectivePolicyHashB64u: policy.effectivePolicyHashB64u,
    });
    const dataHandlingReceipt = await makeDataHandlingReceipt({
      signerDid: signer.did,
      privateKey: signer.privateKey,
      runId,
      effectivePolicyHashB64u: policy.effectivePolicyHashB64u,
    });

    const tampered = {
      ...dataHandlingReceipt,
      signature_b64u: base64UrlEncode(crypto.getRandomValues(new Uint8Array(64))),
    };

    const payload = {
      bundle_version: '1' as const,
      bundle_id: 'bundle_dlp_invalid_sig_001',
      agent_did: signer.did,
      event_chain: eventChain,
      metadata: {
        policy_binding: policy.policyBinding,
        sentinels: {
          interpose_active: true,
          egress_policy_receipt: egressPolicyReceipt,
        },
        data_handling: {
          policy_version: 'prv.dlp.v1',
          taxonomy_version: dataHandlingReceipt.payload.policy.taxonomy_version,
          ruleset_hash_b64u: dataHandlingReceipt.payload.policy.ruleset_hash_b64u,
          built_in_rule_count: dataHandlingReceipt.payload.policy.built_in_rule_count,
          custom_rule_count: dataHandlingReceipt.payload.policy.custom_rule_count,
          effective_policy_hash_b64u: policy.effectivePolicyHashB64u,
          receipts: [tampered],
        },
      },
    };

    const bundleEnvelope = await signEnvelope({
      envelopeType: 'proof_bundle',
      signerDid: signer.did,
      privateKey: signer.privateKey,
      payload,
      issuedAt: '2026-03-20T00:00:03Z',
    });

    const out = await verifyProofBundle(bundleEnvelope);
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('SIGNATURE_INVALID');
    expect(out.error?.field).toBe('payload.metadata.data_handling.receipts[0].signature_b64u');
  });

  it('fails closed when redact evidence does not change the outbound payload hash', async () => {
    const signer = await makeDidKeyEd25519();
    const policy = await makePolicyBinding({
      signerDid: signer.did,
      privateKey: signer.privateKey,
    });
    const runId = 'run_dlp_same_hash_001';
    const eventChain = await makeEventChain(runId);
    const egressPolicyReceipt = await makeEgressPolicyReceipt({
      signerDid: signer.did,
      privateKey: signer.privateKey,
      runId,
      eventHashB64u: eventChain[0]!.event_hash_b64u,
      effectivePolicyHashB64u: policy.effectivePolicyHashB64u,
    });
    const originalPayloadHash = await computeHash({ raw: 'secret' }, 'SHA-256');
    const dataHandlingReceipt = await makeDataHandlingReceipt({
      signerDid: signer.did,
      privateKey: signer.privateKey,
      runId,
      effectivePolicyHashB64u: policy.effectivePolicyHashB64u,
      overrides: {
        redaction: {
          applied: true,
          original_payload_hash_b64u: originalPayloadHash,
          outbound_payload_hash_b64u: originalPayloadHash,
        },
      },
    });

    const payload = {
      bundle_version: '1' as const,
      bundle_id: 'bundle_dlp_same_hash_001',
      agent_did: signer.did,
      event_chain: eventChain,
      metadata: {
        policy_binding: policy.policyBinding,
        sentinels: {
          interpose_active: true,
          egress_policy_receipt: egressPolicyReceipt,
        },
        data_handling: {
          policy_version: 'prv.dlp.v1',
          taxonomy_version: dataHandlingReceipt.payload.policy.taxonomy_version,
          ruleset_hash_b64u: dataHandlingReceipt.payload.policy.ruleset_hash_b64u,
          built_in_rule_count: dataHandlingReceipt.payload.policy.built_in_rule_count,
          custom_rule_count: dataHandlingReceipt.payload.policy.custom_rule_count,
          effective_policy_hash_b64u: policy.effectivePolicyHashB64u,
          receipts: [dataHandlingReceipt],
        },
      },
    };

    const bundleEnvelope = await signEnvelope({
      envelopeType: 'proof_bundle',
      signerDid: signer.did,
      privateKey: signer.privateKey,
      payload,
      issuedAt: '2026-03-20T00:00:03Z',
    });

    const out = await verifyProofBundle(bundleEnvelope);
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('EVIDENCE_MISMATCH');
    expect(out.error?.field).toBe('payload.metadata.data_handling.receipts[0].payload.redaction.outbound_payload_hash_b64u');
  });

  it('fails closed when data handling receipt run_id mismatches event-chain binding', async () => {
    const signer = await makeDidKeyEd25519();
    const policy = await makePolicyBinding({
      signerDid: signer.did,
      privateKey: signer.privateKey,
    });
    const runId = 'run_dlp_unbound_001';
    const eventChain = await makeEventChain(runId);
    const egressPolicyReceipt = await makeEgressPolicyReceipt({
      signerDid: signer.did,
      privateKey: signer.privateKey,
      runId,
      eventHashB64u: eventChain[0]!.event_hash_b64u,
      effectivePolicyHashB64u: policy.effectivePolicyHashB64u,
    });
    const dataHandlingReceipt = await makeDataHandlingReceipt({
      signerDid: signer.did,
      privateKey: signer.privateKey,
      runId: `${runId}_mismatch`,
      effectivePolicyHashB64u: policy.effectivePolicyHashB64u,
    });

    const payload = {
      bundle_version: '1' as const,
      bundle_id: 'bundle_dlp_unbound_001',
      agent_did: signer.did,
      event_chain: eventChain,
      metadata: {
        policy_binding: policy.policyBinding,
        sentinels: {
          interpose_active: true,
          egress_policy_receipt: egressPolicyReceipt,
        },
        data_handling: {
          policy_version: 'prv.dlp.v1',
          taxonomy_version: dataHandlingReceipt.payload.policy.taxonomy_version,
          ruleset_hash_b64u: dataHandlingReceipt.payload.policy.ruleset_hash_b64u,
          built_in_rule_count: dataHandlingReceipt.payload.policy.built_in_rule_count,
          custom_rule_count: dataHandlingReceipt.payload.policy.custom_rule_count,
          effective_policy_hash_b64u: policy.effectivePolicyHashB64u,
          receipts: [dataHandlingReceipt],
        },
      },
    };

    const bundleEnvelope = await signEnvelope({
      envelopeType: 'proof_bundle',
      signerDid: signer.did,
      privateKey: signer.privateKey,
      payload,
      issuedAt: '2026-03-20T00:00:03Z',
    });

    const out = await verifyProofBundle(bundleEnvelope);
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('EVIDENCE_MISMATCH');
    expect(out.error?.field).toBe('payload.metadata.data_handling.receipts[0].payload.run_id');
  });

  it('fails closed when signed approval receipt event binding is not in the proof bundle', async () => {
    const signer = await makeDidKeyEd25519();
    const policy = await makePolicyBinding({
      signerDid: signer.did,
      privateKey: signer.privateKey,
    });
    const runId = 'run_dlp_approval_binding_001';
    const eventChain = await makeEventChain(runId);
    const egressPolicyReceipt = await makeEgressPolicyReceipt({
      signerDid: signer.did,
      privateKey: signer.privateKey,
      runId,
      eventHashB64u: eventChain[0]!.event_hash_b64u,
      effectivePolicyHashB64u: policy.effectivePolicyHashB64u,
    });
    const approvalScopeHashB64u = await computeHash(
      canonicalize({
        scope_version: 'prv.dlp.approval_scope.v1',
        provider: 'openai',
        policy_version: 'prv.dlp.v1',
        effective_policy_hash_b64u: policy.effectivePolicyHashB64u,
        class_ids: ['credential.password'],
      }),
      'SHA-256',
    );
    const approvalReceipt = await makeApprovalReceipt({
      signerDid: signer.did,
      privateKey: signer.privateKey,
      agentDid: signer.did,
      runId,
      eventHashB64u: await computeHash({ wrong: 'event' }, 'SHA-256'),
      effectivePolicyHashB64u: policy.effectivePolicyHashB64u,
      approvalScopeHashB64u,
    });
    const originalPayloadHash = await computeHash({ password: 'approved-send' }, 'SHA-256');
    const dataHandlingReceipt = await makeDataHandlingReceipt({
      signerDid: signer.did,
      privateKey: signer.privateKey,
      runId,
      effectivePolicyHashB64u: policy.effectivePolicyHashB64u,
      overrides: {
        action: 'allow',
        reason_code: 'PRV_DLP_APPROVAL_GRANTED',
        classes: [
          {
            class_id: 'credential.password',
            rule_id: 'prv.dlp.credential.password.inline.v1',
            action: 'require_approval',
            match_count: 1,
          },
        ],
        approval: {
          required: true,
          satisfied: true,
          mechanism: 'signed_receipt',
          scope_hash_b64u: approvalScopeHashB64u,
          receipt_hash_b64u: approvalReceipt.payload_hash_b64u,
          receipt_signer_did: signer.did,
          receipt_envelope: approvalReceipt as unknown as Record<string, unknown>,
        },
        redaction: {
          applied: false,
          original_payload_hash_b64u: originalPayloadHash,
          outbound_payload_hash_b64u: originalPayloadHash,
        },
      },
    });

    const payload = {
      bundle_version: '1' as const,
      bundle_id: 'bundle_dlp_approval_binding_001',
      agent_did: signer.did,
      event_chain: eventChain,
      metadata: {
        policy_binding: policy.policyBinding,
        sentinels: {
          interpose_active: true,
          egress_policy_receipt: egressPolicyReceipt,
        },
        data_handling: {
          policy_version: 'prv.dlp.v1',
          effective_policy_hash_b64u: policy.effectivePolicyHashB64u,
          receipts: [dataHandlingReceipt],
        },
      },
    };

    const bundleEnvelope = await signEnvelope({
      envelopeType: 'proof_bundle',
      signerDid: signer.did,
      privateKey: signer.privateKey,
      payload,
      issuedAt: '2026-03-20T00:00:03Z',
    });

    const out = await verifyProofBundle(bundleEnvelope);
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('EVIDENCE_MISMATCH');
    expect(out.error?.field).toBe(
      'payload.metadata.data_handling.receipts[0].payload.approval.receipt_envelope.payload.binding.event_hash_b64u',
    );
  });

  it('fails closed when custom rule_id class segment does not match class_id', async () => {
    const signer = await makeDidKeyEd25519();
    const runId = 'run_dlp_custom_id_mismatch_001';
    const eventChain = await makeEventChain(runId);
    const policy = await makeDataHandlingPolicyEvidence('custom-id-mismatch');
    const policyBinding = await makePolicyBinding({
      signerDid: signer.did,
      privateKey: signer.privateKey,
    });
    const egressPolicyReceipt = await makeEgressPolicyReceipt({
      signerDid: signer.did,
      privateKey: signer.privateKey,
      runId,
      eventHashB64u: eventChain[0]!.event_hash_b64u,
      effectivePolicyHashB64u: policyBinding.effectivePolicyHashB64u,
    });

    const dataHandlingReceipt = await makeDataHandlingReceipt({
      signerDid: signer.did,
      privateKey: signer.privateKey,
      runId,
      effectivePolicyHashB64u: policyBinding.effectivePolicyHashB64u,
      overrides: {
        action: 'block',
        reason_code: 'PRV_DLP_BLOCKED',
        classes: [
          {
            class_id: 'customer.internal',
            rule_id: 'prv.dlp.custom.customer.other.abcdefghijklmno.v1',
            action: 'block',
            match_count: 1,
          },
        ],
        redaction: {
          applied: false,
          original_payload_hash_b64u: await computeHash({ raw: 'x' }, 'SHA-256'),
          outbound_payload_hash_b64u: null,
        },
        policy,
      },
    });

    const payload = {
      bundle_version: '1' as const,
      bundle_id: 'bundle_dlp_custom_id_mismatch_001',
      agent_did: signer.did,
      event_chain: eventChain,
      metadata: {
        policy_binding: policyBinding.policyBinding,
        sentinels: {
          interpose_active: true,
          egress_policy_receipt: egressPolicyReceipt,
        },
        data_handling: {
          policy_version: 'prv.dlp.v1',
          taxonomy_version: policy.taxonomy_version,
          ruleset_hash_b64u: policy.ruleset_hash_b64u,
          built_in_rule_count: policy.built_in_rule_count,
          custom_rule_count: policy.custom_rule_count,
          effective_policy_hash_b64u: policyBinding.effectivePolicyHashB64u,
          receipts: [dataHandlingReceipt],
        },
      },
    };

    const bundleEnvelope = await signEnvelope({
      envelopeType: 'proof_bundle',
      signerDid: signer.did,
      privateKey: signer.privateKey,
      payload,
      issuedAt: '2026-03-20T00:00:03Z',
    });

    const out = await verifyProofBundle(bundleEnvelope);
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('EVIDENCE_MISMATCH');
    expect(out.error?.field).toBe('payload.metadata.data_handling.receipts[0].payload.classes[0].rule_id');
  });

  it('fails closed when built-in rule_id does not align with class_id', async () => {
    const signer = await makeDidKeyEd25519();
    const runId = 'run_dlp_builtin_id_mismatch_001';
    const eventChain = await makeEventChain(runId);
    const policy = await makeDataHandlingPolicyEvidence('builtin-id-mismatch');
    const policyBinding = await makePolicyBinding({
      signerDid: signer.did,
      privateKey: signer.privateKey,
    });
    const egressPolicyReceipt = await makeEgressPolicyReceipt({
      signerDid: signer.did,
      privateKey: signer.privateKey,
      runId,
      eventHashB64u: eventChain[0]!.event_hash_b64u,
      effectivePolicyHashB64u: policyBinding.effectivePolicyHashB64u,
    });

    const dataHandlingReceipt = await makeDataHandlingReceipt({
      signerDid: signer.did,
      privateKey: signer.privateKey,
      runId,
      effectivePolicyHashB64u: policyBinding.effectivePolicyHashB64u,
      overrides: {
        classes: [
          {
            class_id: 'pii.email',
            rule_id: 'prv.dlp.secret.api_key.v1',
            action: 'redact',
            match_count: 1,
          },
        ],
        policy,
      },
    });

    const payload = {
      bundle_version: '1' as const,
      bundle_id: 'bundle_dlp_builtin_id_mismatch_001',
      agent_did: signer.did,
      event_chain: eventChain,
      metadata: {
        policy_binding: policyBinding.policyBinding,
        sentinels: {
          interpose_active: true,
          egress_policy_receipt: egressPolicyReceipt,
        },
        data_handling: {
          policy_version: 'prv.dlp.v1',
          taxonomy_version: policy.taxonomy_version,
          ruleset_hash_b64u: policy.ruleset_hash_b64u,
          built_in_rule_count: policy.built_in_rule_count,
          custom_rule_count: policy.custom_rule_count,
          effective_policy_hash_b64u: policyBinding.effectivePolicyHashB64u,
          receipts: [dataHandlingReceipt],
        },
      },
    };

    const bundleEnvelope = await signEnvelope({
      envelopeType: 'proof_bundle',
      signerDid: signer.did,
      privateKey: signer.privateKey,
      payload,
      issuedAt: '2026-03-20T00:00:03Z',
    });

    const out = await verifyProofBundle(bundleEnvelope);
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('EVIDENCE_MISMATCH');
    expect(out.error?.field).toBe('payload.metadata.data_handling.receipts[0].payload.classes[0].rule_id');
  });

  it('fails closed when custom rule matches are present without signed policy evidence', async () => {
    const signer = await makeDidKeyEd25519();
    const runId = 'run_dlp_custom_policy_missing_001';
    const eventChain = await makeEventChain(runId);
    const policyBinding = await makePolicyBinding({
      signerDid: signer.did,
      privateKey: signer.privateKey,
    });
    const egressPolicyReceipt = await makeEgressPolicyReceipt({
      signerDid: signer.did,
      privateKey: signer.privateKey,
      runId,
      eventHashB64u: eventChain[0]!.event_hash_b64u,
      effectivePolicyHashB64u: policyBinding.effectivePolicyHashB64u,
    });

    const dataHandlingReceipt = await makeDataHandlingReceipt({
      signerDid: signer.did,
      privateKey: signer.privateKey,
      runId,
      effectivePolicyHashB64u: policyBinding.effectivePolicyHashB64u,
      overrides: {
        action: 'block',
        reason_code: 'PRV_DLP_BLOCKED',
        classes: [
          {
            class_id: 'customer.internal',
            rule_id: 'prv.dlp.custom.customer.internal.abcdefghijklmno.v1',
            action: 'block',
            match_count: 1,
          },
        ],
        redaction: {
          applied: false,
          original_payload_hash_b64u: await computeHash({ raw: 'x' }, 'SHA-256'),
          outbound_payload_hash_b64u: null,
        },
      },
    });

    const unsignedPayload = { ...dataHandlingReceipt.payload };
    delete unsignedPayload.policy;
    const policylessReceipt = await signEnvelope({
      envelopeType: 'data_handling_receipt',
      signerDid: signer.did,
      privateKey: signer.privateKey,
      payload: unsignedPayload,
      issuedAt: unsignedPayload.timestamp,
    });

    const payload = {
      bundle_version: '1' as const,
      bundle_id: 'bundle_dlp_custom_policy_missing_001',
      agent_did: signer.did,
      event_chain: eventChain,
      metadata: {
        policy_binding: policyBinding.policyBinding,
        sentinels: {
          interpose_active: true,
          egress_policy_receipt: egressPolicyReceipt,
        },
        data_handling: {
          policy_version: 'prv.dlp.v1',
          effective_policy_hash_b64u: policyBinding.effectivePolicyHashB64u,
          receipts: [policylessReceipt],
        },
      },
    };

    const bundleEnvelope = await signEnvelope({
      envelopeType: 'proof_bundle',
      signerDid: signer.did,
      privateKey: signer.privateKey,
      payload,
      issuedAt: '2026-03-20T00:00:03Z',
    });

    const out = await verifyProofBundle(bundleEnvelope);
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('EVIDENCE_MISMATCH');
    expect(out.error?.field).toBe('payload.metadata.data_handling.receipts[0].payload.policy');
  });

  it('fails closed when custom rule matches are present but policy custom_rule_count is zero', async () => {
    const signer = await makeDidKeyEd25519();
    const runId = 'run_dlp_custom_policy_count_001';
    const eventChain = await makeEventChain(runId);
    const policy = await makeDataHandlingPolicyEvidence('custom-policy-count');
    const policyBinding = await makePolicyBinding({
      signerDid: signer.did,
      privateKey: signer.privateKey,
    });
    const egressPolicyReceipt = await makeEgressPolicyReceipt({
      signerDid: signer.did,
      privateKey: signer.privateKey,
      runId,
      eventHashB64u: eventChain[0]!.event_hash_b64u,
      effectivePolicyHashB64u: policyBinding.effectivePolicyHashB64u,
    });

    const dataHandlingReceipt = await makeDataHandlingReceipt({
      signerDid: signer.did,
      privateKey: signer.privateKey,
      runId,
      effectivePolicyHashB64u: policyBinding.effectivePolicyHashB64u,
      overrides: {
        action: 'block',
        reason_code: 'PRV_DLP_BLOCKED',
        classes: [
          {
            class_id: 'customer.internal',
            rule_id: 'prv.dlp.custom.customer.internal.abcdefghijklmno.v1',
            action: 'block',
            match_count: 1,
          },
        ],
        redaction: {
          applied: false,
          original_payload_hash_b64u: await computeHash({ raw: 'x' }, 'SHA-256'),
          outbound_payload_hash_b64u: null,
        },
        policy: {
          ...policy,
          custom_rule_count: 0,
        },
      },
    });

    const payload = {
      bundle_version: '1' as const,
      bundle_id: 'bundle_dlp_custom_policy_count_001',
      agent_did: signer.did,
      event_chain: eventChain,
      metadata: {
        policy_binding: policyBinding.policyBinding,
        sentinels: {
          interpose_active: true,
          egress_policy_receipt: egressPolicyReceipt,
        },
        data_handling: {
          policy_version: 'prv.dlp.v1',
          taxonomy_version: dataHandlingReceipt.payload.policy.taxonomy_version,
          ruleset_hash_b64u: dataHandlingReceipt.payload.policy.ruleset_hash_b64u,
          built_in_rule_count: dataHandlingReceipt.payload.policy.built_in_rule_count,
          custom_rule_count: dataHandlingReceipt.payload.policy.custom_rule_count,
          effective_policy_hash_b64u: policyBinding.effectivePolicyHashB64u,
          receipts: [dataHandlingReceipt],
        },
      },
    };

    const bundleEnvelope = await signEnvelope({
      envelopeType: 'proof_bundle',
      signerDid: signer.did,
      privateKey: signer.privateKey,
      payload,
      issuedAt: '2026-03-20T00:00:03Z',
    });

    const out = await verifyProofBundle(bundleEnvelope);
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('EVIDENCE_MISMATCH');
    expect(out.error?.field).toBe(
      'payload.metadata.data_handling.receipts[0].payload.policy.custom_rule_count',
    );
  });

  it('fails closed when metadata policy evidence diverges from signed receipt policy', async () => {
    const signer = await makeDidKeyEd25519();
    const runId = 'run_dlp_policy_mismatch_001';
    const eventChain = await makeEventChain(runId);
    const policyBinding = await makePolicyBinding({
      signerDid: signer.did,
      privateKey: signer.privateKey,
    });
    const egressPolicyReceipt = await makeEgressPolicyReceipt({
      signerDid: signer.did,
      privateKey: signer.privateKey,
      runId,
      eventHashB64u: eventChain[0]!.event_hash_b64u,
      effectivePolicyHashB64u: policyBinding.effectivePolicyHashB64u,
    });
    const dataHandlingReceipt = await makeDataHandlingReceipt({
      signerDid: signer.did,
      privateKey: signer.privateKey,
      runId,
      effectivePolicyHashB64u: policyBinding.effectivePolicyHashB64u,
    });

    const mismatchedRulesetHash = await computeHash({ seed: 'mismatch' }, 'SHA-256');
    const payload = {
      bundle_version: '1' as const,
      bundle_id: 'bundle_dlp_policy_mismatch_001',
      agent_did: signer.did,
      event_chain: eventChain,
      metadata: {
        policy_binding: policyBinding.policyBinding,
        sentinels: {
          interpose_active: true,
          egress_policy_receipt: egressPolicyReceipt,
        },
        data_handling: {
          policy_version: 'prv.dlp.v1',
          taxonomy_version: dataHandlingReceipt.payload.policy.taxonomy_version,
          ruleset_hash_b64u: mismatchedRulesetHash,
          built_in_rule_count: dataHandlingReceipt.payload.policy.built_in_rule_count,
          custom_rule_count: dataHandlingReceipt.payload.policy.custom_rule_count,
          effective_policy_hash_b64u: policyBinding.effectivePolicyHashB64u,
          receipts: [dataHandlingReceipt],
        },
      },
    };

    const bundleEnvelope = await signEnvelope({
      envelopeType: 'proof_bundle',
      signerDid: signer.did,
      privateKey: signer.privateKey,
      payload,
      issuedAt: '2026-03-20T00:00:03Z',
    });

    const out = await verifyProofBundle(bundleEnvelope);
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('EVIDENCE_MISMATCH');
    expect(out.error?.field).toBe('payload.metadata.data_handling.receipts[0].payload.policy');
  });
});
