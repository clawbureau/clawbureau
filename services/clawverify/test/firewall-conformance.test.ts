import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { base64UrlEncode, computeHash } from '../src/crypto';
import { verifyProofBundle } from '../src/verify-proof-bundle';

const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

type FixtureExpected = {
  status: 'VALID' | 'INVALID';
  proof_tier?: string;
  error_code?: string;
  model_identity_tier?: string;
};

type FixtureCase = {
  id: string;
  scenario:
    | 'valid_self'
    | 'valid_witnessed_web'
    | 'valid_gateway'
    | 'valid_sandbox_tee'
    | 'invalid_vir_merkle_mismatch'
    | 'invalid_vir_conflict_unreported'
    | 'invalid_vir_precedence_violation'
    | 'invalid_tee_revoked';
  expected: FixtureExpected;
};

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
    receipt_id: `vir_${args.runId}`,
    source: 'gateway',
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

  if (spec.scenario === 'valid_witnessed_web') {
    const witness = await makeDidKeyEd25519();

    const webPayload: Record<string, unknown> = {
      receipt_version: '1',
      receipt_id: `wr_${runId}`,
      witness_id: 'witness_runtime_firewall_001',
      source: 'chatgpt_web',
      request_hash_b64u: 'req_web_firewall_001',
      response_hash_b64u: 'res_web_firewall_001',
      timestamp: '2026-02-17T00:00:00Z',
      binding: {
        run_id: runId,
        event_hash_b64u: eventHash,
      },
    };

    const webEnvelope = await signEnvelope({
      payload: webPayload,
      envelopeType: 'web_receipt',
      signerDid: witness.did,
      privateKey: witness.privateKey,
      issuedAt: '2026-02-17T00:00:00Z',
    });

    const bundleEnvelope = await signEnvelope({
      payload: {
        ...bundlePayload,
        web_receipts: [webEnvelope],
      },
      envelopeType: 'proof_bundle',
      signerDid: agent.did,
      privateKey: agent.privateKey,
      issuedAt: '2026-02-17T00:00:01Z',
    });

    return {
      envelope: bundleEnvelope,
      options: {
        allowlistedWitnessSignerDids: [witness.did],
      },
    };
  }

  if (spec.scenario === 'valid_gateway') {
    const gateway = await makeDidKeyEd25519();

    const receiptPayload: Record<string, unknown> = {
      receipt_version: '1',
      receipt_id: `rcpt_${runId}`,
      gateway_id: 'gw_firewall_001',
      provider: 'openai',
      model: 'gpt-4',
      request_hash_b64u: 'req_gateway_firewall_001',
      response_hash_b64u: 'res_gateway_firewall_001',
      tokens_input: 10,
      tokens_output: 20,
      latency_ms: 50,
      timestamp: '2026-02-17T00:00:00Z',
      binding: {
        run_id: runId,
        event_hash_b64u: eventHash,
      },
    };

    const receiptEnvelope = await signEnvelope({
      payload: receiptPayload,
      envelopeType: 'gateway_receipt',
      signerDid: gateway.did,
      privateKey: gateway.privateKey,
      issuedAt: '2026-02-17T00:00:00Z',
    });

    const bundleEnvelope = await signEnvelope({
      payload: {
        ...bundlePayload,
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
        allowlistedReceiptSignerDids: [gateway.did],
      },
    };
  }

  if (spec.scenario === 'valid_sandbox_tee' || spec.scenario === 'invalid_tee_revoked') {
    const attester = await makeDidKeyEd25519();
    const tcbVersion = spec.scenario === 'invalid_tee_revoked' ? 'tdx-firewall-revoked' : 'tdx-firewall-good';

    const bundlePayloadHash = await computeHash(bundlePayload, 'SHA-256');

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
          evidence_ref: {
            resource_type: 'tee_quote',
            resource_hash_b64u: 'tee_quote_hash_firewall_001',
          },
          measurements: {
            measurement_hash_b64u: 'tee_measurement_hash_firewall_001',
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

const FIXTURE_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../packages/schema/fixtures/protocol-conformance/clawverify-firewall'
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

describe('clawverify firewall conformance fixtures', () => {
  it.each(fixtures)('validates fixture: $id', async (spec) => {
    const scenario = await buildFixtureScenario(spec);
    const out = await verifyProofBundle(scenario.envelope, scenario.options as any);

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
  });
});
