import { describe, expect, it } from 'vitest';

import worker from '../src/index';
import { base64UrlEncode, computeHash } from '../src/crypto';
import { verifyExecutionAttestation } from '../src/verify-execution-attestation';
import { verifyAgent } from '../src/verify-agent';

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

  // Leading zeros
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
    digits.push(0);
  }

  return digits
    .reverse()
    .map((d) => BASE58_ALPHABET[d])
    .join('');
}

async function makeDidKeyEd25519(): Promise<{
  did: string;
  privateKey: CryptoKey;
}> {
  const keypair = await crypto.subtle.generateKey('Ed25519', true, [
    'sign',
    'verify',
  ]);

  const publicKeyBytes = new Uint8Array(
    await crypto.subtle.exportKey('raw', keypair.publicKey)
  );

  const prefixed = new Uint8Array(2 + publicKeyBytes.length);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(publicKeyBytes, 2);

  const did = `did:key:z${base58Encode(prefixed)}`;
  return { did, privateKey: keypair.privateKey };
}

async function signB64uEd25519(privateKey: CryptoKey, msg: string): Promise<string> {
  const msgBytes = new TextEncoder().encode(msg);
  const sigBuf = await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, msgBytes);
  return base64UrlEncode(new Uint8Array(sigBuf));
}

async function makeExecutionAttestationEnvelope(
  payload: Record<string, unknown>,
  signer: { did: string; privateKey: CryptoKey }
) {
  const payloadHash = await computeHash(payload, 'SHA-256');
  return {
    envelope_version: '1',
    envelope_type: 'execution_attestation',
    payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256',
    signature_b64u: await signB64uEd25519(signer.privateKey, payloadHash),
    algorithm: 'Ed25519',
    signer_did: signer.did,
    issued_at: '2026-02-11T00:00:01Z',
  };
}

describe('CEA-US-010: execution attestation', () => {
  it('verifyExecutionAttestation fails closed without allowlist', async () => {
    const agent = await makeDidKeyEd25519();
    const attester = await makeDidKeyEd25519();

    const runId = 'run_execatt_001';
    const bundleHash = 'bndl_hash_aaaaaaaa';

    const payload = {
      attestation_version: '1',
      attestation_id: 'execatt_001',
      execution_type: 'sandbox_execution',
      agent_did: agent.did,
      attester_did: attester.did,
      run_id: runId,
      proof_bundle_hash_b64u: bundleHash,
      issued_at: '2026-02-11T00:00:00Z',
    };

    const payloadHash = await computeHash(payload, 'SHA-256');

    const envelope = {
      envelope_version: '1',
      envelope_type: 'execution_attestation',
      payload,
      payload_hash_b64u: payloadHash,
      hash_algorithm: 'SHA-256',
      signature_b64u: await signB64uEd25519(attester.privateKey, payloadHash),
      algorithm: 'Ed25519',
      signer_did: attester.did,
      issued_at: '2026-02-11T00:00:01Z',
    };

    const v = await verifyExecutionAttestation(envelope, {
      allowlistedSignerDids: [],
    });

    expect(v.result.status).toBe('INVALID');
    expect(v.error?.code).toBe('DEPENDENCY_NOT_CONFIGURED');
  });

  it('fails closed for tee_execution when TEE allowlists are not configured', async () => {
    const agent = await makeDidKeyEd25519();
    const attester = await makeDidKeyEd25519();

    const payload = {
      attestation_version: '1',
      attestation_id: 'execatt_tee_001',
      execution_type: 'tee_execution',
      agent_did: agent.did,
      attester_did: attester.did,
      run_id: 'run_execatt_tee_001',
      proof_bundle_hash_b64u: 'tee_bundle_hash_aaaaaaaa',
      runtime_metadata: {
        tee: {
          attestation_type: 'tdx_quote',
          root_id: 'tee_root_sim_v1',
          tcb_version: 'tee_tcb_sim_v1',
          evidence_ref: {
            resource_type: 'tee_quote',
            resource_hash_b64u: 'teeQuoteHash_aaaaaaaa',
          },
          measurements: {
            measurement_hash_b64u: 'teeMeasureHash_aaaaaaaa',
          },
        },
      },
      issued_at: '2026-02-11T00:00:00Z',
    };

    const envelope = await makeExecutionAttestationEnvelope(payload, attester);

    const out = await verifyExecutionAttestation(envelope, {
      allowlistedSignerDids: [attester.did],
    });

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('DEPENDENCY_NOT_CONFIGURED');
    expect(out.error?.field).toBe('env.TEE_ATTESTATION_ROOT_ALLOWLIST');
  });

  it('accepts tee_execution when root and TCB are allowlisted', async () => {
    const agent = await makeDidKeyEd25519();
    const attester = await makeDidKeyEd25519();

    const rootId = 'tee_root_sim_v1';
    const tcbVersion = 'tee_tcb_sim_v1';

    const payload = {
      attestation_version: '1',
      attestation_id: 'execatt_tee_002',
      execution_type: 'tee_execution',
      agent_did: agent.did,
      attester_did: attester.did,
      run_id: 'run_execatt_tee_002',
      proof_bundle_hash_b64u: 'tee_bundle_hash_bbbbbbbb',
      runtime_metadata: {
        tee: {
          attestation_type: 'tdx_quote',
          root_id: rootId,
          tcb_version: tcbVersion,
          evidence_ref: {
            resource_type: 'tee_quote',
            resource_hash_b64u: 'teeQuoteHash_bbbbbbbb',
          },
          measurements: {
            measurement_hash_b64u: 'teeMeasureHash_bbbbbbbb',
            runtime_digest_b64u: 'teeRuntimeHash_bbbbbbbb',
          },
        },
      },
      issued_at: '2026-02-11T00:00:00Z',
    };

    const envelope = await makeExecutionAttestationEnvelope(payload, attester);

    const out = await verifyExecutionAttestation(envelope, {
      allowlistedSignerDids: [attester.did],
      teeRootAllowlist: [rootId],
      teeTcbAllowlist: [tcbVersion],
    });

    expect(out.result.status).toBe('VALID');
    expect(out.execution_type).toBe('tee_execution');
    expect(out.tee_root_id).toBe(rootId);
    expect(out.tee_tcb_version).toBe(tcbVersion);
  });

  it('rejects tee_execution when TCB version is revoked', async () => {
    const agent = await makeDidKeyEd25519();
    const attester = await makeDidKeyEd25519();

    const rootId = 'tee_root_sim_v1';
    const tcbVersion = 'tee_tcb_sim_v1';

    const payload = {
      attestation_version: '1',
      attestation_id: 'execatt_tee_003',
      execution_type: 'tee_execution',
      agent_did: agent.did,
      attester_did: attester.did,
      run_id: 'run_execatt_tee_003',
      proof_bundle_hash_b64u: 'tee_bundle_hash_cccccccc',
      runtime_metadata: {
        tee: {
          attestation_type: 'sev_snp_report',
          root_id: rootId,
          tcb_version: tcbVersion,
          evidence_ref: {
            resource_type: 'tee_quote',
            resource_hash_b64u: 'teeQuoteHash_cccccccc',
          },
          measurements: {
            measurement_hash_b64u: 'teeMeasureHash_cccccccc',
          },
        },
      },
      issued_at: '2026-02-11T00:00:00Z',
    };

    const envelope = await makeExecutionAttestationEnvelope(payload, attester);

    const out = await verifyExecutionAttestation(envelope, {
      allowlistedSignerDids: [attester.did],
      teeRootAllowlist: [rootId],
      teeTcbAllowlist: [tcbVersion],
      teeTcbRevoked: [tcbVersion],
    });

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('REVOKED');
    expect(out.error?.field).toBe('payload.runtime_metadata.tee.tcb_version');
  });

  it('uplifts verifyAgent proof_tier to sandbox when execution attestation verifies + binds', async () => {
    const agent = await makeDidKeyEd25519();
    const execAttester = await makeDidKeyEd25519();

    const runId = 'run_execatt_002';

    // Minimal 1-event chain so run_id is available for binding
    const e1PayloadHash = await computeHash({ type: 'llm_call' }, 'SHA-256');
    const e1Header = {
      event_id: 'evt_001',
      run_id: runId,
      event_type: 'llm_call',
      timestamp: '2026-02-11T00:00:00Z',
      payload_hash_b64u: e1PayloadHash,
      prev_hash_b64u: null as string | null,
    };
    const e1Hash = await computeHash(e1Header, 'SHA-256');

    const eventChain = [
      {
        ...e1Header,
        event_hash_b64u: e1Hash,
      },
    ];

    // Build a minimal proof bundle envelope (no receipts) => proof_tier=self
    const bundlePayload = {
      bundle_version: '1',
      bundle_id: 'bundle_execatt_002',
      agent_did: agent.did,
      event_chain: eventChain,
    };

    const bundlePayloadHash = await computeHash(bundlePayload, 'SHA-256');

    const proofBundleEnvelope = {
      envelope_version: '1',
      envelope_type: 'proof_bundle',
      payload: bundlePayload,
      payload_hash_b64u: bundlePayloadHash,
      hash_algorithm: 'SHA-256',
      signature_b64u: await signB64uEd25519(agent.privateKey, bundlePayloadHash),
      algorithm: 'Ed25519',
      signer_did: agent.did,
      issued_at: '2026-02-11T00:00:02Z',
    };

    // Build an execution attestation bound to the proof bundle hash
    const execPayload = {
      attestation_version: '1',
      attestation_id: 'execatt_002',
      execution_type: 'sandbox_execution',
      agent_did: agent.did,
      attester_did: execAttester.did,
      run_id: runId,
      proof_bundle_hash_b64u: bundlePayloadHash,
      issued_at: '2026-02-11T00:00:03Z',
    };

    const execPayloadHash = await computeHash(execPayload, 'SHA-256');

    const execEnvelope = {
      envelope_version: '1',
      envelope_type: 'execution_attestation',
      payload: execPayload,
      payload_hash_b64u: execPayloadHash,
      hash_algorithm: 'SHA-256',
      signature_b64u: await signB64uEd25519(execAttester.privateKey, execPayloadHash),
      algorithm: 'Ed25519',
      signer_did: execAttester.did,
      issued_at: '2026-02-11T00:00:04Z',
    };

    const out = await verifyAgent(
      {
        agent_did: agent.did,
        proof_bundle_envelope: proofBundleEnvelope,
        execution_attestations: [execEnvelope],
      },
      {
        allowlistedExecutionAttesterDids: [execAttester.did],
      }
    );

    expect(out.result.status).toBe('VALID');
    expect(out.proof_tier).toBe('sandbox');
    expect(out.components?.execution_attestation?.status).toBe('VALID');
    expect(out.components?.execution_attestation?.verified_count).toBe(1);
  });

  it('uplifts /v1/verify/bundle proof_tier to sandbox when execution attestation is provided', async () => {
    const agent = await makeDidKeyEd25519();
    const execAttester = await makeDidKeyEd25519();

    const runId = 'run_execatt_003';

    // Minimal 1-event chain so run_id is available for binding
    const e1PayloadHash = await computeHash({ type: 'llm_call' }, 'SHA-256');
    const e1Header = {
      event_id: 'evt_001',
      run_id: runId,
      event_type: 'llm_call',
      timestamp: '2026-02-11T00:00:00Z',
      payload_hash_b64u: e1PayloadHash,
      prev_hash_b64u: null as string | null,
    };
    const e1Hash = await computeHash(e1Header, 'SHA-256');

    const bundlePayload = {
      bundle_version: '1',
      bundle_id: 'bundle_execatt_003',
      agent_did: agent.did,
      event_chain: [
        {
          ...e1Header,
          event_hash_b64u: e1Hash,
        },
      ],
    };

    const bundlePayloadHash = await computeHash(bundlePayload, 'SHA-256');

    const proofBundleEnvelope = {
      envelope_version: '1',
      envelope_type: 'proof_bundle',
      payload: bundlePayload,
      payload_hash_b64u: bundlePayloadHash,
      hash_algorithm: 'SHA-256',
      signature_b64u: await signB64uEd25519(agent.privateKey, bundlePayloadHash),
      algorithm: 'Ed25519',
      signer_did: agent.did,
      issued_at: '2026-02-11T00:00:02Z',
    };

    const execPayload = {
      attestation_version: '1',
      attestation_id: 'execatt_003',
      execution_type: 'sandbox_execution',
      agent_did: agent.did,
      attester_did: execAttester.did,
      run_id: runId,
      proof_bundle_hash_b64u: bundlePayloadHash,
      issued_at: '2026-02-11T00:00:03Z',
    };

    const execPayloadHash = await computeHash(execPayload, 'SHA-256');

    const execEnvelope = {
      envelope_version: '1',
      envelope_type: 'execution_attestation',
      payload: execPayload,
      payload_hash_b64u: execPayloadHash,
      hash_algorithm: 'SHA-256',
      signature_b64u: await signB64uEd25519(execAttester.privateKey, execPayloadHash),
      algorithm: 'Ed25519',
      signer_did: execAttester.did,
      issued_at: '2026-02-11T00:00:04Z',
    };

    const req = new Request('https://clawverify.com/v1/verify/bundle', {
      method: 'POST',
      headers: {
        'content-type': 'application/json; charset=utf-8',
      },
      body: JSON.stringify({
        envelope: proofBundleEnvelope,
        execution_attestations: [execEnvelope],
      }),
    });

    const env = {
      ENVIRONMENT: 'test',
      AUDIT_LOG_DB: undefined,
      GATEWAY_RECEIPT_SIGNER_DIDS: '',
      ATTESTATION_SIGNER_DIDS: '',
      EXECUTION_ATTESTATION_SIGNER_DIDS: execAttester.did,
    };

    const res = await worker.fetch(req, env as any, {} as any);
    expect(res.status).toBe(200);

    const json = await res.json();
    expect(json?.result?.status).toBe('VALID');
    expect(json?.result?.proof_tier).toBe('sandbox');
    expect(json?.proof_tier).toBe('sandbox');
    expect(json?.result?.component_results?.execution_attestations_valid).toBe(true);
  });
});
