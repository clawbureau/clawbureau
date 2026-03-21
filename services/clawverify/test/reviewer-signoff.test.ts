import { describe, expect, it } from 'vitest';

import {
  base64UrlDecode,
  base64UrlEncode,
  didFromPublicKey,
  generateKeyPair,
  signEd25519,
} from '../../../packages/clawsig-sdk/dist/crypto.js';
import { computeHash } from '../src/crypto';
import { verifyProofBundle } from '../src/verify-proof-bundle';

function mutateB64u(value: string): string {
  if (value.length === 0) return value;
  return `${value.slice(0, -1)}${value.endsWith('A') ? 'B' : 'A'}`;
}

function mutateCanonicalB64u(value: string): string {
  const bytes = base64UrlDecode(value);
  if (bytes.length === 0) return value;
  bytes[bytes.length - 1] ^= 0x01;
  const mutated = base64UrlEncode(bytes);
  if (mutated !== value) return mutated;
  bytes[bytes.length - 1] ^= 0x02;
  return base64UrlEncode(bytes);
}

async function buildSingleLeafInclusionProof(args: {
  leafHashB64u: string;
  logId: string;
  signerDid: string;
  signerPrivateKey: CryptoKey;
}) {
  const sig = await signEd25519(
    args.signerPrivateKey,
    new TextEncoder().encode(args.leafHashB64u),
  );

  return {
    proof_version: '1' as const,
    log_id: args.logId,
    tree_size: 1,
    leaf_hash_b64u: args.leafHashB64u,
    root_hash_b64u: args.leafHashB64u,
    audit_path: [] as string[],
    root_published_at: '2026-03-21T05:31:00.000Z',
    root_signature: {
      signer_did: args.signerDid,
      sig_b64u: sig,
    },
    metadata: {
      leaf_index: 0,
    },
  };
}

async function computeReviewerSignoffTransparencyLeafHash(
  payload: Record<string, unknown>,
) {
  const binding = payload.binding as Record<string, unknown>;
  const dispute = payload.dispute as
    | {
        status?: string;
        notes?: Array<{
          note_id: string;
          note: string;
          evidence_refs?: Array<{
            ref_id?: string;
            uri?: string;
            sha256_b64u?: string;
          }>;
        }>;
      }
    | undefined;

  return computeHash(
    {
      leaf_version: 'reviewer_signoff_receipt_v1',
      receipt_version: payload.receipt_version,
      receipt_id: payload.receipt_id,
      reviewer_did: payload.reviewer_did,
      decision: payload.decision,
      timestamp: payload.timestamp,
      binding: {
        run_id: binding.run_id,
        bundle_id: binding.bundle_id,
        proof_bundle_hash_b64u:
          typeof binding.proof_bundle_hash_b64u === 'string'
            ? binding.proof_bundle_hash_b64u
            : null,
        event_hash_b64u: binding.event_hash_b64u,
        target_kind: binding.target_kind,
        export_pack_root_hash_b64u:
          typeof binding.export_pack_root_hash_b64u === 'string'
            ? binding.export_pack_root_hash_b64u
            : null,
      },
      dispute: dispute
        ? {
            status: dispute.status,
            notes: (dispute.notes ?? []).map((note) => ({
              note_id: note.note_id,
              note: note.note,
              evidence_refs: (note.evidence_refs ?? []).map((ref) => ({
                ref_id: ref.ref_id ?? null,
                uri: ref.uri ?? null,
                sha256_b64u: ref.sha256_b64u ?? null,
              })),
            })),
          }
        : null,
    },
    'SHA-256',
  );
}

async function buildEnvelope(options?: {
  dispute?: boolean;
  tamperEventHash?: boolean;
  tamperSignature?: boolean;
  transparencyMode?:
    | 'none'
    | 'valid'
    | 'tamper_leaf'
    | 'bad_consistency'
    | 'bad_prior_root';
  anchorUri?: string;
}) {
  const agentKey = await generateKeyPair();
  const reviewerKey = await generateKeyPair();
  const agentDid = await didFromPublicKey(agentKey.publicKey);
  const reviewerDid = await didFromPublicKey(reviewerKey.publicKey);

  const eventCanonical = {
    event_id: 'evt_service_signoff_1',
    run_id: 'run_service_signoff_1',
    event_type: 'llm_call',
    timestamp: '2026-03-21T05:30:00.000Z',
    payload_hash_b64u: await computeHash({ input: 'service' }, 'SHA-256'),
    prev_hash_b64u: null,
  };
  const eventHash = await computeHash(eventCanonical, 'SHA-256');

  const signoffPayload: Record<string, unknown> = {
    receipt_version: '1',
    receipt_id: 'rsr_service_1',
    reviewer_did: reviewerDid,
    decision: 'needs_changes',
    timestamp: '2026-03-21T05:31:00.000Z',
    binding: {
      run_id: eventCanonical.run_id,
      bundle_id: 'bundle_service_signoff_1',
      event_hash_b64u: options?.tamperEventHash ? 'a'.repeat(43) : eventHash,
      target_kind: 'run',
    },
  };

  if (options?.dispute) {
    signoffPayload.dispute = {
      status: 'resolved',
      notes: [
        {
          note_id: 'dn_service_1',
          note: 'Dispute resolved after corrected export evidence.',
          evidence_refs: [
            {
              sha256_b64u: await computeHash({ artifact: 'resolved' }, 'SHA-256'),
            },
          ],
        },
      ],
    };
  }

  const transparencyMode = options?.transparencyMode ?? 'none';
  if (transparencyMode !== 'none') {
    const expectedLeafHash = await computeReviewerSignoffTransparencyLeafHash(
      signoffPayload,
    );
    const inclusionProof = await buildSingleLeafInclusionProof({
      leafHashB64u:
        transparencyMode === 'tamper_leaf'
          ? mutateCanonicalB64u(expectedLeafHash)
          : expectedLeafHash,
      logId: 'reviewer-signoff-log',
      signerDid: reviewerDid,
      signerPrivateKey: reviewerKey.privateKey,
    });

    const consistencyProof = {
      proof_version: '1' as const,
      log_id: 'reviewer-signoff-log',
      from_tree_size: 1,
      to_tree_size: 1,
      from_root_hash_b64u:
        transparencyMode === 'bad_prior_root'
          ? mutateB64u(expectedLeafHash)
          : expectedLeafHash,
      to_root_hash_b64u:
        transparencyMode === 'bad_consistency'
          ? mutateB64u(expectedLeafHash)
          : expectedLeafHash,
      consistency_path: [] as string[],
    };

    signoffPayload.transparency = {
      inclusion_proof: inclusionProof,
      consistency_proof: consistencyProof,
      anchor_id: 'anchor-reviewer-1',
      anchor_uri: options?.anchorUri,
    };
  }

  const signoffPayloadHash = await computeHash(signoffPayload, 'SHA-256');
  const signoffSignature = options?.tamperSignature
    ? 'a'.repeat(86)
    : await signEd25519(
      reviewerKey.privateKey,
      new TextEncoder().encode(signoffPayloadHash),
    );

  const payload = {
    bundle_version: '1',
    bundle_id: 'bundle_service_signoff_1',
    agent_did: agentDid,
    event_chain: [
      {
        ...eventCanonical,
        event_hash_b64u: eventHash,
      },
    ],
    metadata: {
      reviewer_signoff_receipts: [
        {
          envelope_version: '1',
          envelope_type: 'reviewer_signoff_receipt',
          payload: signoffPayload,
          payload_hash_b64u: signoffPayloadHash,
          hash_algorithm: 'SHA-256',
          signature_b64u: signoffSignature,
          algorithm: 'Ed25519',
          signer_did: reviewerDid,
          issued_at: '2026-03-21T05:31:00.000Z',
        },
      ],
    },
  };

  const payloadHash = await computeHash(payload, 'SHA-256');
  return {
    envelope_version: '1',
    envelope_type: 'proof_bundle',
    payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256',
    signature_b64u: await signEd25519(agentKey.privateKey, new TextEncoder().encode(payloadHash)),
    algorithm: 'Ed25519',
    signer_did: agentDid,
    issued_at: '2026-03-21T05:32:00.000Z',
  };
}

describe('AF2-REV-003 service verifier reviewer signoff/dispute binding', () => {
  it('surfaces reviewer signoff/dispute state in component_results when valid', async () => {
    const envelope = await buildEnvelope({ dispute: true });
    const out = await verifyProofBundle(envelope);

    expect(out.result.status).toBe('VALID');
    expect(out.result.component_results?.reviewer_signoff_present).toBe(true);
    expect(out.result.component_results?.reviewer_signoff_valid).toBe(true);
    expect(out.result.component_results?.reviewer_signoff_receipts_count).toBe(1);
    expect(out.result.component_results?.reviewer_signoff_decision_counts).toEqual({
      approve: 0,
      reject: 0,
      needs_changes: 1,
    });
    expect(out.result.component_results?.reviewer_dispute_present).toBe(true);
    expect(out.result.component_results?.reviewer_dispute_note_count).toBe(1);
    expect(out.result.component_results?.reviewer_dispute_evidence_refs_count).toBe(1);
  });

  it('fails closed when reviewer signoff event binding is not in payload.event_chain', async () => {
    const envelope = await buildEnvelope({ tamperEventHash: true });
    const out = await verifyProofBundle(envelope);

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('EVIDENCE_MISMATCH');
    expect(out.error?.field).toBe(
      'payload.metadata.reviewer_signoff_receipts[0].payload.binding.event_hash_b64u',
    );
  });

  it('fails closed when reviewer signoff signature verification fails', async () => {
    const envelope = await buildEnvelope({ tamperSignature: true });
    const out = await verifyProofBundle(envelope);

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('SIGNATURE_INVALID');
    expect(out.error?.field).toBe(
      'payload.metadata.reviewer_signoff_receipts[0].signature_b64u',
    );
  });

  it('verifies reviewer signoff transparency inclusion + consistency evidence when present', async () => {
    const envelope = await buildEnvelope({ transparencyMode: 'valid' });
    const out = await verifyProofBundle(envelope);

    expect(out.result.status).toBe('VALID');
    expect(out.result.component_results?.reviewer_signoff_valid).toBe(true);
  });

  it('fails closed when reviewer signoff transparency inclusion leaf hash mismatches receipt leaf', async () => {
    const envelope = await buildEnvelope({ transparencyMode: 'tamper_leaf' });
    const out = await verifyProofBundle(envelope);

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('EVIDENCE_MISMATCH');
    expect(out.error?.field).toBe(
      'payload.metadata.reviewer_signoff_receipts[0].payload.transparency.inclusion_proof.leaf_hash_b64u',
    );
  });

  it('fails closed when reviewer signoff transparency consistency evidence is inconsistent', async () => {
    const envelope = await buildEnvelope({ transparencyMode: 'bad_consistency' });
    const out = await verifyProofBundle(envelope);

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('EVIDENCE_MISMATCH');
    expect(out.error?.field).toBe(
      'payload.metadata.reviewer_signoff_receipts[0].payload.transparency.consistency_proof.to_root_hash_b64u',
    );
  });

  it('fails closed when reviewer signoff transparency prior root mismatches for an unchanged tree size', async () => {
    const envelope = await buildEnvelope({ transparencyMode: 'bad_prior_root' });
    const out = await verifyProofBundle(envelope);

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('EVIDENCE_MISMATCH');
    expect(out.error?.field).toBe(
      'payload.metadata.reviewer_signoff_receipts[0].payload.transparency.consistency_proof.from_root_hash_b64u',
    );
  });

  it('fails closed when reviewer signoff transparency anchor_uri is malformed', async () => {
    const envelope = await buildEnvelope({
      transparencyMode: 'valid',
      anchorUri: 'not-a-uri',
    });
    const out = await verifyProofBundle(envelope);

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('MALFORMED_ENVELOPE');
    expect(out.error?.field).toBe(
      'payload.metadata.reviewer_signoff_receipts[0].payload.transparency.anchor_uri',
    );
  });
});
