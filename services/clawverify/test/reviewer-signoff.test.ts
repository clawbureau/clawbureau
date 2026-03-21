import { describe, expect, it } from 'vitest';

import {
  didFromPublicKey,
  generateKeyPair,
  signEd25519,
} from '../../../packages/clawsig-sdk/dist/crypto.js';
import { computeHash } from '../src/crypto';
import { verifyProofBundle } from '../src/verify-proof-bundle';

async function buildEnvelope(options?: {
  dispute?: boolean;
  tamperEventHash?: boolean;
  tamperSignature?: boolean;
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
});
