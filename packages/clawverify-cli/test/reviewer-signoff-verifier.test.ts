import { describe, expect, it } from 'vitest';

import { computeHash } from '../../clawverify-core/src/crypto.js';
import { verifyProofBundle } from '../../clawverify-core/src/verify-proof-bundle.js';
import {
  didFromPublicKey,
  generateKeyPair,
  signEd25519,
} from '../../clawsig-sdk/src/crypto.js';

async function buildProofBundleEnvelope(options?: {
  dispute?: boolean;
  tamperRunId?: boolean;
  tamperSignoffSignature?: boolean;
  revokeReviewer?: boolean;
}) {
  const agentKey = await generateKeyPair();
  const reviewerKey = await generateKeyPair();
  const agentDid = await didFromPublicKey(agentKey.publicKey);
  const reviewerDid = await didFromPublicKey(reviewerKey.publicKey);

  const eventCanonical = {
    event_id: 'evt_signoff_1',
    run_id: 'run_signoff_1',
    event_type: 'llm_call',
    timestamp: '2026-03-21T05:10:00.000Z',
    payload_hash_b64u: await computeHash({ input: 'x' }, 'SHA-256'),
    prev_hash_b64u: null,
  };
  const event_hash_b64u = await computeHash(eventCanonical, 'SHA-256');

  const signoffPayload: Record<string, unknown> = {
    receipt_version: '1',
    receipt_id: 'rsr_core_1',
    reviewer_did: reviewerDid,
    decision: 'approve',
    timestamp: '2026-03-21T05:11:00.000Z',
    binding: {
      run_id: options?.tamperRunId ? 'run_other' : eventCanonical.run_id,
      bundle_id: 'bundle_signoff_core_1',
      proof_bundle_hash_b64u: await computeHash({ external_target: 'bundle_signoff_core_1' }, 'SHA-256'),
      event_hash_b64u,
      target_kind: 'export_pack',
      export_pack_root_hash_b64u: await computeHash({ export_pack: 'pack_root' }, 'SHA-256'),
    },
    ...(options?.revokeReviewer
      ? {
          revoked_reviewer_keys: [
            {
              revocation_version: '1',
              revoked_signer_did: reviewerDid,
              effective_at: '2026-03-21T05:10:30.000Z',
              reason: 'Reviewer signing key revoked by policy',
            },
          ],
        }
      : {}),
  };

  if (options?.dispute) {
    signoffPayload.dispute = {
      status: 'raised',
      notes: [
        {
          note_id: 'dn_core_1',
          note: 'Dispute opened pending timeline clarification.',
          evidence_refs: [
            {
              ref_id: 'ev_core_1',
              uri: 'https://example.invalid/reviewer/ev_core_1',
            },
          ],
        },
      ],
    };
  }

  const signoffPayloadHash = await computeHash(signoffPayload, 'SHA-256');
  const signoffSignature = options?.tamperSignoffSignature
    ? 'a'.repeat(86)
    : await signEd25519(
      reviewerKey.privateKey,
      new TextEncoder().encode(signoffPayloadHash),
    );

  const payload = {
    bundle_version: '1',
    bundle_id: 'bundle_signoff_core_1',
    agent_did: agentDid,
    event_chain: [
      {
        ...eventCanonical,
        event_hash_b64u,
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
          issued_at: '2026-03-21T05:11:00.000Z',
        },
      ],
    },
  };

  const payloadHash = await computeHash(payload, 'SHA-256');
  const envelope = {
    envelope_version: '1',
    envelope_type: 'proof_bundle',
    payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256',
    signature_b64u: await signEd25519(agentKey.privateKey, new TextEncoder().encode(payloadHash)),
    algorithm: 'Ed25519',
    signer_did: agentDid,
    issued_at: '2026-03-21T05:12:00.000Z',
  };

  return envelope;
}

describe('AF2-REV-003 core verifier reviewer signoff/dispute binding', () => {
  it('surfaces valid reviewer signoff + dispute state in component_results', async () => {
    const envelope = await buildProofBundleEnvelope({ dispute: true });

    const out = await verifyProofBundle(envelope);
    expect(out.result.status).toBe('VALID');
    expect(out.result.component_results?.reviewer_signoff_present).toBe(true);
    expect(out.result.component_results?.reviewer_signoff_valid).toBe(true);
    expect(out.result.component_results?.reviewer_signoff_receipts_count).toBe(1);
    expect(out.result.component_results?.reviewer_signoff_decision_counts).toEqual({
      approve: 1,
      reject: 0,
      needs_changes: 0,
    });
    expect(out.result.component_results?.reviewer_dispute_present).toBe(true);
    expect(out.result.component_results?.reviewer_dispute_note_count).toBe(1);
    expect(out.result.component_results?.reviewer_dispute_evidence_refs_count).toBe(1);
  });

  it('fails closed when reviewer signoff run binding mismatches payload.event_chain run_id', async () => {
    const envelope = await buildProofBundleEnvelope({ tamperRunId: true });

    const out = await verifyProofBundle(envelope);
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('RECEIPT_BINDING_MISMATCH');
    expect(out.error?.field).toBe(
      'payload.metadata.reviewer_signoff_receipts[0].payload.binding.run_id',
    );
  });

  it('fails closed when reviewer signoff signature verification fails', async () => {
    const envelope = await buildProofBundleEnvelope({ tamperSignoffSignature: true });

    const out = await verifyProofBundle(envelope);
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('SIGNATURE_INVALID');
    expect(out.error?.field).toBe(
      'payload.metadata.reviewer_signoff_receipts[0].signature_b64u',
    );
  });

  it('prioritizes signature failure over revocation claims in tampered reviewer receipts', async () => {
    const envelope = await buildProofBundleEnvelope({
      revokeReviewer: true,
      tamperSignoffSignature: true,
    });

    const out = await verifyProofBundle(envelope);
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('SIGNATURE_INVALID');
    expect(out.error?.field).toBe(
      'payload.metadata.reviewer_signoff_receipts[0].signature_b64u',
    );
  });
});
