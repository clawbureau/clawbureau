import { describe, expect, it } from 'vitest';

import golden from '../../../packages/schema/fixtures/log_inclusion_proof_golden.v1.json';
import { verifyLogInclusionProof } from '../src/verify-log-inclusion-proof';

type GoldenVector = {
  inclusion_proof_v1: {
    proof_version: '1';
    log_id: string;
    tree_size: number;
    leaf_hash_b64u: string;
    root_hash_b64u: string;
    audit_path: string[];
    root_published_at: string;
    root_signature: {
      signer_did: string;
      sig_b64u: string;
    };
    metadata: {
      leaf_index: number;
      merkle_algorithm: string;
    };
  };
};

const vector = golden as GoldenVector;

function mutateB64u(value: string): string {
  const first = value[0] === 'A' ? 'B' : 'A';
  return `${first}${value.slice(1)}`;
}

describe('CVF-US-019: inclusion proof verification', () => {
  it('verifies the golden inclusion proof', async () => {
    const out = await verifyLogInclusionProof(vector.inclusion_proof_v1);
    expect(out.valid).toBe(true);
  });

  it('fails closed when root signature is tampered', async () => {
    const bad = {
      ...vector.inclusion_proof_v1,
      root_signature: {
        ...vector.inclusion_proof_v1.root_signature,
        sig_b64u: mutateB64u(vector.inclusion_proof_v1.root_signature.sig_b64u),
      },
    };

    const out = await verifyLogInclusionProof(bad);
    expect(out.valid).toBe(false);
    expect(out.error?.code).toBe('SIGNATURE_INVALID');
  });

  it('fails closed when audit path is tampered', async () => {
    const bad = {
      ...vector.inclusion_proof_v1,
      audit_path: [...vector.inclusion_proof_v1.audit_path],
    };

    bad.audit_path[0] = `${bad.audit_path[0].slice(0, -1)}A`;

    const out = await verifyLogInclusionProof(bad);
    expect(out.valid).toBe(false);
    expect(out.error?.code).toBe('INCLUSION_PROOF_INVALID');
  });

  it('fails closed when metadata.leaf_index is missing', async () => {
    const bad = {
      ...vector.inclusion_proof_v1,
      metadata: {
        merkle_algorithm: vector.inclusion_proof_v1.metadata.merkle_algorithm,
      },
    };

    const out = await verifyLogInclusionProof(bad);
    expect(out.valid).toBe(false);
    expect(out.error?.code).toBe('INCLUSION_PROOF_INVALID');
    expect(out.error?.field).toBe('metadata.leaf_index');
  });
});
