import { describe, expect, it } from 'vitest';

import golden from '../../../packages/schema/fixtures/log_inclusion_proof_golden.v1.json';
import { verifyEd25519Signature } from '../src/crypto';
import { buildMerkleProof, computeMerkleRootB64u, verifyMerkleProof } from '../src/merkle';

type GoldenVector = {
  leaves: string[];
  target_leaf_hash_b64u: string;
  proof: {
    leaf_hash_b64u: string;
    leaf_index: number;
    tree_size: number;
    audit_path: string[];
    root_hash_b64u: string;
  };
  signed_root: {
    root_hash_b64u: string;
    signer_did: string;
    sig_b64u: string;
  };
};

const vector = golden as GoldenVector;

describe('clawlogs merkle + signature golden vectors', () => {
  it('computes the expected root for golden leaves', async () => {
    const root = await computeMerkleRootB64u(vector.leaves);
    expect(root).toBe(vector.signed_root.root_hash_b64u);
    expect(root).toBe(vector.proof.root_hash_b64u);
  });

  it('builds the expected inclusion proof for the target leaf', async () => {
    const proof = await buildMerkleProof(vector.leaves, vector.target_leaf_hash_b64u);

    expect(proof).toBeTruthy();
    expect(proof?.leaf_hash_b64u).toBe(vector.proof.leaf_hash_b64u);
    expect(proof?.leaf_index).toBe(vector.proof.leaf_index);
    expect(proof?.tree_size).toBe(vector.proof.tree_size);
    expect(proof?.audit_path).toEqual(vector.proof.audit_path);
    expect(proof?.root_hash_b64u).toBe(vector.proof.root_hash_b64u);
  });

  it('verifies the golden inclusion proof successfully', async () => {
    const ok = await verifyMerkleProof(vector.proof);
    expect(ok).toBe(true);
  });

  it('rejects a tampered audit path', async () => {
    const tampered = {
      ...vector.proof,
      audit_path: [...vector.proof.audit_path],
    };

    tampered.audit_path[1] = tampered.audit_path[1]!.slice(0, -1) + 'A';

    const ok = await verifyMerkleProof(tampered);
    expect(ok).toBe(false);
  });

  it('verifies root signature over root_hash_b64u string', async () => {
    const ok = await verifyEd25519Signature(
      vector.signed_root.signer_did,
      vector.signed_root.sig_b64u,
      vector.signed_root.root_hash_b64u,
    );

    expect(ok).toBe(true);
  });

  it('rejects tampered root signature input', async () => {
    const ok = await verifyEd25519Signature(
      vector.signed_root.signer_did,
      vector.signed_root.sig_b64u,
      `${vector.signed_root.root_hash_b64u.slice(0, -1)}A`,
    );

    expect(ok).toBe(false);
  });
});
