import { base64urlDecode, base64urlEncode, sha256Bytes } from './crypto';

const B64U_RE = /^[A-Za-z0-9_-]+$/;

export interface MerkleProof {
  leaf_hash_b64u: string;
  leaf_index: number;
  tree_size: number;
  audit_path: string[];
  root_hash_b64u: string;
}

export function isBase64urlString(value: unknown, opts?: { minLen?: number; maxLen?: number }): value is string {
  if (typeof value !== 'string') return false;
  if (!B64U_RE.test(value)) return false;
  if (opts?.minLen !== undefined && value.length < opts.minLen) return false;
  if (opts?.maxLen !== undefined && value.length > opts.maxLen) return false;
  return true;
}

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function decodeLeafHash(hash: string): Uint8Array {
  if (!isBase64urlString(hash, { minLen: 8 })) {
    throw new Error('Leaf hash must be base64url with length >= 8');
  }
  const bytes = base64urlDecode(hash);
  if (bytes.length === 0) {
    throw new Error('Leaf hash decodes to empty bytes');
  }
  return bytes;
}

function parentLevel(level: Uint8Array[]): Promise<Uint8Array[]> {
  const pairs: Promise<Uint8Array>[] = [];

  for (let i = 0; i < level.length; i += 2) {
    const left = level[i]!;
    const right = level[i + 1] ?? left; // duplicate-last convention
    pairs.push(sha256Bytes(concatBytes(left, right)));
  }

  return Promise.all(pairs);
}

export async function computeEmptyTreeRootB64u(): Promise<string> {
  return base64urlEncode(await sha256Bytes(new Uint8Array(0)));
}

export async function computeMerkleRootB64u(leafHashesB64u: readonly string[]): Promise<string> {
  if (leafHashesB64u.length === 0) {
    return computeEmptyTreeRootB64u();
  }

  let level = leafHashesB64u.map(decodeLeafHash);

  while (level.length > 1) {
    level = await parentLevel(level);
  }

  return base64urlEncode(level[0]!);
}

export async function buildMerkleProof(
  leafHashesB64u: readonly string[],
  leafHashB64u: string
): Promise<MerkleProof | null> {
  if (leafHashesB64u.length === 0) return null;

  const leafIndex = leafHashesB64u.indexOf(leafHashB64u);
  if (leafIndex === -1) return null;

  const duplicateIndex = leafHashesB64u.indexOf(leafHashB64u, leafIndex + 1);
  if (duplicateIndex !== -1) {
    throw new Error('Leaf hash appears more than once in log; proof-by-hash is ambiguous');
  }

  const auditPath: string[] = [];
  let index = leafIndex;
  let level = leafHashesB64u.map(decodeLeafHash);

  while (level.length > 1) {
    const siblingIndex = index % 2 === 0 ? index + 1 : index - 1;
    const sibling = level[siblingIndex] ?? level[index]!;
    auditPath.push(base64urlEncode(sibling));

    level = await parentLevel(level);
    index = Math.floor(index / 2);
  }

  return {
    leaf_hash_b64u: leafHashB64u,
    leaf_index: leafIndex,
    tree_size: leafHashesB64u.length,
    audit_path: auditPath,
    root_hash_b64u: base64urlEncode(level[0]!),
  };
}

export function expectedAuditPathLength(treeSize: number): number {
  if (!Number.isInteger(treeSize) || treeSize < 0) {
    throw new Error('treeSize must be a non-negative integer');
  }

  let n = treeSize;
  let len = 0;
  while (n > 1) {
    n = Math.floor((n + 1) / 2);
    len += 1;
  }
  return len;
}

export async function verifyMerkleProof(proof: MerkleProof): Promise<boolean> {
  if (!isBase64urlString(proof.leaf_hash_b64u, { minLen: 8 })) return false;
  if (!isBase64urlString(proof.root_hash_b64u, { minLen: 8 })) return false;
  if (!Array.isArray(proof.audit_path)) return false;
  if (!Number.isInteger(proof.tree_size) || proof.tree_size <= 0) return false;
  if (!Number.isInteger(proof.leaf_index) || proof.leaf_index < 0 || proof.leaf_index >= proof.tree_size) return false;

  const expectedLen = expectedAuditPathLength(proof.tree_size);
  if (proof.audit_path.length !== expectedLen) return false;

  if (!proof.audit_path.every((p) => isBase64urlString(p, { minLen: 8 }))) {
    return false;
  }

  let current: Uint8Array;
  try {
    current = decodeLeafHash(proof.leaf_hash_b64u);
  } catch {
    return false;
  }

  let index = proof.leaf_index;
  for (const siblingHash of proof.audit_path) {
    let sibling: Uint8Array;
    try {
      sibling = decodeLeafHash(siblingHash);
    } catch {
      return false;
    }

    current =
      index % 2 === 0
        ? await sha256Bytes(concatBytes(current, sibling))
        : await sha256Bytes(concatBytes(sibling, current));

    index = Math.floor(index / 2);
  }

  const computedRoot = base64urlEncode(current);
  return computedRoot === proof.root_hash_b64u;
}
