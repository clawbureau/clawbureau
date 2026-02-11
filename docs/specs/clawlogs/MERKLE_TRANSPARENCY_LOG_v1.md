> **Type:** Spec
> **Status:** ACTIVE
> **Owner:** @clawbureau/core
> **Last reviewed:** 2026-02-11

# clawlogs Merkle Transparency Log — v1

This document defines the exact Merkle construction and inclusion-proof verification algorithm used by `services/clawlogs`.

## 1) Leaf model

- Input leaves are caller-supplied `leaf_hash_b64u` strings.
- `leaf_hash_b64u` MUST be base64url and decode to non-empty bytes.
- For deterministic `GET /proof/:leaf_hash_b64u`, duplicate leaf hashes are rejected at append time.

## 2) Merkle construction

Given leaves `L[0..n-1]` (decoded bytes):

- Parent hash function:
  - `P = SHA-256(left || right)`
- Odd-node rule:
  - if a level has odd length, duplicate the last node (`right = left`)
- Root for empty tree:
  - `SHA-256(empty_bytes)`

Pseudocode:

```text
level = leaves
if level.length == 0:
  return sha256("")

while level.length > 1:
  next = []
  for i in range(0, level.length, 2):
    left = level[i]
    right = level[i+1] if i+1 < level.length else level[i]
    next.push(sha256(left || right))
  level = next

return level[0]
```

## 3) Inclusion proof encoding (`log_inclusion_proof.v1`)

`audit_path[]` is ordered from leaf-level sibling upward to root-level sibling.

Proof-by-hash does not include `leaf_index` in top-level schema, so `clawlogs` emits it in:

```json
{
  "metadata": {
    "leaf_index": 3,
    "merkle_algorithm": "sha256(left||right), duplicate-last for odd levels"
  }
}
```

`leaf_index` is required by verifiers that use ordered left/right hashing.

## 4) Proof verification

Given:
- `leaf_hash_b64u`
- `tree_size`
- `audit_path[]`
- `metadata.leaf_index`
- `root_hash_b64u`

Algorithm:

```text
h = decode(leaf_hash_b64u)
idx = leaf_index

for sibling_hash in audit_path:
  s = decode(sibling_hash)
  if idx % 2 == 0:
    h = sha256(h || s)
  else:
    h = sha256(s || h)
  idx = floor(idx / 2)

valid iff base64url(h) == root_hash_b64u
```

Additional checks:
- `0 <= leaf_index < tree_size`
- `audit_path.length == expected_height(tree_size)` where:

```text
n = tree_size
height = 0
while n > 1:
  n = floor((n + 1) / 2)
  height += 1
```

## 5) Signed roots

`GET /root` and `GET /proof` expose a root signature:

- Signing input: UTF-8 bytes of `root_hash_b64u` string
- Algorithm: `Ed25519`
- Signer identity: `did:key` derived from `LOGS_SIGNING_KEY`

Verification step:

```text
verify_ed25519(root_signature.sig_b64u, message=root_hash_b64u, public_key=did:key signer)
```

If signature verification fails, inclusion proof verification MUST fail closed.
