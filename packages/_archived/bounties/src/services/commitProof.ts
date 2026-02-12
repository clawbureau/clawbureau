import { CommitSig } from "../types/bounty.js";

/**
 * Extract a commit SHA from a did-work message.
 * Expected format: "commit:<sha>"
 */
export function extractCommitShaFromMessage(message: string): string | null {
  const match = message.match(/^commit:([a-f0-9]{7,64})$/i);
  return match ? match[1] : null;
}

const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Decode(str: string): Uint8Array {
  const bytes: number[] = [0];

  for (const char of str) {
    const value = BASE58_ALPHABET.indexOf(char);
    if (value === -1) {
      throw new Error(`Invalid base58 character: ${char}`);
    }

    for (let i = 0; i < bytes.length; i++) {
      bytes[i] *= 58;
    }
    bytes[0] += value;

    let carry = 0;
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] += carry;
      carry = bytes[i] >> 8;
      bytes[i] &= 0xff;
    }

    while (carry) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }

  // Handle leading zeros
  for (const char of str) {
    if (char !== "1") break;
    bytes.push(0);
  }

  return new Uint8Array(bytes.reverse());
}

/**
 * Extract raw Ed25519 public key bytes from did:key.
 * Expects multibase base58btc (z) and Ed25519 multicodec prefix 0xed01.
 */
function extractEd25519PublicKeyFromDidKey(did: string): Uint8Array | null {
  if (!did.startsWith("did:key:z")) {
    return null;
  }

  try {
    const multibase = did.slice(9);
    const decoded = base58Decode(multibase);

    if (decoded[0] === 0xed && decoded[1] === 0x01) {
      return decoded.slice(2);
    }

    return null;
  } catch {
    return null;
  }
}

function base64DecodeToBytes(b64: string): Uint8Array {
  // did-work currently emits standard base64 (not base64url)
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/** RFC 8785 JSON Canonicalization Scheme (JCS) */
function jcsCanonicalize(value: unknown): string {
  if (value === null) return "null";

  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";

    case "number":
      if (!Number.isFinite(value)) {
        throw new Error("Non-finite number not allowed in JCS");
      }
      return JSON.stringify(value);

    case "string":
      return JSON.stringify(value);

    case "object": {
      if (Array.isArray(value)) {
        return `[${value.map(jcsCanonicalize).join(",")}]`;
      }

      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).sort();
      const parts: string[] = [];

      for (const k of keys) {
        parts.push(`${JSON.stringify(k)}:${jcsCanonicalize(obj[k])}`);
      }

      return `{${parts.join(",")}}`;
    }

    default:
      throw new Error(`Unsupported value type for JCS: ${typeof value}`);
  }
}

export interface VerifyCommitSigResult {
  valid: boolean;
  commit_sha?: string;
  signer_did?: string;
  error?: string;
}

/**
 * Verify a did-work style commit.sig.json.
 *
 * Protocol M: signature is computed over the JCS-canonicalized envelope, with the
 * signature field present and set to the empty string.
 */
export async function verifyCommitSig(commitSig: CommitSig): Promise<VerifyCommitSigResult> {
  const commitSha = extractCommitShaFromMessage(commitSig.message);
  if (!commitSha) {
    return {
      valid: false,
      error: 'Invalid commit signature message format. Expected "commit:<sha>".',
    };
  }

  const publicKeyBytes = extractEd25519PublicKeyFromDidKey(commitSig.did);
  if (!publicKeyBytes) {
    return {
      valid: false,
      commit_sha: commitSha,
      signer_did: commitSig.did,
      error:
        "Unsupported DID format for commit signature. Expected did:key with Ed25519 multicodec.",
    };
  }

  const signatureBytes = base64DecodeToBytes(commitSig.signature);

  let canonical: string;
  try {
    const forSigning = { ...commitSig, signature: "" };
    canonical = jcsCanonicalize(forSigning);
  } catch (err) {
    return {
      valid: false,
      commit_sha: commitSha,
      signer_did: commitSig.did,
      error:
        err instanceof Error
          ? `Canonicalization error: ${err.message}`
          : "Canonicalization error",
    };
  }

  const messageBytes = new TextEncoder().encode(canonical);

  try {
    const publicKey = await crypto.subtle.importKey(
      "raw",
      publicKeyBytes as unknown as BufferSource,
      { name: "Ed25519" },
      false,
      ["verify"]
    );

    const ok = await crypto.subtle.verify(
      { name: "Ed25519" },
      publicKey,
      signatureBytes as unknown as BufferSource,
      messageBytes as unknown as BufferSource
    );

    return {
      valid: ok,
      commit_sha: commitSha,
      signer_did: commitSig.did,
      error: ok ? undefined : "Signature verification failed",
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return {
      valid: false,
      commit_sha: commitSha,
      signer_did: commitSig.did,
      error: `Signature verification error: ${message}`,
    };
  }
}
