import * as fs from 'node:fs/promises';

import {
  verifyExportBundle,
  verifyProofBundle,
  type ExportBundlePayload,
  type ProofBundlePayload,
  type SignedEnvelope,
  type VerifyBundleResponse,
  type VerifyExportBundleResponse,
} from '@clawbureau/clawverify-core';

import type { CliKind, CliVerifyOutput, ResolvedVerifierConfig } from './types.js';
import { CliUsageError } from './errors.js';

function nowIso(): string {
  return new Date().toISOString();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

async function readJsonFile(path: string): Promise<unknown> {
  let raw: string;
  try {
    raw = await fs.readFile(path, 'utf8');
  } catch (err) {
    throw new CliUsageError(
      `Could not read input file at ${path}: ${err instanceof Error ? err.message : 'unknown error'}`
    );
  }

  try {
    return JSON.parse(raw) as unknown;
  } catch (err) {
    throw new CliUsageError(
      `Input file is not valid JSON: ${err instanceof Error ? err.message : 'unknown error'}`
    );
  }
}

function unwrapProofBundleInput(value: unknown): unknown {
  if (!isRecord(value)) return value;
  const envelope = value.envelope;
  if (envelope !== undefined) return envelope;
  return value;
}

function unwrapExportBundleInput(value: unknown): unknown {
  if (!isRecord(value)) return value;
  const bundle = value.bundle;
  if (bundle !== undefined) return bundle;
  return value;
}

function countReceiptsFromEnvelope(envelope: unknown): number {
  if (!isRecord(envelope)) return 0;
  const payload = envelope.payload;
  if (!isRecord(payload)) return 0;
  const receipts = payload.receipts;
  if (!Array.isArray(receipts)) return 0;
  return receipts.length;
}

function strictProofBundleReceiptVerdict(opts: {
  envelope: unknown;
  verification: VerifyBundleResponse;
  config: ResolvedVerifierConfig;
}): { ok: true } | { ok: false; reason_code: string; reason: string } {
  const receiptsCount = countReceiptsFromEnvelope(opts.envelope);
  if (receiptsCount === 0) return { ok: true };

  // Fail-closed: if receipts are present, a signer allowlist MUST be configured.
  if (opts.config.gatewayReceiptSignerDids.length === 0) {
    return {
      ok: false,
      reason_code: 'DEPENDENCY_NOT_CONFIGURED',
      reason: 'Gateway receipt signer allowlist not configured (required to verify receipts)',
    };
  }

  const cr = opts.verification.result.component_results;
  const verified = cr?.receipts_verified_count ?? 0;
  const sigVerified = cr?.receipts_signature_verified_count ?? 0;

  // Conformance mode: all receipts must verify and be bound.
  if (verified !== receiptsCount) {
    if (sigVerified === receiptsCount) {
      return {
        ok: false,
        reason_code: 'RECEIPT_BINDING_MISMATCH',
        reason: 'One or more receipts are not bound to the proof bundle event chain',
      };
    }

    return {
      ok: false,
      reason_code: 'RECEIPT_VERIFICATION_FAILED',
      reason: 'One or more receipts failed cryptographic verification',
    };
  }

  return { ok: true };
}

export async function verifyProofBundleFromFile(opts: {
  inputPath: string;
  /** Optional URM path. If not provided, clawverify will try to auto-load a sibling "-urm.json" file for "-bundle.json" inputs. */
  urmPath?: string;
  configPath?: string;
  config: ResolvedVerifierConfig;
}): Promise<CliVerifyOutput> {
  const verifiedAt = nowIso();

  const raw = await readJsonFile(opts.inputPath);
  const envelope = unwrapProofBundleInput(raw) as SignedEnvelope<ProofBundlePayload>;

  // Optional: load URM from an explicit flag, or auto-detect a sibling file for canonical PoH evidence packs.
  let resolvedUrmPath: string | undefined = opts.urmPath;

  if (!resolvedUrmPath && opts.inputPath.endsWith('-bundle.json')) {
    const candidate = opts.inputPath.replace(/-bundle\.json$/, '-urm.json');
    try {
      await fs.access(candidate);
      resolvedUrmPath = candidate;
    } catch {
      // ignore
    }
  }

  const urm = resolvedUrmPath ? await readJsonFile(resolvedUrmPath) : undefined;

  const input = {
    path: opts.inputPath,
    config_path: opts.configPath,
    urm_path: resolvedUrmPath,
  };

  const verification = await verifyProofBundle(envelope, {
    allowlistedReceiptSignerDids: opts.config.gatewayReceiptSignerDids,
    allowlistedAttesterDids: opts.config.attestationSignerDids,
    urm,
  });

  if (verification.result.status !== 'VALID') {
    return {
      kind: 'proof_bundle',
      status: 'FAIL',
      verified_at: verifiedAt,
      reason_code: verification.error?.code ?? 'INVALID',
      reason: verification.error?.message ?? verification.result.reason,
      input,
      verification,
    };
  }

  const strict = strictProofBundleReceiptVerdict({
    envelope,
    verification,
    config: opts.config,
  });

  if (!strict.ok) {
    return {
      kind: 'proof_bundle',
      status: 'FAIL',
      verified_at: verifiedAt,
      reason_code: strict.reason_code,
      reason: strict.reason,
      input,
      verification,
    };
  }

  return {
    kind: 'proof_bundle',
    status: 'PASS',
    verified_at: verifiedAt,
    reason_code: 'OK',
    reason: 'Proof bundle verified successfully',
    input,
    verification,
  };
}

export async function verifyExportBundleFromFile(opts: {
  inputPath: string;
  configPath?: string;
  config: ResolvedVerifierConfig;
}): Promise<CliVerifyOutput> {
  const verifiedAt = nowIso();

  const raw = await readJsonFile(opts.inputPath);
  const bundle = unwrapExportBundleInput(raw) as ExportBundlePayload;

  const verification: VerifyExportBundleResponse = await verifyExportBundle(bundle, {
    allowlistedReceiptSignerDids: opts.config.gatewayReceiptSignerDids,
    allowlistedAttesterDids: opts.config.attestationSignerDids,
    allowlistedExecutionAttestationSignerDids: opts.config.executionAttestationSignerDids,
    allowlistedDerivationAttestationSignerDids: opts.config.derivationAttestationSignerDids,
    allowlistedAuditResultAttestationSignerDids: opts.config.auditResultAttestationSignerDids,
  });

  if (verification.result.status !== 'VALID') {
    return {
      kind: 'export_bundle',
      status: 'FAIL',
      verified_at: verifiedAt,
      reason_code: verification.error?.code ?? 'INVALID',
      reason: verification.error?.message ?? verification.result.reason,
      input: {
        path: opts.inputPath,
        config_path: opts.configPath,
      },
      verification,
    };
  }

  // Optional strict receipt enforcement for nested proof bundle.
  const nestedProofEnvelope = (bundle as any)?.artifacts?.proof_bundle_envelope;
  if (nestedProofEnvelope !== undefined) {
    const proofOut = await verifyProofBundle(nestedProofEnvelope, {
      allowlistedReceiptSignerDids: opts.config.gatewayReceiptSignerDids,
      allowlistedAttesterDids: opts.config.attestationSignerDids,
    });

    if (proofOut.result.status !== 'VALID') {
      return {
        kind: 'export_bundle',
        status: 'FAIL',
        verified_at: verifiedAt,
        reason_code: proofOut.error?.code ?? 'INVALID',
        reason: `Nested proof bundle verification failed: ${proofOut.error?.message ?? proofOut.result.reason}`,
        input: {
          path: opts.inputPath,
          config_path: opts.configPath,
        },
        verification: {
          export_bundle: verification,
          proof_bundle: proofOut,
        },
      };
    }

    const strict = strictProofBundleReceiptVerdict({
      envelope: nestedProofEnvelope,
      verification: proofOut,
      config: opts.config,
    });

    if (!strict.ok) {
      return {
        kind: 'export_bundle',
        status: 'FAIL',
        verified_at: verifiedAt,
        reason_code: strict.reason_code,
        reason: strict.reason,
        input: {
          path: opts.inputPath,
          config_path: opts.configPath,
        },
        verification: {
          export_bundle: verification,
          proof_bundle: proofOut,
        },
      };
    }
  }

  return {
    kind: 'export_bundle',
    status: 'PASS',
    verified_at: verifiedAt,
    reason_code: 'OK',
    reason: 'Export bundle verified successfully',
    input: {
      path: opts.inputPath,
      config_path: opts.configPath,
    },
    verification,
  };
}

export function exitCodeForOutput(out: { status: string }): number {
  if (out.status === 'PASS') return 0;
  if (out.status === 'FAIL') return 1;
  return 2;
}

// ---------------------------------------------------------------------------
// commit-sig verification (did-work Protocol M)
// ---------------------------------------------------------------------------

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Decode(str: string): Uint8Array {
  const bytes: number[] = [0];
  for (const char of str) {
    const value = BASE58_ALPHABET.indexOf(char);
    if (value === -1) throw new Error(`Invalid base58 character: ${char}`);
    for (let i = 0; i < bytes.length; i++) bytes[i] *= 58;
    bytes[0] += value;
    let carry = 0;
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] += carry;
      carry = bytes[i] >> 8;
      bytes[i] &= 0xff;
    }
    while (carry) { bytes.push(carry & 0xff); carry >>= 8; }
  }
  for (const char of str) { if (char !== '1') break; bytes.push(0); }
  return new Uint8Array(bytes.reverse());
}

function extractEd25519PublicKeyFromDidKey(did: string): Uint8Array | null {
  if (!did.startsWith('did:key:z')) return null;
  try {
    const decoded = base58Decode(did.slice(9));
    if (decoded[0] === 0xed && decoded[1] === 0x01) return decoded.slice(2);
    return null;
  } catch { return null; }
}

/** RFC 8785 JSON Canonicalization Scheme (JCS) */
function jcsCanonicalize(value: unknown): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean': return value ? 'true' : 'false';
    case 'number': {
      if (!Number.isFinite(value)) throw new Error('Non-finite number not allowed in JCS');
      return JSON.stringify(value);
    }
    case 'string': return JSON.stringify(value);
    case 'object': {
      if (Array.isArray(value)) return `[${value.map(jcsCanonicalize).join(',')}]`;
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).sort();
      const parts: string[] = [];
      for (const k of keys) parts.push(`${JSON.stringify(k)}:${jcsCanonicalize(obj[k])}`);
      return `{${parts.join(',')}}`;
    }
    default: throw new Error(`Unsupported value type for JCS: ${typeof value}`);
  }
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buf = bytes.buffer;
  if (buf instanceof ArrayBuffer) return buf.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

export async function verifyCommitSigFromFile(opts: {
  inputPath: string;
}): Promise<CliVerifyOutput> {
  const verifiedAt = nowIso();

  const raw = await readJsonFile(opts.inputPath);
  if (!isRecord(raw)) {
    return {
      kind: 'commit_sig', status: 'FAIL', verified_at: verifiedAt,
      reason_code: 'MALFORMED_ENVELOPE', reason: 'commit.sig.json must be a JSON object',
      input: { path: opts.inputPath },
    };
  }

  const { version, type, algo, did, message, signature } = raw as Record<string, unknown>;

  if (version !== 'm1') {
    return {
      kind: 'commit_sig', status: 'FAIL', verified_at: verifiedAt,
      reason_code: 'UNKNOWN_VERSION', reason: `Unsupported version: ${String(version)}`,
      input: { path: opts.inputPath },
    };
  }
  if (type !== 'message_signature') {
    return {
      kind: 'commit_sig', status: 'FAIL', verified_at: verifiedAt,
      reason_code: 'UNKNOWN_TYPE', reason: `Unsupported type: ${String(type)}`,
      input: { path: opts.inputPath },
    };
  }
  if (algo !== 'ed25519') {
    return {
      kind: 'commit_sig', status: 'FAIL', verified_at: verifiedAt,
      reason_code: 'UNKNOWN_ALGO', reason: `Unsupported algo: ${String(algo)}`,
      input: { path: opts.inputPath },
    };
  }

  const commitMatch = String(message ?? '').match(/^commit:([a-f0-9]{7,64})$/i);
  if (!commitMatch) {
    return {
      kind: 'commit_sig', status: 'FAIL', verified_at: verifiedAt,
      reason_code: 'COMMIT_MESSAGE_INVALID',
      reason: 'Invalid message format (expected "commit:<sha>")',
      input: { path: opts.inputPath },
      verification: { signer_did: typeof did === 'string' ? did : undefined },
    };
  }
  const commitSha = commitMatch[1];

  const publicKeyBytes = typeof did === 'string' ? extractEd25519PublicKeyFromDidKey(did) : null;
  if (!publicKeyBytes) {
    return {
      kind: 'commit_sig', status: 'FAIL', verified_at: verifiedAt,
      reason_code: 'INVALID_DID_FORMAT',
      reason: 'Unsupported DID format (expected did:key with Ed25519 multicodec)',
      input: { path: opts.inputPath },
      verification: { commit_sha: commitSha, signer_did: typeof did === 'string' ? did : undefined },
    };
  }

  if (typeof signature !== 'string' || signature.length === 0) {
    return {
      kind: 'commit_sig', status: 'FAIL', verified_at: verifiedAt,
      reason_code: 'MALFORMED_ENVELOPE', reason: 'Missing signature field',
      input: { path: opts.inputPath },
      verification: { commit_sha: commitSha, signer_did: did as string },
    };
  }

  let sigBytes: Uint8Array;
  try {
    const binary = atob(signature);
    sigBytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) sigBytes[i] = binary.charCodeAt(i);
  } catch {
    return {
      kind: 'commit_sig', status: 'FAIL', verified_at: verifiedAt,
      reason_code: 'MALFORMED_ENVELOPE', reason: 'Invalid base64 signature',
      input: { path: opts.inputPath },
      verification: { commit_sha: commitSha, signer_did: did as string },
    };
  }
  if (sigBytes.length !== 64) {
    return {
      kind: 'commit_sig', status: 'FAIL', verified_at: verifiedAt,
      reason_code: 'MALFORMED_ENVELOPE', reason: 'Signature must be 64 bytes',
      input: { path: opts.inputPath },
      verification: { commit_sha: commitSha, signer_did: did as string },
    };
  }

  // Protocol M: sign JCS-canonicalized envelope with signature=""
  let canonical: string;
  try {
    canonical = jcsCanonicalize({ ...raw, signature: '' });
  } catch (err) {
    return {
      kind: 'commit_sig', status: 'FAIL', verified_at: verifiedAt,
      reason_code: 'CANONICALIZATION_ERROR',
      reason: err instanceof Error ? err.message : 'Canonicalization failed',
      input: { path: opts.inputPath },
      verification: { commit_sha: commitSha, signer_did: did as string },
    };
  }

  const msgBytes = new TextEncoder().encode(canonical);

  try {
    const publicKey = await crypto.subtle.importKey(
      'raw', toArrayBuffer(publicKeyBytes), { name: 'Ed25519' }, false, ['verify'],
    );
    const ok = await crypto.subtle.verify(
      { name: 'Ed25519' }, publicKey, toArrayBuffer(sigBytes), toArrayBuffer(msgBytes),
    );

    return {
      kind: 'commit_sig',
      status: ok ? 'PASS' : 'FAIL',
      verified_at: verifiedAt,
      reason_code: ok ? 'OK' : 'SIGNATURE_INVALID',
      reason: ok ? 'Commit signature verified' : 'Signature verification failed',
      input: { path: opts.inputPath },
      verification: { commit_sha: commitSha, signer_did: did as string, message: String(message) },
    };
  } catch (err) {
    return {
      kind: 'commit_sig', status: 'FAIL', verified_at: verifiedAt,
      reason_code: 'CRYPTO_ERROR',
      reason: err instanceof Error ? err.message : 'Crypto verification error',
      input: { path: opts.inputPath },
      verification: { commit_sha: commitSha, signer_did: did as string },
    };
  }
}

export function kindForSubcommand(cmd: string): CliKind | null {
  if (cmd === 'proof-bundle' || cmd === 'proof_bundle') return 'proof_bundle';
  if (cmd === 'export-bundle' || cmd === 'export_bundle') return 'export_bundle';
  if (cmd === 'commit-sig' || cmd === 'commit_sig') return 'commit_sig';
  return null;
}
