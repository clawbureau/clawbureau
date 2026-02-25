/**
 * EPV-003: clawsig inspect — proof bundle inspection and decryption.
 *
 * Provides:
 * - Public layer summary for v1 and v2 bundles (no keys needed)
 * - Encrypted payload decryption for v2 bundles (requires authorized identity)
 *
 * Fail-closed: all crypto/integrity failures throw with clear error codes.
 */

import { readFile } from 'node:fs/promises';
import {
  createX25519PrivateKeyFromEd25519Jwk,
  unwrapContentKey,
  decryptAndVerifyPayload,
} from './epv-crypto.js';
import type {
  EncryptedPayloadFields,
  ViewerKeyEntry,
} from './epv-crypto.js';

// Type-only import: does not trigger module resolution at runtime.
// The runtime import of identity.ts is dynamic (in runInspect) to avoid
// pulling in @clawbureau/clawsig-sdk at module load time.
import type { ClawsigIdentity } from './identity.js';

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

export type InspectErrorCode =
  | 'INSPECT_FILE_NOT_FOUND'
  | 'INSPECT_INVALID_BUNDLE'
  | 'INSPECT_V1_NO_DECRYPT'
  | 'INSPECT_NO_IDENTITY'
  | 'INSPECT_NOT_AUTHORIZED'
  | 'INSPECT_CRYPTO_FAILURE'
  | 'INSPECT_INTEGRITY_FAILURE';

export class InspectError extends Error {
  constructor(
    public readonly code: InspectErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'InspectError';
  }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface InspectOptions {
  inputPath: string;
  decrypt: boolean;
  json: boolean;
}

export interface PublicLayerSummary {
  bundle_version: string;
  schema_version: string | null;
  visibility: string | null;
  agent_did: string | null;
  signer_did: string | null;
  bundle_id: string | null;
  issued_at: string | null;
  has_encrypted_payload: boolean;
  viewer_count: number;
  viewer_dids: string[];
  viewer_roles: Record<string, string>;
}

export interface InspectResult {
  public_layer: PublicLayerSummary;
  decrypted_payload?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Core logic (testable without filesystem/env)
// ---------------------------------------------------------------------------

/**
 * Extract the public layer summary from a parsed bundle.
 * Works for both v1 and v2 bundles.
 */
export function extractPublicLayer(bundle: Record<string, unknown>): PublicLayerSummary {
  const payload = bundle.payload as Record<string, unknown> | undefined;
  if (!payload || typeof payload !== 'object') {
    throw new InspectError('INSPECT_INVALID_BUNDLE', 'Bundle missing payload object');
  }

  const viewerKeys = Array.isArray(payload.viewer_keys)
    ? (payload.viewer_keys as ViewerKeyEntry[])
    : [];

  const viewerRoles: Record<string, string> = {};
  for (const vk of viewerKeys) {
    if (vk.viewer_did && vk.role) {
      viewerRoles[vk.viewer_did] = vk.role;
    }
  }

  return {
    bundle_version: String(payload.bundle_version ?? '1'),
    schema_version: (payload.schema_version as string) ?? null,
    visibility: (payload.visibility as string) ?? null,
    agent_did: (payload.agent_did as string) ?? null,
    signer_did: (bundle.signer_did as string) ?? null,
    bundle_id: (payload.bundle_id as string) ?? null,
    issued_at: (bundle.issued_at as string) ?? null,
    has_encrypted_payload: payload.encrypted_payload !== undefined,
    viewer_count: viewerKeys.length,
    viewer_dids: viewerKeys.map((vk) => vk.viewer_did),
    viewer_roles: viewerRoles,
  };
}

/**
 * Decrypt an encrypted v2 bundle payload using the given identity.
 *
 * Steps:
 *   1. Validate bundle is v2 with encrypted_payload
 *   2. Find viewer_key entry matching identity DID
 *   3. Create X25519 private key from Ed25519 identity
 *   4. Unwrap content key
 *   5. Decrypt and verify payload integrity
 *
 * Fail-closed on all error paths.
 */
export function decryptBundle(
  bundle: Record<string, unknown>,
  identity: ClawsigIdentity,
): Record<string, unknown> {
  const payload = bundle.payload as Record<string, unknown>;

  // Must be v2
  const version = String(payload.bundle_version ?? '1');
  if (version !== '2') {
    throw new InspectError(
      'INSPECT_V1_NO_DECRYPT',
      `Cannot decrypt a v${version} bundle. Decryption requires a v2 bundle with encrypted payload.`,
    );
  }

  // Must have encrypted_payload
  const encryptedPayload = payload.encrypted_payload as EncryptedPayloadFields | undefined;
  if (!encryptedPayload || typeof encryptedPayload !== 'object') {
    throw new InspectError(
      'INSPECT_INVALID_BUNDLE',
      'v2 bundle is missing encrypted_payload field',
    );
  }

  // Validate encrypted_payload fields
  if (
    !encryptedPayload.ciphertext_b64u ||
    !encryptedPayload.iv_b64u ||
    !encryptedPayload.tag_b64u ||
    !encryptedPayload.plaintext_hash_b64u
  ) {
    throw new InspectError(
      'INSPECT_INVALID_BUNDLE',
      'encrypted_payload is missing required fields (ciphertext_b64u, iv_b64u, tag_b64u, plaintext_hash_b64u)',
    );
  }

  // Find viewer_key for our DID
  const viewerKeys = Array.isArray(payload.viewer_keys)
    ? (payload.viewer_keys as ViewerKeyEntry[])
    : [];

  const myEntry = viewerKeys.find((vk) => vk.viewer_did === identity.did);
  if (!myEntry) {
    throw new InspectError(
      'INSPECT_NOT_AUTHORIZED',
      `Identity DID ${identity.did} is not listed in viewer_keys. ` +
      `Authorized viewers: ${viewerKeys.map((vk) => vk.viewer_did).join(', ') || 'none'}`,
    );
  }

  // Validate viewer key entry fields
  if (
    !myEntry.ephemeral_public_key_b64u ||
    !myEntry.wrapped_key_b64u ||
    !myEntry.wrapped_key_iv_b64u ||
    !myEntry.wrapped_key_tag_b64u
  ) {
    throw new InspectError(
      'INSPECT_INVALID_BUNDLE',
      'Viewer key entry is missing required fields',
    );
  }

  // Create X25519 private key from Ed25519 identity
  let x25519PrivateKey;
  try {
    x25519PrivateKey = createX25519PrivateKeyFromEd25519Jwk(
      identity.privateKeyJwk,
      identity.publicKeyJwk,
    );
  } catch (err) {
    throw new InspectError(
      'INSPECT_CRYPTO_FAILURE',
      `Failed to derive X25519 key from identity: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  // Unwrap content key
  let contentKey: Buffer;
  try {
    contentKey = unwrapContentKey(x25519PrivateKey, myEntry);
  } catch (err) {
    throw new InspectError(
      'INSPECT_CRYPTO_FAILURE',
      `Failed to unwrap content key: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  // Decrypt and verify payload
  try {
    return decryptAndVerifyPayload(contentKey, encryptedPayload);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes('hash mismatch')) {
      throw new InspectError('INSPECT_INTEGRITY_FAILURE', msg);
    }
    throw new InspectError(
      'INSPECT_CRYPTO_FAILURE',
      `Failed to decrypt payload: ${msg}`,
    );
  } finally {
    contentKey.fill(0);
  }
}

// ---------------------------------------------------------------------------
// CLI handler
// ---------------------------------------------------------------------------

/**
 * Run the inspect command. Reads the bundle file, optionally loads identity
 * and decrypts, then outputs results.
 */
export async function runInspect(options: InspectOptions): Promise<void> {
  const { inputPath, decrypt, json } = options;

  // 1. Read bundle file
  let rawJson: string;
  try {
    rawJson = await readFile(inputPath, 'utf-8');
  } catch (err) {
    throw new InspectError(
      'INSPECT_FILE_NOT_FOUND',
      `Cannot read bundle file: ${inputPath} (${err instanceof Error ? err.message : String(err)})`,
    );
  }

  // 2. Parse JSON
  let bundle: Record<string, unknown>;
  try {
    const parsed = JSON.parse(rawJson);
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new Error('not an object');
    }
    bundle = parsed as Record<string, unknown>;
  } catch (err) {
    throw new InspectError(
      'INSPECT_INVALID_BUNDLE',
      `Invalid bundle JSON: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  // 3. Extract public layer
  const publicLayer = extractPublicLayer(bundle);

  // 4. Decrypt if requested
  let decryptedPayload: Record<string, unknown> | undefined;
  if (decrypt) {
    // Dynamic import to avoid pulling in @clawbureau/clawsig-sdk at module load
    const { loadIdentity } = await import('./identity.js');
    const identity = await loadIdentity();
    if (!identity) {
      throw new InspectError(
        'INSPECT_NO_IDENTITY',
        'No persistent identity found. Run `clawsig init` to create one, ' +
        'or set CLAWSIG_IDENTITY to point to an identity file.',
      );
    }

    decryptedPayload = decryptBundle(bundle, identity);
  }

  // 5. Output
  const result: InspectResult = {
    public_layer: publicLayer,
    ...(decryptedPayload !== undefined ? { decrypted_payload: decryptedPayload } : {}),
  };

  if (json) {
    const jsonOut: Record<string, unknown> = {
      status: 'OK',
      ...result,
    };
    process.stdout.write(JSON.stringify(jsonOut, null, 2) + '\n');
  } else {
    printHumanReadable(result, decrypt);
  }
}

// ---------------------------------------------------------------------------
// Human-readable output
// ---------------------------------------------------------------------------

function printHumanReadable(result: InspectResult, decryptRequested: boolean): void {
  const pl = result.public_layer;

  process.stdout.write('\n--- Proof Bundle Inspection ---\n\n');
  process.stdout.write(`  Bundle Version : ${pl.bundle_version}\n`);
  if (pl.schema_version) {
    process.stdout.write(`  Schema Version : ${pl.schema_version}\n`);
  }
  process.stdout.write(`  Bundle ID      : ${pl.bundle_id ?? '(none)'}\n`);
  process.stdout.write(`  Agent DID      : ${pl.agent_did ?? '(none)'}\n`);
  process.stdout.write(`  Signer DID     : ${pl.signer_did ?? '(none)'}\n`);
  process.stdout.write(`  Issued At      : ${pl.issued_at ?? '(none)'}\n`);
  process.stdout.write(`  Visibility     : ${pl.visibility ?? 'public'}\n`);
  process.stdout.write(`  Encrypted      : ${pl.has_encrypted_payload ? 'yes' : 'no'}\n`);

  if (pl.viewer_count > 0) {
    process.stdout.write(`  Viewers (${pl.viewer_count}):\n`);
    for (const did of pl.viewer_dids) {
      const role = pl.viewer_roles[did] ?? 'unknown';
      process.stdout.write(`    - ${did} (${role})\n`);
    }
  }

  if (result.decrypted_payload) {
    process.stdout.write('\n--- Decrypted Payload ---\n\n');
    const keys = Object.keys(result.decrypted_payload);
    for (const key of keys) {
      const val = result.decrypted_payload[key];
      const count = Array.isArray(val) ? val.length : '(object)';
      process.stdout.write(`  ${key}: ${typeof count === 'number' ? `${count} items` : count}\n`);
    }
    process.stdout.write(`\n  (use --json for full decrypted content)\n`);
  } else if (decryptRequested) {
    process.stdout.write('\n  Decryption: not applicable (see error)\n');
  }

  process.stdout.write('\n');
}
