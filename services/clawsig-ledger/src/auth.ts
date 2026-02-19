import { computeHash } from './utils';
import type { Env } from './types';

const DEFAULT_VAAS_POW_DIFFICULTY = 18;
const MIN_VAAS_POW_DIFFICULTY = 4;
const MAX_VAAS_POW_DIFFICULTY = 28;

export interface ApiKeyAuthResult {
  authenticated: boolean;
  error_code?: 'UNAUTHORIZED';
}

function extractApiKey(request: Request): string | null {
  const fromHeader = request.headers.get('X-API-Key')?.trim();
  if (fromHeader) {
    return fromHeader;
  }

  const authHeader = request.headers.get('Authorization');
  if (!authHeader) {
    return null;
  }

  const bearer = authHeader.replace(/^Bearer\s+/i, '').trim();
  return bearer.length > 0 ? bearer : null;
}

function constantTimeEqualStrings(a: string, b: string): boolean {
  const aBytes = new TextEncoder().encode(a);
  const bBytes = new TextEncoder().encode(b);

  const maxLen = Math.max(aBytes.length, bBytes.length);
  let mismatch = aBytes.length ^ bBytes.length;

  for (let i = 0; i < maxLen; i++) {
    mismatch |= (aBytes[i] ?? 0) ^ (bBytes[i] ?? 0);
  }

  return mismatch === 0;
}

export async function authenticateRequestApiKey(
  request: Request,
  env: Pick<Env, 'VAAS_API_KEY_HASH'>
): Promise<ApiKeyAuthResult> {
  const apiKey = extractApiKey(request);
  if (!apiKey) {
    return { authenticated: false };
  }

  const configuredHash = env.VAAS_API_KEY_HASH?.trim();
  if (!configuredHash) {
    return { authenticated: false, error_code: 'UNAUTHORIZED' };
  }

  const apiKeyHash = await computeHash(apiKey);
  if (!constantTimeEqualStrings(apiKeyHash, configuredHash)) {
    return { authenticated: false, error_code: 'UNAUTHORIZED' };
  }

  return { authenticated: true };
}

export function resolvePowDifficulty(rawDifficulty?: string): number {
  if (!rawDifficulty) {
    return DEFAULT_VAAS_POW_DIFFICULTY;
  }

  const parsed = Number.parseInt(rawDifficulty, 10);
  if (!Number.isFinite(parsed)) {
    return DEFAULT_VAAS_POW_DIFFICULTY;
  }

  return Math.min(
    MAX_VAAS_POW_DIFFICULTY,
    Math.max(MIN_VAAS_POW_DIFFICULTY, parsed)
  );
}

export function buildPowChallenge(bundleHashB64u: string): string {
  return `clawsig-ledger:v1:${bundleHashB64u}`;
}

function hasLeadingZeroBits(digest: Uint8Array, difficulty: number): boolean {
  let remaining = difficulty;

  for (const byte of digest) {
    if (remaining <= 0) {
      return true;
    }

    if (remaining >= 8) {
      if (byte !== 0) {
        return false;
      }
      remaining -= 8;
      continue;
    }

    const mask = 0xff << (8 - remaining);
    return (byte & mask) === 0;
  }

  return remaining <= 0;
}

export async function verifyHashcashNonce(
  challenge: string,
  nonce: string,
  difficulty: number
): Promise<boolean> {
  const trimmedNonce = nonce.trim();
  if (trimmedNonce.length === 0 || trimmedNonce.length > 256) {
    return false;
  }

  const payload = `${challenge}:${trimmedNonce}`;
  const digestBuffer = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(payload)
  );

  return hasLeadingZeroBits(new Uint8Array(digestBuffer), difficulty);
}
