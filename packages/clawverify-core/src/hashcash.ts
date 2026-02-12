/**
 * hashcash.ts — Proof-of-Work for VaaS DoS protection
 *
 * Red Team Fix #8: Requires unauthenticated API callers to present a
 * valid PoW token, making volumetric DoS economically infeasible.
 *
 * Uses WebCrypto (crypto.subtle) for Cloudflare Workers compatibility.
 *
 * Challenge format: `${dateHourUTC}:${clientIdentifier}`
 * The client must find a nonce such that SHA-256(challenge + ":" + nonce)
 * has `difficulty` leading zero hex characters.
 *
 * Default difficulty: 4 (approx 65,536 attempts, ~100ms on modern hardware).
 */

/** Default number of leading zero hex chars required. */
export const DEFAULT_POW_DIFFICULTY = 4;

/**
 * Generate the current date-hour challenge component.
 * Format: YYYYMMDDHH (UTC).
 */
export function getDateHourUTC(date?: Date): string {
  const d = date ?? new Date();
  const year = d.getUTCFullYear();
  const month = String(d.getUTCMonth() + 1).padStart(2, '0');
  const day = String(d.getUTCDate()).padStart(2, '0');
  const hour = String(d.getUTCHours()).padStart(2, '0');
  return `${year}${month}${day}${hour}`;
}

/**
 * Build a challenge string from the date-hour and client identifier.
 */
export function buildChallenge(
  clientIdentifier: string,
  date?: Date
): string {
  return `${getDateHourUTC(date)}:${clientIdentifier}`;
}

/**
 * Compute SHA-256 of a string and return hex digest.
 * Uses WebCrypto for CF Workers compatibility.
 */
async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = new Uint8Array(hashBuffer);
  return Array.from(hashArray)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Check if a hex string has the required number of leading zero characters.
 */
function hasLeadingZeros(hex: string, difficulty: number): boolean {
  if (hex.length < difficulty) return false;
  for (let i = 0; i < difficulty; i++) {
    if (hex[i] !== '0') return false;
  }
  return true;
}

/**
 * Find a nonce such that SHA-256(challenge + ":" + nonce) has `difficulty`
 * leading zero hex characters.
 *
 * @param challenge  The challenge string (e.g. "2026021223:192.168.1.1")
 * @param difficulty Number of leading zero hex chars required (default: 4)
 * @returns          The nonce string that satisfies the PoW
 */
export async function generatePoW(
  challenge: string,
  difficulty: number = DEFAULT_POW_DIFFICULTY
): Promise<string> {
  if (difficulty < 1 || difficulty > 16) {
    throw new Error(
      `PoW difficulty must be between 1 and 16, got ${difficulty}`
    );
  }

  for (let nonce = 0; ; nonce++) {
    const candidate = `${challenge}:${nonce}`;
    const hex = await sha256Hex(candidate);
    if (hasLeadingZeros(hex, difficulty)) {
      return String(nonce);
    }
  }
}

/**
 * Verify that a nonce satisfies the PoW requirement.
 *
 * @param challenge  The challenge string
 * @param nonce      The claimed nonce
 * @param difficulty Number of leading zero hex chars required (default: 4)
 * @returns          true if the PoW is valid
 */
export async function verifyPoW(
  challenge: string,
  nonce: string,
  difficulty: number = DEFAULT_POW_DIFFICULTY
): Promise<boolean> {
  if (difficulty < 1 || difficulty > 16) return false;

  // Reject non-numeric or excessively long nonces
  if (!/^\d{1,15}$/.test(nonce)) return false;

  const candidate = `${challenge}:${nonce}`;
  const hex = await sha256Hex(candidate);
  return hasLeadingZeros(hex, difficulty);
}
