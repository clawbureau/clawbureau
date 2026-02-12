/**
 * Cryptographic helpers for clawcuts
 */

/**
 * Encode bytes to base64url (RFC 4648).
 */
export function base64urlEncode(data: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...data));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Compute SHA-256 digest of a UTF-8 string and return the raw bytes.
 */
export async function sha256BytesUtf8(input: string): Promise<Uint8Array> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(digest);
}

/**
 * Compute SHA-256 digest of a UTF-8 string and return base64url.
 */
export async function sha256B64uUtf8(input: string): Promise<string> {
  const bytes = await sha256BytesUtf8(input);
  return base64urlEncode(bytes);
}
