import { getPublicKey, sign } from '@noble/ed25519';
import { base64UrlDecode, base64UrlEncode } from './utils';

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58enc(bytes: Uint8Array): string {
  let zeros = 0;
  for (const b of bytes) { if (b !== 0) break; zeros++; }
  let num = BigInt(0);
  for (const b of bytes) num = num * 256n + BigInt(b);
  const chars: string[] = [];
  while (num > 0n) { chars.unshift(B58[Number(num % 58n)]!); num /= 58n; }
  for (let i = 0; i < zeros; i++) chars.unshift('1');
  return chars.join('');
}

export async function importOracleKey(seedB64u: string): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array; did: string }> {
  const seed = base64UrlDecode(seedB64u);
  if (seed.length !== 32) throw new Error('ORACLE_SIGNING_KEY must be 32-byte Ed25519 seed');
  const pub = getPublicKey(seed);
  const mc = new Uint8Array(2 + pub.length);
  mc[0] = 0xed; mc[1] = 0x01; mc.set(pub, 2);
  return { publicKey: pub, privateKey: seed, did: `did:key:z${b58enc(mc)}` };
}

export async function signWithOracleKey(pk: Uint8Array, msg: string): Promise<string> {
  return base64UrlEncode(sign(new TextEncoder().encode(msg), pk));
}
