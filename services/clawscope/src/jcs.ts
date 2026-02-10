/**
 * RFC 8785 — JSON Canonicalization Scheme (JCS)
 *
 * Produces a deterministic JSON string suitable for hashing/signing.
 */
export function jcsCanonicalize(value: unknown): string {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';

    case 'number':
      if (!Number.isFinite(value)) {
        throw new Error('Non-finite number not allowed in JCS');
      }
      // JSON.stringify() uses the ECMAScript number-to-string algorithm.
      return JSON.stringify(value);

    case 'string':
      return JSON.stringify(value);

    case 'object': {
      if (Array.isArray(value)) {
        return `[${value.map(jcsCanonicalize).join(',')}]`;
      }

      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).sort();
      const parts: string[] = [];

      for (const k of keys) {
        parts.push(`${JSON.stringify(k)}:${jcsCanonicalize(obj[k])}`);
      }

      return `{${parts.join(',')}}`;
    }

    default:
      // undefined | function | symbol | bigint
      throw new Error(`Unsupported value type for JCS: ${typeof value}`);
  }
}
