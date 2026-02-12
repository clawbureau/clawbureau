import { describe, expect, it } from 'vitest';
import { __test } from '../src/index';

describe('clawdelegate validation helpers', () => {
  it('normalizes aud and scope deterministically', () => {
    expect(__test.normalizeAud([' clawproxy.com ', 'clawproxy.com', 'clawbounties.com'])).toEqual([
      'clawbounties.com',
      'clawproxy.com',
    ]);

    expect(__test.normalizeScope([' clawbounties:bounty:create ', 'clawbounties:bounty:create', 'clawproxy:invoke'])).toEqual([
      'clawbounties:bounty:create',
      'clawproxy:invoke',
    ]);
  });

  it('parses ttl and minor-unit values', () => {
    expect(__test.parseTtlSeconds(300)).toBe(300);
    expect(__test.parseMinorString('0', 'spend_cap_minor')).toBe(0n);
    expect(__test.parsePositiveMinorString('1', 'amount_minor')).toBe(1n);
  });
});
