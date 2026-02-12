import { describe, expect, it } from 'vitest';
import { __internals } from '../src/index';

describe('clawincome internals', () => {
  it('stableStringify is deterministic by key order', () => {
    const first = __internals.stableStringify({ b: 2, a: { y: false, x: true } });
    const second = __internals.stableStringify({ a: { x: true, y: false }, b: 2 });
    expect(first).toBe(second);
  });

  it('cursor encoding roundtrips', () => {
    const encoded = __internals.encodeCursorIndex(42);
    const decoded = __internals.decodeCursorIndex(encoded);
    expect(decoded).toBe(42);
  });

  it('invalid cursor decodes as null', () => {
    expect(__internals.decodeCursorIndex('not-valid')).toBeNull();
  });

  it('monthRange returns deterministic UTC boundaries', () => {
    const range = __internals.monthRange('2026-02');
    expect(range.startIso).toBe('2026-02-01T00:00:00.000Z');
    expect(range.endIso).toBe('2026-03-01T00:00:00.000Z');
  });

  it('yearRange returns deterministic UTC boundaries', () => {
    const range = __internals.yearRange('2026');
    expect(range.startIso).toBe('2026-01-01T00:00:00.000Z');
    expect(range.endIso).toBe('2027-01-01T00:00:00.000Z');
  });
});
