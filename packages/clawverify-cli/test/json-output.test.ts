import { describe, expect, it, afterEach } from 'vitest';

import {
  isJsonMode,
  stripJsonFlag,
  printJson,
  printJsonError,
} from '../src/json-output.js';
import {
  explainReasonCodeJson,
  hintForReasonCode,
} from '../src/hints.js';

// ---------------------------------------------------------------------------
// Helpers: capture stdout / stderr writes
// ---------------------------------------------------------------------------

function captureStdout(fn: () => void): string {
  const chunks: string[] = [];
  const orig = process.stdout.write;
  process.stdout.write = ((chunk: string) => {
    chunks.push(chunk);
    return true;
  }) as typeof process.stdout.write;
  try {
    fn();
  } finally {
    process.stdout.write = orig;
  }
  return chunks.join('');
}

function captureStderr(fn: () => void): string {
  const chunks: string[] = [];
  const orig = process.stderr.write;
  process.stderr.write = ((chunk: string) => {
    chunks.push(chunk);
    return true;
  }) as typeof process.stderr.write;
  try {
    fn();
  } finally {
    process.stderr.write = orig;
  }
  return chunks.join('');
}

// ---------------------------------------------------------------------------
// isJsonMode
// ---------------------------------------------------------------------------

describe('isJsonMode', () => {
  it('detects --json as the first arg', () => {
    expect(isJsonMode(['--json', 'verify', 'proof-bundle'])).toBe(true);
  });

  it('detects --json after the subcommand', () => {
    expect(isJsonMode(['verify', '--json', 'proof-bundle'])).toBe(true);
  });

  it('detects --json as the last flag arg before --', () => {
    expect(isJsonMode(['wrap', '--json', '--', 'node', 'agent.js'])).toBe(true);
  });

  it('detects --json between other flags', () => {
    expect(isJsonMode(['verify', 'proof-bundle', '--json', '--input', 'b.json'])).toBe(true);
  });

  it('returns false when --json is absent', () => {
    expect(isJsonMode(['verify', 'proof-bundle', '--input', 'b.json'])).toBe(false);
  });

  it('returns false for empty args', () => {
    expect(isJsonMode([])).toBe(false);
  });

  it('returns false when --json appears only after -- separator', () => {
    expect(isJsonMode(['wrap', '--', 'node', '--json'])).toBe(false);
  });

  it('returns false for --jsonl or --json-lines (strict match)', () => {
    expect(isJsonMode(['verify', '--jsonl'])).toBe(false);
    expect(isJsonMode(['verify', '--json-lines'])).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// stripJsonFlag
// ---------------------------------------------------------------------------

describe('stripJsonFlag', () => {
  it('removes --json from a simple arg list', () => {
    expect(stripJsonFlag(['--json', 'verify'])).toEqual(['verify']);
  });

  it('removes --json from the middle', () => {
    expect(stripJsonFlag(['verify', '--json', '--input', 'b.json'])).toEqual([
      'verify',
      '--input',
      'b.json',
    ]);
  });

  it('does not remove --json after -- separator', () => {
    expect(stripJsonFlag(['wrap', '--json', '--', 'node', '--json'])).toEqual([
      'wrap',
      '--',
      'node',
      '--json',
    ]);
  });

  it('returns args unchanged when --json is absent', () => {
    const args = ['verify', 'proof-bundle', '--input', 'b.json'];
    expect(stripJsonFlag(args)).toEqual(args);
  });

  it('removes all occurrences of --json before --', () => {
    expect(stripJsonFlag(['--json', 'wrap', '--json', '--', 'cmd'])).toEqual([
      'wrap',
      '--',
      'cmd',
    ]);
  });

  it('handles args with no -- separator', () => {
    expect(stripJsonFlag(['explain', '--json', 'HASH_MISMATCH'])).toEqual([
      'explain',
      'HASH_MISMATCH',
    ]);
  });
});

// ---------------------------------------------------------------------------
// printJson
// ---------------------------------------------------------------------------

describe('printJson', () => {
  it('outputs valid JSON to stdout', () => {
    const raw = captureStdout(() => printJson({ result: 'PASS', count: 42 }));
    const parsed = JSON.parse(raw);
    expect(parsed).toEqual({ result: 'PASS', count: 42 });
  });

  it('outputs pretty-printed JSON (indented)', () => {
    const raw = captureStdout(() => printJson({ a: 1 }));
    expect(raw).toContain('\n');
    expect(raw).toContain('  ');
  });

  it('ends with a single newline', () => {
    const raw = captureStdout(() => printJson({ ok: true }));
    expect(raw.endsWith('\n')).toBe(true);
    expect(raw.endsWith('\n\n')).toBe(false);
  });

  it('does not contain ANSI escape codes', () => {
    const raw = captureStdout(() =>
      printJson({ message: 'test', code: 'OK' }),
    );
    // eslint-disable-next-line no-control-regex
    expect(raw).not.toMatch(/\x1b\[/);
  });

  it('handles null, arrays, and nested objects', () => {
    const data = { arr: [1, 2], nested: { key: null } };
    const raw = captureStdout(() => printJson(data));
    expect(JSON.parse(raw)).toEqual(data);
  });
});

// ---------------------------------------------------------------------------
// printJsonError
// ---------------------------------------------------------------------------

describe('printJsonError', () => {
  const savedExitCode = process.exitCode;
  afterEach(() => {
    process.exitCode = savedExitCode;
  });

  it('outputs error JSON to stderr', () => {
    process.exitCode = 2;
    const raw = captureStderr(() =>
      printJsonError({ code: 'USAGE_ERROR', message: 'Missing --input' }),
    );
    const parsed = JSON.parse(raw);
    expect(parsed.error).toBe(true);
    expect(parsed.code).toBe('USAGE_ERROR');
    expect(parsed.message).toBe('Missing --input');
    expect(parsed.exit_code).toBe(2);
  });

  it('includes details when provided', () => {
    process.exitCode = 1;
    const raw = captureStderr(() =>
      printJsonError({
        code: 'INTERNAL_ERROR',
        message: 'boom',
        details: { stack: 'trace' },
      }),
    );
    const parsed = JSON.parse(raw);
    expect(parsed.details).toEqual({ stack: 'trace' });
  });

  it('does not include details key when undefined', () => {
    process.exitCode = 2;
    const raw = captureStderr(() =>
      printJsonError({ code: 'CONFIG_ERROR', message: 'bad config' }),
    );
    const parsed = JSON.parse(raw);
    expect(parsed).not.toHaveProperty('details');
  });

  it('defaults exit_code to 2 when process.exitCode is unset', () => {
    process.exitCode = undefined;
    const raw = captureStderr(() =>
      printJsonError({ code: 'USAGE_ERROR', message: 'test' }),
    );
    expect(JSON.parse(raw).exit_code).toBe(2);
  });

  it('does not contain ANSI escape codes', () => {
    process.exitCode = 2;
    const raw = captureStderr(() =>
      printJsonError({ code: 'INTERNAL_ERROR', message: 'err' }),
    );
    // eslint-disable-next-line no-control-regex
    expect(raw).not.toMatch(/\x1b\[/);
  });
});

// ---------------------------------------------------------------------------
// explainReasonCodeJson
// ---------------------------------------------------------------------------

describe('explainReasonCodeJson', () => {
  it('returns structured data for a known FAIL code', () => {
    const result = explainReasonCodeJson('HASH_MISMATCH');
    expect(result.code).toBe('HASH_MISMATCH');
    expect(result.severity).toBe('FAIL');
    expect(typeof result.description).toBe('string');
    expect(result.description.length).toBeGreaterThan(0);
    expect(typeof result.remediation).toBe('string');
    expect(result.remediation.length).toBeGreaterThan(0);
  });

  it('returns PASS severity for OK', () => {
    expect(explainReasonCodeJson('OK').severity).toBe('PASS');
  });

  it('returns PASS severity for VALID', () => {
    expect(explainReasonCodeJson('VALID').severity).toBe('PASS');
  });

  it('returns ERROR severity for error-class codes', () => {
    expect(explainReasonCodeJson('INTERNAL_ERROR').severity).toBe('ERROR');
    expect(explainReasonCodeJson('USAGE_ERROR').severity).toBe('ERROR');
    expect(explainReasonCodeJson('CONFIG_ERROR').severity).toBe('ERROR');
    expect(explainReasonCodeJson('PARSE_ERROR').severity).toBe('ERROR');
    expect(explainReasonCodeJson('CANONICALIZATION_ERROR').severity).toBe('ERROR');
  });

  it('returns UNKNOWN severity for unregistered codes', () => {
    const result = explainReasonCodeJson('TOTALLY_MADE_UP_CODE');
    expect(result.severity).toBe('UNKNOWN');
    expect(result.description).toContain('Unknown reason code');
  });

  it('description matches hintForReasonCode for known codes', () => {
    const code = 'SIGNATURE_INVALID';
    const hint = hintForReasonCode(code);
    const result = explainReasonCodeJson(code);
    expect(result.description).toBe(hint);
  });
});
