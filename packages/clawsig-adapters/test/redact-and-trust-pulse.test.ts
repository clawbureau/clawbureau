import { describe, expect, it } from 'vitest';

import { createSession } from '../src/session';
import { generateKeyPair, didFromPublicKey, hashJsonB64u } from '../src/crypto';
import { redactDeep, redactText } from '../src/redact';

async function makeSession() {
  const keyPair = await generateKeyPair();
  const agentDid = await didFromPublicKey(keyPair.publicKey);

  const session = await createSession({
    proxyBaseUrl: 'https://example.invalid',
    proxyToken: undefined,
    keyPair,
    agentDid,
    harness: { id: 'test-harness', version: '0.0.0', runtime: 'host' },
    outputDir: '.clawsig-test',
  });

  return { session, agentDid };
}

describe('POH-US-020: pre-hash redaction', () => {
  it('redacts known secrets in strings', () => {
    const input = 'Bearer sk-ant-1234567890abcdef1234567890abcdef and eyJhbGciOiJFZERTQSJ9.aaaaaaaaaa.bbbbbbbbbb';
    const out = redactText(input);

    // Bearer redaction may consume the raw API key substring; the important property
    // is that the secret is removed and the structure is redacted.
    expect(out).not.toContain('sk-ant-');
    expect(out).toContain('Bearer [REDACTED:bearer]');
    expect(out).toContain('[REDACTED:jwt]');

    // Also ensure raw API keys are redacted when they appear standalone.
    expect(redactText('sk-ant-1234567890abcdef1234567890abcdef')).toContain('[REDACTED:api_key]');
  });

  it('redacts event payloads before hashing', async () => {
    const { session } = await makeSession();

    const payload = {
      message: 'token=sk-ant-1234567890abcdef1234567890abcdef',
      nested: { auth: 'Bearer abcdefghijklmnop' },
    };

    const { event } = await session.recordEvent({ eventType: 'run_start', payload });

    const expectedRedacted = redactDeep(payload);
    const expectedHash = await hashJsonB64u(expectedRedacted);

    expect(event.payloadHashB64u).toBe(expectedHash);
  });
});

describe('OCL-US-004: trust pulse generation', () => {
  it('counts tools and file touches from tool_call events', async () => {
    const { session } = await makeSession();

    await session.recordEvent({ eventType: 'run_start', payload: { ok: true } });

    await session.recordEvent({
      eventType: 'tool_call',
      payload: {
        tool: 'Read',
        args: 'file_path="src/index.ts"',
      },
    });

    await session.recordEvent({
      eventType: 'tool_call',
      payload: {
        tool: 'Edit',
        args: 'path="src/index.ts" old_string="a" new_string="b"',
      },
    });

    await session.recordEvent({ eventType: 'run_end', payload: { ok: true } });

    const result = await session.finalize({
      inputs: [{ type: 'in', hashB64u: await hashJsonB64u('in') }],
      outputs: [{ type: 'out', hashB64u: await hashJsonB64u('out') }],
    });

    // Tools counted
    const toolMap = new Map(result.trustPulse.tools.map((t) => [t.name, t.calls]));
    expect(toolMap.get('Read')).toBe(1);
    expect(toolMap.get('Edit')).toBe(1);

    // File touches counted
    const fileMap = new Map(result.trustPulse.files.map((f) => [f.path, f.touches]));
    expect(fileMap.get('src/index.ts')).toBe(2);

    // URM includes trust_pulse pointer
    const md: any = result.urm.metadata;
    expect(md?.trust_pulse?.artifact_hash_b64u).toBe(await hashJsonB64u(result.trustPulse));
    expect(md?.trust_pulse?.tier_uplift).toBe(false);
  });
});
