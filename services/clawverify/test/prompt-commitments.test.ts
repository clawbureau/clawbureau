import { describe, expect, it } from 'vitest';

import { base64UrlEncode, computeHash } from '../src/crypto';
import { verifyProofBundle } from '../src/verify-proof-bundle';

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';

  const digits: number[] = [0];

  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      const x = digits[i] * 256 + carry;
      digits[i] = x % 58;
      carry = Math.floor(x / 58);
    }
    while (carry) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }

  // Leading zeros
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
    digits.push(0);
  }

  return digits
    .reverse()
    .map((d) => BASE58_ALPHABET[d])
    .join('');
}

async function makeDidKeyEd25519(): Promise<{ did: string; privateKey: CryptoKey }> {
  const keypair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);

  const publicKeyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', keypair.publicKey));

  const prefixed = new Uint8Array(2 + publicKeyBytes.length);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(publicKeyBytes, 2);

  const did = `did:key:z${base58Encode(prefixed)}`;
  return { did, privateKey: keypair.privateKey };
}

function tamperB64u(b64u: string): string {
  if (b64u.length === 0) return 'A';
  const last = b64u[b64u.length - 1];
  const replacement = last !== 'A' ? 'A' : 'B';
  return b64u.slice(0, -1) + replacement;
}

async function computePromptRootHashB64u(entries: Array<{ entry_id: string; content_hash_b64u: string }>): Promise<string> {
  const canonicalEntries = [...entries]
    .map((e) => ({ entry_id: e.entry_id.trim(), content_hash_b64u: e.content_hash_b64u.trim() }))
    .sort((a, b) => a.entry_id.localeCompare(b.entry_id));

  const canonical = {
    prompt_pack_version: '1',
    entries: canonicalEntries,
  };

  return computeHash(canonical, 'SHA-256');
}

describe('POH-US-016/017: prompt commitments (prompt_pack + system_prompt_report)', () => {
  it('accepts valid prompt_pack + system_prompt_report and marks component results', async () => {
    const agent = await makeDidKeyEd25519();
    const runId = 'run_prompt_commit_001';

    const e1PayloadHash = await computeHash({ type: 'run_start' }, 'SHA-256');
    const e1Header = {
      event_id: 'evt_001',
      run_id: runId,
      event_type: 'run_start',
      timestamp: '2026-02-09T00:00:00Z',
      payload_hash_b64u: e1PayloadHash,
      prev_hash_b64u: null as string | null,
    };
    const e1Hash = await computeHash(e1Header, 'SHA-256');

    const e2PayloadHash = await computeHash({ type: 'llm_call' }, 'SHA-256');
    const e2Header = {
      event_id: 'evt_002',
      run_id: runId,
      event_type: 'llm_call',
      timestamp: '2026-02-09T00:00:01Z',
      payload_hash_b64u: e2PayloadHash,
      prev_hash_b64u: e1Hash,
    };
    const e2Hash = await computeHash(e2Header, 'SHA-256');

    const entries = [
      { entry_id: 'AGENTS.md', content_hash_b64u: await computeHash('agents', 'SHA-256') },
      { entry_id: 'SOUL.md', content_hash_b64u: await computeHash('soul', 'SHA-256') },
    ];

    const promptRoot = await computePromptRootHashB64u(entries);

    const prompt_pack = {
      prompt_pack_version: '1',
      prompt_pack_id: 'pp_test_001',
      hash_algorithm: 'SHA-256',
      prompt_root_hash_b64u: promptRoot,
      entries,
    };

    const system_prompt_report = {
      system_prompt_report_version: '1',
      report_id: 'spr_test_001',
      run_id: runId,
      agent_did: agent.did,
      issued_at: '2026-02-09T00:00:02Z',
      hash_algorithm: 'SHA-256',
      prompt_root_hash_b64u: promptRoot,
      calls: [
        {
          event_id: 'evt_002',
          event_hash_b64u: e2Hash,
          provider: 'openai',
          model: 'gpt-test',
          rendered_system_prompt_hash_b64u: await computeHash('system-prompt-bytes', 'SHA-256'),
        },
      ],
    };

    const payload: any = {
      bundle_version: '1',
      bundle_id: 'bundle_test_001',
      agent_did: agent.did,
      event_chain: [
        { ...e1Header, event_hash_b64u: e1Hash },
        { ...e2Header, event_hash_b64u: e2Hash },
      ],
      metadata: {
        harness: { id: 'openclaw', version: 'test' },
        prompt_pack,
        system_prompt_report,
      },
    };

    const payloadHash = await computeHash(payload, 'SHA-256');
    const sigMsg = new TextEncoder().encode(payloadHash);

    const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', agent.privateKey, sigMsg));

    const envelope: any = {
      envelope_version: '1',
      envelope_type: 'proof_bundle',
      payload,
      payload_hash_b64u: payloadHash,
      hash_algorithm: 'SHA-256',
      signature_b64u: base64UrlEncode(signature),
      algorithm: 'Ed25519',
      signer_did: agent.did,
      issued_at: '2026-02-09T00:00:03Z',
    };

    const out = await verifyProofBundle(envelope);
    expect(out.result.status).toBe('VALID');
    expect(out.result.component_results?.prompt_pack_valid).toBe(true);
    expect(out.result.component_results?.system_prompt_report_valid).toBe(true);
  });

  it('rejects when prompt_pack.prompt_root_hash_b64u does not match canonical entries', async () => {
    const agent = await makeDidKeyEd25519();
    const runId = 'run_prompt_commit_002';

    const e1PayloadHash = await computeHash({ type: 'run_start' }, 'SHA-256');
    const e1Header = {
      event_id: 'evt_101',
      run_id: runId,
      event_type: 'run_start',
      timestamp: '2026-02-09T00:00:00Z',
      payload_hash_b64u: e1PayloadHash,
      prev_hash_b64u: null as string | null,
    };
    const e1Hash = await computeHash(e1Header, 'SHA-256');

    const entries = [
      { entry_id: 'AGENTS.md', content_hash_b64u: await computeHash('agents', 'SHA-256') },
    ];

    const promptRoot = await computePromptRootHashB64u(entries);

    const prompt_pack = {
      prompt_pack_version: '1',
      prompt_pack_id: 'pp_test_002',
      hash_algorithm: 'SHA-256',
      prompt_root_hash_b64u: tamperB64u(promptRoot),
      entries,
    };

    const payload: any = {
      bundle_version: '1',
      bundle_id: 'bundle_test_002',
      agent_did: agent.did,
      event_chain: [
        { ...e1Header, event_hash_b64u: e1Hash },
      ],
      metadata: {
        harness: { id: 'openclaw', version: 'test' },
        prompt_pack,
      },
    };

    const payloadHash = await computeHash(payload, 'SHA-256');
    const sigMsg = new TextEncoder().encode(payloadHash);

    const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', agent.privateKey, sigMsg));

    const envelope: any = {
      envelope_version: '1',
      envelope_type: 'proof_bundle',
      payload,
      payload_hash_b64u: payloadHash,
      hash_algorithm: 'SHA-256',
      signature_b64u: base64UrlEncode(signature),
      algorithm: 'Ed25519',
      signer_did: agent.did,
      issued_at: '2026-02-09T00:00:03Z',
    };

    const out = await verifyProofBundle(envelope);
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('HASH_MISMATCH');
    expect(out.error?.field).toBe('payload.metadata.prompt_pack.prompt_root_hash_b64u');
  });

  it('rejects when system_prompt_report references an unknown event_id', async () => {
    const agent = await makeDidKeyEd25519();
    const runId = 'run_prompt_commit_003';

    const e1PayloadHash = await computeHash({ type: 'run_start' }, 'SHA-256');
    const e1Header = {
      event_id: 'evt_201',
      run_id: runId,
      event_type: 'run_start',
      timestamp: '2026-02-09T00:00:00Z',
      payload_hash_b64u: e1PayloadHash,
      prev_hash_b64u: null as string | null,
    };
    const e1Hash = await computeHash(e1Header, 'SHA-256');

    const e2PayloadHash = await computeHash({ type: 'llm_call' }, 'SHA-256');
    const e2Header = {
      event_id: 'evt_202',
      run_id: runId,
      event_type: 'llm_call',
      timestamp: '2026-02-09T00:00:01Z',
      payload_hash_b64u: e2PayloadHash,
      prev_hash_b64u: e1Hash,
    };
    const e2Hash = await computeHash(e2Header, 'SHA-256');

    const entries = [
      { entry_id: 'AGENTS.md', content_hash_b64u: await computeHash('agents', 'SHA-256') },
    ];
    const promptRoot = await computePromptRootHashB64u(entries);

    const prompt_pack = {
      prompt_pack_version: '1',
      prompt_pack_id: 'pp_test_003',
      hash_algorithm: 'SHA-256',
      prompt_root_hash_b64u: promptRoot,
      entries,
    };

    const system_prompt_report = {
      system_prompt_report_version: '1',
      report_id: 'spr_test_003',
      run_id: runId,
      agent_did: agent.did,
      issued_at: '2026-02-09T00:00:02Z',
      hash_algorithm: 'SHA-256',
      prompt_root_hash_b64u: promptRoot,
      calls: [
        {
          event_id: 'evt_DOES_NOT_EXIST',
          rendered_system_prompt_hash_b64u: await computeHash('system-prompt-bytes', 'SHA-256'),
        },
      ],
    };

    const payload: any = {
      bundle_version: '1',
      bundle_id: 'bundle_test_003',
      agent_did: agent.did,
      event_chain: [
        { ...e1Header, event_hash_b64u: e1Hash },
        { ...e2Header, event_hash_b64u: e2Hash },
      ],
      metadata: {
        harness: { id: 'openclaw', version: 'test' },
        prompt_pack,
        system_prompt_report,
      },
    };

    const payloadHash = await computeHash(payload, 'SHA-256');
    const sigMsg = new TextEncoder().encode(payloadHash);

    const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', agent.privateKey, sigMsg));

    const envelope: any = {
      envelope_version: '1',
      envelope_type: 'proof_bundle',
      payload,
      payload_hash_b64u: payloadHash,
      hash_algorithm: 'SHA-256',
      signature_b64u: base64UrlEncode(signature),
      algorithm: 'Ed25519',
      signer_did: agent.did,
      issued_at: '2026-02-09T00:00:03Z',
    };

    const out = await verifyProofBundle(envelope);
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('PROMPT_COMMITMENT_MISMATCH');
  });

  it('is deterministic: prompt_root_hash_b64u is independent of entry order', async () => {
    const a = { entry_id: 'AGENTS.md', content_hash_b64u: await computeHash('agents', 'SHA-256') };
    const b = { entry_id: 'SOUL.md', content_hash_b64u: await computeHash('soul', 'SHA-256') };

    const h1 = await computePromptRootHashB64u([a, b]);
    const h2 = await computePromptRootHashB64u([b, a]);

    expect(h1).toEqual(h2);
  });
});
