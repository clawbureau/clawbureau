import { describe, expect, it } from 'vitest';
import { execFile } from 'node:child_process';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import {
  computeSignedPolicyBundlePayloadHashB64u,
  computeSignedPolicyLayerHashB64u,
} from '../../clawsig-sdk/src/policy-resolution.js';
import {
  didFromPublicKey,
  generateKeyPair,
  hashJsonB64u,
  signEd25519,
} from '../../clawsig-sdk/src/crypto.js';
import { verifyProofBundle } from '../../clawverify-core/src/verify-proof-bundle.js';

const execFileAsync = promisify(execFile);
const __dirname = fileURLToPath(new URL('.', import.meta.url));
const CLI_PATH = resolve(__dirname, '../dist/cli.js');

type HeaderValue = string | string[] | undefined;

function firstHeader(value: HeaderValue): string | undefined {
  if (Array.isArray(value)) {
    return value[0];
  }
  if (typeof value === 'string') {
    return value;
  }
  return undefined;
}

async function readBody(req: IncomingMessage): Promise<string> {
  return await new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
    req.on('error', reject);
  });
}

async function writeSignedPolicyBundle(workdir: string, orgId: string): Promise<void> {
  const clawsigDir = join(workdir, '.clawsig');
  await mkdir(clawsigDir, { recursive: true });

  const keyPair = await generateKeyPair();
  const issuerDid = await didFromPublicKey(keyPair.publicKey);

  const payload = {
    policy_bundle_version: '1' as const,
    bundle_id: 'bundle_wrap_python_proofed_1',
    issuer_did: issuerDid,
    issued_at: '2026-03-21T00:00:00.000Z',
    hash_algorithm: 'SHA-256' as const,
    layers: [
      {
        layer_id: 'org',
        scope: { scope_type: 'org' as const, org_id: orgId },
        apply_mode: 'merge' as const,
        policy: {
          statements: [
            {
              sid: 'org.allow.model',
              effect: 'Allow' as const,
              actions: ['model:invoke', 'side_effect:network_egress', 'tool:execute'],
              resources: ['*'],
            },
          ],
        },
        policy_hash_b64u: '',
      },
    ],
  };

  payload.layers[0]!.policy_hash_b64u = await computeSignedPolicyLayerHashB64u(payload.layers[0]!.policy);

  const payloadHash = await computeSignedPolicyBundlePayloadHashB64u(payload);
  const signature = await signEd25519(keyPair.privateKey, new TextEncoder().encode(payloadHash));

  await writeFile(
    join(clawsigDir, 'policy.bundle.json'),
    JSON.stringify(
      {
        envelope_version: '1',
        envelope_type: 'policy_bundle',
        payload,
        payload_hash_b64u: payloadHash,
        hash_algorithm: 'SHA-256',
        signature_b64u: signature,
        algorithm: 'Ed25519',
        signer_did: issuerDid,
        issued_at: payload.issued_at,
      },
      null,
      2,
    ),
    'utf-8',
  );
}

async function buildGatewayReceiptEnvelope(args: {
  signerDid: string;
  sign: (message: Uint8Array) => Promise<string>;
  runId: string;
  eventHashB64u: string;
  nonce?: string;
}): Promise<Record<string, unknown>> {
  const timestamp = new Date().toISOString();
  const requestHashB64u = await hashJsonB64u({
    kind: 'python_request',
    run_id: args.runId,
    event_hash_b64u: args.eventHashB64u,
  });
  const responseHashB64u = await hashJsonB64u({
    kind: 'python_response',
    run_id: args.runId,
    event_hash_b64u: args.eventHashB64u,
  });

  const payload = {
    receipt_version: '1',
    receipt_id: `rcpt_python_${crypto.randomUUID()}`,
    gateway_id: 'gw_mock_python',
    provider: 'openai',
    model: 'gpt-4o-mini',
    request_hash_b64u: requestHashB64u,
    response_hash_b64u: responseHashB64u,
    tokens_input: 5,
    tokens_output: 7,
    latency_ms: 12,
    timestamp,
    binding: {
      run_id: args.runId,
      event_hash_b64u: args.eventHashB64u,
      ...(args.nonce ? { nonce: args.nonce } : {}),
    },
  };

  const payloadHashB64u = await hashJsonB64u(payload);
  const signatureB64u = await args.sign(new TextEncoder().encode(payloadHashB64u));

  return {
    envelope_version: '1',
    envelope_type: 'gateway_receipt',
    payload,
    payload_hash_b64u: payloadHashB64u,
    hash_algorithm: 'SHA-256',
    signature_b64u: signatureB64u,
    algorithm: 'Ed25519',
    signer_did: args.signerDid,
    issued_at: timestamp,
  };
}

async function startMockClawproxy(): Promise<{
  url: string;
  signerDid: string;
  stop: () => Promise<void>;
}> {
  const keyPair = await generateKeyPair();
  const signerDid = await didFromPublicKey(keyPair.publicKey);

  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    if (req.method === 'POST' && req.url?.startsWith('/v1/proxy/')) {
      await readBody(req);
      const runId = firstHeader(req.headers['x-run-id']) ?? `run_missing_${crypto.randomUUID()}`;
      const eventHash = firstHeader(req.headers['x-event-hash']) ?? `evt_missing_${crypto.randomUUID()}`;
      const nonce = firstHeader(req.headers['x-idempotency-key']);

      const envelope = await buildGatewayReceiptEnvelope({
        signerDid,
        sign: (message) => signEd25519(keyPair.privateKey, message),
        runId,
        eventHashB64u: eventHash,
        nonce,
      });

      const payload = envelope['payload'] as Record<string, unknown>;
      const timestamp = typeof payload['timestamp'] === 'string' ? payload['timestamp'] : new Date().toISOString();

      const legacyReceipt = {
        version: '1.0',
        proxyDid: signerDid,
        provider: 'openai',
        model: 'gpt-4o-mini',
        requestHash: `sha256:${payload['request_hash_b64u']}`,
        responseHash: `sha256:${payload['response_hash_b64u']}`,
        timestamp,
        latencyMs: 12,
        binding: {
          runId,
          eventHash,
          ...(nonce ? { nonce } : {}),
        },
      };

      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          id: 'chatcmpl-mock-python',
          object: 'chat.completion',
          model: 'gpt-4o-mini',
          choices: [
            {
              index: 0,
              message: { role: 'assistant', content: 'ok' },
              finish_reason: 'stop',
            },
          ],
          _receipt: legacyReceipt,
          _receipt_envelope: envelope,
        }),
      );
      return;
    }

    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'NOT_FOUND' }));
  });

  await new Promise<void>((resolve, reject) => {
    server.listen(0, '127.0.0.1', () => resolve());
    server.on('error', reject);
  });

  const address = server.address();
  if (!address || typeof address !== 'object') {
    throw new Error('Failed to start mock clawproxy server');
  }

  return {
    url: `http://127.0.0.1:${address.port}`,
    signerDid,
    stop: async () =>
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

describe('AF2-XRT-001 python proofed adapter parity', () => {
  it('rejects proofed python flags that disable the sitecustomize adapter', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'clawsig-wrap-python-proofed-'));
    const mock = await startMockClawproxy();

    try {
      await writeSignedPolicyBundle(workdir, 'acme');

      const childScriptPath = join(workdir, 'python-proofed-bypass.py');
      await writeFile(childScriptPath, 'raise SystemExit(0)\n', 'utf-8');

      let failure: Error & { code?: number; stderr?: string } | null = null;
      try {
        await execFileAsync(
          process.execPath,
          [
            CLI_PATH,
            'wrap',
            '--no-publish',
            '--',
            'python3',
            '-S',
            childScriptPath,
          ],
          {
            cwd: workdir,
            env: {
              ...process.env,
              CLAWSIG_DISABLE_INTERPOSE: '1',
              CLAWSIG_PROOFED: '1',
              CLAWSIG_CLAWPROXY_URL: mock.url,
              CLAWSIG_POLICY_ORG_ID: 'acme',
            },
            timeout: 90_000,
          },
        );
      } catch (err) {
        failure = err as Error & { code?: number; stderr?: string };
      }

      expect(failure).not.toBeNull();
      expect(failure?.code).toBe(2);
      expect(failure?.stderr).toContain('PRV_PYTHON_ADAPTER_BYPASS_FLAG');
      expect(failure?.stderr).toContain('-S');
    } finally {
      await mock.stop();
      await rm(workdir, { recursive: true, force: true });
    }
  });

  it('emits policy-bound proofed evidence and verifier-compatible receipts for python runs', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'clawsig-wrap-python-proofed-'));
    const mock = await startMockClawproxy();

    try {
      await writeSignedPolicyBundle(workdir, 'acme');

      const childScriptPath = join(workdir, 'python-proofed-e2e.py');
      await writeFile(
        childScriptPath,
        [
          'import json',
          'import os',
          'import sys',
          'import urllib.request',
          '',
          'def denied(exc):',
          "    code = getattr(exc, 'code', None)",
          "    return code == 'PRV_EGRESS_DENIED' or 'PRV_EGRESS_DENIED' in str(exc)",
          '',
          'try:',
          "    urllib.request.urlopen('https://api.openai.com/v1/models', timeout=2)",
          "    print('expected PRV_EGRESS_DENIED for direct egress', file=sys.stderr)",
          '    sys.exit(3)',
          'except Exception as err:',
          '    if not denied(err):',
          "        print(f'unexpected direct-egress error: {err!r}', file=sys.stderr)",
          '        sys.exit(4)',
          '',
          "base_url = os.environ.get('OPENAI_BASE_URL')",
          'if not base_url:',
          "    print('missing OPENAI_BASE_URL', file=sys.stderr)",
          '    sys.exit(5)',
          '',
          "payload = json.dumps({'model': 'gpt-4o-mini', 'messages': [{'role': 'user', 'content': 'hello from python'}]}).encode('utf-8')",
          'request = urllib.request.Request(',
          "    base_url.rstrip('/') + '/chat/completions',",
          '    data=payload,',
          '    method="POST",',
          "    headers={'content-type': 'application/json', 'authorization': 'Bearer sk-test'},",
          ')',
          '',
          'with urllib.request.urlopen(request, timeout=10) as response:',
          "    body = json.loads(response.read().decode('utf-8'))",
          '',
          "if not isinstance(body, dict) or not isinstance(body.get('choices'), list):",
          "    print('unexpected response from local proxy', file=sys.stderr)",
          '    sys.exit(6)',
          '',
          'sys.exit(0)',
          '',
        ].join('\n'),
        'utf-8',
      );

      await execFileAsync(
        process.execPath,
        [
          CLI_PATH,
          'wrap',
          '--no-publish',
          '--',
          'python3',
          childScriptPath,
        ],
        {
          cwd: workdir,
          env: {
            ...process.env,
            CLAWSIG_DISABLE_INTERPOSE: '1',
            CLAWSIG_PROOFED: '1',
            CLAWSIG_CLAWPROXY_URL: mock.url,
            CLAWSIG_POLICY_ORG_ID: 'acme',
          },
          timeout: 90_000,
        },
      );

      const proofBundle = JSON.parse(
        await readFile(join(workdir, '.clawsig', 'proof_bundle.json'), 'utf-8'),
      ) as {
        payload: {
          receipts?: Array<Record<string, unknown>>;
          metadata?: {
            policy_binding?: {
              effective_policy_hash_b64u?: string;
            };
            sentinels?: {
              egress_policy_receipt?: {
                payload?: {
                  effective_policy_hash_b64u?: string;
                };
              };
            };
            runner_measurement?: {
              manifest?: {
                proofed?: {
                  proofed_mode?: boolean;
                };
                policy?: {
                  effective_policy_hash_b64u?: string;
                };
              };
            };
            runner_attestation_receipt?: {
              envelope_type?: string;
              payload?: {
                policy?: {
                  effective_policy_hash_b64u?: string;
                };
              };
            };
          };
        };
      };

      const policyHash =
        proofBundle.payload.metadata?.policy_binding?.effective_policy_hash_b64u;
      expect(policyHash).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(proofBundle.payload.metadata?.runner_measurement?.manifest?.proofed?.proofed_mode)
        .toBe(true);
      expect(proofBundle.payload.metadata?.runner_attestation_receipt?.envelope_type)
        .toBe('runner_attestation_receipt');
      expect(proofBundle.payload.metadata?.sentinels?.egress_policy_receipt?.payload?.effective_policy_hash_b64u)
        .toBe(policyHash);
      expect(proofBundle.payload.metadata?.runner_measurement?.manifest?.policy?.effective_policy_hash_b64u)
        .toBe(policyHash);
      expect(proofBundle.payload.metadata?.runner_attestation_receipt?.payload?.policy?.effective_policy_hash_b64u)
        .toBe(policyHash);

      const gatewayReceipts = (proofBundle.payload.receipts ?? []).filter(
        (receipt) => receipt.envelope_type === 'gateway_receipt',
      );
      expect(gatewayReceipts.length).toBeGreaterThan(0);
      expect(
        gatewayReceipts.some((receipt) => receipt.signer_did === mock.signerDid),
      ).toBe(true);

      const verification = await verifyProofBundle(proofBundle as any, {
        allowlistedReceiptSignerDids: [mock.signerDid],
      });
      expect(verification.result.status).toBe('VALID');
      expect(verification.result.component_results?.receipts_signature_verified_count ?? 0)
        .toBeGreaterThan(0);
    } finally {
      await mock.stop();
      await rm(workdir, { recursive: true, force: true });
    }
  });
});
