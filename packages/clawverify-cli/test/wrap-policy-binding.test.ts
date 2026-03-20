import { describe, expect, it } from 'vitest';
import { execFile } from 'node:child_process';
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
  signEd25519,
} from '../../clawsig-sdk/src/crypto.js';

const execFileAsync = promisify(execFile);
const __dirname = fileURLToPath(new URL('.', import.meta.url));
const CLI_PATH = resolve(__dirname, '../dist/cli.js');

describe('AF2-POL wrap policy binding surface', () => {
  it('materializes effective policy snapshot/hash and binds it into proofed egress evidence', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'clawsig-wrap-policy-binding-'));
    const keyPair = await generateKeyPair();
    const issuerDid = await didFromPublicKey(keyPair.publicKey);

    try {
      const clawsigDir = join(workdir, '.clawsig');
      await mkdir(clawsigDir, { recursive: true });

      const payload = {
        policy_bundle_version: '1' as const,
        bundle_id: 'bundle_wrap_policy_1',
        issuer_did: issuerDid,
        issued_at: '2026-03-20T00:00:00.000Z',
        hash_algorithm: 'SHA-256' as const,
        layers: [
          {
            layer_id: 'org',
            scope: { scope_type: 'org', org_id: 'acme' },
            apply_mode: 'merge',
            policy: {
              statements: [
                { sid: 'org.base', effect: 'Allow', actions: ['model:invoke'], resources: ['*'] },
              ],
            },
            policy_hash_b64u: '',
          },
          {
            layer_id: 'task',
            scope: {
              scope_type: 'task',
              org_id: 'acme',
              project_id: 'proj-a',
              task_id: 'task-9',
            },
            apply_mode: 'merge',
            policy: {
              statements: [
                { sid: 'task.egress', effect: 'Deny', actions: ['side_effect:network_egress'], resources: ['*'] },
              ],
            },
            policy_hash_b64u: '',
          },
        ],
      };

      for (const layer of payload.layers) {
        layer.policy_hash_b64u = await computeSignedPolicyLayerHashB64u(layer.policy);
      }

      const payloadHash = await computeSignedPolicyBundlePayloadHashB64u(payload);
      const signature = await signEd25519(
        keyPair.privateKey,
        new TextEncoder().encode(payloadHash),
      );

      const bundleEnvelope = {
        envelope_version: '1',
        envelope_type: 'policy_bundle',
        payload,
        payload_hash_b64u: payloadHash,
        hash_algorithm: 'SHA-256',
        signature_b64u: signature,
        algorithm: 'Ed25519',
        signer_did: issuerDid,
        issued_at: payload.issued_at,
      };

      await writeFile(
        join(clawsigDir, 'policy.bundle.json'),
        JSON.stringify(bundleEnvelope, null, 2),
        'utf-8',
      );

      await execFileAsync(
        process.execPath,
        [
          CLI_PATH,
          'wrap',
          '--no-publish',
          '--',
          process.execPath,
          '-e',
          "console.log('policy-binding-wrap-test')",
        ],
        {
          cwd: workdir,
          env: {
            ...process.env,
            CLAWSIG_DISABLE_INTERPOSE: '1',
            CLAWSIG_PROOFED: '1',
            CLAWSIG_POLICY_ORG_ID: 'acme',
            CLAWSIG_POLICY_PROJECT_ID: 'proj-a',
            CLAWSIG_POLICY_TASK_ID: 'task-9',
          },
          timeout: 60_000,
        },
      );

      const proofBundle = JSON.parse(
        await readFile(join(clawsigDir, 'proof_bundle.json'), 'utf-8')
      ) as {
        payload: {
          metadata?: {
            policy_binding?: {
              binding_version?: string;
              effective_policy_hash_b64u?: string;
              effective_policy_snapshot?: {
                applied_layers?: Array<{ layer_id?: string }>;
              };
            };
            sentinels?: {
              egress_policy_receipt?: {
                payload?: {
                  policy_hash_b64u?: string;
                  effective_policy_hash_b64u?: string;
                };
              };
            };
          };
        };
      };

      const binding = proofBundle.payload.metadata?.policy_binding;
      const egress = proofBundle.payload.metadata?.sentinels?.egress_policy_receipt?.payload;

      expect(binding?.binding_version).toBe('1');
      expect(binding?.effective_policy_hash_b64u).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(binding?.effective_policy_snapshot?.applied_layers?.map((layer) => layer.layer_id)).toEqual([
        'org',
        'task',
      ]);
      expect(egress?.policy_hash_b64u).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(egress?.effective_policy_hash_b64u).toBe(binding?.effective_policy_hash_b64u);
      expect(egress?.policy_hash_b64u).not.toBe(binding?.effective_policy_hash_b64u);
    } finally {
      await rm(workdir, { recursive: true, force: true });
    }
  });

  it('fails closed in proofed mode when no signed policy bundle is available', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'clawsig-wrap-policy-required-'));

    try {
      const clawsigDir = join(workdir, '.clawsig');
      await mkdir(clawsigDir, { recursive: true });
      await writeFile(
        join(clawsigDir, 'policy.json'),
        JSON.stringify(
          {
            statements: [
              { sid: 'legacy.local', effect: 'Allow', actions: ['model:invoke'], resources: ['*'] },
            ],
          },
          null,
          2,
        ),
        'utf-8',
      );

      let failure: Error | null = null;
      try {
        await execFileAsync(
          process.execPath,
          [
            CLI_PATH,
            'wrap',
            '--no-publish',
            '--',
            process.execPath,
            '-e',
            "console.log('policy-binding-wrap-test')",
          ],
          {
            cwd: workdir,
            env: {
              ...process.env,
              CLAWSIG_DISABLE_INTERPOSE: '1',
              CLAWSIG_PROOFED: '1',
            },
            timeout: 60_000,
          },
        );
      } catch (err) {
        failure = err as Error;
      }

      expect(failure).toBeTruthy();
      expect((failure as Error & { stderr?: string }).stderr ?? '').toContain(
        'PRV_POLICY_BINDING_REQUIRED',
      );
    } finally {
      await rm(workdir, { recursive: true, force: true });
    }
  });
});
