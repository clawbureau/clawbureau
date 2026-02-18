import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { hashJsonB64u } from '../../clawsig-sdk/dist/crypto.js';

const execFileAsync = promisify(execFile);

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const REPO_ROOT = resolve(__dirname, '../../..');
const CLI_PATH = resolve(__dirname, '../dist/cli.js');

describe('clawverify-cli wrap reseal sequencing (CAV-US-003)', () => {
  it('writes a bundle whose recorded payload hash matches post-mutation payload bytes', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'clawsig-wrap-reseal-'));

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
          "console.log('wrap-reseal-test')",
        ],
        {
          cwd: workdir,
          env: {
            ...process.env,
            CLAWSIG_DISABLE_INTERPOSE: '1',
          },
          timeout: 60_000,
        },
      );

      const bundlePath = join(workdir, '.clawsig', 'proof_bundle.json');
      const bundleRaw = await readFile(bundlePath, 'utf8');
      const bundle = JSON.parse(bundleRaw) as {
        payload: unknown;
        payload_hash_b64u: string;
        signature_b64u: string;
      };

      const computedPayloadHash = await hashJsonB64u(bundle.payload);

      assert.equal(
        bundle.payload_hash_b64u,
        computedPayloadHash,
        'payload_hash_b64u must match hash(payload) after all wrap mutations',
      );

      assert.match(
        bundle.signature_b64u,
        /^[A-Za-z0-9_-]+$/,
        'signature must remain base64url-encoded after reseal',
      );
    } finally {
      await rm(workdir, { recursive: true, force: true });
    }
  });
});
