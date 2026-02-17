#!/usr/bin/env node

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../..');
const serviceRoot = path.join(repoRoot, 'services/clawverify');

const result = spawnSync(
  'npm',
  ['test', '--', '--run', 'test/binary-semantic-conformance.test.ts'],
  {
    cwd: serviceRoot,
    stdio: 'inherit',
  }
);

if (result.status !== 0) {
  process.exit(result.status ?? 1);
}

console.log('\n[clawverify-binary-semantic-conformance] PASS');
