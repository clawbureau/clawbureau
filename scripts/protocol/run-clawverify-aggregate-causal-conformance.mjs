#!/usr/bin/env node

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../..');
const cliRoot = path.join(repoRoot, 'packages/clawverify-cli');

const result = spawnSync(
  'npm',
  ['test', '--', '--run', 'test/aggregate-causal-conformance.test.ts'],
  {
    cwd: cliRoot,
    stdio: 'inherit',
  }
);

if (result.status !== 0) {
  process.exit(result.status ?? 1);
}

console.log('\n[clawverify-aggregate-causal-conformance] PASS');
