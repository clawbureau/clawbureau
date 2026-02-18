#!/usr/bin/env node

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../..');
const serviceRoot = path.join(repoRoot, 'services/clawverify');

const result = spawnSync(
  'npm',
  ['test', '--', '--run', 'test/firewall-conformance.test.ts'],
  {
    cwd: serviceRoot,
    stdio: 'inherit',
    env: {
      ...process.env,
      CLAWVERIFY_FIREWALL_FIXTURE_SUITE: 'clawverify-causal-clock',
    },
  }
);

if (result.status !== 0) {
  process.exit(result.status ?? 1);
}

console.log('\n[clawverify-causal-clock-conformance] PASS');
