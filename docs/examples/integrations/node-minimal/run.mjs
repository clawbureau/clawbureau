#!/usr/bin/env node

import { runIntegrationPack } from '../_shared/run-pack.mjs';

await runIntegrationPack({
  packName: 'node-minimal',
  description: 'Minimal Node.js integration pack (fixture-based proof-bundle verification).',
  fixturePath:
    'packages/schema/fixtures/protocol-conformance/proof_bundle_pass.v1.json',
  outputDir: 'artifacts/examples/integrations/node-minimal',
});
