#!/usr/bin/env node

import { runIntegrationPack } from '../_shared/run-pack.mjs';

await runIntegrationPack({
  packName: 'github-actions',
  description: 'GitHub Actions starter pack (v0.2 co-signature fixture verification).',
  fixturePath:
    'packages/schema/fixtures/protocol-conformance/r48-r49-v02/proof_bundle/v2_tool_receipt_cosig_valid.v1.json',
  outputDir: 'artifacts/examples/integrations/github-actions',
});
