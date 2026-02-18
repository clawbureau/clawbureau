#!/usr/bin/env node

import { runIntegrationPack } from '../_shared/run-pack.mjs';

await runIntegrationPack({
  packName: 'enterprise-ci',
  description: 'Enterprise CI starter pack (v0.2 rate-limit fixture verification).',
  fixturePath:
    'packages/schema/fixtures/protocol-conformance/cpl-v2-rate-limit/proof_bundle_rate_limit_pass.v1.json',
  outputDir: 'artifacts/examples/integrations/enterprise-ci',
});
