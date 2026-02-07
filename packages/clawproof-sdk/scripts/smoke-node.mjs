// Node ESM smoke test for @clawbureau/clawproof-sdk
//
// Purpose: Ensure the built dist/ output is directly runnable under plain Node
// (i.e. relative imports include explicit `.js` extensions).
//
// Run:
//   npm run build
//   node scripts/smoke-node.mjs

import { createRun, generateKeyPair, didFromPublicKey } from '../dist/index.js';

const keyPair = await generateKeyPair();
const agentDid = await didFromPublicKey(keyPair.publicKey);

const run = await createRun({
  proxyBaseUrl: 'https://example.invalid',
  keyPair,
  harness: {
    id: 'node-smoke',
    version: '0.0.0',
    runtime: 'node',
  },
});

await run.recordEvent({
  eventType: 'run_start',
  payload: { agentDid, smoke: true },
});

const result = await run.finalize({
  inputs: [],
  outputs: [],
  urmMetadata: { smoke: true },
});

if (result.envelope.envelope_type !== 'proof_bundle') {
  throw new Error(`Unexpected envelope_type: ${result.envelope.envelope_type}`);
}

console.log(
  JSON.stringify(
    {
      ok: true,
      agentDid,
      bundleId: result.envelope.payload.bundle_id,
      receipts: result.envelope.payload.receipts?.length ?? 0,
    },
    null,
    2
  )
);
