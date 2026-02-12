/**
 * Basic agent example: callLLM + finalize
 *
 * Demonstrates the minimum viable proof bundle — a single LLM call
 * routed through the clawsig proxy, producing a signed proof bundle.
 *
 * Usage:
 *   CLAWSIG_PROXY_URL=https://proxy.clawbureau.com \
 *   node --loader tsx examples/basic-agent.ts
 */

import { createClawsigRun } from '../src/index.js';

async function main() {
  const run = await createClawsigRun({
    agentDid: process.env.AGENT_DID || 'did:key:z6MkExample...',
    proxyUrl: process.env.CLAWSIG_PROXY_URL || 'https://proxy.clawbureau.com',
    keyFile: process.env.CLAWSIG_KEY_FILE || '.clawsig-key.json',
  });

  // Make an LLM call — routed through the proxy, receipt auto-collected
  const response = await run.callLLM({
    model: 'claude-sonnet-4-20250514',
    messages: [
      { role: 'user', content: 'What is a proof bundle?' },
    ],
  });

  console.log('LLM response:', response.choices?.[0]?.message?.content?.slice(0, 100));

  // Finalize: signs the event chain, writes proof bundle + URM
  const result = await run.finalize();

  console.log(`Proof bundle: ${result.path}`);
  console.log(`Events: ${result.eventCount}, Receipts: ${result.receiptCount}`);
  console.log(`Run ID: ${result.runId}`);
}

main().catch(console.error);
