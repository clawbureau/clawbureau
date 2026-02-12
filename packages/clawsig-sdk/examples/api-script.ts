/**
 * Example: API script with clawsig SDK
 *
 * Demonstrates how to use the SDK to produce a signed proof bundle
 * from a Node.js script that makes LLM calls via clawproxy.
 *
 * Run with:
 *   CLAWPROXY_URL=https://proxy.example.com npx tsx examples/api-script.ts
 */

import {
  createRun,
  generateKeyPair,
  didFromPublicKey,
  hashJsonB64u,
} from '../src/index';

async function main() {
  // 1. Generate (or load) an agent key pair
  const keyPair = await generateKeyPair();
  const agentDid = await didFromPublicKey(keyPair.publicKey);
  console.log(`Agent DID: ${agentDid}`);

  // 2. Create a run
  const proxyUrl = process.env.CLAWPROXY_URL ?? 'https://proxy.example.com';
  const run = await createRun({
    proxyBaseUrl: proxyUrl,
    keyPair,
    agentDid,
    harness: {
      id: 'my-api-script',
      version: '1.0.0',
      runtime: `node/${process.version}`,
    },
  });
  console.log(`Run ID: ${run.runId}`);

  // 3. Record start event
  await run.recordEvent({
    eventType: 'run_start',
    payload: { task: 'summarize document', source: 'api-script' },
  });

  // 4. Make an LLM call through clawproxy
  //    (In a real script, this would reach the proxy and return a response
  //    with a _receipt field. Here we simulate the flow.)
  try {
    const result = await run.callLLM({
      provider: 'anthropic',
      model: 'claude-sonnet-4-5-20250929',
      body: {
        model: 'claude-sonnet-4-5-20250929',
        max_tokens: 256,
        messages: [
          { role: 'user', content: 'Summarize this document in one paragraph.' },
        ],
      },
    });
    console.log(`LLM call status: ${result.status}`);
    if (result.receipt) {
      console.log('Receipt collected from proxy');
    }
  } catch {
    // Expected to fail without a real proxy — that's OK for the example
    console.log('LLM call skipped (no proxy available)');

    // Record a simulated tool event instead
    await run.recordEvent({
      eventType: 'tool_call',
      payload: { tool: 'summarize', input: 'document.txt' },
    });
  }

  // 5. Record end event
  await run.recordEvent({
    eventType: 'run_end',
    payload: { status: 'success' },
  });

  // 6. Finalize — produces signed proof bundle + URM
  const taskHash = await hashJsonB64u({ task: 'summarize document' });
  const outputHash = await hashJsonB64u({ summary: 'A one paragraph summary.' });

  const { envelope, urm } = await run.finalize({
    inputs: [{ type: 'task', hashB64u: taskHash }],
    outputs: [{ type: 'summary', hashB64u: outputHash, contentType: 'text/plain' }],
  });

  // 7. Print results
  console.log('\n--- Proof Bundle ---');
  console.log(JSON.stringify(envelope, null, 2));

  console.log('\n--- URM ---');
  console.log(JSON.stringify(urm, null, 2));

  // In production, write these to files:
  //   fs.writeFileSync('proof-bundle.json', JSON.stringify(envelope, null, 2));
  //   fs.writeFileSync('urm.json', JSON.stringify(urm, null, 2));
}

main().catch(console.error);
