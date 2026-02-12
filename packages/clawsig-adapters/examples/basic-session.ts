/**
 * Example: basic programmatic session with clawsig adapters.
 *
 * Demonstrates how to create a session, record events, proxy LLM calls,
 * and produce a signed proof bundle.
 *
 * Run with:
 *   CLAWSIG_PROXY_URL=https://proxy.example.com npx tsx examples/basic-session.ts
 */

import {
  createSession,
  getAdapter,
  generateKeyPair,
  didFromPublicKey,
  hashJsonB64u,
} from '../src/index';

async function main() {
  // 1. Generate (or load) an agent key pair
  const keyPair = await generateKeyPair();
  const agentDid = await didFromPublicKey(keyPair.publicKey);
  console.log(`Agent DID: ${agentDid}`);

  // 2. Get the Claude Code adapter config
  const adapter = getAdapter('claude-code');
  if (!adapter) throw new Error('adapter not found');

  // 3. Show what env vars would be set
  const proxyUrl = process.env.CLAWSIG_PROXY_URL ?? 'https://proxy.example.com';
  console.log('Proxy env vars:', adapter.getProxyEnv(proxyUrl));

  // 4. Create a session
  const session = await createSession({
    proxyBaseUrl: proxyUrl,
    keyPair,
    agentDid,
    harness: adapter.HARNESS,
  });

  console.log(`Run ID: ${session.runId}`);

  // 5. Record events (simulating a harness run)
  const { binding: startBinding } = await session.recordEvent({
    eventType: 'run_start',
    payload: { task: 'fix authentication bug', repo: 'example/repo' },
  });
  console.log('run_start binding:', startBinding);

  await session.recordEvent({
    eventType: 'tool_call',
    payload: { tool: 'Read', file: 'src/auth.ts' },
  });

  await session.recordEvent({
    eventType: 'tool_call',
    payload: { tool: 'Edit', file: 'src/auth.ts', change: 'fix token validation' },
  });

  await session.recordEvent({
    eventType: 'run_end',
    payload: { status: 'success', exitCode: 0 },
  });

  // 6. Finalize
  const taskHash = await hashJsonB64u({ task: 'fix authentication bug' });
  const patchHash = await hashJsonB64u({ file: 'src/auth.ts', change: 'fix token validation' });

  const result = await session.finalize({
    inputs: [{ type: 'task', hashB64u: taskHash }],
    outputs: [{ type: 'patch', hashB64u: patchHash, path: 'src/auth.ts' }],
  });

  // 7. Print the proof bundle
  console.log('\n--- Proof Bundle ---');
  console.log(JSON.stringify(result.envelope, null, 2));

  console.log('\n--- URM ---');
  console.log(JSON.stringify(result.urm, null, 2));
}

main().catch(console.error);
