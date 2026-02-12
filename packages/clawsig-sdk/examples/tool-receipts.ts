/**
 * Tool receipts example: recordToolCall + finalize
 *
 * Demonstrates Coverage MT — model call plus tool invocation receipts.
 * Tool receipts are hash-only: arguments and results are digested,
 * never stored in the proof bundle.
 *
 * Usage:
 *   CLAWSIG_PROXY_URL=https://proxy.clawbureau.com \
 *   node --loader tsx examples/tool-receipts.ts
 */

import { createHash } from 'node:crypto';
import { createClawsigRun } from '../src/index.js';

function sha256(data: string): string {
  return 'sha256:' + createHash('sha256').update(data).digest('hex');
}

async function main() {
  const run = await createClawsigRun({
    agentDid: process.env.AGENT_DID || 'did:key:z6MkExample...',
    proxyUrl: process.env.CLAWSIG_PROXY_URL || 'https://proxy.clawbureau.com',
    keyFile: process.env.CLAWSIG_KEY_FILE || '.clawsig-key.json',
  });

  // 1. Agent calls LLM to decide what tool to use
  const planResponse = await run.callLLM({
    model: 'claude-sonnet-4-20250514',
    messages: [
      { role: 'user', content: 'Read the file src/index.ts and summarize it' },
    ],
  });

  // 2. Agent executes the tool
  const toolArgs = JSON.stringify({ path: 'src/index.ts' });
  const toolResult = JSON.stringify({ content: 'export function main() { ... }', lines: 42 });

  const start = Date.now();
  // ... actual tool execution would happen here ...
  const duration = Date.now() - start;

  // 3. Record the tool call — only digests are stored, not raw content
  run.recordToolCall({
    tool_name: 'file_read',
    args_digest: sha256(toolArgs),
    result_digest: sha256(toolResult),
    duration_ms: duration,
  });

  // 4. Agent calls LLM again with the tool result
  const summaryResponse = await run.callLLM({
    model: 'claude-sonnet-4-20250514',
    messages: [
      { role: 'user', content: 'Read the file src/index.ts and summarize it' },
      { role: 'assistant', content: 'I\'ll read that file for you.' },
      { role: 'user', content: `File contents: ${toolResult}` },
    ],
  });

  // 5. Finalize — bundle includes both LLM receipts and the tool receipt
  const result = await run.finalize();

  console.log(`Proof bundle: ${result.path}`);
  console.log(`Events: ${result.eventCount}, Receipts: ${result.receiptCount}`);
  console.log('Coverage level: MT (model + tools)');
}

main().catch(console.error);
