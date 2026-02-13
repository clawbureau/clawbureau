#!/usr/bin/env node
/**
 * clawsig mcp-wrap CLI.
 *
 * Wraps an MCP server process to automatically capture Clawsig tool receipts.
 *
 * Usage:
 *   npx clawsig mcp-wrap -- npx @modelcontextprotocol/server-filesystem /path
 *   npx clawsig mcp-wrap -- python my_mcp_server.py
 *   npx clawsig mcp-wrap --trace-file ./mcp-trace.jsonl -- node server.js
 */

import { startStdioShim } from './stdio-shim.js';

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  // Parse our flags vs the -- separator
  let traceFile: string | undefined;
  let commandStart = 0;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--') {
      commandStart = i + 1;
      break;
    }
    if (args[i] === '--trace-file' && args[i + 1]) {
      traceFile = args[i + 1];
      i++; // skip value
      continue;
    }
    // If no -- found, treat everything as the command
    commandStart = i;
    break;
  }

  const commandArgs = args.slice(commandStart);
  if (commandArgs.length === 0) {
    process.stderr.write(
      'Usage: clawsig mcp-wrap [--trace-file PATH] -- <command> [args...]\n\n' +
      'Wraps an MCP server to capture Clawsig tool receipts.\n\n' +
      'Examples:\n' +
      '  clawsig mcp-wrap -- npx @modelcontextprotocol/server-filesystem /home\n' +
      '  clawsig mcp-wrap -- python my_server.py\n' +
      '  clawsig mcp-wrap --trace-file ./trace.jsonl -- node server.js\n',
    );
    process.exit(1);
  }

  const command = commandArgs[0]!;
  const serverArgs = commandArgs.slice(1);

  process.stderr.write(`[clawsig:mcp] Wrapping MCP server: ${command} ${serverArgs.join(' ')}\n`);
  if (traceFile) {
    process.stderr.write(`[clawsig:mcp] Trace file: ${traceFile}\n`);
  }

  const exitCode = await startStdioShim({
    command,
    args: serverArgs,
    traceFile,
    onReceipt: (receipt) => {
      process.stderr.write(
        `[clawsig:mcp] Receipt: ${receipt.tool_name} (${receipt.result_status}, ${receipt.latency_ms}ms)\n`,
      );
    },
  });

  process.exit(exitCode);
}

main().catch((err) => {
  process.stderr.write(`[clawsig:mcp] Fatal: ${err.message}\n`);
  process.exit(1);
});
