/**
 * MCP Stdio Transport Shim.
 *
 * Wraps an MCP server process, intercepting stdin/stdout to capture
 * JSON-RPC tool invocations and inject Clawsig receipts.
 *
 * Usage:
 *   npx clawsig mcp-wrap -- npx @modelcontextprotocol/server-filesystem /path
 *
 * Architecture:
 *   Agent (stdin) → [StdioShim] → MCP Server (stdin)
 *   Agent (stdout) ← [StdioShim] ← MCP Server (stdout)
 *
 * The shim sits between the agent's MCP client and the MCP server process.
 * It parses JSON-RPC messages line by line (MCP stdio uses newline-delimited JSON),
 * intercepts tools/call requests and responses, and injects receipts.
 */

import { spawn, type ChildProcess } from 'node:child_process';
import { createInterface } from 'node:readline';
import { McpInterceptor, type McpToolReceipt } from './interceptor.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface StdioShimOptions {
  /** Command to spawn the MCP server. */
  command: string;
  /** Arguments for the MCP server command. */
  args: string[];
  /** Working directory. */
  cwd?: string;
  /** Additional env vars. */
  env?: Record<string, string>;
  /** Callback for each receipt. */
  onReceipt?: (receipt: McpToolReceipt) => void;
  /** Write receipts to this JSONL file. */
  traceFile?: string;
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

/**
 * Start the stdio shim.
 *
 * Spawns the MCP server as a child process and pipes stdio through
 * the McpInterceptor. Returns a promise that resolves when the child exits.
 */
export async function startStdioShim(options: StdioShimOptions): Promise<number> {
  const interceptor = new McpInterceptor({
    onReceipt: options.onReceipt,
  });

  // Spawn the MCP server
  const child: ChildProcess = spawn(options.command, options.args, {
    cwd: options.cwd ?? process.cwd(),
    env: {
      ...process.env,
      ...options.env,
    },
    stdio: ['pipe', 'pipe', 'inherit'], // pipe stdin/stdout, inherit stderr
  });

  if (!child.stdin || !child.stdout) {
    throw new Error('Failed to pipe stdio to MCP server');
  }

  // Forward stdin: Agent → Interceptor → MCP Server
  const stdinRl = createInterface({ input: process.stdin, crlfDelay: Infinity });
  stdinRl.on('line', (line) => {
    const processed = interceptor.processRequest(line);
    child.stdin!.write(processed + '\n');
  });

  // Forward stdout: MCP Server → Interceptor → Agent
  const stdoutRl = createInterface({ input: child.stdout, crlfDelay: Infinity });
  stdoutRl.on('line', (line) => {
    const processed = interceptor.processResponse(line);
    process.stdout.write(processed + '\n');
  });

  // Handle trace file
  let traceStream: import('node:fs').WriteStream | null = null;
  if (options.traceFile) {
    const { createWriteStream } = await import('node:fs');
    traceStream = createWriteStream(options.traceFile, { flags: 'a' });

    // Override onReceipt to also write to trace file
    const originalOnReceipt = interceptor['options'].onReceipt;
    interceptor['options'].onReceipt = (receipt: McpToolReceipt) => {
      originalOnReceipt?.(receipt);
      traceStream?.write(JSON.stringify({ layer: 'mcp', ...receipt }) + '\n');
    };
  }

  // Wait for child to exit
  return new Promise<number>((resolve) => {
    child.on('error', (err) => {
      process.stderr.write(`[clawsig:mcp] Server spawn error: ${err.message}\n`);
      resolve(1);
    });

    child.on('close', (code) => {
      stdinRl.close();
      stdoutRl.close();
      traceStream?.end();

      const receiptCount = interceptor.receiptCount;
      if (receiptCount > 0) {
        process.stderr.write(
          `[clawsig:mcp] ${receiptCount} tool receipt(s) captured\n`,
        );
      }

      resolve(code ?? 0);
    });

    // Propagate signals
    process.on('SIGINT', () => child.kill('SIGINT'));
    process.on('SIGTERM', () => child.kill('SIGTERM'));
  });
}
