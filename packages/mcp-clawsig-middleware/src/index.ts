/**
 * @clawbureau/mcp-clawsig-middleware
 *
 * Automatically generates Clawsig tool_receipts from MCP (Model Context Protocol)
 * tool invocations. Wraps the MCP server transport to intercept JSON-RPC messages
 * without modifying the MCP server code.
 *
 * Why MCP middleware matters:
 * - An LLM-layer tool_receipt proves "the model ASKED to use a tool"
 * - An MCP-layer tool_receipt proves "the host ACTUALLY EXECUTED the tool"
 * - Reconciling both proves causal integrity (no TOCTOU exploits)
 *
 * Usage (stdio transport):
 *   npx clawsig mcp-wrap -- npx @modelcontextprotocol/server-filesystem /path
 *
 * Usage (programmatic):
 *   import { McpInterceptor } from '@clawbureau/mcp-clawsig-middleware';
 *   const interceptor = new McpInterceptor({ onReceipt: console.log });
 *   // For each message from client:
 *   const processed = interceptor.processRequest(message);
 *   // For each message from server:
 *   const enriched = interceptor.processResponse(message);
 */

export { McpInterceptor } from './interceptor.js';
export { startStdioShim } from './stdio-shim.js';

export type {
  McpToolReceipt,
  PendingToolCall,
  InterceptorOptions,
} from './interceptor.js';

export type {
  StdioShimOptions,
} from './stdio-shim.js';
