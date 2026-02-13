# @clawbureau/mcp-clawsig-middleware

Clawsig middleware for the [Model Context Protocol](https://modelcontextprotocol.io/) (MCP).

Automatically generates cryptographic `tool_receipts` from MCP tool invocations without modifying the MCP server code.

## Why?

An LLM-layer tool_receipt proves **the model asked** to use a tool.
An MCP-layer tool_receipt proves **the host actually executed** the tool.
Reconciling both proves causal integrity.

## Quick Start (stdio transport)

```bash
# Wrap any MCP server
npx clawsig mcp-wrap -- npx @modelcontextprotocol/server-filesystem /home

# With trace logging
npx clawsig mcp-wrap --trace-file ./mcp-trace.jsonl -- python my_server.py
```

In your agent's MCP config (e.g., `cline_mcp_settings.json`):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["clawsig", "mcp-wrap", "--", "npx", "@modelcontextprotocol/server-filesystem", "/home"]
    }
  }
}
```

## Programmatic Usage

```typescript
import { McpInterceptor } from '@clawbureau/mcp-clawsig-middleware';

const interceptor = new McpInterceptor({
  onReceipt: (receipt) => console.log('Tool receipt:', receipt),
});

// For each JSON-RPC message from client → server:
const forwardToServer = interceptor.processRequest(clientMessage);

// For each JSON-RPC message from server → client:
const forwardToClient = interceptor.processResponse(serverMessage);

// Get all receipts
const receipts = interceptor.getReceipts();
```

## How It Works

The middleware sits between the MCP client (agent) and MCP server:

```
Agent → [stdin] → McpInterceptor.processRequest() → MCP Server
Agent ← [stdout] ← McpInterceptor.processResponse() ← MCP Server
```

For each `tools/call` JSON-RPC request:
1. Hash the tool arguments (SHA-256)
2. Start a timer
3. When the response arrives, hash the result
4. Synthesize a `McpToolReceipt` with args_hash, result_hash, latency
5. Inject the receipt into `result._meta.clawsig_receipt`

## Receipt Format

```json
{
  "receipt_version": "1",
  "receipt_id": "mcp_a1b2c3d4-...",
  "receipt_source": "mcp",
  "tool_name": "read_file",
  "args_hash_b64u": "abc123...",
  "result_hash_b64u": "def456...",
  "result_status": "success",
  "latency_ms": 42,
  "timestamp": "2026-02-13T23:00:00.000Z",
  "mcp_request_id": 1
}
```

## License

Apache-2.0
