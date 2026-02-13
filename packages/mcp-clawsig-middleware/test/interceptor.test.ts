/**
 * Tests for the MCP JSON-RPC interceptor.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { McpInterceptor } from '../dist/interceptor.js';

describe('McpInterceptor', () => {
  it('captures tools/call request and synthesizes receipt on response', () => {
    const receipts: unknown[] = [];
    const interceptor = new McpInterceptor({
      onReceipt: (r) => receipts.push(r),
    });

    // Client sends tools/call
    const request = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: {
        name: 'read_file',
        arguments: { path: '/etc/hostname' },
      },
    });

    const processedReq = interceptor.processRequest(request);
    assert.equal(processedReq, request, 'Request should pass through unmodified');
    assert.equal(interceptor.receiptCount, 0, 'No receipt yet');

    // Server responds
    const response = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      result: {
        content: [{ type: 'text', text: 'my-hostname' }],
      },
    });

    const processedResp = interceptor.processResponse(response);
    assert.equal(interceptor.receiptCount, 1, 'Should have 1 receipt');

    // Check receipt was injected into _meta
    const parsed = JSON.parse(processedResp);
    assert.ok(parsed.result._meta?.clawsig_receipt, 'Receipt should be injected');
    assert.equal(parsed.result._meta.clawsig_receipt.tool_name, 'read_file');
    assert.equal(parsed.result._meta.clawsig_receipt.result_status, 'success');
    assert.ok(parsed.result._meta.clawsig_receipt.receipt_id.startsWith('mcp_'));

    // Check callback
    assert.equal(receipts.length, 1);
  });

  it('handles error responses', () => {
    const interceptor = new McpInterceptor();

    interceptor.processRequest(JSON.stringify({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: { name: 'write_file', arguments: { path: '/root/nope', content: 'x' } },
    }));

    interceptor.processResponse(JSON.stringify({
      jsonrpc: '2.0',
      id: 2,
      error: { code: -32000, message: 'Permission denied' },
    }));

    assert.equal(interceptor.receiptCount, 1);
    const receipt = interceptor.getReceipts()[0]!;
    assert.equal(receipt.tool_name, 'write_file');
    assert.equal(receipt.result_status, 'error');
  });

  it('ignores non-tool messages', () => {
    const interceptor = new McpInterceptor();

    // Initialize message (not tools/call)
    interceptor.processRequest(JSON.stringify({
      jsonrpc: '2.0',
      id: 0,
      method: 'initialize',
      params: { protocolVersion: '2024-11-05' },
    }));

    interceptor.processResponse(JSON.stringify({
      jsonrpc: '2.0',
      id: 0,
      result: { protocolVersion: '2024-11-05', capabilities: {} },
    }));

    assert.equal(interceptor.receiptCount, 0, 'Should not capture non-tool messages');
  });

  it('handles multiple concurrent tool calls', () => {
    const interceptor = new McpInterceptor();

    // Two concurrent tool calls
    interceptor.processRequest(JSON.stringify({
      jsonrpc: '2.0', id: 10, method: 'tools/call',
      params: { name: 'list_files', arguments: { path: '/home' } },
    }));

    interceptor.processRequest(JSON.stringify({
      jsonrpc: '2.0', id: 11, method: 'tools/call',
      params: { name: 'read_file', arguments: { path: '/etc/passwd' } },
    }));

    // Responses arrive out of order
    interceptor.processResponse(JSON.stringify({
      jsonrpc: '2.0', id: 11,
      result: { content: [{ type: 'text', text: 'root:x:0:0:...' }] },
    }));

    interceptor.processResponse(JSON.stringify({
      jsonrpc: '2.0', id: 10,
      result: { content: [{ type: 'text', text: 'file1.txt\nfile2.txt' }] },
    }));

    assert.equal(interceptor.receiptCount, 2);
    const names = interceptor.getReceipts().map(r => r.tool_name);
    assert.ok(names.includes('list_files'));
    assert.ok(names.includes('read_file'));
  });

  it('passes through malformed JSON without crashing', () => {
    const interceptor = new McpInterceptor();

    const result1 = interceptor.processRequest('not json at all');
    assert.equal(result1, 'not json at all');

    const result2 = interceptor.processResponse('{broken');
    assert.equal(result2, '{broken');

    assert.equal(interceptor.receiptCount, 0);
  });
});
