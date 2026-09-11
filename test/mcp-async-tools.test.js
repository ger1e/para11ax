import test from 'node:test';
import assert from 'node:assert/strict';

import { createMcpHttpHandler, MCP_PROTOCOL_VERSION } from '../src/mcp/transport.js';

const TOKEN = 'test-gateway-token';

function call(name, argumentsValue) {
  return {
    method: 'POST',
    headers: {
      authorization: `Bearer ${TOKEN}`,
      'content-type': 'application/json',
      'mcp-protocol-version': MCP_PROTOCOL_VERSION,
      'mcp-method': 'tools/call',
      'mcp-name': name,
    },
    body: {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name, arguments: argumentsValue },
    },
  };
}

const workerEnvelope = {
  summary: { total_scanned: 3, found: 1, not_found: 1, errors: 1, skipped: 0 },
  results: [{ status: 'Found', site_name: 'Example', category: 'social', url: 'https://example.test/ger1e', extra: {} }],
  errored_sites: ['Broken'],
};

test('MCP awaits asynchronous User Scanner handler before shaping tool result', async () => {
  const fetchCalls = [];
  const handle = createMcpHttpHandler({
    env: {
      PARA11AX_TOKEN: TOKEN,
      PARA11AX_USER_SCANNER_URL: 'https://worker.example/scan',
      PARA11AX_USER_SCANNER_TOKEN: 'worker-secret',
    },
    fetchImpl: async (url, init) => {
      fetchCalls.push({ url, init });
      await Promise.resolve();
      return new Response(JSON.stringify(workerEnvelope), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    },
    nowMs: (() => { let value = 1000; return () => value += 5; })(),
  });

  const result = await handle(call('para11ax_user_scan', {
    scanType: 'username',
    target: 'ger1e',
    crossScan: false,
    noNsfw: true,
  }));

  assert.equal(result.status, 200);
  assert.equal(result.body.result.isError, false);
  assert.equal(fetchCalls.length, 1);
  assert.equal(result.body.result.structuredContent.result.target, 'ger1e');
  assert.equal(result.body.result.structuredContent.result.summary.found, 1);
  assert.equal(result.body.result.structuredContent.result.summary.totalScanned, 3);
});
