import test from 'node:test';
import assert from 'node:assert/strict';

import { createMcpHttpHandler, MCP_PROTOCOL_VERSION } from '../src/mcp/transport.js';

const TOKEN = 'test-gateway-token';

function mcpCall(name, args) {
  return {
    method: 'POST',
    headers: {
      authorization: `Bearer ${TOKEN}`,
      'content-type': 'application/json',
      'mcp-protocol-version': MCP_PROTOCOL_VERSION,
      'mcp-method': 'tools/call',
      'mcp-name': name,
      'x-vercel-oidc-token': 'runtime-oidc-token',
    },
    body: {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name, arguments: args },
    },
  };
}

test('MCP preserves the Vercel runtime workload token for User Scanner bridge calls', async () => {
  const calls = [];
  const handle = createMcpHttpHandler({
    env: { PARA11AX_TOKEN: TOKEN, VERCEL: '1', VERCEL_ENV: 'production' },
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      return new Response(JSON.stringify({
        summary: { total_scanned: 1, found: 1, not_found: 0, errors: 0, skipped: 0 },
        results: [{ status: 'Found', site_name: 'Example', category: 'social', url: 'https://example.test/ger1e', extra: {} }],
        errored_sites: [],
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    },
  });

  const result = await handle(mcpCall('para11ax_user_scan', {
    scanType: 'username', target: 'ger1e', crossScan: false, noNsfw: true,
  }));

  assert.equal(result.body.result.isError, false);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].init.headers.Authorization, 'Bearer runtime-oidc-token');
  assert.equal(calls[0].init.headers['x-vercel-trusted-oidc-idp-token'], 'runtime-oidc-token');
});
