import test from 'node:test';
import assert from 'node:assert/strict';

import { createMcpHttpHandler, MCP_PROTOCOL_VERSION } from '../src/mcp/transport.js';

const TOKEN = 'test-gateway-token';
const WORKER_TOKEN = 'test-worker-token';

function callRequest(name, args) {
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
      params: { name, arguments: args },
    },
  };
}

test('MCP awaits async-backed User Scanner handlers before normalizing the tool result', async () => {
  let workerRequest = null;
  const fetchImpl = async (url, options) => {
    workerRequest = { url: String(url), options };
    const payload = {
      summary: { totalScanned: 3, found: 1, notFound: 1, errors: 0, skipped: 1 },
      results: [],
      erroredSites: [],
    };
    return new Response(JSON.stringify(payload), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };

  const handle = createMcpHttpHandler({
    env: {
      PARA11AX_TOKEN: TOKEN,
      PARA11AX_USER_SCANNER_URL: 'https://scanner.example/scan',
      PARA11AX_USER_SCANNER_TOKEN: WORKER_TOKEN,
    },
    fetchImpl,
    nowMs: () => 1_789_108_000_000,
  });

  const result = await handle(callRequest('para11ax_user_scan', {
    scanType: 'username',
    target: 'ger1e',
    crossScan: false,
    noNsfw: true,
  }));

  assert.equal(result.status, 200);
  assert.equal(result.body.result.isError, false);
  assert.equal(result.body.result.structuredContent.result.summary.totalScanned, 3);
  assert.equal(workerRequest.url, 'https://scanner.example/scan');
  assert.equal(workerRequest.options.headers.Authorization, `Bearer ${WORKER_TOKEN}`);
});
