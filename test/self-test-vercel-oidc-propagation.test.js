import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';

import {
  createSignedProductionSelfTestHandler,
  SELF_TEST_MESSAGE_PREFIX,
} from '../src/mcp/self-test.js';

const TOKEN = 'test-gateway-token';
const NOW_MS = 1_789_111_500_000;
const TS = Math.floor(NOW_MS / 1000);

function signedRequest() {
  const sig = createHmac('sha256', TOKEN)
    .update(`${SELF_TEST_MESSAGE_PREFIX}${TS}`)
    .digest('hex');
  return {
    method: 'GET',
    url: `https://para11ax.example/api/para11ax/self-test?ts=${TS}&sig=${sig}`,
    headers: { 'x-vercel-oidc-token': 'runtime-oidc-token' },
  };
}

test('production self-test forwards Vercel runtime OIDC header to every internal MCP request', async () => {
  const calls = [];
  const mcpHandler = async req => {
    calls.push(structuredClone(req));
    if (req.body.method === 'tools/list') {
      return { status: 200, body: { jsonrpc: '2.0', id: 1, result: {
        tools: [
          { name: 'para11ax_enrich' },
          { name: 'para11ax_user_scan' },
          ...Array.from({ length: 11 }, (_, i) => ({ name: `tool_${i}` })),
        ],
      } } };
    }
    if (req.body.params?.name === 'para11ax_enrich') {
      return { status: 200, body: { jsonrpc: '2.0', id: 2, result: {
        isError: false,
        structuredContent: { enrichment: { status: 'partial', evidence: [], failures: [] } },
      } } };
    }
    if (req.body.params?.name === 'para11ax_user_scan') {
      return { status: 200, body: { jsonrpc: '2.0', id: 3, result: {
        isError: false,
        structuredContent: { result: {
          summary: { totalScanned: 1, found: 1, notFound: 0, errors: 0, skipped: 0 },
          durationMs: 10,
        } },
      } } };
    }
    throw new Error('unexpected request');
  };

  const handle = createSignedProductionSelfTestHandler({
    env: { PARA11AX_TOKEN: TOKEN },
    nowMs: () => NOW_MS,
    mcpHandler,
  });
  const result = await handle(signedRequest());

  assert.equal(result.status, 200);
  assert.equal(result.body.status, 'pass');
  assert.equal(calls.length, 3);
  assert.ok(calls.every(call => call.headers['x-vercel-oidc-token'] === 'runtime-oidc-token'));
});
