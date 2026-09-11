import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';

import {
  createSignedProductionSelfTestHandler,
  SELF_TEST_MESSAGE_PREFIX,
} from '../src/mcp/self-test.js';

const TOKEN = 'unit-test-gateway-token';
const NOW_MS = 1_789_094_000_000;
const NOW_SECONDS = Math.floor(NOW_MS / 1000);

function signature(ts = NOW_SECONDS) {
  return createHmac('sha256', TOKEN)
    .update(`${SELF_TEST_MESSAGE_PREFIX}${ts}`)
    .digest('hex');
}

function request(ts = NOW_SECONDS, sig = signature(ts)) {
  return {
    method: 'GET',
    url: `https://para11ax.example/api/para11ax/self-test?ts=${ts}&sig=${sig}`,
    headers: {},
  };
}

function fakeMcp(calls) {
  return async req => {
    calls.push(structuredClone(req));
    const body = req.body;
    if (body.method === 'tools/list') {
      return {
        status: 200,
        body: {
          jsonrpc: '2.0',
          id: body.id,
          result: {
            resultType: 'complete',
            tools: Array.from({ length: 13 }, (_, i) => ({
              name: i === 0 ? 'para11ax_enrich' : i === 1 ? 'para11ax_user_scan' : `tool_${i}`,
            })),
          },
        },
      };
    }
    if (body.params?.name === 'para11ax_enrich') {
      return {
        status: 200,
        body: {
          jsonrpc: '2.0',
          id: body.id,
          result: {
            resultType: 'complete',
            isError: false,
            structuredContent: {
              enrichment: {
                status: 'partial',
                subject: { type: 'ip', value: '1.1.1.1' },
                evidence: [{ provider: 'fixture-a' }, { provider: 'fixture-b' }],
                failures: [{ provider: 'fixture-c' }],
              },
            },
          },
        },
      };
    }
    if (body.params?.name === 'para11ax_user_scan') {
      return {
        status: 200,
        body: {
          jsonrpc: '2.0',
          id: body.id,
          result: {
            resultType: 'complete',
            isError: false,
            structuredContent: {
              result: {
                target: 'ger1e',
                summary: { totalScanned: 455, found: 17, notFound: 420, errors: 8, skipped: 10 },
                results: [{ status: 'found', siteName: 'must-not-leak', url: 'https://example.invalid/private-detail' }],
                erroredSites: ['must-not-leak-error-site'],
                durationMs: 1234,
              },
            },
          },
        },
      };
    }
    throw new Error('unexpected MCP request');
  };
}

test('signed production self-test rejects missing invalid expired signatures before MCP dispatch', async () => {
  const calls = [];
  const handle = createSignedProductionSelfTestHandler({
    env: { PARA11AX_TOKEN: TOKEN },
    nowMs: () => NOW_MS,
    mcpHandler: fakeMcp(calls),
  });

  for (const req of [
    { method: 'GET', url: 'https://para11ax.example/api/para11ax/self-test', headers: {} },
    request(NOW_SECONDS, '0'.repeat(64)),
    request(NOW_SECONDS - 121),
  ]) {
    const result = await handle(req);
    assert.equal(result.status, 401);
  }
  assert.equal(calls.length, 0);
});

test('signed production self-test is GET-only, no-store and fails closed without gateway secret', async () => {
  const handle = createSignedProductionSelfTestHandler({
    env: {},
    nowMs: () => NOW_MS,
    mcpHandler: async () => assert.fail('MCP must not run'),
  });
  const missingSecret = await handle(request());
  assert.equal(missingSecret.status, 503);
  assert.equal(missingSecret.headers['cache-control'], 'no-store');

  const post = await createSignedProductionSelfTestHandler({ env: { PARA11AX_TOKEN: TOKEN }, nowMs: () => NOW_MS })({ method: 'POST', url: 'https://para11ax.example/api/para11ax/self-test' });
  assert.equal(post.status, 405);
  assert.equal(post.headers.allow, 'GET');
});

test('valid signature runs only fixed MCP catalog, public IP enrichment and self username scan', async () => {
  const calls = [];
  const handle = createSignedProductionSelfTestHandler({
    env: { PARA11AX_TOKEN: TOKEN },
    nowMs: () => NOW_MS,
    mcpHandler: fakeMcp(calls),
  });

  const result = await handle(request());
  assert.equal(result.status, 200);
  assert.equal(result.headers['cache-control'], 'no-store');
  assert.equal(result.body.status, 'pass');
  assert.deepEqual(result.body.mcp, { authenticated: true, toolCount: 13 });
  assert.deepEqual(result.body.enrichment, {
    target: '1.1.1.1',
    profile: 'fast',
    status: 'partial',
    evidenceCount: 2,
    failureCount: 1,
  });
  assert.deepEqual(result.body.userScanner, {
    target: 'ger1e',
    totalScanned: 455,
    found: 17,
    notFound: 420,
    errors: 8,
    skipped: 10,
    durationMs: 1234,
  });
  assert.equal(JSON.stringify(result.body).includes('must-not-leak'), false);
  assert.equal(JSON.stringify(result.body).includes(TOKEN), false);

  assert.equal(calls.length, 3);
  assert.equal(calls[0].body.method, 'tools/list');
  assert.deepEqual(calls[1].body.params, {
    name: 'para11ax_enrich',
    arguments: { indicator: '1.1.1.1', profile: 'fast' },
  });
  assert.deepEqual(calls[2].body.params, {
    name: 'para11ax_user_scan',
    arguments: { scanType: 'username', target: 'ger1e', crossScan: false, noNsfw: true },
  });
  for (const call of calls) {
    assert.equal(call.headers.authorization, `Bearer ${TOKEN}`);
    assert.equal(call.headers['mcp-protocol-version'], '2026-07-28');
    assert.equal(call.headers['mcp-method'], call.body.method);
    if (call.body.method === 'tools/call') assert.equal(call.headers['mcp-name'], call.body.params.name);
  }
});
