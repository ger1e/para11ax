import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/app.js';
import { createMcpHttpHandler, MCP_PROTOCOL_VERSION } from '../src/mcp/server.js';

const TOKEN = 'gateway-test-token';
const WORKER_TOKEN = 'worker-test-token';
const USERNAME = 'para11ax_qa_fixture';

function jsonResponse(payload) {
  const bytes = new TextEncoder().encode(JSON.stringify(payload));
  return {
    ok: true,
    status: 200,
    headers: { get(name) { return String(name).toLowerCase() === 'content-length' ? String(bytes.byteLength) : null; } },
    async arrayBuffer() { return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength); },
  };
}

function workerPayload() {
  return {
    summary: { totalScanned: 1, found: 1, notFound: 0, errors: 0, skipped: 0 },
    results: [{ status: 'Found', siteName: 'Fixture', category: 'social', url: `https://example.org/${USERNAME}`, extra: { username: USERNAME } }],
    erroredSites: [],
  };
}

test('username intelligence search delegates to the bounded User Scanner and is never enrichment fanout', async () => {
  const calls = [];
  const app = createApp({
    env: {
      PARA11AX_TOKEN: TOKEN,
      PARA11AX_USER_SCANNER_URL: 'https://scanner.example.test/scan',
      PARA11AX_USER_SCANNER_TOKEN: WORKER_TOKEN,
    },
    fetchImpl: async (url, options) => {
      calls.push({ url: String(url), options });
      return jsonResponse(workerPayload());
    },
    nowMs: (() => { let n = 100; return () => n++; })(),
  });

  const result = await app.handleIntelligence({
    method: 'POST',
    headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' },
    body: { operation: 'search', indicator: `user:${USERNAME}` },
  });

  assert.equal(result.status, 200);
  assert.equal(result.body.operation, 'search');
  assert.equal(result.body.subject.type, 'username');
  assert.equal(result.body.subject.value, USERNAME);
  assert.equal(result.body.policy.fanoutEligible, false);
  assert.equal(result.body.policy.retentionClass, 'no_store');
  assert.equal(result.body.scanner.summary.found, 1);
  assert.equal(result.body.scanner.results[0].matchConfidence, 'exact');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://scanner.example.test/scan');
  assert.equal(JSON.parse(calls[0].options.body).scan_type, 'username');
  assert.equal(JSON.parse(calls[0].options.body).target, USERNAME);

  const enrich = await app.handleEnrich({
    method: 'POST',
    headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' },
    body: { indicator: `user:${USERNAME}` },
  });
  assert.equal(enrich.status, 400);
  assert.equal(calls.length, 1);
});

test('MCP intelligence username search preserves runtime workload identity for the existing scanner bridge', async () => {
  const calls = [];
  const handler = createMcpHttpHandler({
    env: {
      PARA11AX_TOKEN: TOKEN,
      PARA11AX_USER_SCANNER_URL: 'https://scanner.example.test/scan',
    },
    fetchImpl: async (url, options) => {
      calls.push({ url: String(url), options });
      return jsonResponse(workerPayload());
    },
  });

  const result = await handler({
    method: 'POST',
    headers: {
      authorization: `Bearer ${TOKEN}`,
      'content-type': 'application/json',
      'mcp-protocol-version': MCP_PROTOCOL_VERSION,
      'x-vercel-oidc-token': 'runtime-workload-token',
    },
    body: {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'para11ax_intelligence', arguments: { operation: 'search', indicator: `user:${USERNAME}` } },
    },
  });

  assert.equal(result.status, 200);
  assert.equal(result.body.result.isError, false);
  assert.equal(result.body.result.structuredContent.intelligence.policy.fanoutEligible, false);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].options.headers['x-vercel-trusted-oidc-idp-token'], 'runtime-workload-token');
});
