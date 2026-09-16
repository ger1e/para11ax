import test from 'node:test';
import assert from 'node:assert/strict';

import mcpApiHandler from '../api/mcp.js';
import para11axApiHandler from '../api/para11ax/[...path].js';
import { requestQueryValues, singleRequestQueryValue } from '../src/core/http.js';
import {
  MCP_OAUTH_SCOPE,
  MCP_RESOURCE,
  createMcpOAuthHandlers,
} from '../src/mcp/oauth.js';
import { createSignedProductionSelfTestHandler } from '../src/mcp/self-test.js';

const TOKEN = 'unit-test-gateway-token';

function requestWithLegacyQueryTrap(url) {
  return {
    method: 'GET',
    url,
    headers: { accept: 'application/json' },
    get query() {
      throw new Error('legacy_req_query_getter_accessed');
    },
  };
}

function fakeResponse() {
  return {
    statusCode: 0,
    headers: {},
    body: '',
    status(value) { this.statusCode = value; return this; },
    setHeader(name, value) { this.headers[String(name).toLowerCase()] = value; },
    end(value = '') { this.body = value ?? ''; },
  };
}

test('duplicate URL query controls remain ambiguous instead of becoming last-value-wins', () => {
  const req = { url: 'https://para11ax.vercel.app/self-test?mode=full&mode=invalid' };

  assert.deepEqual(requestQueryValues(req).mode, ['full', 'invalid']);
  assert.equal(singleRequestQueryValue(req, 'mode'), null);
});

test('PARA11AX catch-all routes URL-backed requests without reading Vercel req.query', async () => {
  const req = requestWithLegacyQueryTrap('https://para11ax.vercel.app/api/para11ax/self-test');
  const res = fakeResponse();

  await para11axApiHandler(req, res);

  assert.equal(res.statusCode, 503);
  assert.deepEqual(JSON.parse(res.body), { error: 'self_test_unconfigured' });
});

test('production self-test parses URL parameters without reading Vercel req.query', async () => {
  const handle = createSignedProductionSelfTestHandler({
    env: { PARA11AX_TOKEN: TOKEN },
    mcpHandler: async () => assert.fail('invalid mode must fail before MCP dispatch'),
  });

  const result = await handle(requestWithLegacyQueryTrap(
    'https://para11ax.vercel.app/api/para11ax/self-test?mode=invalid',
  ));

  assert.equal(result.status, 400);
  assert.deepEqual(result.body, { error: 'invalid_self_test_mode' });
});

test('MCP gateway resolves its internal route from the URL without reading Vercel req.query', async () => {
  const req = requestWithLegacyQueryTrap(
    'https://para11ax.vercel.app/api/mcp.js?_para11ax_mcp_route=protected-resource',
  );
  const res = fakeResponse();

  await mcpApiHandler(req, res);

  assert.equal(res.statusCode, 200);
  assert.equal(JSON.parse(res.body).resource, MCP_RESOURCE);
});

test('OAuth authorization parses URL parameters without reading Vercel req.query', () => {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: 'https://chatgpt.com/oauth/client.json',
    redirect_uri: 'https://chatgpt.com/connector_platform_oauth_redirect',
    resource: MCP_RESOURCE,
    scope: MCP_OAUTH_SCOPE,
    state: 'opaque-chatgpt-state',
    code_challenge: 'a'.repeat(43),
    code_challenge_method: 'S256',
  });
  const handlers = createMcpOAuthHandlers({ env: { PARA11AX_TOKEN: TOKEN } });

  const result = handlers.handleAuthorize(requestWithLegacyQueryTrap(
    `https://para11ax.vercel.app/oauth/authorize?${params}`,
  ));

  assert.equal(result.status, 200);
  assert.match(result.body, /Authorize ChatGPT/);
});
