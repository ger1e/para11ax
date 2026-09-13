import test from 'node:test';
import assert from 'node:assert/strict';

import { normalizeExternalMcpResponse } from '../src/mcp/external-auth-recovery.js';
import { MCP_OAUTH_SCOPE, MCP_OFFLINE_SCOPE } from '../src/mcp/oauth.js';

const CHALLENGE = 'Bearer resource_metadata="https://para11ax.vercel.app/.well-known/oauth-protected-resource", scope="para11ax:use", error="invalid_token"';

test('external stale OAuth tool calls become HTTP 401 challenges for ChatGPT relinking', () => {
  const result = normalizeExternalMcpResponse('', {
    status: 200,
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: {
      jsonrpc: '2.0',
      id: 7,
      result: {
        structuredContent: { error: 'authentication_required' },
        _meta: { 'mcp/www_authenticate': [CHALLENGE] },
        isError: true,
      },
    },
  });

  assert.equal(result.status, 401);
  assert.equal(result.headers['www-authenticate'], CHALLENGE);
  assert.deepEqual(result.body, { error: 'unauthorized' });
});

test('external response normalization does not rewrite ordinary successful MCP calls', () => {
  const input = {
    status: 200,
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: { jsonrpc: '2.0', id: 1, result: { structuredContent: { ok: true }, isError: false } },
  };
  assert.deepEqual(normalizeExternalMcpResponse('', input), input);
});

test('protected-resource metadata advertises refresh-capable authorization scope', () => {
  const result = normalizeExternalMcpResponse('protected-resource', {
    status: 200,
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: {
      resource: 'https://para11ax.vercel.app/mcp',
      authorization_servers: ['https://para11ax.vercel.app'],
      scopes_supported: [MCP_OAUTH_SCOPE],
    },
  });

  assert.deepEqual(result.body.scopes_supported, [MCP_OAUTH_SCOPE, MCP_OFFLINE_SCOPE]);
});

test('malformed auth errors fail closed without inventing a challenge', () => {
  const input = {
    status: 200,
    headers: {},
    body: {
      jsonrpc: '2.0',
      id: 9,
      result: { structuredContent: { error: 'authentication_required' }, isError: true },
    },
  };
  assert.deepEqual(normalizeExternalMcpResponse('', input), input);
});
