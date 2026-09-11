import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import {
  MCP_AUTH_ISSUER,
  MCP_OAUTH_SCOPE,
  MCP_PROTECTED_RESOURCE_METADATA,
  MCP_RESOURCE,
  createMcpOAuthHandlers,
  verifyMcpAuthorization,
} from '../src/mcp/oauth.js';
import { createMcpHttpHandler, MCP_PROTOCOL_VERSION } from '../src/mcp/transport.js';

const SECRET = 'correct-horse-battery-staple';
const NOW_MS = Date.parse('2026-09-11T10:00:00.000Z');
const VERIFIER = 'v'.repeat(64);
const CHALLENGE = createHash('sha256').update(VERIFIER, 'ascii').digest('base64url');

function authorizeParams(overrides = {}) {
  return {
    response_type: 'code',
    client_id: 'https://chatgpt.com/oauth/client.json',
    redirect_uri: 'https://chatgpt.com/connector_platform_oauth_redirect',
    resource: MCP_RESOURCE,
    scope: MCP_OAUTH_SCOPE,
    state: 'opaque-chatgpt-state',
    code_challenge: CHALLENGE,
    code_challenge_method: 'S256',
    ...overrides,
  };
}

function formRequest(body) {
  const encoded = new URLSearchParams(body).toString();
  return {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      'content-length': String(Buffer.byteLength(encoded)),
    },
    body: encoded,
  };
}

function issueAccessToken() {
  const handlers = createMcpOAuthHandlers({ env: { PARA11AX_TOKEN: SECRET }, nowMs: () => NOW_MS });
  const consent = handlers.handleAuthorize(formRequest({ ...authorizeParams(), gateway_token: SECRET }));
  assert.equal(consent.status, 302);
  const code = new URL(consent.headers.location).searchParams.get('code');
  assert.ok(code);
  const exchange = handlers.handleToken(formRequest({
    grant_type: 'authorization_code',
    code,
    client_id: authorizeParams().client_id,
    redirect_uri: authorizeParams().redirect_uri,
    resource: MCP_RESOURCE,
    code_verifier: VERIFIER,
  }));
  assert.equal(exchange.status, 200);
  return exchange.body.access_token;
}

function mcpRequest(method, params = {}, token = null) {
  return {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'mcp-protocol-version': MCP_PROTOCOL_VERSION,
      'mcp-method': method,
      ...(method === 'tools/call' ? { 'mcp-name': params.name } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: { jsonrpc: '2.0', id: 1, method, params },
  };
}

test('publishes protected-resource and OAuth authorization metadata for ChatGPT', () => {
  const handlers = createMcpOAuthHandlers({ env: { PARA11AX_TOKEN: SECRET } });
  const resource = handlers.handleProtectedResource({ method: 'GET' });
  assert.equal(resource.status, 200);
  assert.equal(resource.body.resource, MCP_RESOURCE);
  assert.deepEqual(resource.body.authorization_servers, [MCP_AUTH_ISSUER]);
  assert.deepEqual(resource.body.scopes_supported, [MCP_OAUTH_SCOPE]);

  const metadata = handlers.handleAuthorizationMetadata({ method: 'GET' });
  assert.equal(metadata.status, 200);
  assert.equal(metadata.body.issuer, MCP_AUTH_ISSUER);
  assert.equal(metadata.body.client_id_metadata_document_supported, true);
  assert.equal(metadata.body.authorization_response_iss_parameter_supported, true);
  assert.deepEqual(metadata.body.code_challenge_methods_supported, ['S256']);
  assert.deepEqual(metadata.body.token_endpoint_auth_methods_supported, ['none']);
});

test('Vercel routes every OAuth endpoint through the existing MCP function before catch-all handling', async () => {
  const config = JSON.parse(await readFile(new URL('../vercel.json', import.meta.url), 'utf8'));
  const sources = config.routes.map(route => route.src).filter(Boolean);
  const mcpIndex = sources.indexOf('/mcp');
  const catchAllIndex = sources.indexOf('/api/para11ax/(.*)');
  for (const source of [
    '/\\.well-known/oauth-protected-resource',
    '/\\.well-known/oauth-protected-resource/mcp',
    '/\\.well-known/oauth-authorization-server',
    '/oauth/authorize',
    '/oauth/token',
  ]) {
    const index = sources.indexOf(source);
    assert.ok(index >= 0, `missing OAuth route ${source}`);
    assert.ok(index < mcpIndex && index < catchAllIndex, `${source} must precede MCP/API fallbacks`);
  }
});

test('authorization form accepts only the fixed ChatGPT client and never echoes credentials', () => {
  const handlers = createMcpOAuthHandlers({ env: { PARA11AX_TOKEN: SECRET }, nowMs: () => NOW_MS });
  const page = handlers.handleAuthorize({ method: 'GET', query: authorizeParams() });
  assert.equal(page.status, 200);
  assert.match(page.body, /Authorize ChatGPT/);

  const rejected = handlers.handleAuthorize(formRequest({ ...authorizeParams(), gateway_token: 'do-not-echo-this' }));
  assert.equal(rejected.status, 401);
  assert.match(rejected.body, /not accepted/);
  assert.doesNotMatch(rejected.body, /do-not-echo-this/);

  const redirectAttack = handlers.handleAuthorize({ method: 'GET', query: authorizeParams({ redirect_uri: 'https://evil.example/callback' }) });
  assert.equal(redirectAttack.status, 400);
  assert.equal(redirectAttack.headers.location, undefined);
});

test('authorization-code exchange enforces PKCE and issues a resource-bound access token', () => {
  const handlers = createMcpOAuthHandlers({ env: { PARA11AX_TOKEN: SECRET }, nowMs: () => NOW_MS });
  const consent = handlers.handleAuthorize(formRequest({ ...authorizeParams(), gateway_token: SECRET }));
  const callback = new URL(consent.headers.location);
  assert.equal(callback.origin + callback.pathname, authorizeParams().redirect_uri);
  assert.equal(callback.searchParams.get('state'), authorizeParams().state);
  assert.equal(callback.searchParams.get('iss'), MCP_AUTH_ISSUER);
  const code = callback.searchParams.get('code');

  const rejected = handlers.handleToken(formRequest({
    grant_type: 'authorization_code', code,
    client_id: authorizeParams().client_id,
    redirect_uri: authorizeParams().redirect_uri,
    resource: MCP_RESOURCE,
    code_verifier: 'x'.repeat(64),
  }));
  assert.equal(rejected.status, 400);
  assert.equal(rejected.body.error, 'invalid_grant');

  const exchange = handlers.handleToken(formRequest({
    grant_type: 'authorization_code', code,
    client_id: authorizeParams().client_id,
    redirect_uri: authorizeParams().redirect_uri,
    resource: MCP_RESOURCE,
    code_verifier: VERIFIER,
  }));
  assert.equal(exchange.status, 200);
  assert.equal(exchange.body.token_type, 'Bearer');
  assert.equal(exchange.body.scope, MCP_OAUTH_SCOPE);
  assert.equal(verifyMcpAuthorization({ headers: { authorization: `Bearer ${exchange.body.access_token}` } }, SECRET, NOW_MS).scheme, 'oauth2');
  assert.equal(verifyMcpAuthorization({ headers: { authorization: `Bearer ${exchange.body.access_token}` } }, SECRET, NOW_MS + (31 * 24 * 60 * 60 * 1000)).authorized, false);

  const replay = handlers.handleToken(formRequest({
    grant_type: 'authorization_code', code,
    client_id: authorizeParams().client_id,
    redirect_uri: authorizeParams().redirect_uri,
    resource: MCP_RESOURCE,
    code_verifier: VERIFIER,
  }));
  assert.equal(replay.status, 400);
  assert.equal(replay.body.error, 'invalid_grant');
});

test('MCP discovery is public while every tool declares OAuth and calls trigger linking', async () => {
  const handle = createMcpHttpHandler({ env: { PARA11AX_TOKEN: SECRET }, nowMs: () => NOW_MS });
  const listed = await handle(mcpRequest('tools/list'));
  assert.equal(listed.status, 200);
  assert.equal(listed.body.result.tools.length, 13);
  for (const tool of listed.body.result.tools) {
    assert.deepEqual(tool.securitySchemes, [{ type: 'oauth2', scopes: [MCP_OAUTH_SCOPE] }]);
  }

  const blocked = await handle(mcpRequest('tools/call', { name: 'para11ax_capabilities', arguments: { view: 'catalog' } }));
  assert.equal(blocked.status, 200);
  assert.equal(blocked.body.result.isError, true);
  assert.equal(blocked.body.result.structuredContent.error, 'authentication_required');
  assert.match(blocked.body.result._meta['mcp/www_authenticate'][0], new RegExp(MCP_PROTECTED_RESOURCE_METADATA.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
});

test('MCP accepts both scoped OAuth access tokens and the existing gateway bearer', async () => {
  const handle = createMcpHttpHandler({ env: { PARA11AX_TOKEN: SECRET }, nowMs: () => NOW_MS });
  for (const token of [issueAccessToken(), SECRET]) {
    const result = await handle(mcpRequest('tools/call', {
      name: 'para11ax_capabilities',
      arguments: { view: 'catalog' },
    }, token));
    assert.equal(result.status, 200);
    assert.equal(result.body.result.isError, false);
    assert.equal(result.body.result.structuredContent.tools.length, 13);
  }
});

test('MCP fails closed instead of throwing when gateway auth is unconfigured', async () => {
  const handle = createMcpHttpHandler({ env: {}, nowMs: () => NOW_MS });
  const result = await handle(mcpRequest('tools/call', {
    name: 'para11ax_capabilities', arguments: { view: 'catalog' },
  }, 'attacker-controlled-bearer'));
  assert.equal(result.status, 200);
  assert.equal(result.body.result.structuredContent.error, 'authentication_required');
});
