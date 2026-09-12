import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { requireGatewayAuth } from '../src/core/auth.js';
import {
  MCP_OAUTH_SCOPE,
  MCP_OFFLINE_SCOPE,
  MCP_RESOURCE,
  createMcpOAuthHandlers,
  verifyMcpAuthorization,
} from '../src/mcp/oauth.js';

const SECRET = 'correct-horse-battery-staple';
const NOW_MS = Date.parse('2026-09-12T07:00:00.000Z');
const VERIFIER = 'v'.repeat(64);
const CHALLENGE = createHash('sha256').update(VERIFIER, 'ascii').digest('base64url');

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

function authorizeParams() {
  return {
    response_type: 'code',
    client_id: 'https://chatgpt.com/oauth/client.json',
    redirect_uri: 'https://chatgpt.com/connector_platform_oauth_redirect',
    resource: MCP_RESOURCE,
    scope: `${MCP_OAUTH_SCOPE} ${MCP_OFFLINE_SCOPE}`,
    state: 'crypto-hardening-state',
    code_challenge: CHALLENGE,
    code_challenge_method: 'S256',
  };
}

function tamper(token) {
  const last = token.at(-1);
  return `${token.slice(0, -1)}${last === 'A' ? 'B' : 'A'}`;
}

test('gateway bearer comparison is direct constant-time bytes without fast hashing', () => {
  const source = readFileSync(new URL('../src/core/auth.js', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /createHash|createHmac/);
  assert.equal(requireGatewayAuth({ headers: { authorization: `Bearer ${SECRET}` } }, SECRET), true);
  assert.equal(requireGatewayAuth({ headers: { authorization: 'Bearer wrong' } }, SECRET), false);
  assert.equal(requireGatewayAuth({ headers: { authorization: `Bearer ${SECRET}x` } }, SECRET), false);
});

test('OAuth grants use a sealed authenticated envelope and reject tampering', () => {
  const source = readFileSync(new URL('../src/mcp/oauth.js', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /createHmac|HS256|signingKey/);
  assert.match(source, /createCipheriv/);
  assert.match(source, /createDecipheriv/);

  const handlers = createMcpOAuthHandlers({ env: { PARA11AX_TOKEN: SECRET }, nowMs: () => NOW_MS });
  const consent = handlers.handleAuthorize(formRequest({ ...authorizeParams(), gateway_token: SECRET }));
  assert.equal(consent.status, 302);
  const code = new URL(consent.headers.location).searchParams.get('code');
  assert.match(code, /^p1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);

  const exchange = handlers.handleToken(formRequest({
    grant_type: 'authorization_code',
    code,
    client_id: authorizeParams().client_id,
    redirect_uri: authorizeParams().redirect_uri,
    resource: MCP_RESOURCE,
    code_verifier: VERIFIER,
  }));
  assert.equal(exchange.status, 200);
  assert.match(exchange.body.access_token, /^p1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  assert.match(exchange.body.refresh_token, /^p1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  assert.notEqual(exchange.body.access_token, exchange.body.refresh_token);

  const badAccess = tamper(exchange.body.access_token);
  assert.equal(verifyMcpAuthorization({ headers: { authorization: `Bearer ${badAccess}` } }, SECRET, NOW_MS).authorized, false);

  const badRefresh = handlers.handleToken(formRequest({
    grant_type: 'refresh_token',
    refresh_token: tamper(exchange.body.refresh_token),
    client_id: authorizeParams().client_id,
    resource: MCP_RESOURCE,
  }));
  assert.equal(badRefresh.status, 400);
  assert.equal(badRefresh.body.error, 'invalid_grant');
});
