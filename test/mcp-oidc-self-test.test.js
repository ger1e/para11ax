import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createSign } from 'node:crypto';

import { createSignedProductionSelfTestHandler } from '../src/mcp/self-test.js';

const TOKEN = 'internal-gateway-token';
const NOW_MS = 1_789_104_600_000;
const NOW_SECONDS = Math.floor(NOW_MS / 1000);
const AUDIENCE = 'para11ax-production-smoke';
const ISSUER = 'https://token.actions.githubusercontent.com';
const JWKS_URL = `${ISSUER}/.well-known/jwks`;

function b64url(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function signedGithubToken(overrides = {}) {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const kid = 'fixture-key';
  const header = { alg: 'RS256', typ: 'JWT', kid };
  const payload = {
    iss: ISSUER,
    aud: AUDIENCE,
    iat: NOW_SECONDS - 5,
    nbf: NOW_SECONDS - 5,
    exp: NOW_SECONDS + 300,
    repository: 'ger1e/para11ax',
    repository_id: '1339112568',
    repository_owner_id: '121339626',
    repository_visibility: 'public',
    ref: 'refs/heads/main',
    ref_protected: 'true',
    event_name: 'push',
    workflow_ref: 'ger1e/para11ax/.github/workflows/production-mcp-smoke.yml@refs/heads/main',
    sha: 'a'.repeat(40),
    ...overrides,
  };
  const signingInput = `${b64url(header)}.${b64url(payload)}`;
  const signer = createSign('RSA-SHA256');
  signer.update(signingInput);
  signer.end();
  const jwt = `${signingInput}.${signer.sign(privateKey).toString('base64url')}`;
  const jwk = publicKey.export({ format: 'jwk' });
  return { jwt, jwks: { keys: [{ ...jwk, kid, alg: 'RS256', use: 'sig' }] } };
}

function fakeMcp() {
  return async req => {
    if (req.body.method === 'tools/list') {
      return { status: 200, body: { jsonrpc: '2.0', id: 1, result: { tools: [
        { name: 'para11ax_enrich' },
        { name: 'para11ax_user_scan' },
        ...Array.from({ length: 11 }, (_, i) => ({ name: `tool_${i}` })),
      ] } } };
    }
    if (req.body.params?.name === 'para11ax_enrich') {
      return { status: 200, body: { jsonrpc: '2.0', id: 2, result: { isError: false, structuredContent: { enrichment: {
        status: 'partial', evidence: [{ provider: 'one' }], failures: [{ provider: 'two' }],
      } } } } };
    }
    if (req.body.params?.name === 'para11ax_user_scan') {
      return { status: 200, body: { jsonrpc: '2.0', id: 3, result: { isError: false, structuredContent: { result: {
        summary: { totalScanned: 100, found: 7, notFound: 88, errors: 3, skipped: 2 }, durationMs: 123,
      } } } } };
    }
    throw new Error('unexpected MCP request');
  };
}

function oidcFetch(jwks) {
  return async (url) => {
    assert.equal(String(url), JWKS_URL);
    return {
      ok: true,
      status: 200,
      async text() { return JSON.stringify(jwks); },
    };
  };
}

test('GitHub Actions OIDC can authorize the fixed production MCP self-test without the analyst bearer', async () => {
  const { jwt, jwks } = signedGithubToken();
  const handle = createSignedProductionSelfTestHandler({
    env: { PARA11AX_TOKEN: TOKEN, VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40) },
    nowMs: () => NOW_MS,
    fetchImpl: oidcFetch(jwks),
    mcpHandler: fakeMcp(),
  });

  const result = await handle({
    method: 'GET',
    url: 'https://para11ax.example/api/para11ax/self-test',
    headers: { authorization: `Bearer ${jwt}` },
  });

  assert.equal(result.status, 200);
  assert.equal(result.body.authorization, 'github_oidc');
  assert.equal(result.body.deploymentSha, 'a'.repeat(40));
  assert.equal(result.body.mcp.authenticated, true);
  assert.equal(result.body.mcp.toolCount, 13);
  assert.equal(result.body.enrichment.target, '1.1.1.1');
  assert.equal(result.body.userScanner.target, 'ger1e');
});

test('GitHub OIDC trust is denied when repository, branch, event, workflow or audience claims drift', async () => {
  const variants = [
    { repository: 'evil/fork' },
    { repository_id: '999' },
    { ref: 'refs/heads/feature' },
    { event_name: 'pull_request' },
    { workflow_ref: 'ger1e/para11ax/.github/workflows/other.yml@refs/heads/main' },
    { aud: 'wrong-audience' },
  ];

  for (const overrides of variants) {
    const { jwt, jwks } = signedGithubToken(overrides);
    const handle = createSignedProductionSelfTestHandler({
      env: { PARA11AX_TOKEN: TOKEN },
      nowMs: () => NOW_MS,
      fetchImpl: oidcFetch(jwks),
      mcpHandler: async () => assert.fail('MCP must not execute for untrusted OIDC claims'),
    });
    const result = await handle({
      method: 'GET',
      url: 'https://para11ax.example/api/para11ax/self-test',
      headers: { authorization: `Bearer ${jwt}` },
    });
    assert.equal(result.status, 401, JSON.stringify(overrides));
  }
});
