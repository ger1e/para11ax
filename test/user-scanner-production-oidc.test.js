import test from 'node:test';
import assert from 'node:assert/strict';

import { createUserScannerHandler } from '../src/user-scanner.js';

const TOKEN = 'gateway-token';
const OIDC = 'header.payload.signature';
const PROD_WORKER = 'https://user-scanner-geri6.vercel.app/scan';

function request() {
  return {
    method: 'POST',
    headers: {
      authorization: `Bearer ${TOKEN}`,
      'content-type': 'application/json',
    },
    body: { scanType: 'username', target: 'ger1e', crossScan: false, noNsfw: true },
  };
}

function workerResponse() {
  return new Response(JSON.stringify({
    summary: { totalScanned: 2, found: 1, notFound: 1, errors: 0, skipped: 0 },
    results: [],
    erroredSites: [],
  }), { status: 200, headers: { 'content-type': 'application/json' } });
}

test('production User Scanner bridge defaults to owned worker and forwards Vercel workload identity', async () => {
  let seen = null;
  const handle = createUserScannerHandler({
    env: { PARA11AX_TOKEN: TOKEN, VERCEL_ENV: 'production', VERCEL_OIDC_TOKEN: OIDC },
    fetchImpl: async (url, options) => {
      seen = { url: String(url), options };
      return workerResponse();
    },
    nowMs: (() => { let n = 1000; return () => n += 5; })(),
  });

  const result = await handle(request());
  assert.equal(result.status, 200);
  assert.equal(seen.url, PROD_WORKER);
  assert.equal(seen.options.headers['X-Para11ax-Vercel-OIDC'], OIDC);
  assert.equal(seen.options.headers.Authorization, undefined);
});

test('production bridge fails closed when neither static worker token nor Vercel identity exists', async () => {
  const handle = createUserScannerHandler({
    env: { PARA11AX_TOKEN: TOKEN, VERCEL_ENV: 'production' },
    fetchImpl: async () => assert.fail('worker must not be called without service identity'),
  });
  const result = await handle(request());
  assert.equal(result.status, 503);
  assert.equal(result.body.error, 'user_scanner_auth_unconfigured');
});

test('explicit static worker configuration remains available for local and recovery use', async () => {
  let seen = null;
  const handle = createUserScannerHandler({
    env: {
      PARA11AX_TOKEN: TOKEN,
      PARA11AX_USER_SCANNER_URL: 'https://scanner.example/scan',
      PARA11AX_USER_SCANNER_TOKEN: 'static-worker-token',
    },
    fetchImpl: async (url, options) => {
      seen = { url: String(url), options };
      return workerResponse();
    },
  });
  const result = await handle(request());
  assert.equal(result.status, 200);
  assert.equal(seen.url, 'https://scanner.example/scan');
  assert.equal(seen.options.headers.Authorization, 'Bearer static-worker-token');
  assert.equal(seen.options.headers['X-Para11ax-Vercel-OIDC'], undefined);
});
