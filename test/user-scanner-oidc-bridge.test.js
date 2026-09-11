import test from 'node:test';
import assert from 'node:assert/strict';

import { createUserScannerHandler } from '../src/user-scanner.js';

const response = body => new Response(JSON.stringify(body), {
  status: 200,
  headers: { 'content-type': 'application/json' },
});

const request = (body, extraHeaders = {}) => ({
  method: 'POST',
  headers: {
    authorization: 'Bearer gateway-token',
    'content-type': 'application/json',
    ...extraHeaders,
  },
  body,
});

test('production Vercel bridge uses the public production worker alias and forwards runtime workload identity', async () => {
  const calls = [];
  const handle = createUserScannerHandler({
    env: {
      PARA11AX_TOKEN: 'gateway-token',
      VERCEL: '1',
      VERCEL_ENV: 'production',
    },
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      return response({
        summary: { total_scanned: 2, found: 1, not_found: 1, errors: 0, skipped: 0 },
        results: [{ status: 'Found', site_name: 'Example', category: 'social', url: 'https://example.test/ger1e', extra: {} }],
        errored_sites: [],
      });
    },
  });

  const result = await handle(request(
    { scanType: 'username', target: 'ger1e', crossScan: false, noNsfw: true },
    { 'x-vercel-oidc-token': 'vercel-runtime-workload-jwt' },
  ));
  assert.equal(result.status, 200);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://user-scanner-kappa.vercel.app/scan');
  assert.equal(calls[0].init.headers.Authorization, 'Bearer vercel-runtime-workload-jwt');
  assert.equal(calls[0].init.headers['x-vercel-trusted-oidc-idp-token'], 'vercel-runtime-workload-jwt');
});

test('non-Vercel environments still fail closed without explicit worker URL', async () => {
  const handle = createUserScannerHandler({ env: { PARA11AX_TOKEN: 'gateway-token' } });
  const result = await handle(request({ scanType: 'username', target: 'ger1e' }));
  assert.equal(result.status, 503);
  assert.equal(result.body.error, 'user_scanner_unconfigured');
});
