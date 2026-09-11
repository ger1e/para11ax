import test from 'node:test';
import assert from 'node:assert/strict';

import { createUserScannerHandler } from '../src/user-scanner.js';

const response = body => new Response(JSON.stringify(body), {
  status: 200,
  headers: { 'content-type': 'application/json' },
});

const request = body => ({
  method: 'POST',
  headers: { authorization: 'Bearer gateway-token', 'content-type': 'application/json' },
  body,
});

test('production Vercel bridge defaults to owned worker alias and forwards workload identity', async () => {
  const calls = [];
  const handle = createUserScannerHandler({
    env: {
      PARA11AX_TOKEN: 'gateway-token',
      VERCEL: '1',
      VERCEL_ENV: 'production',
      VERCEL_OIDC_TOKEN: 'vercel-workload-jwt',
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

  const result = await handle(request({ scanType: 'username', target: 'ger1e', crossScan: false, noNsfw: true }));
  assert.equal(result.status, 200);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://user-scanner-git-main-geri6.vercel.app/scan');
  assert.equal(calls[0].init.headers.Authorization, 'Bearer vercel-workload-jwt');
  assert.equal(calls[0].init.headers['x-vercel-trusted-oidc-idp-token'], 'vercel-workload-jwt');
});

test('non-Vercel environments still fail closed without explicit worker URL', async () => {
  const handle = createUserScannerHandler({ env: { PARA11AX_TOKEN: 'gateway-token' } });
  const result = await handle(request({ scanType: 'username', target: 'ger1e' }));
  assert.equal(result.status, 503);
  assert.equal(result.body.error, 'user_scanner_unconfigured');
});
