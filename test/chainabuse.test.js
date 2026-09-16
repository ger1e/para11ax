import test from 'node:test';
import assert from 'node:assert/strict';
import { chainabuseProvider } from '../src/providers/chainabuse.js';

const ADDRESS = `eth:${'a'.repeat(40)}`;

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

test('Chainabuse performs one bounded read-only crypto address screening lookup', async () => {
  const calls = [];
  const out = await chainabuseProvider.run({ type: 'crypto-address', value: ADDRESS }, {
    env: { CHAINABUSE_API_KEY: 'test-key' },
    fetchImpl: async (url, options) => {
      calls.push([String(url), options]);
      return jsonResponse({
        reports: [{
          id: 'report-1',
          trusted: true,
          checked: true,
          isPrivate: false,
          scamCategory: 'PHISHING',
          createdAt: '2026-09-01T00:00:00Z',
          description: 'public source claim',
          addresses: [], losses: [], accusedScammers: [], evidences: [], ips: [],
        }],
        count: 1,
      });
    },
  });
  assert.equal(calls.length, 1);
  const url = new URL(calls[0][0]);
  assert.equal(url.origin, 'https://api.chainabuse.com');
  assert.equal(url.pathname, '/v0/reports');
  assert.equal(url.searchParams.get('address'), 'a'.repeat(40));
  assert.equal(url.searchParams.get('page'), '1');
  assert.equal(url.searchParams.get('perPage'), '50');
  assert.equal(calls[0][1].method, 'GET');
  assert.equal(calls[0][1].headers.Authorization, `Basic ${Buffer.from('test-key:test-key').toString('base64')}`);
  assert.equal(out.observationType, 'crypto_abuse');
  assert.equal(out.verdict, 'reported');
  assert.equal(out.attributes.reportCount, 1);
  assert.deepEqual(out.attributes.reports, [{ id: 'report-1', category: 'PHISHING', createdAt: '2026-09-01T00:00:00Z', trusted: true, checked: true }]);
  assert.deepEqual(out.relationships, []);
  assert.equal(Object.hasOwn(chainabuseProvider, 'submit'), false);
});

test('Chainabuse no reports is neutral absence and malformed successful schema fails closed', async () => {
  const empty = await chainabuseProvider.run({ type: 'crypto-address', value: ADDRESS }, {
    env: { CHAINABUSE_API_KEY: 'test-key' },
    fetchImpl: async () => jsonResponse({ reports: [], count: 0 }),
  });
  assert.equal(empty.verdict, 'not_found');
  await assert.rejects(
    () => chainabuseProvider.run({ type: 'crypto-address', value: ADDRESS }, {
      env: { CHAINABUSE_API_KEY: 'test-key' },
      fetchImpl: async () => jsonResponse({ reports: 'oops', count: 1 }),
    }),
    /provider_schema_invalid/,
  );
});
