import test from 'node:test';
import assert from 'node:assert/strict';
import { censysHistoryProvider, censysProvider, censysSearchProvider } from '../src/providers/censys.js';

function json(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
}

function context(fetchImpl, env = {}) {
  return {
    env: { CENSYS_PAT: 'test-token', ...env },
    signal: new AbortController().signal,
    fetchImpl,
  };
}

const CERT = 'a'.repeat(64);

test('Censys search and history are explicit capabilities that preserve point lookup', () => {
  assert.equal(censysProvider.name, 'censys');
  assert.notEqual(censysProvider.mode, 'search');
  assert.notEqual(censysProvider.mode, 'graph');
  assert.equal(censysSearchProvider.name, 'censys-search');
  assert.equal(censysSearchProvider.mode, 'search');
  assert.equal(censysSearchProvider.fanoutEligible, false);
  assert.deepEqual(censysSearchProvider.types, ['ip', 'domain', 'certificate']);
  assert.equal(censysHistoryProvider.name, 'censys-history');
  assert.equal(censysHistoryProvider.mode, 'graph');
  assert.equal(censysHistoryProvider.fanoutEligible, false);
  assert.deepEqual(censysHistoryProvider.types, ['certificate']);
});

test('Censys host search uses one fixed bounded POST page and ignores next_page_token', async () => {
  const calls = [];
  const result = await censysSearchProvider.run({ type: 'ip', value: '203.0.113.8' }, context(async (url, options = {}) => {
    calls.push({ url: String(url), options });
    return json({
      result: {
        total_hits: 2,
        next_page_token: 'do-not-follow',
        hits: [
          { host_v1: { resource: { ip: '203.0.113.8', autonomous_system: { asn: 64500 }, dns: { names: ['host.example.com'] } } } },
          { host_v1: { resource: { ip: '<mark>203.0.113.9</mark>', autonomous_system: { asn: 64501 }, dns: { names: ['<mark>bad.example</mark>'] } } } },
        ],
      },
    });
  }));

  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://api.platform.censys.io/v3/global/search/query');
  assert.equal(calls[0].options.method, 'POST');
  assert.equal(calls[0].options.headers.Authorization, 'Bearer test-token');
  const body = JSON.parse(calls[0].options.body);
  assert.equal(body.query, 'host.ip="203.0.113.8"');
  assert.equal(body.page_size, 25);
  assert.equal(Object.hasOwn(body, 'page_token'), false);
  assert.deepEqual(result.relationships, [
    { targetType: 'ip', target: '203.0.113.8', relationship: 'search_hit' },
    { targetType: 'asn', target: 'AS64500', relationship: 'asn' },
    { targetType: 'domain', target: 'host.example.com', relationship: 'dns_name' },
  ]);
  assert.equal(JSON.stringify(result).includes('<mark>'), false);
});

test('Censys certificate search uses exact fingerprint query and emits typed certificate/name relationships', async () => {
  const result = await censysSearchProvider.run({ type: 'certificate', value: `cert-sha256:${CERT}` }, context(async (_url, options = {}) => {
    const body = JSON.parse(options.body);
    assert.equal(body.query, `cert.fingerprint_sha256="${CERT}"`);
    return json({
      result: {
        hits: [
          { certificate_v1: { resource: { fingerprint_sha256: CERT, names: ['one.example', 'two.example'] } } },
        ],
      },
    });
  }));

  assert.deepEqual(result.relationships, [
    { targetType: 'certificate', target: `cert-sha256:${CERT}`, relationship: 'search_hit' },
    { targetType: 'domain', target: 'one.example', relationship: 'certificate_name' },
    { targetType: 'domain', target: 'two.example', relationship: 'certificate_name' },
  ]);
});

test('Censys certificate history requires a configured organization id and fetches exactly one bounded page', async () => {
  let called = false;
  await assert.rejects(
    censysHistoryProvider.run({ type: 'certificate', value: `cert-sha256:${CERT}` }, context(async () => { called = true; return json({}); })),
    error => error?.status === 503 && /organization/i.test(error.message),
  );
  assert.equal(called, false);

  const calls = [];
  const result = await censysHistoryProvider.run({ type: 'certificate', value: `cert-sha256:${CERT}` }, context(async (url, options = {}) => {
    calls.push({ url: String(url), options });
    return json({
      result: {
        ranges: [
          { ip: '139.59.49.150', port: 443, transport_protocol: 'TCP', protocols: ['HTTP'], start_time: '2025-07-26T21:51:41.111883Z', end_time: '2025-08-17T23:47:12.053004Z' },
          { ip: '206.189.140.135', port: 443, transport_protocol: 'TCP', protocols: ['HTTP'], start_time: '2025-07-27T03:57:20.3719Z', end_time: '2025-08-17T18:53:23.154132Z' },
          { ip: '<mark>198.51.100.3</mark>', port: 443 },
        ],
        total_results: 3,
        next_page_token: 'do-not-follow',
      },
    });
  }, { CENSYS_ORG_ID: '11111111-2222-3333-4444-555555555555' }));

  assert.equal(calls.length, 1);
  const url = new URL(calls[0].url);
  assert.equal(url.origin, 'https://api.platform.censys.io');
  assert.equal(url.pathname, `/v3/threat-hunting/certificate/${CERT}/observations/hosts`);
  assert.equal(url.searchParams.get('organization_id'), '11111111-2222-3333-4444-555555555555');
  assert.equal(url.searchParams.get('page_size'), '50');
  assert.equal(url.searchParams.has('page_token'), false);
  assert.deepEqual(result.relationships, [
    { targetType: 'ip', target: '139.59.49.150', relationship: 'historically_presented_certificate', startTime: '2025-07-26T21:51:41.111883Z', endTime: '2025-08-17T23:47:12.053004Z', port: 443, transportProtocol: 'TCP', protocols: ['HTTP'] },
    { targetType: 'ip', target: '206.189.140.135', relationship: 'historically_presented_certificate', startTime: '2025-07-27T03:57:20.3719Z', endTime: '2025-08-17T18:53:23.154132Z', port: 443, transportProtocol: 'TCP', protocols: ['HTTP'] },
  ]);
});

test('Censys explicit capabilities preserve entitlement denial and reject malformed successful schemas', async () => {
  await assert.rejects(
    censysSearchProvider.run({ type: 'ip', value: '203.0.113.8' }, context(async () => json({ title: 'Forbidden' }, 403))),
    error => error?.status === 403,
  );
  await assert.rejects(
    censysHistoryProvider.run({ type: 'certificate', value: `cert-sha256:${CERT}` }, context(async () => json({ result: { ranges: 'not-an-array' } }), { CENSYS_ORG_ID: '11111111-2222-3333-4444-555555555555' })),
    /provider_schema_invalid/,
  );
});
