import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { shadowserverProvider as rawShadowserverProvider } from '../src/providers/shadowserver.js';
import { shadowserverProvider, ALL_PROVIDERS } from '../src/providers/index.js';
import { createTrustedAuthorizationContext } from '../src/core/authorization-context.js';
import { authorizeCapability } from '../src/core/intelligence-policy.js';
import { WORKFLOWS } from '../src/workflows.js';

const ENV = Object.freeze({
  SHADOWSERVER_API_KEY: 'fixture-api-key',
  SHADOWSERVER_API_SECRET: 'fixture-api-secret',
});

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

test('Shadowserver uses one fixed account-scoped reports query with HMAC2 and never reflects its secret', async () => {
  const calls = [];
  const rows = [
    { type: 'scan_rdp', timestamp: '2026-09-13 00:00:00', ip: '192.0.2.7', port: '3389', protocol: 'tcp', hostname: 'rdp.example.test' },
    { type: 'scan_ics', timestamp: '2026-09-13 00:01:00', ip: '192.0.2.8', port: '502', protocol: 'tcp' },
  ];
  const result = await rawShadowserverProvider.run({ type: 'ip', value: '192.0.2.7' }, {
    env: ENV,
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return jsonResponse(rows);
    },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://transform.shadowserver.org/api2/reports/query');
  assert.equal(calls[0].options.method, 'POST');
  assert.equal(calls[0].options.redirect, 'error');
  const body = JSON.parse(calls[0].options.body);
  assert.deepEqual(body, {
    query: { ip: '192.0.2.7' },
    date: '-1:now',
    limit: 50,
    page: 1,
    apikey: ENV.SHADOWSERVER_API_KEY,
  });
  const expectedHmac = createHmac('sha256', ENV.SHADOWSERVER_API_SECRET).update(calls[0].options.body).digest('hex');
  assert.equal(calls[0].options.headers.HMAC2, expectedHmac);
  assert.equal(calls[0].options.headers['content-type'], 'application/json');
  assert.equal(result.observationType, 'internet_exposure');
  assert.equal(result.verdict, 'observed');
  assert.equal(result.attributes.eventCount, 2);
  assert.deepEqual(result.attributes.reportTypes, ['scan_ics', 'scan_rdp']);
  assert.equal(result.relationships.length, 0);
  assert.equal(JSON.stringify(result).includes(ENV.SHADOWSERVER_API_SECRET), false);
  assert.deepEqual(result.references, ['https://www.shadowserver.org/what-we-do/network-reporting/api-reports-query/']);
});

test('Shadowserver CIDR monitoring is bounded, account-scoped, and absence stays neutral', async () => {
  let captured;
  const result = await rawShadowserverProvider.run({ type: 'cidr', value: '192.0.2.0/24' }, {
    env: ENV,
    fetchImpl: async (_url, options) => {
      captured = JSON.parse(options.body);
      return jsonResponse([]);
    },
  });
  assert.deepEqual(captured.query, { network: '192.0.2.0/24' });
  assert.equal(captured.limit, 50);
  assert.equal(captured.page, 1);
  assert.equal(result.verdict, 'no_result');
  assert.equal(result.confidence, 0);
  assert.equal(result.attributes.eventCount, 0);
  assert.notEqual(result.verdict, 'clean');
  assert.notEqual(result.verdict, 'benign');
});

test('Shadowserver fails closed on missing credentials, malformed rows, markup, and oversized success sets', async () => {
  for (const env of [
    { SHADOWSERVER_API_KEY: ENV.SHADOWSERVER_API_KEY },
    { SHADOWSERVER_API_SECRET: ENV.SHADOWSERVER_API_SECRET },
    {},
  ]) {
    await assert.rejects(
      rawShadowserverProvider.run({ type: 'ip', value: '192.0.2.7' }, { env, fetchImpl: async () => jsonResponse([]) }),
      /not configured/i,
    );
  }

  for (const body of [
    {},
    [{ type: '<mark>scan_rdp</mark>', ip: '192.0.2.7' }],
    Array.from({ length: 51 }, (_, index) => ({ type: 'scan_rdp', ip: `192.0.2.${index % 250}` })),
  ]) {
    await assert.rejects(
      rawShadowserverProvider.run({ type: 'ip', value: '192.0.2.7' }, {
        env: ENV,
        fetchImpl: async () => jsonResponse(body),
      }),
      /provider_schema_invalid/,
    );
  }
});

test('Shadowserver is a protected owned-asset monitor and never enters ordinary enrichment fanout', () => {
  assert.equal(ALL_PROVIDERS.some(provider => provider.name === 'shadowserver'), true);
  assert.equal(shadowserverProvider.mode, 'monitor');
  assert.equal(shadowserverProvider.fanoutEligible, false);
  assert.equal(shadowserverProvider.sensitivity, 'owned_asset');
  assert.equal(shadowserverProvider.authorization, 'owned_network');
  assert.equal(shadowserverProvider.retentionClass, 'restricted');
  assert.deepEqual(shadowserverProvider.requiredEnvs, ['SHADOWSERVER_API_KEY', 'SHADOWSERVER_API_SECRET']);
  assert.equal(Object.values(WORKFLOWS).flat().includes('shadowserver'), false);

  const denied = authorizeCapability({
    adapter: shadowserverProvider,
    requestedMode: 'monitor',
    authz: createTrustedAuthorizationContext({}),
  });
  assert.equal(denied.reason, 'owned_network_required');
  const allowed = authorizeCapability({
    adapter: shadowserverProvider,
    requestedMode: 'monitor',
    authz: createTrustedAuthorizationContext({ ownedCidrs: ['192.0.2.0/24'] }),
  });
  assert.deepEqual(allowed, { allowed: true, reason: 'allowed' });
});
