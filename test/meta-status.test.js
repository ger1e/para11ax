import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/app.js';
import { sanitizePublicMeta } from '../api/para11ax/meta.js';
import { TtlCache } from '../src/core/cache.js';
import { createTelemetry } from '../src/core/telemetry.js';

function adapter() {
  return Object.freeze({
    name: 'rdap', types: ['ip', 'domain'], observationTypes: ['registration'], requiredEnv: 'RDAP_SECRET_TEST',
    costClass: 'free', tier: 1, timeoutMs: 5000, cacheTtlMs: 1000, negativeCacheTtlMs: 1000,
    maxResponseBytes: 2048, fixedHosts: ['fixture.invalid'], methods: ['GET'], protocols: ['https:'], parserVersion: 'test-parser', sourceUrl: 'https://fixture.invalid/',
    schedulerByType: {
      ip: { authorityClass: 'authoritative', semanticUniqueness: 'unique', intelligenceValue: 'contextual', pivotValue: 'medium', latencyClass: 'fast' },
    },
    schedulerMetadataInvalidTypes: [],
    async run() { return { observationType: 'registration', verdict: 'unknown', attributes: {}, relationships: [], references: [] }; },
  });
}
function get(token = null) { return { method: 'GET', headers: token ? { authorization: `Bearer ${token}` } : {} }; }

test('public meta is a minimal capability contract and does not expose provider topology or internal limits', async () => {
  const app = createApp({ env: { PARA11AX_TOKEN: 'gateway', RDAP_SECRET_TEST: 'actual-secret' }, adapters: [adapter()] });
  const out = sanitizePublicMeta(await app.handleMeta(get()));
  assert.equal(out.status, 200);
  assert.deepEqual(Object.keys(out.body).sort(), [
    'documentation',
    'gatewayVersion',
    'profiles',
    'schemaVersion',
    'security',
    'types',
  ]);
  assert.equal(out.body.gatewayVersion, '2.0.0');
  assert.equal(out.body.schemaVersion, '2.0');
  assert.deepEqual(out.body.profiles, ['fast', 'standard', 'full']);
  assert.ok(out.body.types.includes('asn'));
  assert.equal(out.body.documentation, 'https://github.com/ger1e/para11ax/blob/main/docs/API.md');
  assert.equal(out.body.security, 'https://para11ax.vercel.app/.well-known/security.txt');

  const text = JSON.stringify(out.body);
  for (const forbidden of [
    'providers', 'limits', 'fixedHosts', 'requiresCredential', 'scheduler',
    'RDAP_SECRET_TEST', 'actual-secret', 'configured', 'fixture.invalid',
  ]) {
    assert.equal(text.includes(forbidden), false, `public meta leaked ${forbidden}`);
  }
});

test('authenticated status is no-store and aggregate-only', async () => {
  let now = 1000;
  const cache = new TtlCache({ maxEntries: 10, now: () => now });
  cache.set('x', { sensitive: 'not exposed' }, 1000);
  const telemetry = createTelemetry();
  telemetry.emit({ event: 'request_start', requestId: 'r1', type: 'ip', indicator: '192.0.2.44', status: 'start' });
  telemetry.emit({ event: 'provider_complete', requestId: 'r1', type: 'ip', provider: 'rdap', status: 'ok', indicator: '192.0.2.44', authorization: 'Bearer actual-secret' });
  telemetry.emit({ event: 'provider_outcome', requestId: 'r1', type: 'ip', provider: 'rdap', status: 'success', indicator: '192.0.2.44', authorization: 'Bearer actual-secret' });
  const app = createApp({ env: { PARA11AX_TOKEN: 'gateway', RDAP_SECRET_TEST: 'actual-secret' }, adapters: [adapter()], cache, telemetry, nowMs: () => now });
  assert.equal((await app.handleStatus(get())).status, 401);
  now = 1500;
  const out = await app.handleStatus(get('gateway'));
  assert.equal(out.status, 200);
  assert.equal(out.headers['cache-control'], 'no-store');
  assert.equal(out.body.uptimeMs, 500);
  assert.equal(out.body.providers.rdap.configured, true);
  assert.equal(out.body.providers.rdap.parserVersion, 'test-parser');
  assert.equal(out.body.cache.entries, 1);
  assert.equal(out.body.circuit.providers >= 0, true);
  assert.equal(out.body.telemetry.events, 3);
  assert.deepEqual(out.body.telemetry.byProvider, { rdap: 2 });
  assert.deepEqual(out.body.telemetry.providerOutcomes, { rdap: { success: 1, failure: 0, timeout: 0, rate_limited: 0, skipped: 0 } });
  const text = JSON.stringify(out.body);
  assert.equal(text.includes('actual-secret'), false);
  assert.equal(text.includes('192.0.2.44'), false);
  assert.equal(text.includes('sensitive'), false);
});

test('meta and status are GET-only', async () => {
  const app = createApp({ env: { PARA11AX_TOKEN: 'gateway' }, adapters: [adapter()] });
  assert.equal((await app.handleMeta({ method: 'POST', headers: {} })).status, 405);
  assert.equal((await app.handleStatus({ method: 'POST', headers: { authorization: 'Bearer gateway' } })).status, 405);
});
