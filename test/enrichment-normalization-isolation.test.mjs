import test from 'node:test';
import assert from 'node:assert/strict';

import { TtlCache } from '../src/core/cache.js';
import { enrich } from '../src/core/orchestrator.js';
import { createProviderRegistry } from '../src/core/provider-registry.js';

function adapter(name, run) {
  return {
    name,
    types: ['ip'],
    observationTypes: ['network_identity'],
    cacheTtlMs: 1000,
    negativeCacheTtlMs: 100,
    costClass: 'free',
    tier: 1,
    timeoutMs: 100,
    maxResponseBytes: 2048,
    fixedHosts: ['example.test'],
    parserVersion: '1',
    sourceUrl: 'https://example.test/docs',
    sourceRole: 'community',
    run,
  };
}

test('malformed successful provider evidence is isolated and is not cached', async () => {
  const malformed = { verdict: 'unknown' };
  Object.defineProperty(malformed, 'observationType', {
    enumerable: false,
    get() {
      throw new Error('malformed_success_payload');
    },
  });

  const good = adapter('good', async () => ({
    observationType: 'network_identity',
    verdict: 'observed',
    references: ['https://example.test/good'],
  }));
  const bad = adapter('bad', async () => malformed);
  const registry = createProviderRegistry([good, bad]);
  const cache = new TtlCache();

  const result = await enrich({
    indicator: '8.8.8.8',
    type: 'ip',
    providerNames: ['good', 'bad'],
    registry,
    cache,
    requestId: 'normalization-isolation',
    now: () => '2026-09-11T05:00:00Z',
  });

  assert.equal(result.status, 'partial');
  assert.deepEqual(result.evidence.map(item => item.provider), ['good']);
  assert.equal(result.providerSummary.ok, 1);
  assert.equal(result.providerSummary.failed, 1);
  assert.equal(result.failures.length, 1);
  assert.equal(result.failures[0].provider, 'bad');
  assert.equal(result.failures[0].reason, 'evidence_normalization_error');
  assert.equal(result.meta.providerHealth.bad, 'evidence_normalization_error');
  assert.equal(cache.get('bad:ip:8.8.8.8'), undefined);
  assert.equal(cache.get('good:ip:8.8.8.8')?.ok, true);
});
