import test from 'node:test';
import assert from 'node:assert/strict';
import { createProviderRegistry } from '../src/core/provider-registry.js';
import { createTrustedAuthorizationContext, normalizeAuthorizationContext } from '../src/core/authorization-context.js';
import { runIntelligenceMode } from '../src/core/intelligence-operation.js';

function monitorAdapter() {
  return Object.freeze({
    name: 'owned-monitor-fixture',
    types: Object.freeze(['cidr']),
    observationTypes: Object.freeze(['internet_exposure']),
    tier: 1,
    costClass: 'free',
    timeoutMs: 1000,
    cacheTtlMs: 1000,
    negativeCacheTtlMs: 1000,
    maxResponseBytes: 4096,
    fixedHosts: Object.freeze(['example.org']),
    methods: Object.freeze(['POST']),
    protocols: Object.freeze(['https:']),
    parserVersion: '1',
    sourceUrl: 'https://example.org/docs',
    sourceRole: 'first_party',
    distribution: 'internal_only',
    active: true,
    mode: 'monitor',
    fanoutEligible: false,
    sensitivity: 'owned_asset',
    authorization: 'owned_network',
    retentionClass: 'restricted',
    schedulerByType: Object.freeze({}),
    async run(input) {
      return {
        observationType: 'internet_exposure',
        verdict: 'observed',
        confidence: 80,
        attributes: { scope: input.value },
        relationships: [],
        references: ['https://example.org/reference'],
      };
    },
  });
}

async function execute(subject, authz) {
  return runIntelligenceMode({
    operation: 'asset',
    mode: 'monitor',
    subject: { type: 'cidr', value: subject },
    registry: createProviderRegistry([monitorAdapter()]),
    authz,
    env: {},
    context: { fetchImpl: async () => { throw new Error('unexpected egress'); } },
  });
}

test('owned-asset monitor permits only a CIDR wholly contained in a trusted server scope', async () => {
  const authz = createTrustedAuthorizationContext({ ownedCidrs: ['192.0.2.0/24'] });
  const exact = await execute('192.0.2.0/24', authz);
  assert.deepEqual(exact.providers.executed, ['owned-monitor-fixture']);

  const subset = await execute('192.0.2.128/25', authz);
  assert.deepEqual(subset.providers.executed, ['owned-monitor-fixture']);

  const outside = await execute('198.51.100.0/24', authz);
  assert.deepEqual(outside.providers.executed, []);
  assert.deepEqual(outside.providers.denied, [{ provider: 'owned-monitor-fixture', reason: 'owned_network_scope_mismatch' }]);
});

test('caller-shaped authorization context cannot unlock owned-asset monitoring', async () => {
  const untrusted = normalizeAuthorizationContext({ ownedCidrs: ['192.0.2.0/24'] });
  const result = await execute('192.0.2.128/25', untrusted);
  assert.deepEqual(result.providers.executed, []);
  assert.deepEqual(result.providers.denied, [{ provider: 'owned-monitor-fixture', reason: 'owned_network_required' }]);
});
