import test from 'node:test';
import assert from 'node:assert/strict';
import { runIntelligenceMode } from '../src/core/intelligence-operation.js';
import { runIntelligencePivots } from '../src/core/intelligence-orchestrator.js';
import { createProviderRegistry } from '../src/core/provider-registry.js';
import { createTrustedAuthorizationContext } from '../src/core/authorization-context.js';

function adapter(overrides = {}) {
  return {
    name: 'fixture',
    types: ['domain'],
    observationTypes: ['web_archive_observation'],
    tier: 1,
    costClass: 'free',
    timeoutMs: 1000,
    cacheTtlMs: 60000,
    negativeCacheTtlMs: 1000,
    maxResponseBytes: 4096,
    fixedHosts: ['example.org'],
    methods: ['GET'],
    protocols: ['https:'],
    parserVersion: '1',
    sourceUrl: 'https://example.org/docs',
    sourceRole: 'first_party',
    distribution: 'internal',
    mode: 'search',
    fanoutEligible: false,
    sensitivity: 'public',
    authorization: 'none',
    retentionClass: 'normal',
    schedulerByType: {
      domain: { authorityClass: 'specialist', semanticUniqueness: 'unique', intelligenceValue: 'supporting', pivotValue: 'high', latencyClass: 'fast' },
    },
    async run() {
      return {
        observationType: 'web_archive_observation',
        verdict: 'observed',
        attributes: {},
        relationships: [],
        references: [],
      };
    },
    ...overrides,
  };
}

test('no-store intelligence evidence is never inserted into the shared cache', async () => {
  let setCalls = 0;
  const cache = {
    get() { return undefined; },
    set() { setCalls += 1; },
  };
  const a = adapter({ retentionClass: 'no_store' });
  const registry = createProviderRegistry([a]);
  const result = await runIntelligenceMode({
    operation: 'search',
    mode: 'search',
    subject: { type: 'domain', value: 'example.com' },
    registry,
    authz: createTrustedAuthorizationContext({ requestedMode: 'search' }),
    cache,
    now: () => '2026-09-13T00:00:00.000Z',
    nowMs: (() => { let n = 0; return () => n++; })(),
  });
  assert.equal(result.evidence.length, 1);
  assert.equal(setCalls, 0);
});

test('phase-two pivots do not execute after the baseline consumed the request deadline', async () => {
  let runs = 0;
  const graph = adapter({
    name: 'graph-fixture',
    mode: 'graph',
    types: ['certificate'],
    observationTypes: ['certificate_metadata'],
    schedulerByType: {
      certificate: { authorityClass: 'specialist', semanticUniqueness: 'unique', intelligenceValue: 'direct', pivotValue: 'high', latencyClass: 'fast' },
    },
    async run() { runs += 1; return { observationType: 'certificate_metadata', verdict: 'observed', attributes: {}, relationships: [], references: [] }; },
  });
  const registry = createProviderRegistry([graph]);
  const baseline = {
    status: 'ok',
    indicator: 'example.com',
    type: 'domain',
    durationMs: 20000,
    evidence: [{ provider: 'baseline', observation: { kind: 'internet_exposure' } }],
    relationships: [{ type: 'uses_certificate', targetType: 'certificate', target: `cert-sha256:${'a'.repeat(64)}` }],
    budget: { providerCalls: 1, providerCallLimit: 4, deadlineMs: 20000, deadlineExhausted: false, callBudgetExhausted: false },
  };
  const output = await runIntelligencePivots({
    baseline,
    registry,
    authz: createTrustedAuthorizationContext({ requestedMode: 'graph' }),
  });
  assert.equal(runs, 0);
  assert.equal(output.evidence.length, 0);
  assert.equal(output.budget.deadlineExhausted, true);
});
