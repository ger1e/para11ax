import test from 'node:test';
import assert from 'node:assert/strict';
import { runIntelligencePivots } from '../src/core/intelligence-orchestrator.js';
import { createTrustedAuthorizationContext } from '../src/core/authorization-context.js';
import { createProviderRegistry } from '../src/core/provider-registry.js';

function graphAdapter() {
  return {
    name: 'graph-fixture',
    types: ['certificate'],
    observationTypes: ['certificate_metadata'],
    tier: 1,
    costClass: 'free',
    timeoutMs: 1000,
    cacheTtlMs: 1000,
    negativeCacheTtlMs: 1000,
    maxResponseBytes: 4096,
    fixedHosts: ['example.org'],
    methods: ['GET'],
    protocols: ['https:'],
    parserVersion: '1',
    sourceUrl: 'https://example.org/docs',
    sourceRole: 'first_party',
    distribution: 'internal',
    mode: 'graph',
    sensitivity: 'public',
    authorization: 'none',
    schedulerByType: {
      certificate: { authorityClass: 'specialist', semanticUniqueness: 'unique', intelligenceValue: 'direct', pivotValue: 'high', latencyClass: 'fast' },
    },
    async run(input) {
      return {
        observationType: 'certificate_metadata', verdict: 'observed', confidence: null,
        firstSeen: null, lastSeen: null, tags: [], malwareFamily: null, actor: null,
        attributes: { pivot: input.value },
        relationships: [{ type: 'related_to', targetType: 'domain', target: 'example.net' }],
        references: ['https://example.org/reference'],
      };
    },
  };
}

const baseline = {
  status: 'ok',
  indicator: 'example.com',
  type: 'domain',
  evidence: [{ provider: 'baseline', observation: { kind: 'internet_exposure' } }],
  relationships: [{ type: 'uses_certificate', targetType: 'certificate', target: `cert-sha256:${'a'.repeat(64)}` }],
  budget: { providerCalls: 1, providerCallLimit: 4, deadlineMs: 20000, deadlineExhausted: false, callBudgetExhausted: false },
};

test('phase-two execution returns pivot evidence separately from root evidence', async () => {
  const registry = createProviderRegistry([graphAdapter()]);
  const output = await runIntelligencePivots({ baseline, registry, authz: createTrustedAuthorizationContext({}), now: () => '2026-09-13T00:00:00.000Z', nowMs: (() => { let n = 0; return () => n++; })() });
  assert.equal(output.plans.length, 1);
  assert.equal(output.evidence.length, 1);
  assert.equal(output.evidence[0].indicator.startsWith('cert-sha256:'), true);
  assert.equal(output.evidence[0].type, 'certificate');
  assert.equal(output.relationships[0].provider, 'graph-fixture');
  assert.equal(output.failures.length, 0);
  assert.equal(output.budget.providerCalls, 1);
  assert.equal(baseline.evidence.length, 1, 'baseline root evidence must remain untouched');
});

test('phase-two execution obeys remaining baseline call budget', async () => {
  const registry = createProviderRegistry([graphAdapter()]);
  const exhausted = { ...baseline, budget: { ...baseline.budget, providerCalls: 4 } };
  const output = await runIntelligencePivots({ baseline: exhausted, registry, authz: createTrustedAuthorizationContext({}) });
  assert.deepEqual(output.plans, []);
  assert.equal(output.budget.providerCalls, 0);
});

test('phase-two failures remain pivot failures and never become root negative evidence', async () => {
  const failing = { ...graphAdapter(), name: 'graph-fail', async run() { throw new Error('upstream unavailable'); } };
  const registry = createProviderRegistry([failing]);
  const output = await runIntelligencePivots({ baseline, registry, authz: createTrustedAuthorizationContext({}) });
  assert.equal(output.evidence.length, 0);
  assert.equal(output.failures.length, 1);
  assert.equal(output.failures[0].provider, 'graph-fail');
  assert.equal(output.failures[0].reason, 'provider_error');
});
