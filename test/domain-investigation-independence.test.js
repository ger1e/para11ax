import test from 'node:test';
import assert from 'node:assert/strict';
import { createProviderIndependenceRegistry } from '../src/core/provider-independence.js';
import { applyProviderIndependencePolicy } from '../src/core/domain-investigation-policy.js';

function artifact(directSources, { contextSources = [], contradictions = [], authority = ['evidence_v2'] } = {}) {
  return {
    schemaVersion: 'domain-investigation-v1.0',
    target: { type: 'domain', value: 'suspicious.example' },
    recommendations: [{
      type: 'domain', value: 'suspicious.example', disposition: 'BLOCK', ruleId: 'legacy',
      authority, directSources, contextSources, contradictions, reasons: [],
    }],
    _authoritative: { enrichment: { schemaVersion: '2.0' } },
  };
}

function registry(entries) {
  return createProviderIndependenceRegistry(entries.map(([provider, group]) => ({
    provider,
    independenceGroup: group,
    lineageConfidence: 'confirmed',
    basis: 'maintained_mapping',
    references: [],
    updatedAt: '2026-09-13T00:00:00.000Z',
  })));
}

test('two providers in the same family count as one vote', () => {
  const r = registry([['vt', 'google-vt'], ['vt-mirror', 'google-vt']]);
  const rec = applyProviderIndependencePolicy(artifact(['vt', 'vt-mirror']), r).recommendations[0];
  assert.equal(rec.independence.rawProviderCount, 2);
  assert.equal(rec.independence.quorumEligibleGroupCount, 1);
  assert.deepEqual(rec.independence.quorumGroups, ['google-vt']);
  assert.equal(rec.disposition, 'MONITOR');
});

test('two known independent families can BLOCK', () => {
  const r = registry([['vt', 'google-vt'], ['urlhaus', 'abuse-ch']]);
  const rec = applyProviderIndependencePolicy(artifact(['vt', 'urlhaus']), r).recommendations[0];
  assert.equal(rec.disposition, 'BLOCK');
  assert.equal(rec.ruleId, 'DI-BLOCK-2-DIRECT');
  assert.equal(rec.independence.quorumEligibleGroupCount, 2);
});

test('two unknown providers never satisfy BLOCK quorum', () => {
  const rec = applyProviderIndependencePolicy(artifact(['mystery-a', 'mystery-b']), registry([])).recommendations[0];
  assert.equal(rec.independence.quorumEligibleGroupCount, 0);
  assert.deepEqual(rec.independence.unknownProviders, ['mystery-a', 'mystery-b']);
  assert.equal(rec.disposition, 'MONITOR');
});

test('one known plus one unknown is not two-family quorum', () => {
  const r = registry([['known', 'family-known']]);
  const rec = applyProviderIndependencePolicy(artifact(['known', 'unknown']), r).recommendations[0];
  assert.equal(rec.independence.quorumEligibleGroupCount, 1);
  assert.deepEqual(rec.independence.unknownProviders, ['unknown']);
  assert.equal(rec.disposition, 'MONITOR');
});

test('one known family plus independent context is BLOCK_CANDIDATE', () => {
  const r = registry([['known', 'family-known']]);
  const rec = applyProviderIndependencePolicy(artifact(['known'], { contextSources: ['context-feed'] }), r).recommendations[0];
  assert.equal(rec.disposition, 'BLOCK_CANDIDATE');
  assert.equal(rec.independence.quorumEligibleGroupCount, 1);
});

test('contradiction prevents BLOCK despite two-family quorum', () => {
  const r = registry([['a', 'family-a'], ['b', 'family-b']]);
  const rec = applyProviderIndependencePolicy(artifact(['a', 'b'], { contradictions: [{ provider: 'c', verdict: 'clean' }] }), r).recommendations[0];
  assert.equal(rec.disposition, 'BLOCK_CANDIDATE');
  assert.equal(rec.ruleId, 'DI-CANDIDATE-CONTRADICTION');
});
