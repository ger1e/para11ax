import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createProviderIndependenceRegistry,
  resolveProviderIndependence,
  summarizeProviderIndependence,
} from '../src/core/provider-independence.js';

test('known providers resolve to configured quorum-eligible groups', () => {
  const registry = createProviderIndependenceRegistry([
    { provider: 'VirusTotal', independenceGroup: 'google-vt', lineageConfidence: 'confirmed', basis: 'declared', references: ['https://example.com/vt'], updatedAt: '2026-09-13T00:00:00.000Z' },
    { provider: 'VT Mirror', independenceGroup: 'google-vt', lineageConfidence: 'confirmed', basis: 'documented_upstream', references: ['https://example.com/mirror'], updatedAt: '2026-09-13T00:00:00.000Z' },
    { provider: 'URLhaus', independenceGroup: 'abuse-ch', lineageConfidence: 'confirmed', basis: 'declared', references: ['https://example.com/urlhaus'], updatedAt: '2026-09-13T00:00:00.000Z' },
  ]);

  const vt = resolveProviderIndependence('VirusTotal', registry);
  assert.equal(vt.independenceGroup, 'google-vt');
  assert.equal(vt.quorumEligible, true);

  const summary = summarizeProviderIndependence(['VirusTotal', 'VT Mirror', 'URLhaus'], registry);
  assert.deepEqual(summary.quorumGroups, ['abuse-ch', 'google-vt']);
  assert.equal(summary.quorumEligibleGroupCount, 2);
  assert.equal(summary.rawProviderCount, 3);
});

test('unknown lineage is stable provenance only and never quorum eligible', () => {
  const registry = createProviderIndependenceRegistry([]);
  const unknown = resolveProviderIndependence('Mystery Feed', registry);

  assert.equal(unknown.independenceGroup, 'provider:Mystery Feed');
  assert.equal(unknown.lineageConfidence, 'unknown');
  assert.equal(unknown.basis, 'fallback');
  assert.equal(unknown.quorumEligible, false);

  const summary = summarizeProviderIndependence(['Mystery Feed', 'Other Mystery'], registry);
  assert.equal(summary.quorumEligibleGroupCount, 0);
  assert.deepEqual(summary.quorumGroups, []);
  assert.deepEqual(summary.unknownProviders, ['Mystery Feed', 'Other Mystery']);
});

test('one known provider plus one unknown provider is still one quorum group', () => {
  const registry = createProviderIndependenceRegistry([
    { provider: 'URLhaus', independenceGroup: 'abuse-ch', lineageConfidence: 'confirmed', basis: 'declared', references: [], updatedAt: '2026-09-13T00:00:00.000Z' },
  ]);
  const summary = summarizeProviderIndependence(['URLhaus', 'Unknown Wrapper'], registry);
  assert.equal(summary.quorumEligibleGroupCount, 1);
  assert.deepEqual(summary.quorumGroups, ['abuse-ch']);
  assert.deepEqual(summary.unknownProviders, ['Unknown Wrapper']);
});

test('registry and summaries are deterministic regardless of input order', () => {
  const a = { provider: 'A', independenceGroup: 'family-a', lineageConfidence: 'probable', basis: 'maintained_mapping', references: ['https://example.com/a'], updatedAt: '2026-09-13T00:00:00.000Z' };
  const b = { provider: 'B', independenceGroup: 'family-b', lineageConfidence: 'confirmed', basis: 'declared', references: [], updatedAt: '2026-09-13T00:00:00.000Z' };
  const left = createProviderIndependenceRegistry([a, b]);
  const right = createProviderIndependenceRegistry([b, a]);
  assert.deepEqual(left, right);
  assert.deepEqual(
    summarizeProviderIndependence(['B', 'A', 'B'], left),
    summarizeProviderIndependence(['A', 'B'], right),
  );
});

test('invalid lineage metadata fails closed', () => {
  assert.throws(() => createProviderIndependenceRegistry([
    { provider: 'A', independenceGroup: 'family-a', lineageConfidence: 'certain', basis: 'declared', references: [], updatedAt: '2026-09-13T00:00:00.000Z' },
  ]), /lineageConfidence/i);

  assert.throws(() => createProviderIndependenceRegistry([
    { provider: 'A', independenceGroup: 'family-a', lineageConfidence: 'confirmed', basis: 'magic', references: [], updatedAt: '2026-09-13T00:00:00.000Z' },
  ]), /basis/i);

  assert.throws(() => createProviderIndependenceRegistry([
    { provider: 'A', independenceGroup: 'family-a', lineageConfidence: 'confirmed', basis: 'declared', references: ['ftp://example.com/nope'], updatedAt: '2026-09-13T00:00:00.000Z' },
  ]), /reference/i);
});
