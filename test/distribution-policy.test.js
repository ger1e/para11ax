import test from 'node:test';
import assert from 'node:assert/strict';
import { toStixBundle } from '../src/export/stix.js';

function enrichment(distribution) {
  return {
    schemaVersion: '2.0',
    gatewayVersion: '2.0.0',
    requestId: 'req-1',
    indicator: 'example.com',
    type: 'domain',
    queriedAt: '2026-09-13T00:00:00.000Z',
    relationships: [],
    evidence: [{
      provider: 'fixture',
      references: ['https://example.org/internal-observation'],
      policy: { mode: 'search', sensitivity: 'public', retentionClass: 'normal', distribution },
      observation: { kind: 'web_archive_observation', attributes: {} },
    }],
  };
}

test('STIX export excludes references derived from internal-only evidence', () => {
  const bundle = toStixBundle(enrichment('internal_only'), { now: () => '2026-09-13T00:00:00.000Z' });
  assert.equal(bundle.objects.length, 1);
  assert.equal(Object.hasOwn(bundle.objects[0], 'external_references'), false);
});

test('STIX export preserves evidence references that are not export-prohibited', () => {
  const bundle = toStixBundle(enrichment('shareable'), { now: () => '2026-09-13T00:00:00.000Z' });
  assert.deepEqual(bundle.objects[0].external_references, [{ source_name: 'fixture', url: 'https://example.org/internal-observation' }]);
});
