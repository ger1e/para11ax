import test from 'node:test';
import assert from 'node:assert/strict';
import { semanticClass } from '../src/core/semantics.js';
import { evidenceRole } from '../src/core/evidence-semantics.js';
import { normalizeEvidence } from '../src/core/normalize.js';

const CASES = new Map([
  ['credential_exposure','credential_exposure'],
  ['infostealer_exposure','infostealer_exposure'],
  ['passive_dns_history','passive_dns_history'],
  ['domain_ownership_history','domain_ownership_history'],
  ['malware_configuration','malware_configuration'],
  ['malware_similarity','malware_similarity'],
  ['supply_chain','supply_chain'],
  ['anonymization_infrastructure','anonymization_infrastructure'],
  ['web_archive_observation','web_archive_observation'],
  ['secret_exposure','secret_exposure'],
  ['crypto_abuse','crypto_abuse'],
  ['legal_entity_context','legal_entity_context'],
  ['tls_malware_infrastructure','tls_malware_infrastructure'],
  ['exploit_maturity','exploit_maturity'],
  ['underground_mention','underground_mention'],
  ['defensive_knowledge','defensive_knowledge'],
]);

test('new intelligence observation kinds retain deterministic semantic classes', () => {
  for (const [kind, expected] of CASES) assert.equal(semanticClass(kind), expected, kind);
});

test('defensive knowledge is knowledge-only regardless of source authority', () => {
  for (const sourceRole of ['authoritative','first_party','specialist','aggregator','community','contextual']) {
    assert.equal(evidenceRole({ semanticClass: 'defensive_knowledge', sourceRole }), 'knowledge_only');
  }
});

test('normalized evidence receives policy from trusted metadata not provider payload', () => {
  const evidence = normalizeEvidence('fixture', 'example.com', 'domain', {
    observationType: 'web_archive_observation',
    verdict: 'observed',
    policy: { mode: 'sensitive', distribution: 'shareable' },
  }, {
    parserVersion: '1',
    sourceRole: 'first_party',
    mode: 'search',
    sensitivity: 'public',
    retentionClass: 'normal',
    distribution: 'internal_only',
  });
  assert.deepEqual(evidence.policy, {
    mode: 'search', sensitivity: 'public', retentionClass: 'normal', distribution: 'internal_only',
  });
  assert.equal(evidence.semantics.semanticClass, 'web_archive_observation');
});
