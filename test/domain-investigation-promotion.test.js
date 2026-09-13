import test from 'node:test';
import assert from 'node:assert/strict';
import { createProviderIndependenceRegistry } from '../src/core/provider-independence.js';
import { createDomainInvestigation, applyDomainPromotionEvent } from '../src/core/domain-investigation.js';

const operator = {
  id: 'SURF-X',
  kind: 'authorized_surface_finding',
  capturedAt: '2026-09-13T12:00:00.000Z',
  source: 'authorized-discovery',
  summary: 'Validated suspicious domain finding.',
  references: ['https://scanner.invalid/run/x'],
  observable: { type: 'domain', value: 'suspicious.example' },
  observation: { kind: 'operator_finding', verdict: 'malicious' },
};
const registry = createProviderIndependenceRegistry([{
  provider: 'known', independenceGroup: 'family-known', lineageConfidence: 'confirmed', basis: 'maintained_mapping', references: [], updatedAt: '2026-09-13T00:00:00.000Z',
}]);
const baseRec = {
  type: 'domain', value: 'suspicious.example', disposition: 'MONITOR', ruleId: 'legacy', authority: ['evidence_v2'], directSources: ['known'], contextSources: [], contradictions: [], reasons: [],
};

test('candidate initialization has zero recommendation impact; approval raises only to candidate', () => {
  let artifact = createDomainInvestigation(
    { indicator: 'suspicious.example', recommendations: [baseRec] },
    'suspicious.example',
    { providerIndependenceRegistry: registry, operatorArtifacts: [operator] },
  );
  assert.equal(artifact.recommendations[0].disposition, 'MONITOR');
  assert.equal(artifact.promotion.candidates.length, 1);
  assert.equal(artifact.promotion.effectiveAttestations.length, 0);
  artifact = applyDomainPromotionEvent(artifact, {
    type: 'approved', candidateId: artifact.promotion.candidates[0].id, at: '2026-09-13T13:00:00.000Z', actorLabel: 'analyst:g', reason: 'Validated.',
  });
  assert.equal(artifact.recommendations[0].disposition, 'BLOCK_CANDIDATE');
  assert.equal(artifact.recommendations[0].independence.quorumEligibleGroupCount, 1);
  assert.equal(artifact.promotion.effectiveAttestations.length, 1);
});

test('revocation downgrades recommendation while keeping audit events', () => {
  let artifact = createDomainInvestigation(
    { indicator: 'suspicious.example', recommendations: [baseRec] },
    'suspicious.example',
    { providerIndependenceRegistry: registry, operatorArtifacts: [operator] },
  );
  artifact = applyDomainPromotionEvent(artifact, {
    type: 'approved', candidateId: artifact.promotion.candidates[0].id, at: '2026-09-13T13:00:00.000Z', actorLabel: 'analyst:g', reason: 'Validated.',
  });
  const id = artifact.promotion.effectiveAttestations[0].id;
  artifact = applyDomainPromotionEvent(artifact, {
    type: 'revoked', attestationId: id, at: '2026-09-13T14:00:00.000Z', actorLabel: 'analyst:g', reason: 'Disproved.',
  });
  assert.equal(artifact.recommendations[0].disposition, 'MONITOR');
  assert.equal(artifact.promotion.events.length, 2);
  assert.equal(artifact.promotion.effectiveAttestations.length, 0);
});
