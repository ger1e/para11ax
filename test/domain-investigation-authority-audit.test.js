import test from 'node:test';
import assert from 'node:assert/strict';

import {
  createDomainInvestigation,
  applyDomainPromotionEvent,
} from '../src/core/domain-investigation.js';

const fp = char => char.repeat(64);

function evidence(provider, verdict, fingerprint) {
  return {
    provider,
    indicator: 'suspicious.example',
    type: 'domain',
    observation: {
      kind: 'reputation',
      verdict,
      confidence: null,
      firstSeen: null,
      lastSeen: null,
      tags: [],
      malwareFamily: null,
      actor: null,
      attributes: {},
    },
    relationships: [],
    references: [],
    retrievedAt: '2026-09-13T12:00:00.000Z',
    cacheState: 'miss',
    durationMs: 1,
    integrity: { rawHash: null, parserVersion: '1', fingerprint },
    semantics: { class: 'provider_claim', semanticClass: 'reputation', sourceRole: 'community' },
  };
}

function enrichment() {
  const items = [
    evidence('virustotal', 'malicious', fp('1')),
    evidence('mystery-provider', 'malicious', fp('2')),
    evidence('openphish', 'clean', fp('3')),
  ];
  return {
    schemaVersion: '2.0',
    gatewayVersion: 'test',
    requestId: 'req-authority-audit',
    indicator: 'suspicious.example',
    type: 'domain',
    queriedAt: '2026-09-13T12:00:00.000Z',
    profile: 'standard',
    status: 'ok',
    evidence: items,
    relationships: [],
    coverage: {},
    limitations: [],
    failures: [],
    huntContext: {
      indicator: 'suspicious.example',
      type: 'domain',
      firstSeen: null,
      lastSeen: null,
      families: [],
      actors: [],
      sourceReferences: [],
    },
  };
}

const operatorArtifact = {
  id: 'surface-review-001',
  kind: 'analyst_note',
  capturedAt: '2026-09-13T12:10:00.000Z',
  source: 'authorized-review',
  summary: 'SENSITIVE-RAW-ARTIFACT-SUMMARY-MUST-NOT-BE-IN-HANDOFF',
  references: ['https://analyst.example/review/1'],
  observable: { type: 'domain', value: 'suspicious.example' },
  observation: { kind: 'operator_context', verdict: 'malicious' },
};

test('report and handoff expose bounded authority reconstruction and promotion audit context', () => {
  let artifact = createDomainInvestigation(enrichment(), 'suspicious.example', {
    operatorArtifacts: [operatorArtifact],
  });
  artifact = applyDomainPromotionEvent(artifact, {
    type: 'approved',
    candidateId: artifact.promotion.candidates[0].id,
    at: '2026-09-13T12:15:00.000Z',
    actorLabel: 'analyst-1',
    reason: 'Approved after independent analyst review.',
  });

  const rec = artifact.recommendations.find(item => item.value === 'suspicious.example');
  const attestation = artifact.promotion.effectiveAttestations[0];
  assert.equal(rec.disposition, 'BLOCK_CANDIDATE');
  assert.deepEqual(rec.independence.quorumGroups, ['google-virustotal']);
  assert.deepEqual(rec.independence.unknownProviders, ['mystery-provider']);
  assert.equal(rec.contradictions.length, 1);

  for (const surface of [artifact.report, artifact.handoff]) {
    assert.equal(surface.authorityAudit.registryVersion, 'provider-independence-v1.0');
    assert.deepEqual(surface.authorityAudit.knownQuorumGroups, ['google-virustotal']);
    assert.equal(surface.authorityAudit.unknownLineageCount, 1);
    assert.equal(surface.authorityAudit.analystAttestations.authorityClass, 'analyst_attestation');
    assert.deepEqual(surface.authorityAudit.analystAttestations.effective, [{
      id: attestation.id,
      fingerprint: attestation.fingerprint,
    }]);
    assert.deepEqual(surface.authorityAudit.promotionAudit, {
      eventCount: 1,
      approved: 1,
      rejected: 0,
      revoked: 0,
      superseded: 0,
      expired: 0,
    });
    assert.deepEqual(surface.authorityAudit.contradictions, [{
      type: 'domain',
      value: 'suspicious.example',
      count: 1,
    }]);
  }

  assert.match(artifact.report.text, /provider-independence-v1\.0/i);
  assert.match(artifact.report.text, /google-virustotal/i);
  assert.match(artifact.report.text, /analyst_attestation/i);

  const handoffJson = JSON.stringify(artifact.handoff);
  assert.equal(handoffJson.includes(operatorArtifact.summary), false);
  assert.equal(handoffJson.includes('Approved after independent analyst review.'), false);
  assert.equal(artifact.handoff.contextBudget.serializedBytes, Buffer.byteLength(handoffJson, 'utf8'));
  assert.ok(artifact.handoff.contextBudget.serializedBytes < artifact.handoff.contextBudget.maximumBytes);
});
