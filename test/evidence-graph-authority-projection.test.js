import test from 'node:test';
import assert from 'node:assert/strict';

import { buildEvidenceGraph } from '../src/core/evidence-graph.js';
import {
  createProviderIndependenceRegistry,
  summarizeProviderIndependence,
} from '../src/core/provider-independence.js';
import {
  createPromotionState,
  applyPromotionEvent,
  deriveEffectiveAttestations,
} from '../src/core/evidence-promotion.js';

const KNOWN_FINGERPRINT = 'a'.repeat(64);
const UNKNOWN_FINGERPRINT = 'b'.repeat(64);

function authorityFixture() {
  const operatorArtifact = {
    id: 'artifact-001',
    kind: 'analyst_note',
    capturedAt: '2026-09-13T10:00:00.000Z',
    source: 'case-notes',
    summary: 'Analyst observed infrastructure corroborating the exact domain.',
    references: ['https://analyst.example/report/1'],
    observable: { type: 'domain', value: 'evil.example' },
    observation: { kind: 'operator_context', verdict: 'malicious' },
  };

  const initialPromotion = createPromotionState([operatorArtifact]);
  const approvedPromotion = applyPromotionEvent(initialPromotion, {
    type: 'approved',
    candidateId: initialPromotion.candidates[0].id,
    at: '2026-09-13T10:05:00.000Z',
    actorLabel: 'analyst@example',
    reason: 'Corroborates the provider finding after analyst review.',
  });
  const effectiveAttestations = deriveEffectiveAttestations(
    approvedPromotion.candidates,
    approvedPromotion.events,
  );

  const registry = createProviderIndependenceRegistry([
    {
      provider: 'virustotal',
      independenceGroup: 'google-virustotal',
      lineageConfidence: 'confirmed',
      basis: 'maintained_mapping',
      references: [],
      updatedAt: '2026-09-13T00:00:00.000Z',
    },
  ]);
  const providerIndependence = summarizeProviderIndependence(
    ['virustotal', 'mystery-provider'],
    registry,
  );

  const evidence = [
    {
      provider: 'virustotal',
      integrity: { fingerprint: KNOWN_FINGERPRINT },
      observation: { kind: 'direct', verdict: 'malicious' },
    },
    {
      provider: 'mystery-provider',
      integrity: { fingerprint: UNKNOWN_FINGERPRINT },
      observation: { kind: 'direct', verdict: 'malicious' },
    },
  ];

  const recommendations = [{
    type: 'domain',
    value: 'evil.example',
    disposition: 'BLOCK_CANDIDATE',
    ruleId: 'DI-CANDIDATE-DIRECT-CONTEXT',
    uniqueQuorumGroups: ['google-virustotal'],
    contradictions: [],
    evidenceFingerprints: [KNOWN_FINGERPRINT, UNKNOWN_FINGERPRINT],
    analystAttestations: [effectiveAttestations[0].id],
  }];

  return {
    operatorArtifact,
    providerIndependence,
    evidence,
    promotion: {
      candidates: approvedPromotion.candidates,
      events: approvedPromotion.events,
      effectiveAttestations,
    },
    recommendations,
  };
}

function buildFixtureGraph(fixture, evidence = fixture.evidence) {
  return buildEvidenceGraph({
    indicator: 'evil.example',
    type: 'domain',
    evidence,
    providerIndependence: fixture.providerIndependence,
    operatorArtifacts: [fixture.operatorArtifact],
    promotion: fixture.promotion,
    recommendations: fixture.recommendations,
  });
}

test('Evidence Graph projects provider independence, promotion authority, and recommendation explanation', () => {
  const fixture = authorityFixture();
  const graph = buildFixtureGraph(fixture);

  const nodeTypes = new Set(graph.nodes.map(node => node.type));
  for (const type of [
    'independence_group',
    'operator_artifact',
    'promotion_candidate',
    'promoted_evidence',
    'promotion_event',
    'recommendation',
  ]) {
    assert.equal(nodeTypes.has(type), true, `graph must project ${type} nodes`);
  }

  const edgeTypes = new Set(graph.edges.map(edge => edge.type));
  for (const type of [
    'member_of',
    'supports',
    'describes',
    'candidate_for',
    'derived_from',
    'promoted_from',
    'affects',
    'applies_to',
    'based_on',
    'corroborated_by',
    'quorum_from',
  ]) {
    assert.equal(edgeTypes.has(type), true, `graph must project ${type} edges`);
  }

  const knownGroup = graph.nodes.find(node =>
    node.type === 'independence_group' && node.name === 'google-virustotal');
  const unknownGroup = graph.nodes.find(node =>
    node.type === 'independence_group' && node.name === 'provider:mystery-provider');
  assert.ok(knownGroup, 'known provider family must be projected');
  assert.ok(unknownGroup, 'unknown provider display bucket must remain visible');
  assert.equal(knownGroup.quorumEligible, true);
  assert.equal(unknownGroup.quorumEligible, false);

  const quorumTargets = graph.edges
    .filter(edge => edge.type === 'quorum_from')
    .map(edge => edge.target)
    .sort();
  assert.deepEqual(quorumTargets, [knownGroup.id], 'unknown lineage must never produce a quorum edge');
});

test('authority projection is deterministic under input ordering and does not mutate source authority state', () => {
  const fixture = authorityFixture();
  const source = {
    providerIndependence: fixture.providerIndependence,
    operatorArtifact: fixture.operatorArtifact,
    promotion: fixture.promotion,
    recommendations: fixture.recommendations,
  };
  const before = structuredClone(source);

  const forward = buildFixtureGraph(fixture, fixture.evidence);
  const reversed = buildFixtureGraph(fixture, [...fixture.evidence].reverse());

  assert.deepEqual(reversed, forward, 'graph IDs and ordering must be deterministic');
  assert.deepEqual(source, before, 'graph projection must not mutate source authority state');
});

test('legacy graph callers remain compatible and authority projection inputs stay bounded', () => {
  const legacy = buildEvidenceGraph({
    indicator: 'evil.example',
    type: 'domain',
    evidence: [{
      provider: 'virustotal',
      integrity: { fingerprint: KNOWN_FINGERPRINT },
      observation: { kind: 'direct', verdict: 'malicious' },
    }],
  });
  assert.equal(legacy.schemaVersion, '1.0');
  assert.equal(legacy.nodes.some(node => node.type === 'observable'), true);
  assert.equal(legacy.nodes.some(node => node.type === 'evidence'), true);

  assert.throws(() => buildEvidenceGraph({
    indicator: 'evil.example',
    type: 'domain',
    operatorArtifacts: Array.from({ length: 257 }, (_, index) => ({ id: `artifact-${index}` })),
  }), /evidence_graph_operator_artifact_limit/);
});
