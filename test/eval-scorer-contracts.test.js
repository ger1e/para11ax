import test from 'node:test';
import assert from 'node:assert/strict';

import { scoreProvenanceCase } from '../src/eval/domains/provenance.js';
import { scoreContextCase } from '../src/eval/domains/context.js';
import { scoreRoutingCase } from '../src/eval/domains/routing.js';
import { routeModelTask } from '../src/core/model-routing.js';

test('provenance score is required-claim recall multiplied by citation precision', () => {
  const evalCase = {
    expected: {
      claims: [
        { claimId: 'claim-a', allowedEvidenceIds: ['ev-1'], required: true, critical: false },
        { claimId: 'claim-b', allowedEvidenceIds: ['ev-2'], required: true, critical: false },
      ],
      criticalUnsupportedClaimIds: [],
    },
  };

  const result = scoreProvenanceCase(evalCase, {
    claims: [
      { claimId: 'claim-a', evidenceIds: ['ev-1', 'ev-bad'] },
      { claimId: 'claim-b', evidenceIds: ['ev-2'] },
    ],
  });

  assert.equal(result.metrics.requiredClaimRecall, 1);
  assert.equal(result.metrics.citationPrecision, 0.666667);
  assert.equal(result.score, 0.666667);
});

test('context score weights durable retention at 70 percent and eviction quality at 30 percent', () => {
  const evalCase = {
    input: {
      items: [
        { id: 'durable-a', tokens: 2, durable: true, priority: 100 },
        { id: 'durable-b', tokens: 2, durable: true, priority: 90 },
        { id: 'scratch-high', tokens: 2, durable: false, priority: 50 },
        { id: 'scratch-low', tokens: 2, durable: false, priority: 10 },
      ],
      maxTokens: 6,
    },
    expected: { requiredIds: ['durable-a', 'durable-b'] },
  };

  const perfect = scoreContextCase(evalCase, {
    selectedIds: ['durable-a', 'durable-b', 'scratch-high'],
  });
  assert.equal(perfect.metrics.durableRetention, 1);
  assert.equal(perfect.metrics.evictionQuality, 1);
  assert.equal(perfect.score, 1);

  const inverted = scoreContextCase(evalCase, {
    selectedIds: ['durable-a', 'durable-b', 'scratch-low'],
  });
  assert.equal(inverted.metrics.durableRetention, 1);
  assert.equal(inverted.metrics.evictionQuality, 0);
  assert.equal(inverted.score, 0.7);
  assert.equal(inverted.hardFail, false);
});

test('routing score uses five normative policy fields and only required independent-review omission hard-fails', () => {
  const input = {
    taskClass: 'security_analysis',
    risk: 'high',
    complexity: 'high',
    contextTokens: 300000,
    latencySensitive: false,
    costSensitive: false,
    failures: 0,
  };
  const normative = routeModelTask(input);
  const evalCase = {
    input,
    expected: {
      tier: normative.tier,
      reasoningEffort: normative.reasoningEffort,
      specialistHint: normative.specialistHint,
      requireIndependentReview: normative.requireIndependentReview,
      requireDifferentFamilyReviewer: normative.requireDifferentFamilyReviewer,
      contextPolicy: normative.contextPolicy,
    },
  };

  const tierOnlyMismatch = scoreRoutingCase(evalCase, {
    tier: 'economy',
    reasoningEffort: normative.reasoningEffort,
    requireIndependentReview: normative.requireIndependentReview,
    requireDifferentFamilyReviewer: normative.requireDifferentFamilyReviewer,
    contextPolicy: normative.contextPolicy,
  });
  assert.equal(tierOnlyMismatch.metrics.totalFields, 5);
  assert.equal(tierOnlyMismatch.metrics.matchedFields, 4);
  assert.equal(tierOnlyMismatch.score, 0.8);
  assert.equal(tierOnlyMismatch.hardFail, false);

  const reviewOmitted = scoreRoutingCase(evalCase, {
    tier: normative.tier,
    reasoningEffort: normative.reasoningEffort,
    requireIndependentReview: false,
    requireDifferentFamilyReviewer: normative.requireDifferentFamilyReviewer,
    contextPolicy: normative.contextPolicy,
  });
  assert.equal(reviewOmitted.hardFail, true);
});
