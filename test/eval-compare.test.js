import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { loadCorpusDirectory } from '../src/eval/corpus.js';
import { compareScorecards, scoreResultBundle } from '../src/eval/index.js';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const corpus = loadCorpusDirectory(join(ROOT, 'evals/corpus/v1'));

function loadFixture(name) {
  return JSON.parse(readFileSync(join(ROOT, 'evals/fixtures/candidate-results', name), 'utf8'));
}

function score(name) {
  return scoreResultBundle({ corpus, resultBundle: loadFixture(name) });
}

function clone(value) {
  return structuredClone(value);
}

function compatibleCandidate() {
  return clone(score('baseline-v1.json'));
}

test('comparison requires exact corpus scorer evaluator domain and policy compatibility', () => {
  const baseline = score('baseline-v1.json');
  const changes = [
    candidate => { candidate.corpus.corpusId = 'other-corpus'; },
    candidate => { candidate.corpus.corpusVersion = '2.0.0'; },
    candidate => { candidate.corpus.corpusHash = 'sha256:'.padEnd(71, '1'); },
    candidate => { candidate.corpus.scorerVersions.cti = '2.0.0'; },
    candidate => { candidate.evaluatorVersion = '2.0.0'; },
    candidate => { delete candidate.domains.coding; },
    candidate => { candidate.corpus.promotionPolicy.minimumEfficiencyReductionRatio = 0.25; },
  ];

  for (const mutate of changes) {
    const candidate = compatibleCandidate();
    mutate(candidate);
    assert.throws(() => compareScorecards({ baseline, candidate }), /compatib|mismatch/i);
  }
});

test('comparison reports scalar and domain deltas with null unknown measurements', () => {
  const baseline = score('baseline-v1.json');
  const candidate = compatibleCandidate();
  candidate.aggregate.weightedScore = 0.98;
  candidate.domains.cti.score = 0.9;
  candidate.measurements.inputTokens = 800;
  candidate.measurements.outputTokens = 90;
  candidate.measurements.totalTokens = 890;

  const comparison = compareScorecards({ baseline, candidate });
  assert.equal(comparison.deltas.weightedScore, -0.02);
  assert.equal(comparison.deltas.domains.cti, -0.1);
  assert.equal(comparison.deltas.inputTokens, -100);
  assert.equal(comparison.deltas.outputTokens, -10);
  assert.equal(comparison.deltas.totalTokens, -110);
  assert.equal(comparison.deltas.costUsd, null);
  assert.equal(comparison.deltas.latencyMs, null);
});

test('critical hard-failure regression blocks promotion regardless of weighted score', () => {
  const baseline = score('baseline-v1.json');
  const candidate = compatibleCandidate();
  candidate.aggregate.criticalHardFailures = baseline.aggregate.criticalHardFailures + 1;
  candidate.aggregate.weightedScore = 1;

  const comparison = compareScorecards({ baseline, candidate, requirePromotion: true });
  assert.equal(comparison.promotion.passed, false);
  assert.ok(comparison.promotion.reasons.includes('CRITICAL_HARD_FAILURE_REGRESSION'));
});

test('provenance handoff and KQL regressions use manifest thresholds', () => {
  const baseline = score('baseline-v1.json');
  for (const [domain, delta, reason] of [
    ['provenance', -0.021, 'PROVENANCE_REGRESSION'],
    ['handoff', -0.021, 'HANDOFF_REGRESSION'],
    ['kql', -0.031, 'KQL_REGRESSION'],
  ]) {
    const candidate = compatibleCandidate();
    candidate.domains[domain].score = baseline.domains[domain].score + delta;
    const comparison = compareScorecards({ baseline, candidate, requirePromotion: true });
    assert.equal(comparison.promotion.passed, false);
    assert.ok(comparison.promotion.reasons.includes(reason));
  }
});

test('twenty percent known token reduction passes the efficiency path with equal quality', () => {
  const baseline = score('baseline-v1.json');
  const candidate = score('improved-v1.json');
  const comparison = compareScorecards({ baseline, candidate, requirePromotion: true });

  assert.equal(comparison.deltas.weightedScore, 0);
  assert.equal(comparison.efficiency.costReductionRatio, null);
  assert.equal(comparison.efficiency.totalTokenReductionRatio, 0.2);
  assert.equal(comparison.promotion.passed, true);
  assert.ok(comparison.promotion.reasons.includes('EFFICIENCY_REDUCTION_MET'));
});

test('twenty percent known cost reduction can pass when token use is unchanged', () => {
  const baseline = compatibleCandidate();
  baseline.measurements.costUsd = 10;
  const candidate = clone(baseline);
  candidate.measurements.costUsd = 8;
  const comparison = compareScorecards({ baseline, candidate, requirePromotion: true });
  assert.equal(comparison.efficiency.costReductionRatio, 0.2);
  assert.equal(comparison.promotion.passed, true);
});

test('pending or failed required human review blocks promotion; completed pass permits gate evaluation', () => {
  const baseline = score('baseline-v1.json');

  const pending = compatibleCandidate();
  pending.cases[0].humanReview = {
    required: true,
    fields: ['SEMANTIC_QUALITY'],
    reviewStatus: 'pending',
    reviewDecision: null,
  };
  let comparison = compareScorecards({ baseline, candidate: pending, requirePromotion: true });
  assert.equal(comparison.promotion.passed, false);
  assert.ok(comparison.promotion.reasons.includes('HUMAN_REVIEW_INCOMPLETE'));

  const failed = compatibleCandidate();
  failed.cases[0].humanReview = {
    required: true,
    fields: ['SEMANTIC_QUALITY'],
    reviewStatus: 'completed',
    reviewDecision: 'fail',
  };
  comparison = compareScorecards({ baseline, candidate: failed, requirePromotion: true });
  assert.equal(comparison.promotion.passed, false);
  assert.ok(comparison.promotion.reasons.includes('HUMAN_REVIEW_FAILED'));

  const passed = score('improved-v1.json');
  const mutable = clone(passed);
  mutable.cases[0].humanReview = {
    required: true,
    fields: ['SEMANTIC_QUALITY'],
    reviewStatus: 'completed',
    reviewDecision: 'pass',
  };
  comparison = compareScorecards({ baseline, candidate: mutable, requirePromotion: true });
  assert.equal(comparison.promotion.passed, true);
  assert.equal(comparison.promotion.reasons.includes('HUMAN_REVIEW_INCOMPLETE'), false);
  assert.equal(comparison.promotion.reasons.includes('HUMAN_REVIEW_FAILED'), false);
});

test('quality path passes only at the manifest minimum improvement threshold', () => {
  const baseline = compatibleCandidate();
  baseline.aggregate.weightedScore = 0.9;
  const candidate = clone(baseline);
  candidate.aggregate.weightedScore = 0.92;
  const comparison = compareScorecards({ baseline, candidate, requirePromotion: true });
  assert.equal(comparison.deltas.weightedScore, 0.02);
  assert.equal(comparison.promotion.passed, true);
  assert.ok(comparison.promotion.reasons.includes('WEIGHTED_SCORE_IMPROVED'));
});

test('promotion fails when neither quality nor known efficiency reaches policy threshold', () => {
  const baseline = score('baseline-v1.json');
  const candidate = compatibleCandidate();
  candidate.measurements.inputTokens = 850;
  candidate.measurements.outputTokens = 100;
  candidate.measurements.totalTokens = 950;
  const comparison = compareScorecards({ baseline, candidate, requirePromotion: true });
  assert.equal(comparison.promotion.passed, false);
  assert.ok(comparison.promotion.reasons.includes('INSUFFICIENT_QUALITY_OR_EFFICIENCY_GAIN'));
});
