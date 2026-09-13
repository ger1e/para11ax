import { canonicalJson, roundScore } from './canonical.js';
import {
  EVAL_COMPARISON_SCHEMA,
  EVAL_SCORECARD_SCHEMA,
  deepFreeze,
} from './schemas.js';

function plainObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError(`${label} must be a plain object`);
  }
  return value;
}

function finiteNumber(value, label) {
  if (!Number.isFinite(value)) throw new TypeError(`${label} must be finite`);
  return value;
}

function assertScorecard(value, label) {
  plainObject(value, label);
  if (value.schemaVersion !== EVAL_SCORECARD_SCHEMA) throw new TypeError(`incompatible scorecards: ${label} schema mismatch`);
  if (typeof value.evaluatorVersion !== 'string' || value.evaluatorVersion.trim() === '') {
    throw new TypeError(`incompatible scorecards: ${label} evaluator version mismatch`);
  }
  plainObject(value.corpus, `${label}.corpus`);
  plainObject(value.corpus.scorerVersions, `${label}.corpus.scorerVersions`);
  plainObject(value.corpus.promotionPolicy, `${label}.corpus.promotionPolicy`);
  plainObject(value.aggregate, `${label}.aggregate`);
  plainObject(value.domains, `${label}.domains`);
  plainObject(value.measurements, `${label}.measurements`);
  if (!Array.isArray(value.cases)) throw new TypeError(`incompatible scorecards: ${label} cases mismatch`);
  finiteNumber(value.aggregate.weightedScore, `${label}.aggregate.weightedScore`);
  finiteNumber(value.aggregate.hardFailures, `${label}.aggregate.hardFailures`);
  finiteNumber(value.aggregate.criticalHardFailures, `${label}.aggregate.criticalHardFailures`);
  return value;
}

function exactEqual(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function assertCompatibility(baseline, candidate) {
  const checks = [
    ['corpus id', baseline.corpus.corpusId, candidate.corpus.corpusId],
    ['corpus version', baseline.corpus.corpusVersion, candidate.corpus.corpusVersion],
    ['corpus hash', baseline.corpus.corpusHash, candidate.corpus.corpusHash],
    ['evaluator version', baseline.evaluatorVersion, candidate.evaluatorVersion],
  ];
  for (const [label, left, right] of checks) {
    if (!Object.is(left, right)) throw new TypeError(`incompatible scorecards: ${label} mismatch`);
  }
  if (!exactEqual(baseline.corpus.scorerVersions, candidate.corpus.scorerVersions)) {
    throw new TypeError('incompatible scorecards: scorer version mismatch');
  }
  if (!exactEqual(baseline.corpus.promotionPolicy, candidate.corpus.promotionPolicy)) {
    throw new TypeError('incompatible scorecards: promotion policy mismatch');
  }
  const baselineDomains = Object.keys(baseline.domains).sort();
  const candidateDomains = Object.keys(candidate.domains).sort();
  if (!exactEqual(baselineDomains, candidateDomains)) {
    throw new TypeError('incompatible scorecards: domain set mismatch');
  }
}

function delta(candidate, baseline) {
  return roundScore(finiteNumber(candidate, 'candidate delta value') - finiteNumber(baseline, 'baseline delta value'));
}

function nullableDelta(candidate, baseline) {
  if (candidate === null || baseline === null) return null;
  return delta(candidate, baseline);
}

function reductionRatio(baseline, candidate) {
  if (baseline === null || candidate === null) return null;
  finiteNumber(baseline, 'baseline efficiency measurement');
  finiteNumber(candidate, 'candidate efficiency measurement');
  if (baseline <= 0) return null;
  return roundScore((baseline - candidate) / baseline);
}

function humanReviewState(candidate) {
  let incomplete = false;
  let failed = false;
  for (const item of candidate.cases) {
    const review = item?.humanReview;
    if (!review?.required) continue;
    if (review.reviewStatus !== 'completed') incomplete = true;
    else if (review.reviewDecision !== 'pass') failed = true;
  }
  return { incomplete, failed };
}

function domainDelta(baseline, candidate, domain) {
  const left = baseline.domains[domain];
  const right = candidate.domains[domain];
  if (!left || !right) throw new TypeError(`incompatible scorecards: domain ${domain} mismatch`);
  return delta(right.score, left.score);
}

export function compareScorecards({ baseline, candidate, requirePromotion = false } = {}) {
  if (typeof requirePromotion !== 'boolean') throw new TypeError('requirePromotion must be boolean');
  const left = assertScorecard(baseline, 'baseline');
  const right = assertScorecard(candidate, 'candidate');
  assertCompatibility(left, right);

  const domains = {};
  for (const domain of Object.keys(left.domains).sort()) {
    domains[domain] = domainDelta(left, right, domain);
  }

  const deltas = {
    weightedScore: delta(right.aggregate.weightedScore, left.aggregate.weightedScore),
    hardFailures: delta(right.aggregate.hardFailures, left.aggregate.hardFailures),
    criticalHardFailures: delta(right.aggregate.criticalHardFailures, left.aggregate.criticalHardFailures),
    inputTokens: delta(right.measurements.inputTokens, left.measurements.inputTokens),
    outputTokens: delta(right.measurements.outputTokens, left.measurements.outputTokens),
    totalTokens: delta(right.measurements.totalTokens, left.measurements.totalTokens),
    costUsd: nullableDelta(right.measurements.costUsd, left.measurements.costUsd),
    latencyMs: nullableDelta(right.measurements.latencyMs, left.measurements.latencyMs),
    domains,
  };

  const efficiency = {
    costReductionRatio: reductionRatio(left.measurements.costUsd, right.measurements.costUsd),
    totalTokenReductionRatio: reductionRatio(left.measurements.totalTokens, right.measurements.totalTokens),
  };

  const policy = right.corpus.promotionPolicy;
  const reasons = [];
  if (right.aggregate.criticalHardFailures > left.aggregate.criticalHardFailures) {
    reasons.push('CRITICAL_HARD_FAILURE_REGRESSION');
  }
  if (domains.provenance < -policy.provenanceMaxRegression) reasons.push('PROVENANCE_REGRESSION');
  if (domains.handoff < -policy.handoffMaxRegression) reasons.push('HANDOFF_REGRESSION');
  if (domains.kql < -policy.kqlMaxRegression) reasons.push('KQL_REGRESSION');

  const review = humanReviewState(right);
  if (policy.requireHumanReviewComplete && review.incomplete) reasons.push('HUMAN_REVIEW_INCOMPLETE');
  if (policy.requireHumanReviewComplete && review.failed) reasons.push('HUMAN_REVIEW_FAILED');

  const qualityPath = deltas.weightedScore >= policy.minimumWeightedImprovement;
  const efficientEnough = [efficiency.costReductionRatio, efficiency.totalTokenReductionRatio]
    .some(value => value !== null && value >= policy.minimumEfficiencyReductionRatio);
  const efficiencyPath = deltas.weightedScore >= -policy.maximumWeightedRegressionForEfficiency && efficientEnough;
  if (!qualityPath && !efficiencyPath) reasons.push('INSUFFICIENT_QUALITY_OR_EFFICIENCY_GAIN');

  const blockingReasons = [...new Set(reasons)].sort();
  const passed = blockingReasons.length === 0;
  const promotionReasons = [...blockingReasons];
  if (passed) {
    if (qualityPath) promotionReasons.push('WEIGHTED_SCORE_IMPROVED');
    else if (efficiencyPath) promotionReasons.push('EFFICIENCY_REDUCTION_MET');
  }

  const comparison = {
    schemaVersion: EVAL_COMPARISON_SCHEMA,
    baseline: {
      scorecardHash: left.scorecardHash,
      candidate: structuredClone(left.candidate),
    },
    candidate: {
      scorecardHash: right.scorecardHash,
      candidate: structuredClone(right.candidate),
    },
    deltas,
    efficiency,
    promotion: {
      required: requirePromotion,
      passed,
      reasons: promotionReasons.sort(),
    },
  };
  return deepFreeze(comparison);
}
