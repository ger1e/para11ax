import { roundScore, sha256Canonical } from './canonical.js';
import { assertAggregateOnlyScorecard } from './privacy.js';
import {
  EVAL_DOMAINS,
  EVAL_SCORECARD_SCHEMA,
  deepFreeze,
  validateResultBundle,
} from './schemas.js';
import { scoreCtiCase } from './domains/cti.js';
import { scoreProvenanceCase } from './domains/provenance.js';
import { scoreClassificationCase } from './domains/classification.js';
import { scoreAttackCase } from './domains/attack.js';
import { scoreKqlCase } from './domains/kql.js';
import { scoreHandoffCase } from './domains/handoff.js';
import { scoreContextCase } from './domains/context.js';
import { scoreRoutingCase } from './domains/routing.js';
import { scoreCodingCase } from './domains/coding.js';

export const EVALUATOR_VERSION = '1.0.0';

const SCORERS = Object.freeze({
  cti: scoreCtiCase,
  provenance: scoreProvenanceCase,
  classification: scoreClassificationCase,
  attack: scoreAttackCase,
  kql: scoreKqlCase,
  handoff: scoreHandoffCase,
  context: scoreContextCase,
  routing: scoreRoutingCase,
  coding: scoreCodingCase,
});

function plainObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError(`${label} must be a plain object`);
  }
  return value;
}

function normalizeViolation(code) {
  if (typeof code !== 'string' || code.length === 0) throw new TypeError('scorer violation must be a non-empty string');
  const stable = code.split(':', 1)[0];
  if (!/^[A-Z][A-Z0-9_]*$/.test(stable)) throw new TypeError('scorer violation must use a stable symbolic code');
  return stable;
}

function normalizeMetrics(metrics) {
  plainObject(metrics, 'scorer metrics');
  const normalized = {};
  for (const [key, value] of Object.entries(metrics)) {
    if (!/^[a-zA-Z][a-zA-Z0-9]*$/.test(key)) throw new TypeError(`unsafe scorer metric key: ${key}`);
    if (value === null || typeof value === 'boolean') normalized[key] = value;
    else if (typeof value === 'number' && Number.isFinite(value)) normalized[key] = value;
    else throw new TypeError(`unsafe scorer metric value: ${key}`);
  }
  return normalized;
}

function normalizeHumanReview(scored, resultCase) {
  const review = scored.humanReview ?? { required: false, fields: [] };
  if (typeof review.required !== 'boolean' || !Array.isArray(review.fields)) {
    throw new TypeError('scorer humanReview contract is invalid');
  }
  const fields = [...new Set(review.fields.map(field => normalizeViolation(field)))].sort();
  if (!review.required) {
    return {
      required: false,
      fields,
      reviewStatus: 'not_required',
      reviewDecision: null,
    };
  }
  if (resultCase.review?.status === 'completed') {
    return {
      required: true,
      fields,
      reviewStatus: 'completed',
      reviewDecision: resultCase.review.decision,
    };
  }
  return {
    required: true,
    fields,
    reviewStatus: 'pending',
    reviewDecision: null,
  };
}

function criticalHardFail(domain, hardFail, violations) {
  if (!hardFail) return false;
  if (domain === 'handoff' || domain === 'context') return true;
  if (domain === 'provenance') {
    return violations.some(code => code.startsWith('PROVENANCE_CRITICAL_'));
  }
  return false;
}

function normalizeScoredCase(evalCase, resultCase, scored) {
  if (!scored || typeof scored !== 'object') throw new TypeError(`scorer returned invalid result for ${evalCase.caseId}`);
  if (!Number.isFinite(scored.score) || scored.score < 0 || scored.score > 1) {
    throw new TypeError(`scorer returned invalid score for ${evalCase.caseId}`);
  }
  if (typeof scored.hardFail !== 'boolean' || !Array.isArray(scored.violations)) {
    throw new TypeError(`scorer returned invalid failure contract for ${evalCase.caseId}`);
  }
  if (typeof scored.scorerVersion !== 'string' || scored.scorerVersion.trim() === '') {
    throw new TypeError(`scorer returned invalid version for ${evalCase.caseId}`);
  }
  const violations = [...new Set(scored.violations.map(normalizeViolation))].sort();
  const hardFail = scored.hardFail;
  return {
    caseId: evalCase.caseId,
    domain: evalCase.domain,
    score: roundScore(scored.score),
    hardFail,
    criticalHardFail: criticalHardFail(evalCase.domain, hardFail, violations),
    violations,
    metrics: normalizeMetrics(scored.metrics ?? {}),
    humanReview: normalizeHumanReview(scored, resultCase),
    scorerVersion: scored.scorerVersion,
  };
}

function normalizedBundleForHash(bundle) {
  return {
    ...structuredClone(bundle),
    cases: [...bundle.cases]
      .map(item => structuredClone(item))
      .sort((a, b) => a.caseId.localeCompare(b.caseId)),
  };
}

function requireExactCaseSet(corpus, bundle) {
  const expected = new Set(corpus.cases.map(item => item.caseId));
  const actual = new Set(bundle.cases.map(item => item.caseId));
  for (const id of actual) {
    if (!expected.has(id)) throw new TypeError(`result bundle contains unknown corpus case: ${id}`);
  }
  if (actual.size !== expected.size || [...expected].some(id => !actual.has(id))) {
    throw new TypeError('result bundle must contain the full corpus case set');
  }
}

function aggregateDomains(corpus, cases) {
  const byCase = new Map(corpus.cases.map(item => [item.caseId, item]));
  const domains = {};
  for (const domain of EVAL_DOMAINS) {
    const domainCases = cases.filter(item => item.domain === domain);
    const weightedDenominator = domainCases.reduce((sum, item) => sum + byCase.get(item.caseId).weight, 0);
    const weightedNumerator = domainCases.reduce(
      (sum, item) => sum + item.score * byCase.get(item.caseId).weight,
      0,
    );
    domains[domain] = {
      score: roundScore(weightedDenominator === 0 ? 0 : weightedNumerator / weightedDenominator),
      cases: domainCases.length,
      hardFailures: domainCases.filter(item => item.hardFail).length,
      criticalHardFailures: domainCases.filter(item => item.criticalHardFail).length,
      humanReviewCases: domainCases.filter(item => item.humanReview.required).length,
    };
  }
  return domains;
}

function aggregateGlobal(manifest, domains, cases) {
  let weightedScore = 0;
  for (const domain of EVAL_DOMAINS) {
    weightedScore += domains[domain].score * manifest.weights[domain];
  }
  return {
    weightedScore: roundScore(weightedScore),
    hardFailures: cases.filter(item => item.hardFail).length,
    criticalHardFailures: cases.filter(item => item.criticalHardFail).length,
    scoredCases: cases.length,
    humanReviewCases: cases.filter(item => item.humanReview.required).length,
  };
}

export function scoreResultBundle({ corpus, resultBundle, evaluatorVersion = EVALUATOR_VERSION } = {}) {
  plainObject(corpus, 'corpus');
  plainObject(corpus.manifest, 'corpus manifest');
  if (!Array.isArray(corpus.cases)) throw new TypeError('corpus cases must be an array');
  if (typeof evaluatorVersion !== 'string' || evaluatorVersion.trim() === '') throw new TypeError('evaluatorVersion is required');

  const bundle = validateResultBundle(resultBundle);
  if (bundle.corpusId !== corpus.manifest.corpusId) throw new TypeError('result bundle corpusId does not match corpus');
  requireExactCaseSet(corpus, bundle);

  const resultById = new Map(bundle.cases.map(item => [item.caseId, item]));
  const cases = [...corpus.cases]
    .sort((a, b) => a.caseId.localeCompare(b.caseId))
    .map(evalCase => {
      const scorer = SCORERS[evalCase.domain];
      if (!scorer) throw new TypeError(`no scorer registered for domain ${evalCase.domain}`);
      const resultCase = resultById.get(evalCase.caseId);
      return normalizeScoredCase(evalCase, resultCase, scorer(evalCase, resultCase.output));
    });

  const domains = aggregateDomains(corpus, cases);
  const aggregate = aggregateGlobal(corpus.manifest, domains, cases);
  const normalizedBundle = normalizedBundleForHash(bundle);
  const base = {
    schemaVersion: EVAL_SCORECARD_SCHEMA,
    evaluatorVersion,
    corpus: {
      corpusId: corpus.manifest.corpusId,
      corpusVersion: corpus.manifest.corpusVersion,
      corpusHash: corpus.manifest.corpusHash,
      scorerVersions: structuredClone(corpus.manifest.scorerVersions),
      promotionPolicy: structuredClone(corpus.manifest.promotionPolicy),
    },
    candidate: structuredClone(bundle.candidate),
    resultHash: sha256Canonical(normalizedBundle),
    aggregate,
    domains,
    cases,
    measurements: {
      inputTokens: bundle.measurements.inputTokens,
      outputTokens: bundle.measurements.outputTokens,
      totalTokens: bundle.measurements.inputTokens + bundle.measurements.outputTokens,
      costUsd: bundle.measurements.costUsd,
      latencyMs: bundle.measurements.latencyMs,
    },
  };

  assertAggregateOnlyScorecard({ ...base, scorecardHash: 'sha256:'.padEnd(71, '0') });
  const scorecard = {
    ...base,
    scorecardHash: sha256Canonical(base),
  };
  assertAggregateOnlyScorecard(scorecard);
  return deepFreeze(scorecard);
}
