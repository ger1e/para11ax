const FORBIDDEN_KEYS = new Set([
  'output',
  'query',
  'text',
  'body',
  'evidence',
  'prompt',
  'content',
  'indicator',
  'observable',
  'clientName',
  'serviceNow',
  'raw',
]);

const SAFE_CODE = /^[A-Z][A-Z0-9_]*$/;
const SAFE_CASE_ID = /^[a-z]+-[0-9]{3}$/;
const SAFE_DOMAIN = /^[a-z]+$/;
const SAFE_VERSION = /^[0-9]+\.[0-9]+\.[0-9]+$/;

function plainObject(value) {
  return Boolean(value)
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function assertNoForbiddenKeys(value, path = 'scorecard') {
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      assertNoForbiddenKeys(value[index], `${path}[${index}]`);
    }
    return;
  }
  if (!plainObject(value)) return;
  for (const [key, nested] of Object.entries(value)) {
    if (FORBIDDEN_KEYS.has(key)) {
      throw new TypeError(`aggregate scorecard contains forbidden payload key at ${path}.${key}`);
    }
    assertNoForbiddenKeys(nested, `${path}.${key}`);
  }
}

function assertMetricValue(value, path) {
  if (value === null || typeof value === 'boolean') return;
  if (typeof value === 'number' && Number.isFinite(value)) return;
  throw new TypeError(`aggregate metric must be finite scalar or null at ${path}`);
}

function assertBoundedCaseResult(item) {
  if (!plainObject(item) || !SAFE_CASE_ID.test(item.caseId)) {
    throw new TypeError('aggregate case result has invalid caseId');
  }
  if (typeof item.domain !== 'string' || !SAFE_DOMAIN.test(item.domain)) {
    throw new TypeError(`aggregate case result has invalid domain for ${item.caseId}`);
  }
  if (!Number.isFinite(item.score) || item.score < 0 || item.score > 1) {
    throw new TypeError(`aggregate case result has invalid score for ${item.caseId}`);
  }
  if (typeof item.hardFail !== 'boolean' || typeof item.criticalHardFail !== 'boolean') {
    throw new TypeError(`aggregate case result has invalid failure flags for ${item.caseId}`);
  }
  if (!Array.isArray(item.violations) || !item.violations.every(code => typeof code === 'string' && SAFE_CODE.test(code))) {
    throw new TypeError(`aggregate case result has unsafe violation codes for ${item.caseId}`);
  }
  if (!plainObject(item.metrics)) {
    throw new TypeError(`aggregate case result has invalid metrics for ${item.caseId}`);
  }
  for (const [key, value] of Object.entries(item.metrics)) {
    if (!/^[a-zA-Z][a-zA-Z0-9]*$/.test(key)) {
      throw new TypeError(`aggregate case result has unsafe metric key for ${item.caseId}`);
    }
    assertMetricValue(value, `${item.caseId}.metrics.${key}`);
  }
  if (!plainObject(item.humanReview)) {
    throw new TypeError(`aggregate case result has invalid human review for ${item.caseId}`);
  }
  const review = item.humanReview;
  if (typeof review.required !== 'boolean') throw new TypeError(`invalid human review requirement for ${item.caseId}`);
  if (!Array.isArray(review.fields) || !review.fields.every(field => typeof field === 'string' && SAFE_CODE.test(field))) {
    throw new TypeError(`unsafe human review fields for ${item.caseId}`);
  }
  if (!['not_required', 'pending', 'completed'].includes(review.reviewStatus)) {
    throw new TypeError(`invalid human review status for ${item.caseId}`);
  }
  if (review.reviewDecision !== null && !['pass', 'fail'].includes(review.reviewDecision)) {
    throw new TypeError(`invalid human review decision for ${item.caseId}`);
  }
  if (typeof item.scorerVersion !== 'string' || !SAFE_VERSION.test(item.scorerVersion)) {
    throw new TypeError(`invalid scorer version for ${item.caseId}`);
  }
}

export function assertAggregateOnlyScorecard(scorecard) {
  if (!plainObject(scorecard)) throw new TypeError('scorecard must be a plain object');
  assertNoForbiddenKeys(scorecard);
  if (!Array.isArray(scorecard.cases)) throw new TypeError('scorecard cases must be an array');
  for (const item of scorecard.cases) assertBoundedCaseResult(item);
  return true;
}
