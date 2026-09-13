export const EVAL_CASE_SCHEMA = 'para11ax-eval-case-v1.0';
export const EVAL_RESULT_SCHEMA = 'para11ax-eval-result-v1.0';
export const EVAL_SCORECARD_SCHEMA = 'para11ax-eval-scorecard-v1.0';
export const EVAL_COMPARISON_SCHEMA = 'para11ax-eval-comparison-v1.0';
export const CORPUS_MANIFEST_SCHEMA = 'para11ax-eval-corpus-manifest-v1.0';

export const EVAL_DOMAINS = Object.freeze([
  'cti',
  'provenance',
  'classification',
  'attack',
  'kql',
  'handoff',
  'context',
  'routing',
  'coding',
]);

const CASE_ID = /^[a-z]+-[0-9]{3}$/;

function plainObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  if (Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError(`${label} must be a plain object`);
  }
  return value;
}

function exactKeys(value, expected, label) {
  const actual = Object.keys(plainObject(value, label)).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new TypeError(`${label} has unexpected keys`);
  }
}

function nonEmptyString(value, label) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new TypeError(`${label} must be a non-empty string`);
  }
  return value;
}

function finiteNonNegative(value, label, { integer = false, nullable = false } = {}) {
  if (nullable && value === null) return value;
  if (!Number.isFinite(value) || value < 0 || (integer && !Number.isInteger(value))) {
    throw new TypeError(`${label} must be ${nullable ? 'null or ' : ''}a finite non-negative${integer ? ' integer' : ' number'}`);
  }
  return value;
}

function validateCaseId(value, label = 'caseId') {
  if (typeof value !== 'string' || !CASE_ID.test(value)) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

function scalarMeasurements(value, label) {
  plainObject(value, label);
  for (const [key, item] of Object.entries(value)) {
    nonEmptyString(key, `${label} key`);
    const scalar = item === null || typeof item === 'string' || typeof item === 'boolean' || typeof item === 'number';
    if (!scalar || (typeof item === 'number' && !Number.isFinite(item))) {
      throw new TypeError(`${label}.${key} must be a finite scalar or null`);
    }
  }
  return value;
}

function validateReview(value) {
  if (value === null) return null;
  plainObject(value, 'review');
  if (value.status === 'pending') {
    exactKeys(value, ['status'], 'review');
    return value;
  }
  if (value.status === 'completed') {
    exactKeys(value, ['status', 'decision'], 'review');
    if (value.decision !== 'pass' && value.decision !== 'fail') {
      throw new TypeError('review decision must be pass or fail');
    }
    return value;
  }
  throw new TypeError('review status must be pending or completed');
}

export function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const nested of Object.values(value)) deepFreeze(nested);
  return Object.freeze(value);
}

export function validateEvalCase(value) {
  exactKeys(value, ['schemaVersion', 'caseId', 'domain', 'weight', 'input', 'expected'], 'eval case');
  if (value.schemaVersion !== EVAL_CASE_SCHEMA) throw new TypeError('eval case schemaVersion is unsupported');
  validateCaseId(value.caseId);
  if (!EVAL_DOMAINS.includes(value.domain)) throw new TypeError('eval case domain is unsupported');
  if (!Number.isFinite(value.weight) || value.weight <= 0) throw new TypeError('eval case weight must be finite and greater than zero');
  plainObject(value.input, 'eval case input');
  plainObject(value.expected, 'eval case expected');
  return deepFreeze(structuredClone(value));
}

function validateCandidate(value) {
  exactKeys(value, ['provider', 'model', 'family', 'effort', 'harness', 'harnessVersion'], 'candidate');
  for (const key of ['provider', 'model', 'family', 'effort', 'harness', 'harnessVersion']) {
    nonEmptyString(value[key], `candidate.${key}`);
  }
}

function validateMeasurements(value) {
  exactKeys(value, ['inputTokens', 'outputTokens', 'costUsd', 'latencyMs'], 'measurements');
  finiteNonNegative(value.inputTokens, 'inputTokens', { integer: true });
  finiteNonNegative(value.outputTokens, 'outputTokens', { integer: true });
  finiteNonNegative(value.costUsd, 'costUsd', { nullable: true });
  finiteNonNegative(value.latencyMs, 'latencyMs', { nullable: true });
}

function validateResultCase(value) {
  exactKeys(value, ['caseId', 'output', 'measurements', 'review'], 'result case');
  validateCaseId(value.caseId, 'result case caseId');
  plainObject(value.output, 'result case output');
  scalarMeasurements(value.measurements, 'result case measurements');
  validateReview(value.review);
}

export function validateResultBundle(value) {
  exactKeys(value, ['schemaVersion', 'corpusId', 'runId', 'candidate', 'measurements', 'cases'], 'result bundle');
  if (value.schemaVersion !== EVAL_RESULT_SCHEMA) throw new TypeError('result bundle schemaVersion is unsupported');
  nonEmptyString(value.corpusId, 'corpusId');
  nonEmptyString(value.runId, 'runId');
  validateCandidate(value.candidate);
  validateMeasurements(value.measurements);
  if (!Array.isArray(value.cases) || value.cases.length === 0) {
    throw new TypeError('result bundle cases must be a non-empty array');
  }
  const seen = new Set();
  for (const item of value.cases) {
    validateResultCase(item);
    if (seen.has(item.caseId)) throw new TypeError(`duplicate result caseId: ${item.caseId}`);
    seen.add(item.caseId);
  }
  return deepFreeze(structuredClone(value));
}
