import { roundScore } from '../canonical.js';

export const CLASSIFICATION_SCORER_VERSION = '1.0.0';

const NO_REVIEW = Object.freeze({ required: false, fields: Object.freeze([]) });
const LABELS = new Set(['ioc', 'ioa', 'ttp']);

function ratio(numerator, denominator) {
  return denominator === 0 ? 1 : numerator / denominator;
}

function finish(score, hardFail, violations, metrics) {
  return Object.freeze({
    score: roundScore(score),
    hardFail,
    violations: Object.freeze([...new Set(violations)].sort()),
    metrics: Object.freeze(metrics),
    humanReview: NO_REVIEW,
    scorerVersion: CLASSIFICATION_SCORER_VERSION,
  });
}

export function scoreClassificationCase(evalCase, output) {
  const expectedItems = evalCase?.expected?.items;
  if (!Array.isArray(expectedItems) || !output || !Array.isArray(output.items)) {
    return finish(0, true, ['CLASSIFICATION_MALFORMED_OUTPUT'], { correct: 0, expected: 0, candidate: 0, precision: 0, recall: 0 });
  }

  const expected = new Map(expectedItems.map(item => [item.id, item.label]));
  const seen = new Set();
  const violations = [];
  let correct = 0;
  let validCandidate = 0;

  for (const item of output.items) {
    if (!item || typeof item.id !== 'string' || typeof item.label !== 'string' || !LABELS.has(item.label)) {
      violations.push('CLASSIFICATION_MALFORMED_ITEM');
      continue;
    }
    if (seen.has(item.id)) {
      violations.push(`CLASSIFICATION_DUPLICATE_ITEM:${item.id}`);
      continue;
    }
    seen.add(item.id);
    validCandidate += 1;
    if (!expected.has(item.id)) {
      violations.push(`CLASSIFICATION_UNEXPECTED_ITEM:${item.id}`);
      continue;
    }
    if (expected.get(item.id) !== item.label) {
      violations.push(`CLASSIFICATION_WRONG_LABEL:${item.id}`);
      continue;
    }
    correct += 1;
  }

  for (const id of expected.keys()) {
    if (!seen.has(id)) violations.push(`CLASSIFICATION_MISSING_ITEM:${id}`);
  }

  const precision = ratio(correct, validCandidate);
  const recall = ratio(correct, expected.size);
  const score = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  return finish(score, false, violations, {
    correct,
    expected: expected.size,
    candidate: validCandidate,
    precision: roundScore(precision),
    recall: roundScore(recall),
  });
}
