import { roundScore } from '../canonical.js';

export const CODING_SCORER_VERSION = '1.0.0';

const NO_REVIEW = Object.freeze({ required: false, fields: Object.freeze([]) });

function ratio(numerator, denominator) {
  return denominator === 0 ? 1 : numerator / denominator;
}

export function scoreCodingCase(evalCase, output) {
  const expectedDefects = evalCase?.expected?.defects;
  const forbidden = evalCase?.expected?.forbiddenFalsePositives;
  if (!Array.isArray(expectedDefects) || !expectedDefects.every(item => typeof item === 'string')
      || !Array.isArray(forbidden) || !forbidden.every(item => typeof item === 'string')
      || !output || !Array.isArray(output.defects) || !output.defects.every(item => typeof item === 'string')) {
    return Object.freeze({
      score: 0,
      hardFail: true,
      violations: Object.freeze(['CODING_MALFORMED_OUTPUT']),
      metrics: Object.freeze({ correct: 0, expected: 0, candidate: 0, precision: 0, recall: 0 }),
      humanReview: NO_REVIEW,
      scorerVersion: CODING_SCORER_VERSION,
    });
  }

  const expected = new Set(expectedDefects);
  const forbiddenSet = new Set(forbidden);
  const actual = new Set(output.defects);
  const correct = [...actual].filter(item => expected.has(item)).length;
  const precision = ratio(correct, actual.size);
  const recall = ratio(correct, expected.size);
  const score = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  const violations = [];

  if ([...expected].some(item => !actual.has(item))) violations.push('CODING_MISSING_DEFECT');
  if ([...actual].some(item => !expected.has(item))) violations.push('CODING_UNEXPECTED_DEFECT');
  if ([...actual].some(item => forbiddenSet.has(item))) violations.push('CODING_FORBIDDEN_FALSE_POSITIVE');

  return Object.freeze({
    score: roundScore(score),
    hardFail: false,
    violations: Object.freeze([...new Set(violations)].sort()),
    metrics: Object.freeze({
      correct,
      expected: expected.size,
      candidate: actual.size,
      precision: roundScore(precision),
      recall: roundScore(recall),
    }),
    humanReview: NO_REVIEW,
    scorerVersion: CODING_SCORER_VERSION,
  });
}
