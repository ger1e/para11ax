import { roundScore } from '../canonical.js';

export const ATTACK_SCORER_VERSION = '1.0.0';

const NO_REVIEW = Object.freeze({ required: false, fields: Object.freeze([]) });

function ratio(numerator, denominator) {
  return denominator === 0 ? 1 : numerator / denominator;
}

export function scoreAttackCase(evalCase, output) {
  const expectedTechniques = evalCase?.expected?.techniques;
  if (!Array.isArray(expectedTechniques) || !expectedTechniques.every(item => typeof item === 'string')
      || !output || !Array.isArray(output.techniques) || !output.techniques.every(item => typeof item === 'string')) {
    return Object.freeze({
      score: 0,
      hardFail: true,
      violations: Object.freeze(['ATTACK_MALFORMED_OUTPUT']),
      metrics: Object.freeze({ correct: 0, expected: 0, candidate: 0, precision: 0, recall: 0 }),
      humanReview: NO_REVIEW,
      scorerVersion: ATTACK_SCORER_VERSION,
    });
  }

  const expected = new Set(expectedTechniques);
  const actual = new Set(output.techniques);
  const correct = [...actual].filter(item => expected.has(item)).length;
  const precision = ratio(correct, actual.size);
  const recall = ratio(correct, expected.size);
  const score = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  const violations = [];
  for (const item of expected) if (!actual.has(item)) violations.push(`ATTACK_MISSING_TECHNIQUE:${item}`);
  for (const item of actual) if (!expected.has(item)) violations.push(`ATTACK_UNEXPECTED_TECHNIQUE:${item}`);

  return Object.freeze({
    score: roundScore(score),
    hardFail: false,
    violations: Object.freeze(violations.sort()),
    metrics: Object.freeze({
      correct,
      expected: expected.size,
      candidate: actual.size,
      precision: roundScore(precision),
      recall: roundScore(recall),
    }),
    humanReview: NO_REVIEW,
    scorerVersion: ATTACK_SCORER_VERSION,
  });
}
