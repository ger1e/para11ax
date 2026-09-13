import { roundScore } from '../canonical.js';

export const CTI_SCORER_VERSION = '1.0.0';

const NO_REVIEW = Object.freeze({ required: false, fields: Object.freeze([]) });

function strings(value) {
  return Array.isArray(value) && value.every(item => typeof item === 'string');
}

function unique(value) {
  return [...new Set(value)];
}

function ratio(numerator, denominator) {
  return denominator === 0 ? 1 : numerator / denominator;
}

function f1(expected, actual) {
  const expectedSet = new Set(expected);
  const actualSet = new Set(actual);
  const correct = [...actualSet].filter(item => expectedSet.has(item)).length;
  const precision = ratio(correct, actualSet.size);
  const recall = ratio(correct, expectedSet.size);
  const score = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  return { correct, precision: roundScore(precision), recall: roundScore(recall), score: roundScore(score) };
}

function malformed() {
  return Object.freeze({
    score: 0,
    hardFail: true,
    violations: Object.freeze(['CTI_MALFORMED_OUTPUT']),
    metrics: Object.freeze({ entityPrecision: 0, entityRecall: 0, relationshipPrecision: 0, relationshipRecall: 0 }),
    humanReview: NO_REVIEW,
    scorerVersion: CTI_SCORER_VERSION,
  });
}

export function scoreCtiCase(evalCase, output) {
  const expected = evalCase?.expected;
  if (!expected || !strings(expected.entities) || !strings(expected.relationships)
      || !output || !strings(output.entities) || !strings(output.relationships)) {
    return malformed();
  }

  const expectedEntities = unique(expected.entities);
  const expectedRelationships = unique(expected.relationships);
  const actualEntities = unique(output.entities);
  const actualRelationships = unique(output.relationships);
  const entity = f1(expectedEntities, actualEntities);
  const relationship = f1(expectedRelationships, actualRelationships);
  const violations = [];

  if (expectedEntities.some(item => !actualEntities.includes(item))) violations.push('CTI_MISSING_ENTITY');
  if (actualEntities.some(item => !expectedEntities.includes(item))) violations.push('CTI_UNEXPECTED_ENTITY');
  if (expectedRelationships.some(item => !actualRelationships.includes(item))) violations.push('CTI_MISSING_RELATIONSHIP');
  if (actualRelationships.some(item => !expectedRelationships.includes(item))) violations.push('CTI_UNEXPECTED_RELATIONSHIP');

  return Object.freeze({
    score: roundScore((entity.score + relationship.score) / 2),
    hardFail: false,
    violations: Object.freeze(violations.sort()),
    metrics: Object.freeze({
      entityPrecision: entity.precision,
      entityRecall: entity.recall,
      relationshipPrecision: relationship.precision,
      relationshipRecall: relationship.recall,
    }),
    humanReview: NO_REVIEW,
    scorerVersion: CTI_SCORER_VERSION,
  });
}
