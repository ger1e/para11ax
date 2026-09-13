import { roundScore } from '../canonical.js';

export const HANDOFF_SCORER_VERSION = '1.0.0';

const NO_REVIEW = Object.freeze({ required: false, fields: Object.freeze([]) });

function stringArray(value) {
  return Array.isArray(value) && value.every(item => typeof item === 'string');
}

function finish({ passed, total, hardFail, violations }) {
  return Object.freeze({
    score: roundScore(total === 0 ? 1 : passed / total),
    hardFail,
    violations: Object.freeze([...new Set(violations)].sort()),
    metrics: Object.freeze({ passedChecks: passed, totalChecks: total }),
    humanReview: NO_REVIEW,
    scorerVersion: HANDOFF_SCORER_VERSION,
  });
}

export function scoreHandoffCase(evalCase, output) {
  const expected = evalCase?.expected;
  if (!expected || typeof expected.objective !== 'string'
      || !stringArray(expected.constraints) || !stringArray(expected.decisions)
      || !stringArray(expected.nextActions) || typeof expected.allowCompleted !== 'boolean'
      || !output || typeof output.objective !== 'string'
      || !stringArray(output.constraints) || !stringArray(output.decisions)
      || !stringArray(output.nextActions) || typeof output.completed !== 'boolean') {
    return Object.freeze({
      score: 0,
      hardFail: true,
      violations: Object.freeze(['HANDOFF_MALFORMED_OUTPUT']),
      metrics: Object.freeze({ passedChecks: 0, totalChecks: 0 }),
      humanReview: NO_REVIEW,
      scorerVersion: HANDOFF_SCORER_VERSION,
    });
  }

  const violations = [];
  let passed = 0;
  let total = 1;
  let hardFail = false;

  if (output.objective === expected.objective) passed += 1;
  else {
    violations.push('HANDOFF_OBJECTIVE_CHANGED');
    hardFail = true;
  }

  const constraints = new Set(output.constraints);
  for (const required of expected.constraints) {
    total += 1;
    if (constraints.has(required)) passed += 1;
    else {
      violations.push('HANDOFF_CONSTRAINT_LOST');
      hardFail = true;
    }
  }

  const decisions = new Set(output.decisions);
  for (const required of expected.decisions) {
    total += 1;
    if (decisions.has(required)) passed += 1;
    else {
      violations.push('HANDOFF_DECISION_LOST');
      hardFail = true;
    }
  }

  const nextActions = new Set(output.nextActions);
  for (const required of expected.nextActions) {
    total += 1;
    if (nextActions.has(required)) passed += 1;
    else violations.push('HANDOFF_NEXT_ACTION_LOST');
  }

  total += 1;
  if (expected.allowCompleted || !output.completed) passed += 1;
  else {
    violations.push('HANDOFF_PREMATURE_COMPLETION');
    hardFail = true;
  }

  if (output.completed && expected.nextActions.some(action => !nextActions.has(action))) {
    hardFail = true;
  }

  return finish({ passed, total, hardFail, violations });
}
