import { roundScore } from '../canonical.js';
import { routeModelTask } from '../../core/model-routing.js';

export const ROUTING_SCORER_VERSION = '1.0.0';

const NO_REVIEW = Object.freeze({ required: false, fields: Object.freeze([]) });
const EXPECTED_FIELDS = Object.freeze([
  'tier',
  'reasoningEffort',
  'specialistHint',
  'requireIndependentReview',
  'requireDifferentFamilyReviewer',
  'contextPolicy',
]);
const SCORED_FIELDS = Object.freeze([
  'tier',
  'reasoningEffort',
  'contextPolicy',
  'requireIndependentReview',
  'requireDifferentFamilyReviewer',
]);

function malformed() {
  return Object.freeze({
    score: 0,
    hardFail: true,
    violations: Object.freeze(['ROUTING_MALFORMED_OUTPUT']),
    metrics: Object.freeze({ matchedFields: 0, totalFields: SCORED_FIELDS.length }),
    humanReview: NO_REVIEW,
    scorerVersion: ROUTING_SCORER_VERSION,
  });
}

export function scoreRoutingCase(evalCase, output) {
  if (!evalCase?.input || typeof evalCase.input !== 'object'
      || !evalCase?.expected || typeof evalCase.expected !== 'object'
      || !output || typeof output !== 'object' || Array.isArray(output)) {
    return malformed();
  }

  const normative = routeModelTask(evalCase.input);
  for (const field of EXPECTED_FIELDS) {
    if (!Object.hasOwn(evalCase.expected, field) || !Object.is(evalCase.expected[field], normative[field])) {
      throw new TypeError(`routing corpus expected policy drift at ${field}`);
    }
  }

  const violations = [];
  let matchedFields = 0;
  for (const field of SCORED_FIELDS) {
    if (Object.hasOwn(output, field) && Object.is(output[field], normative[field])) matchedFields += 1;
    else violations.push(`ROUTING_POLICY_MISMATCH:${field}`);
  }

  const hardFail = normative.requireIndependentReview === true
    && output.requireIndependentReview !== true;

  return Object.freeze({
    score: roundScore(matchedFields / SCORED_FIELDS.length),
    hardFail,
    violations: Object.freeze(violations.sort()),
    metrics: Object.freeze({ matchedFields, totalFields: SCORED_FIELDS.length }),
    humanReview: NO_REVIEW,
    scorerVersion: ROUTING_SCORER_VERSION,
  });
}
