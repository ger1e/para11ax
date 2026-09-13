import { roundScore } from '../canonical.js';
import { routeModelTask } from '../../core/model-routing.js';

export const ROUTING_SCORER_VERSION = '1.0.0';

const NO_REVIEW = Object.freeze({ required: false, fields: Object.freeze([]) });
const FIELDS = Object.freeze([
  'tier',
  'reasoningEffort',
  'specialistHint',
  'requireIndependentReview',
  'requireDifferentFamilyReviewer',
  'contextPolicy',
]);

function malformed() {
  return Object.freeze({
    score: 0,
    hardFail: true,
    violations: Object.freeze(['ROUTING_MALFORMED_OUTPUT']),
    metrics: Object.freeze({ matchedFields: 0, totalFields: FIELDS.length }),
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
  for (const field of FIELDS) {
    if (!Object.hasOwn(evalCase.expected, field) || !Object.is(evalCase.expected[field], normative[field])) {
      throw new TypeError(`routing corpus expected policy drift at ${field}`);
    }
  }

  const violations = [];
  let matchedFields = 0;
  for (const field of FIELDS) {
    if (Object.hasOwn(output, field) && Object.is(output[field], normative[field])) matchedFields += 1;
    else violations.push(`ROUTING_POLICY_MISMATCH:${field}`);
  }

  return Object.freeze({
    score: roundScore(matchedFields / FIELDS.length),
    hardFail: violations.length > 0,
    violations: Object.freeze(violations.sort()),
    metrics: Object.freeze({ matchedFields, totalFields: FIELDS.length }),
    humanReview: NO_REVIEW,
    scorerVersion: ROUTING_SCORER_VERSION,
  });
}
