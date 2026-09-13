import { roundScore } from '../canonical.js';

export const KQL_SCORER_VERSION = '1.0.0';

const NO_REVIEW = Object.freeze({ required: false, fields: Object.freeze([]) });

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function finish({ score, hardFail, violations, passed, total }) {
  return Object.freeze({
    score: roundScore(score),
    hardFail,
    violations: Object.freeze([...new Set(violations)].sort()),
    metrics: Object.freeze({ passedChecks: passed, totalChecks: total }),
    humanReview: NO_REVIEW,
    scorerVersion: KQL_SCORER_VERSION,
  });
}

export function scoreKqlCase(evalCase, output) {
  const expected = evalCase?.expected;
  if (!expected || !Array.isArray(expected.requiredTables) || !Array.isArray(expected.forbiddenTokens)
      || !Array.isArray(expected.requiredRegexes) || !Array.isArray(expected.forbiddenRegexes)
      || !Array.isArray(expected.requiredHeaderKeys) || !output || typeof output.query !== 'string'
      || !output.headers || typeof output.headers !== 'object' || Array.isArray(output.headers)) {
    return finish({ score: 0, hardFail: true, violations: ['KQL_MALFORMED_OUTPUT'], passed: 0, total: 0 });
  }

  const query = output.query;
  const lower = query.toLowerCase();
  const violations = [];
  let total = 0;
  let passed = 0;
  let hardFail = false;

  for (const table of expected.requiredTables) {
    total += 1;
    const present = new RegExp(`\\b${escapeRegex(table)}\\b`, 'i').test(query);
    if (present) passed += 1;
    else violations.push(`KQL_MISSING_REQUIRED_TABLE:${table}`);
  }

  for (const token of expected.forbiddenTokens) {
    total += 1;
    if (lower.includes(String(token).toLowerCase())) {
      violations.push(`KQL_FORBIDDEN_TOKEN:${String(token).toLowerCase()}`);
      hardFail = true;
    } else passed += 1;
  }

  for (const pattern of expected.requiredRegexes) {
    total += 1;
    if (new RegExp(pattern, 'i').test(query)) passed += 1;
    else violations.push(`KQL_MISSING_REQUIRED_PATTERN:${pattern}`);
  }

  for (const pattern of expected.forbiddenRegexes) {
    total += 1;
    if (new RegExp(pattern, 'i').test(query)) {
      violations.push(`KQL_FORBIDDEN_PATTERN:${pattern}`);
      hardFail = true;
    } else passed += 1;
  }

  for (const header of expected.requiredHeaderKeys) {
    total += 1;
    const value = output.headers[header];
    if (typeof value === 'string' && value.trim() !== '') passed += 1;
    else violations.push(`KQL_MISSING_HEADER:${header}`);
  }

  return finish({
    score: total === 0 ? 1 : passed / total,
    hardFail,
    violations,
    passed,
    total,
  });
}
