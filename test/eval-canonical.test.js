import test from 'node:test';
import assert from 'node:assert/strict';

import {
  canonicalJson,
  roundScore,
  sha256Canonical,
} from '../src/eval/canonical.js';
import {
  EVAL_CASE_SCHEMA,
  EVAL_DOMAINS,
  EVAL_RESULT_SCHEMA,
  validateEvalCase,
  validateResultBundle,
} from '../src/eval/schemas.js';

function validResult(overrides = {}) {
  return {
    schemaVersion: EVAL_RESULT_SCHEMA,
    corpusId: 'para11ax-internal-v1',
    runId: 'run-001',
    candidate: {
      provider: 'openai',
      model: 'example',
      family: 'example',
      effort: 'high',
      harness: 'manual',
      harnessVersion: '1.0.0',
    },
    measurements: {
      inputTokens: 10,
      outputTokens: 5,
      costUsd: null,
      latencyMs: null,
    },
    cases: [{
      caseId: 'cti-001',
      output: {},
      measurements: {},
      review: null,
    }],
    ...overrides,
  };
}

test('canonical JSON sorts object keys recursively and preserves supplied array order', () => {
  const value = { z: 1, a: { y: 2, b: 3 }, list: [{ q: 2, a: 1 }] };
  assert.equal(
    canonicalJson(value),
    '{"a":{"b":3,"y":2},"list":[{"a":1,"q":2}],"z":1}',
  );
});

test('score rounding is stable to six decimals', () => {
  assert.equal(roundScore(0.123456789), 0.123457);
  assert.equal(roundScore(1), 1);
  assert.throws(() => roundScore(Infinity), /finite/);
});

test('canonical hashes ignore object insertion order', () => {
  assert.equal(
    sha256Canonical({ a: 1, b: 2 }),
    sha256Canonical({ b: 2, a: 1 }),
  );
});

test('result validation preserves null measurements and review state', () => {
  const result = validateResultBundle(validResult());
  assert.equal(result.measurements.costUsd, null);
  assert.equal(result.measurements.latencyMs, null);
  assert.equal(result.cases[0].review, null);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.cases), true);
});

test('completed human review requires an explicit pass/fail decision', () => {
  const make = review => validResult({
    cases: [{ caseId: 'cti-001', output: {}, measurements: {}, review }],
  });

  assert.throws(
    () => validateResultBundle(make({ status: 'completed' })),
    /decision/,
  );
  assert.doesNotThrow(
    () => validateResultBundle(make({ status: 'completed', decision: 'pass' })),
  );
  assert.doesNotThrow(
    () => validateResultBundle(make({ status: 'completed', decision: 'fail' })),
  );
});

test('pending review has no decision and closed schemas reject extra fields', () => {
  const pending = validResult({
    cases: [{
      caseId: 'cti-001',
      output: {},
      measurements: {},
      review: { status: 'pending' },
    }],
  });
  assert.doesNotThrow(() => validateResultBundle(pending));
  assert.throws(
    () => validateResultBundle({ ...pending, surprise: true }),
    /unexpected|unknown|keys/i,
  );
});

test('result validation rejects non-finite, negative and malformed measurements', () => {
  assert.throws(
    () => validateResultBundle(validResult({
      measurements: { inputTokens: 10, outputTokens: 5, costUsd: null, latencyMs: Infinity },
    })),
    /latencyMs/,
  );
  assert.throws(
    () => validateResultBundle(validResult({
      measurements: { inputTokens: -1, outputTokens: 5, costUsd: null, latencyMs: null },
    })),
    /inputTokens/,
  );
  assert.throws(
    () => validateResultBundle(validResult({
      measurements: { inputTokens: 1.5, outputTokens: 5, costUsd: null, latencyMs: null },
    })),
    /inputTokens/,
  );
});

test('duplicate result case IDs fail closed', () => {
  const duplicate = validResult({
    cases: [
      { caseId: 'cti-001', output: {}, measurements: {}, review: null },
      { caseId: 'cti-001', output: {}, measurements: {}, review: null },
    ],
  });
  assert.throws(() => validateResultBundle(duplicate), /duplicate/i);
});

test('eval case validation enforces schema, domain and identifier contract', () => {
  const value = validateEvalCase({
    schemaVersion: EVAL_CASE_SCHEMA,
    caseId: 'cti-001',
    domain: 'cti',
    weight: 1,
    input: {},
    expected: {},
  });
  assert.equal(value.domain, 'cti');
  assert.ok(EVAL_DOMAINS.includes(value.domain));
  assert.equal(Object.isFrozen(value), true);

  assert.throws(() => validateEvalCase({
    ...value,
    caseId: '../cti-001',
  }), /caseId/);
  assert.throws(() => validateEvalCase({
    ...value,
    domain: 'unknown',
  }), /domain/);
  assert.throws(() => validateEvalCase({
    ...value,
    weight: 0,
  }), /weight/);
});
