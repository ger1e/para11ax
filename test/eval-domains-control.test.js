import test from 'node:test';
import assert from 'node:assert/strict';

import { scoreHandoffCase } from '../src/eval/domains/handoff.js';
import { scoreContextCase } from '../src/eval/domains/context.js';
import { scoreRoutingCase } from '../src/eval/domains/routing.js';
import { scoreCodingCase } from '../src/eval/domains/coding.js';
import { routeModelTask } from '../src/core/model-routing.js';

function normalized(result) {
  assert.equal(typeof result.score, 'number');
  assert.ok(result.score >= 0 && result.score <= 1);
  assert.equal(typeof result.hardFail, 'boolean');
  assert.ok(Array.isArray(result.violations));
  assert.deepEqual(result.violations, [...result.violations].sort());
  assert.equal(typeof result.metrics, 'object');
  assert.deepEqual(result.humanReview, { required: false, fields: [] });
  assert.equal(result.scorerVersion, '1.0.0');
  return result;
}

const handoffCase = {
  expected: {
    objective: 'Complete the synthetic investigation without changing accepted scope.',
    constraints: ['Preserve provenance.', 'Do not treat missing evidence as benign.'],
    decisions: ['Use DeviceProcessEvents as the primary synthetic telemetry source.'],
    nextActions: ['validate-kql', 'analyze-results'],
    allowCompleted: false,
  },
};

function validHandoff() {
  return {
    objective: handoffCase.expected.objective,
    constraints: [...handoffCase.expected.constraints],
    decisions: [...handoffCase.expected.decisions],
    nextActions: [...handoffCase.expected.nextActions],
    completed: false,
  };
}

test('handoff scorer rewards exact durable-state retention', () => {
  const result = normalized(scoreHandoffCase(handoffCase, validHandoff()));
  assert.equal(result.score, 1);
  assert.equal(result.hardFail, false);
});

test('handoff constraint or accepted-decision loss is a hard failure', () => {
  const missingConstraint = validHandoff();
  missingConstraint.constraints = [handoffCase.expected.constraints[0]];
  const constraint = normalized(scoreHandoffCase(handoffCase, missingConstraint));
  assert.equal(constraint.hardFail, true);
  assert.ok(constraint.violations.includes('HANDOFF_CONSTRAINT_LOST'));

  const missingDecision = validHandoff();
  missingDecision.decisions = [];
  const decision = normalized(scoreHandoffCase(handoffCase, missingDecision));
  assert.equal(decision.hardFail, true);
  assert.ok(decision.violations.includes('HANDOFF_DECISION_LOST'));
});

test('handoff objective drift and premature completion fail closed', () => {
  const drifted = validHandoff();
  drifted.objective = 'Different objective';
  const drift = normalized(scoreHandoffCase(handoffCase, drifted));
  assert.equal(drift.hardFail, true);
  assert.ok(drift.violations.includes('HANDOFF_OBJECTIVE_CHANGED'));

  const completed = validHandoff();
  completed.completed = true;
  completed.nextActions = [];
  const premature = normalized(scoreHandoffCase(handoffCase, completed));
  assert.equal(premature.hardFail, true);
  assert.ok(premature.violations.includes('HANDOFF_PREMATURE_COMPLETION'));
  assert.ok(premature.violations.includes('HANDOFF_NEXT_ACTION_LOST'));
});

const contextCase = {
  input: {
    items: [
      { id: 'objective', tokens: 4, durable: true, priority: 100 },
      { id: 'constraints', tokens: 5, durable: true, priority: 100 },
      { id: 'decision-1', tokens: 4, durable: true, priority: 90 },
      { id: 'tool-noise', tokens: 9, durable: false, priority: 10 },
    ],
    maxTokens: 15,
  },
  expected: { requiredIds: ['objective', 'constraints', 'decision-1'] },
};

test('context scorer preserves required durable items inside budget', () => {
  const result = normalized(scoreContextCase(contextCase, {
    selectedIds: ['constraints', 'decision-1', 'objective'],
  }));
  assert.equal(result.score, 1);
  assert.equal(result.hardFail, false);
  assert.equal(result.metrics.usedTokens, 13);
});

test('context scorer hard-fails durable loss, budget overflow and unknown IDs', () => {
  const lost = normalized(scoreContextCase(contextCase, {
    selectedIds: ['objective', 'constraints'],
  }));
  assert.equal(lost.hardFail, true);
  assert.ok(lost.violations.includes('CONTEXT_DURABLE_ITEM_LOST'));

  const overflow = normalized(scoreContextCase(contextCase, {
    selectedIds: ['objective', 'constraints', 'decision-1', 'tool-noise'],
  }));
  assert.equal(overflow.hardFail, true);
  assert.ok(overflow.violations.includes('CONTEXT_BUDGET_EXCEEDED'));

  const unknown = normalized(scoreContextCase(contextCase, {
    selectedIds: ['objective', 'constraints', 'decision-1', 'secret-payload-id'],
  }));
  assert.equal(unknown.hardFail, true);
  assert.ok(unknown.violations.includes('CONTEXT_UNKNOWN_ID'));
  assert.equal(JSON.stringify(unknown).includes('secret-payload-id'), false);
});

const routingCase = {
  input: {
    taskClass: 'security_analysis',
    risk: 'high',
    complexity: 'high',
    contextTokens: 300000,
    latencySensitive: false,
    costSensitive: false,
    failures: 0,
  },
  expected: {
    tier: 'frontier',
    reasoningEffort: 'high',
    specialistHint: null,
    requireIndependentReview: true,
    requireDifferentFamilyReviewer: true,
    contextPolicy: 'durable-state-plus-jit-retrieval',
  },
};

test('routing scorer accepts candidate that matches normative production routing policy', () => {
  const normative = routeModelTask(routingCase.input);
  const candidate = Object.fromEntries(Object.keys(routingCase.expected).map(key => [key, normative[key]]));
  const result = normalized(scoreRoutingCase(routingCase, candidate));
  assert.equal(result.score, 1);
  assert.equal(result.hardFail, false);
});

test('routing scorer rejects stale corpus expectation and policy-divergent candidate', () => {
  assert.throws(
    () => scoreRoutingCase({
      ...routingCase,
      expected: { ...routingCase.expected, tier: 'economy' },
    }, routingCase.expected),
    /corpus expected|policy drift/i,
  );

  const result = normalized(scoreRoutingCase(routingCase, {
    ...routingCase.expected,
    tier: 'economy',
    requireIndependentReview: false,
  }));
  assert.equal(result.hardFail, true);
  assert.ok(result.score < 1);
  assert.ok(result.violations.includes('ROUTING_POLICY_MISMATCH:tier'));
  assert.ok(result.violations.includes('ROUTING_POLICY_MISMATCH:requireIndependentReview'));
});

const codingCase = {
  expected: {
    defects: ['missing-input-validation', 'nondeterministic-wall-clock'],
    forbiddenFalsePositives: ['sql-injection'],
  },
};

test('coding scorer rewards exact defect identification', () => {
  const result = normalized(scoreCodingCase(codingCase, {
    defects: [...codingCase.expected.defects],
  }));
  assert.equal(result.score, 1);
  assert.equal(result.hardFail, false);
});

test('coding scorer penalizes misses and forbidden false positives without leaking raw IDs', () => {
  const result = normalized(scoreCodingCase(codingCase, {
    defects: ['missing-input-validation', 'sql-injection'],
  }));
  assert.ok(result.score < 1);
  assert.equal(result.hardFail, false);
  assert.ok(result.violations.includes('CODING_MISSING_DEFECT'));
  assert.ok(result.violations.includes('CODING_FORBIDDEN_FALSE_POSITIVE'));
});
