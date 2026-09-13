import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createAgentState,
  createHandoffEnvelope,
  detectAgentDrift,
  importAgentState,
  reduceAgentState,
} from '../src/core/agent-state.js';

const NOW = '2026-09-13T12:00:00.000Z';
const LATER = '2026-09-13T12:05:00.000Z';
const fixed = { now: () => NOW, uuid: () => 'agent-001' };

test('creates a frozen canonical task state with an invariant checkpoint', () => {
  const state = createAgentState({
    objective: 'Harden PARA11AX orchestration without adding nondeterministic model calls to the core.',
    constraints: ['Preserve provenance', 'Fail closed on drift'],
    taskClass: 'coding',
    risk: 'high',
    ...fixed,
  });

  assert.equal(state.schemaVersion, 'para11ax-agent-state-v1.0');
  assert.equal(state.revision, 0);
  assert.equal(state.epoch, 0);
  assert.equal(state.checkpoint.revision, 0);
  assert.match(state.checkpoint.invariantHash, /^[a-f0-9]{64}$/);
  assert.equal(Object.isFrozen(state), true);
  assert.equal(Object.isFrozen(state.constraints), true);
  assert.equal(importAgentState(state).id, 'agent-001');
});

test('reducer persists decisions, artifact references, next actions, and explicit handoffs', () => {
  let sequence = 0;
  const deps = { now: () => LATER, uuid: () => `id-${++sequence}` };
  let state = createAgentState({ objective: 'Ship drift controls', constraints: ['No hidden state'], ...fixed });
  const original = state;

  state = reduceAgentState(state, { type: 'DECISION_ADD', text: 'Use immutable canonical state instead of recursive summaries.' }, deps);
  state = reduceAgentState(state, { type: 'ARTIFACT_ADD', value: { kind: 'commit', ref: 'sha:abc', summary: 'State contract tests' } }, deps);
  state = reduceAgentState(state, { type: 'NEXT_ACTIONS_SET', values: ['Implement context budget', 'Run CI'] }, deps);
  state = reduceAgentState(state, { type: 'HANDOFF', to: 'reviewer', reason: 'Independent verification' }, deps);

  assert.equal(original.revision, 0);
  assert.equal(state.revision, 4);
  assert.deepEqual(state.decisions, ['Use immutable canonical state instead of recursive summaries.']);
  assert.equal(state.artifacts[0].ref, 'sha:abc');
  assert.deepEqual(state.nextActions, ['Implement context budget', 'Run CI']);
  assert.equal(state.handoffs.length, 1);
  assert.equal(state.handoffs[0].to, 'reviewer');
  assert.equal(state.handoffs[0].invariantHash, state.checkpoint.invariantHash);
});

test('objective and constraint changes require explicit reducer actions and advance the epoch', () => {
  let state = createAgentState({ objective: 'Old objective', constraints: ['A'], ...fixed });
  state = reduceAgentState(state, { type: 'OBJECTIVE_REVISE', objective: 'New objective', reason: 'User changed scope' }, { now: () => LATER, uuid: () => 'evt-1' });
  state = reduceAgentState(state, { type: 'CONSTRAINTS_SET', values: ['A', 'B'], reason: 'New safety boundary' }, { now: () => LATER, uuid: () => 'evt-2' });

  assert.equal(state.epoch, 2);
  assert.equal(state.objective, 'New objective');
  assert.deepEqual(state.constraints, ['A', 'B']);
  assert.equal(state.timeline.filter(item => item.type === 'SCOPE_CHANGE').length, 2);
});

test('detects invariant drift and distinguishes loss of accepted decisions', () => {
  let baseline = createAgentState({ objective: 'Keep objective stable', constraints: ['C1'], ...fixed });
  baseline = reduceAgentState(baseline, { type: 'DECISION_ADD', text: 'D1' }, { now: () => LATER, uuid: () => 'evt-1' });

  const objectiveDrift = structuredClone(baseline);
  objectiveDrift.objective = 'Quietly changed objective';
  const critical = detectAgentDrift(baseline, objectiveDrift);
  assert.equal(critical.drifted, true);
  assert.equal(critical.severity, 'critical');
  assert.ok(critical.fields.includes('objective'));

  const decisionLoss = structuredClone(baseline);
  decisionLoss.decisions = [];
  const high = detectAgentDrift(baseline, decisionLoss);
  assert.equal(high.drifted, true);
  assert.equal(high.severity, 'high');
  assert.ok(high.fields.includes('decisions'));
});

test('handoff envelope preserves only durable state and rejects forged checkpoints on import', () => {
  let state = createAgentState({ objective: 'Continue safely', constraints: ['Exact refs'], ...fixed });
  state = reduceAgentState(state, { type: 'DECISION_ADD', text: 'Keep raw tool output out of handoff state.' }, { now: () => LATER, uuid: () => 'evt-1' });
  state = reduceAgentState(state, { type: 'ARTIFACT_ADD', value: { kind: 'url', ref: 'https://example.test/evidence', summary: 'Retrievable evidence' } }, { now: () => LATER, uuid: () => 'evt-2' });

  const handoff = createHandoffEnvelope(state, { to: 'reviewer', reason: 'Verify', contextRefs: ['repo:ger1e/para11ax'] });
  assert.equal(handoff.invariantHash, state.checkpoint.invariantHash);
  assert.deepEqual(handoff.decisions, state.decisions);
  assert.deepEqual(handoff.artifacts, state.artifacts);
  assert.equal(Object.hasOwn(handoff, 'timeline'), false);

  const forged = structuredClone(state);
  forged.checkpoint.invariantHash = '0'.repeat(64);
  assert.throws(() => importAgentState(forged), /checkpoint mismatch/i);
});
