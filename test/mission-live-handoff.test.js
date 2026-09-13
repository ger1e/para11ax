import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createMissionWorkspace,
  exportMissionWorkspace,
  importMissionWorkspace,
  reduceMissionWorkspace,
} from '../src/core/mission/workspace.js';

const LEGACY_EMPTY = Object.freeze({
  schemaVersion: 'mission-workspace-v1.0',
  revision: 0,
  profile: null,
  context: null,
  relevance: null,
  hunt: null,
  kqlValidations: [],
  result: null,
  serviceNow: null,
});

test('new mission persists canonical agent state and a resumable handoff', () => {
  const workspace = createMissionWorkspace();

  assert.equal(workspace.schemaVersion, 'mission-workspace-v1.1');
  assert.equal(workspace.agentState.taskClass, 'security_analysis');
  assert.equal(workspace.agentState.risk, 'medium');
  assert.deepEqual(workspace.agentState.nextActions, ['mission-profile-set']);
  assert.equal(workspace.handoff.stateId, workspace.agentState.id);
  assert.equal(workspace.handoff.revision, workspace.agentState.revision);
  assert.equal(workspace.handoff.invariantHash, workspace.agentState.checkpoint.invariantHash);
  assert.equal(workspace.handoff.sourceStateHash, workspace.agentState.checkpoint.stateHash);
  assert.ok(workspace.handoff.contextRefs.includes('mission:revision:0'));
  assert.ok(workspace.handoff.contextRefs.includes('mission:action:new'));
  assert.deepEqual(importMissionWorkspace(workspace), workspace);
});

test('every successful state transition refreshes handoff against the new mission revision', () => {
  const initial = createMissionWorkspace();
  const next = reduceMissionWorkspace(initial, { type: 'KQL_VALIDATE', value: 'DeviceProcessEvents | take 1' });

  assert.equal(next.revision, 1);
  assert.notEqual(next.handoff.handoffHash, initial.handoff.handoffHash);
  assert.equal(next.handoff.sourceStateHash, next.agentState.checkpoint.stateHash);
  assert.equal(next.handoff.revision, next.agentState.revision);
  assert.ok(next.handoff.contextRefs.includes('mission:revision:1'));
  assert.ok(next.handoff.contextRefs.includes('mission:action:kql-validate'));
  assert.deepEqual(next.agentState.nextActions, ['mission-profile-set']);
});

test('stale but otherwise valid handoff cannot be paired with a newer mission workspace', () => {
  const initial = createMissionWorkspace();
  const next = reduceMissionWorkspace(initial, { type: 'KQL_VALIDATE', value: 'DeviceProcessEvents | take 1' });
  const forged = structuredClone(next);
  forged.handoff = initial.handoff;

  assert.throws(() => importMissionWorkspace(forged), /handoff/i);
});

test('legacy v1.0 mission bundles deterministically upgrade to handoff-enabled v1.1', () => {
  const first = importMissionWorkspace(LEGACY_EMPTY);
  const second = importMissionWorkspace(JSON.stringify(LEGACY_EMPTY));

  assert.equal(first.schemaVersion, 'mission-workspace-v1.1');
  assert.deepEqual(first, second);
  assert.deepEqual(first.agentState.nextActions, ['mission-profile-set']);
  assert.ok(first.handoff.contextRefs.includes('mission:action:legacy-import'));
  assert.ok(first.handoff.contextRefs.includes('mission:revision:0'));
});

test('export and import preserve the exact validated continuation state', () => {
  const current = reduceMissionWorkspace(createMissionWorkspace(), { type: 'KQL_VALIDATE', value: 'DeviceProcessEvents | take 1' });
  const roundTrip = importMissionWorkspace(exportMissionWorkspace(current));
  assert.deepEqual(roundTrip, current);
});

test('clear resets mission progress and emits a fresh handoff for the next agent', () => {
  const current = reduceMissionWorkspace(createMissionWorkspace(), { type: 'KQL_VALIDATE', value: 'DeviceProcessEvents | take 1' });
  const cleared = reduceMissionWorkspace(current, { type: 'CLEAR' });

  assert.equal(cleared.revision, 2);
  assert.equal(cleared.profile, null);
  assert.deepEqual(cleared.kqlValidations, []);
  assert.deepEqual(cleared.agentState.nextActions, ['mission-profile-set']);
  assert.notEqual(cleared.agentState.id, current.agentState.id);
  assert.ok(cleared.handoff.contextRefs.includes('mission:revision:2'));
  assert.ok(cleared.handoff.contextRefs.includes('mission:action:clear'));
});
