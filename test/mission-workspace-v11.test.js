import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createMissionWorkspace,
  exportMissionWorkspace,
  importMissionWorkspace,
  reduceMissionWorkspace,
} from '../src/core/mission/workspace.js';
import { normalizeClientProfile } from '../src/core/mission/client-profile.js';
import { assessClientRelevance } from '../src/core/mission/relevance.js';
import { buildHuntPackage } from '../src/core/mission/hunt-package.js';
import { analyzeMissionResults } from '../src/core/mission/result-analysis.js';
import { buildServiceNowProjection } from '../src/report/render-servicenow.js';

const profileInput = {
  id: 'bor',
  name: 'Example Industrial',
  technologies: ['fortinet'],
  telemetry: ['DeviceNetworkEvents'],
};

const context = {
  technologies: ['fortinet'],
  observedExploitation: true,
  requiredTelemetry: ['devicenetworkevents'],
  evidenceConfidence: 0.8,
};

const huntInput = {
  subject: 'Remote-access credential abuse',
  hypothesis: 'Valid-account abuse may produce anomalous endpoint activity.',
  attackIds: ['T1078'],
  evidenceFingerprints: ['a'.repeat(64)],
  sourceReferences: ['https://example.org/research'],
  kqlCandidates: ['DeviceNetworkEvents | where Timestamp > ago(24h) | project Timestamp, DeviceName, RemoteIP'],
};

function completeWorkspace() {
  const profile = normalizeClientProfile(profileInput);
  const relevance = assessClientRelevance(profile, context);
  const hunt = buildHuntPackage({ ...huntInput, profile, context });
  const result = analyzeMissionResults('DeviceName,RemoteIP\nhost-1,203.0.113.10\n');
  return {
    schemaVersion: 'mission-workspace-v1.0',
    revision: 6,
    profile,
    context,
    relevance,
    hunt,
    kqlValidations: hunt.kqlCandidates,
    result,
    serviceNow: buildServiceNowProjection(hunt, result),
  };
}

function domainProjection(workspace) {
  return {
    revision: workspace.revision,
    profile: workspace.profile,
    context: workspace.context,
    relevance: workspace.relevance,
    hunt: workspace.hunt,
    kqlValidations: workspace.kqlValidations,
    result: workspace.result,
    serviceNow: workspace.serviceNow,
  };
}

test('empty mission workspace has the exact portable frozen contract', () => {
  const workspace = createMissionWorkspace();
  assert.deepEqual(domainProjection(workspace), {
    revision: 0,
    profile: null,
    context: null,
    relevance: null,
    hunt: null,
    kqlValidations: [],
    result: null,
    serviceNow: null,
  });
  assert.equal(workspace.schemaVersion, 'mission-workspace-v1.1');
  assert.equal(workspace.agentState.taskClass, 'security_analysis');
  assert.equal(workspace.handoff.stateId, workspace.agentState.id);
  assert.equal(Object.isFrozen(workspace), true);
  assert.equal(Object.isFrozen(workspace.kqlValidations), true);
  assert.equal(Object.isFrozen(workspace.agentState), true);
  assert.equal(Object.isFrozen(workspace.handoff), true);
});

test('mission bundle export and import are byte-stable', () => {
  const serialized = exportMissionWorkspace(createMissionWorkspace());
  assert.equal(serialized.endsWith('\n'), true);
  assert.equal(exportMissionWorkspace(importMissionWorkspace(serialized)), serialized);
});

test('mission import reconstructs and freezes every derived projection', () => {
  const legacy = completeWorkspace();
  const imported = importMissionWorkspace(legacy);
  const { schemaVersion: _legacyVersion, ...legacyDomain } = legacy;
  assert.equal(imported.schemaVersion, 'mission-workspace-v1.1');
  assert.deepEqual(domainProjection(imported), legacyDomain);
  assert.deepEqual(imported.agentState.nextActions, []);
  assert.equal(imported.handoff.sourceStateHash, imported.agentState.checkpoint.stateHash);
  assert.equal(Object.isFrozen(imported.profile.technologies), true);
  assert.equal(Object.isFrozen(imported.hunt.kqlCandidates[0].validation), true);
  assert.equal(Object.isFrozen(imported.serviceNow.provenance), true);
});

test('mission import rejects unknown keys versions prototypes and oversized input', () => {
  const empty = createMissionWorkspace();
  assert.throws(() => importMissionWorkspace({ ...empty, extra: true }), /mission workspace/i);
  assert.throws(() => importMissionWorkspace({ ...empty, schemaVersion: 'mission-workspace-v2.0' }), /version/i);
  assert.throws(() => importMissionWorkspace(Object.assign(Object.create({ inherited: true }), empty)), /plain object/i);
  assert.throws(() => importMissionWorkspace({ ...empty, revision: Number.MAX_SAFE_INTEGER + 1 }), /revision/i);
  assert.throws(() => importMissionWorkspace('x'.repeat((2 * 1024 * 1024) + 1)), /too large/i);
});

test('mission import rejects nested non-JSON structures before property access', () => {
  const nestedPrototype = { ...createMissionWorkspace(), context: Object.create({ technologies: [] }) };
  assert.throws(() => importMissionWorkspace(nestedPrototype), /plain object/i);

  let accessed = false;
  const accessor = { ...createMissionWorkspace() };
  Object.defineProperty(accessor, 'profile', { enumerable: true, get() { accessed = true; return null; } });
  assert.throws(() => importMissionWorkspace(accessor), /accessor/i);
  assert.equal(accessed, false);

  const sparse = { ...createMissionWorkspace(), kqlValidations: new Array(1) };
  assert.throws(() => importMissionWorkspace(sparse), /sparse/i);
});

test('mission import rejects tampered derived and result state', () => {
  const complete = completeWorkspace();
  assert.throws(() => importMissionWorkspace({
    ...complete,
    relevance: { ...complete.relevance, score: complete.relevance.score + 1 },
  }), /relevance/i);
  assert.throws(() => importMissionWorkspace({
    ...complete,
    result: { ...complete.result, state: 'NO_RESULTS' },
  }), /result/i);
  assert.throws(() => importMissionWorkspace({
    ...complete,
    result: { ...complete.result, formulaLikeCellCount: complete.result.rowCount * complete.result.columnCount + 1 },
  }), /result/i);
});

test('workspace reducer executes the complete mission lifecycle', () => {
  let state = createMissionWorkspace();
  state = reduceMissionWorkspace(state, { type: 'PROFILE_SET', value: profileInput });
  state = reduceMissionWorkspace(state, { type: 'CONTEXT_SET', value: context });
  state = reduceMissionWorkspace(state, { type: 'RELEVANCE_ASSESS' });
  state = reduceMissionWorkspace(state, { type: 'HUNT_BUILD', value: huntInput });
  state = reduceMissionWorkspace(state, { type: 'RESULT_ANALYZE', value: 'DeviceName,RemoteIP\nhost-1,203.0.113.10\n' });
  state = reduceMissionWorkspace(state, { type: 'SERVICENOW_BUILD' });
  assert.equal(state.revision, 6);
  assert.equal(state.hunt.state, 'READY');
  assert.deepEqual(state.kqlValidations, state.hunt.kqlCandidates);
  assert.equal(state.result.state, 'RESULTS_PRESENT');
  assert.equal(state.serviceNow.provenance.autoSubmission, false);
  assert.deepEqual(state.agentState.nextActions, []);
  assert.equal(state.handoff.sourceStateHash, state.agentState.checkpoint.stateHash);
  assert.equal(Object.isFrozen(state), true);
});

test('changing profile invalidates every downstream projection', () => {
  const complete = importMissionWorkspace(completeWorkspace());
  const next = reduceMissionWorkspace(complete, { type: 'PROFILE_SET', value: { id: 'new', name: 'New Client' } });
  assert.deepEqual({
    relevance: next.relevance,
    hunt: next.hunt,
    result: next.result,
    serviceNow: next.serviceNow,
  }, {
    relevance: null,
    hunt: null,
    result: null,
    serviceNow: null,
  });
  assert.deepEqual(next.kqlValidations, []);
  assert.deepEqual(next.agentState.nextActions, ['mission-relevance']);
});

test('failed transitions leave the frozen current workspace unchanged', () => {
  const state = createMissionWorkspace();
  assert.throws(() => reduceMissionWorkspace(state, { type: 'RELEVANCE_ASSESS' }), /profile/i);
  assert.throws(() => reduceMissionWorkspace(state, { type: 'HUNT_BUILD', value: { ...huntInput, profile: profileInput } }), /profile/i);
  assert.deepEqual(state, createMissionWorkspace());
});

test('clear removes all content and increments revision exactly once', () => {
  const state = reduceMissionWorkspace(createMissionWorkspace(), { type: 'PROFILE_SET', value: profileInput });
  const cleared = reduceMissionWorkspace(state, { type: 'CLEAR' });
  assert.equal(cleared.revision, 2);
  assert.equal(cleared.profile, null);
  assert.deepEqual(cleared.kqlValidations, []);
  assert.deepEqual(cleared.agentState.nextActions, ['mission-profile-set']);
  assert.ok(cleared.handoff.contextRefs.includes('mission:action:clear'));
});

test('independent KQL validation is sorted deduplicated bounded and non-destructive', () => {
  const complete = importMissionWorkspace(completeWorkspace());
  const extra = 'DeviceProcessEvents | where Timestamp > ago(1h) | project Timestamp, DeviceName, FileName';
  const once = reduceMissionWorkspace(complete, { type: 'KQL_VALIDATE', value: extra });
  const twice = reduceMissionWorkspace(once, { type: 'KQL_VALIDATE', value: extra });
  assert.equal(once.kqlValidations.length, 2);
  assert.equal(twice.kqlValidations.length, 2);
  assert.equal(twice.serviceNow.huntId, complete.serviceNow.huntId);

  let state = createMissionWorkspace();
  for (let index = 1; index <= 8; index += 1) {
    state = reduceMissionWorkspace(state, {
      type: 'KQL_VALIDATE',
      value: `DeviceNetworkEvents | where Timestamp > ago(${index}h) | project Timestamp, DeviceName`,
    });
  }
  assert.throws(() => reduceMissionWorkspace(state, {
    type: 'KQL_VALIDATE',
    value: 'DeviceNetworkEvents | where Timestamp > ago(9h) | project Timestamp, DeviceName',
  }), /eight|8|limit/i);
});

test('workspace import preserves the imported revision', () => {
  const imported = reduceMissionWorkspace(createMissionWorkspace(), { type: 'IMPORT', value: completeWorkspace() });
  assert.equal(imported.revision, 6);
  assert.equal(imported.hunt.state, 'READY');
  assert.deepEqual(imported.agentState.nextActions, []);
  assert.ok(imported.handoff.contextRefs.includes('mission:revision:6'));
});
