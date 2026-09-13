import { randomUUID } from 'node:crypto';
import { isAgentRiskLevel, isAgentTaskClass } from './agent-policy.js';
import { sha256Hex } from './sha256.js';

const SCHEMA_VERSION = 'para11ax-agent-state-v1.0';
const HANDOFF_SCHEMA_VERSION = 'para11ax-agent-handoff-v1.0';
const ACTIONS = new Set(['DECISION_ADD', 'ARTIFACT_ADD', 'NEXT_ACTIONS_SET', 'OBJECTIVE_REVISE', 'CONSTRAINTS_SET', 'HANDOFF']);
const UNSAFE_CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/;
const MAX_TEXT = 8192;
const MAX_LIST = 128;
const MAX_TIMELINE = 256;

function fail(message, ErrorType = TypeError) {
  throw new ErrorType(`invalid agent state: ${message}`);
}

function handoffFail(message, ErrorType = TypeError) {
  throw new ErrorType(`invalid agent handoff: ${message}`);
}

function text(value, field, maximum = MAX_TEXT) {
  if (typeof value !== 'string') fail(field);
  const normalized = value.replace(/\r\n?/g, '\n').trim();
  if (!normalized || normalized.length > maximum || UNSAFE_CONTROL.test(normalized)) fail(field);
  return normalized;
}

function handoffText(value, field, maximum = MAX_TEXT) {
  try { return text(value, field, maximum); } catch { handoffFail(field); }
}

function timestamp(value, field) {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) fail(`${field} timestamp`);
  if (new Date(value).toISOString() !== value) fail(`${field} timestamp`);
  return value;
}

function uniqueText(values, field) {
  if (!Array.isArray(values) || values.length > MAX_LIST) fail(field);
  const normalized = values.map(value => text(value, field, 2048));
  if (new Set(normalized).size !== normalized.length) fail(`${field} duplicate`);
  return normalized;
}

function handoffUniqueText(values, field) {
  try { return uniqueText(values, field); } catch { handoffFail(field); }
}

function ensureUniqueIds(values, field, error = fail) {
  const ids = values.map(value => value.id);
  if (new Set(ids).size !== ids.length) error(`${field} duplicate id`);
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.keys(value).sort((a, b) => a.localeCompare(b)).map(key => [key, canonicalize(value[key])]));
}

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function clone(value) {
  return structuredClone(value);
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function invariantPayload(state) {
  return {
    objective: state.objective,
    taskClass: state.taskClass,
    risk: state.risk,
    constraints: state.constraints,
    decisions: state.decisions,
  };
}

function fullStatePayload(state) {
  const { checkpoint: _checkpoint, ...payload } = state;
  return payload;
}

function handoffPayload(handoff) {
  const { handoffHash: _handoffHash, ...payload } = handoff;
  return payload;
}

export function agentInvariantHash(state) {
  return sha256Hex(canonicalJson(invariantPayload(state)));
}

export function agentStateHash(state) {
  return sha256Hex(canonicalJson(fullStatePayload(state)));
}

export function agentHandoffHash(handoff) {
  return sha256Hex(canonicalJson(handoffPayload(handoff)));
}

function validateArtifact(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('artifact');
  return {
    id: text(value.id, 'artifact id', 160),
    kind: text(value.kind, 'artifact kind', 64),
    ref: text(value.ref, 'artifact ref', 2048),
    summary: text(value.summary, 'artifact summary', 2048),
    at: timestamp(value.at, 'artifact at'),
  };
}

function validateHandoffArtifact(value) {
  try { return validateArtifact(value); } catch { handoffFail('artifact'); }
}

function validateHandoffRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('handoff');
  const invariantHash = text(value.invariantHash, 'handoff invariant hash', 64);
  if (!/^[a-f0-9]{64}$/.test(invariantHash)) fail('handoff invariant hash');
  return {
    id: text(value.id, 'handoff id', 160),
    at: timestamp(value.at, 'handoff at'),
    to: text(value.to, 'handoff to', 160),
    reason: text(value.reason, 'handoff reason', 2048),
    invariantHash,
  };
}

function validateTimeline(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('timeline entry');
  return {
    id: text(value.id, 'timeline id', 160),
    at: timestamp(value.at, 'timeline at'),
    type: text(value.type, 'timeline type', 64),
    reason: value.reason === null ? null : text(value.reason, 'timeline reason', 2048),
  };
}

export function importAgentState(input) {
  let value = input;
  if (typeof input === 'string') {
    try { value = JSON.parse(input); } catch { fail('malformed JSON'); }
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('object');

  const expectedKeys = [
    'schemaVersion', 'id', 'objective', 'taskClass', 'risk', 'constraints', 'decisions', 'artifacts', 'nextActions',
    'revision', 'epoch', 'createdAt', 'updatedAt', 'checkpoint', 'handoffs', 'timeline',
  ].sort();
  const actualKeys = Object.keys(value).sort();
  if (canonicalJson(actualKeys) !== canonicalJson(expectedKeys)) fail('top-level keys');
  if (value.schemaVersion !== SCHEMA_VERSION) fail('schema version');

  const normalized = {
    schemaVersion: SCHEMA_VERSION,
    id: text(value.id, 'id', 160),
    objective: text(value.objective, 'objective'),
    taskClass: text(value.taskClass, 'task class', 64),
    risk: text(value.risk, 'risk', 16),
    constraints: uniqueText(value.constraints, 'constraints'),
    decisions: uniqueText(value.decisions, 'decisions'),
    artifacts: Array.isArray(value.artifacts) && value.artifacts.length <= MAX_LIST ? value.artifacts.map(validateArtifact) : fail('artifacts'),
    nextActions: uniqueText(value.nextActions, 'next actions'),
    revision: value.revision,
    epoch: value.epoch,
    createdAt: timestamp(value.createdAt, 'createdAt'),
    updatedAt: timestamp(value.updatedAt, 'updatedAt'),
    checkpoint: value.checkpoint,
    handoffs: Array.isArray(value.handoffs) && value.handoffs.length <= MAX_LIST ? value.handoffs.map(validateHandoffRecord) : fail('handoffs'),
    timeline: Array.isArray(value.timeline) && value.timeline.length <= MAX_TIMELINE ? value.timeline.map(validateTimeline) : fail('timeline'),
  };

  ensureUniqueIds(normalized.artifacts, 'artifacts');
  ensureUniqueIds(normalized.handoffs, 'handoffs');
  ensureUniqueIds(normalized.timeline, 'timeline');
  if (!isAgentTaskClass(normalized.taskClass)) fail('task class');
  if (!isAgentRiskLevel(normalized.risk)) fail('risk');
  if (!Number.isSafeInteger(normalized.revision) || normalized.revision < 0) fail('revision');
  if (!Number.isSafeInteger(normalized.epoch) || normalized.epoch < 0) fail('epoch');
  if (!value.checkpoint || typeof value.checkpoint !== 'object' || Array.isArray(value.checkpoint)) fail('checkpoint');

  const checkpointKeys = Object.keys(value.checkpoint).sort();
  if (canonicalJson(checkpointKeys) !== canonicalJson(['at', 'invariantHash', 'revision', 'stateHash'].sort())) fail('checkpoint keys');
  const checkpoint = {
    at: timestamp(value.checkpoint.at, 'checkpoint at'),
    revision: value.checkpoint.revision,
    invariantHash: text(value.checkpoint.invariantHash, 'checkpoint invariant hash', 64),
    stateHash: text(value.checkpoint.stateHash, 'checkpoint state hash', 64),
  };
  if (!Number.isSafeInteger(checkpoint.revision) || checkpoint.revision !== normalized.revision) fail('checkpoint revision');
  if (!/^[a-f0-9]{64}$/.test(checkpoint.invariantHash)) fail('checkpoint invariant hash');
  if (!/^[a-f0-9]{64}$/.test(checkpoint.stateHash)) fail('checkpoint state hash');
  normalized.checkpoint = checkpoint;

  if (checkpoint.invariantHash !== agentInvariantHash(normalized)) fail('checkpoint invariant mismatch');
  if (checkpoint.stateHash !== agentStateHash(normalized)) fail('checkpoint state mismatch');
  return deepFreeze(normalized);
}

export function createAgentState({
  objective,
  constraints = [],
  taskClass = 'analysis',
  risk = 'medium',
  now = () => new Date().toISOString(),
  uuid = () => randomUUID(),
} = {}) {
  const at = timestamp(now(), 'createdAt');
  const base = {
    schemaVersion: SCHEMA_VERSION,
    id: text(uuid(), 'id', 160),
    objective: text(objective, 'objective'),
    taskClass: text(taskClass, 'task class', 64),
    risk: text(risk, 'risk', 16),
    constraints: uniqueText(constraints, 'constraints'),
    decisions: [],
    artifacts: [],
    nextActions: [],
    revision: 0,
    epoch: 0,
    createdAt: at,
    updatedAt: at,
    checkpoint: null,
    handoffs: [],
    timeline: [],
  };
  if (!isAgentTaskClass(base.taskClass)) fail('task class');
  if (!isAgentRiskLevel(base.risk)) fail('risk');
  base.checkpoint = { at, revision: 0, invariantHash: agentInvariantHash(base), stateHash: agentStateHash(base) };
  return importAgentState(base);
}

function addTimeline(next, { id, at, type, reason = null }) {
  if (next.timeline.length >= MAX_TIMELINE) fail('timeline limit', RangeError);
  next.timeline.push({ id, at, type, reason });
}

export function reduceAgentState(current, action, dependencies = {}) {
  const valid = importAgentState(current);
  if (!action || typeof action !== 'object' || Array.isArray(action) || !ACTIONS.has(action.type)) fail('unsupported action');
  if (valid.revision === Number.MAX_SAFE_INTEGER) fail('revision limit', RangeError);
  const now = dependencies.now ?? (() => new Date().toISOString());
  const uuid = dependencies.uuid ?? (() => randomUUID());
  const at = timestamp(now(), 'updatedAt');
  const next = clone(valid);
  let timelineType = action.type;
  let timelineReason = null;

  switch (action.type) {
    case 'DECISION_ADD': {
      const decision = text(action.text, 'decision', 2048);
      if (next.decisions.includes(decision)) fail('duplicate decision');
      if (next.decisions.length >= MAX_LIST) fail('decision limit', RangeError);
      next.decisions.push(decision);
      break;
    }
    case 'ARTIFACT_ADD': {
      const value = action.value;
      if (!value || typeof value !== 'object' || Array.isArray(value)) fail('artifact');
      if (next.artifacts.length >= MAX_LIST) fail('artifact limit', RangeError);
      next.artifacts.push({
        id: text(uuid(), 'artifact id', 160),
        kind: text(value.kind, 'artifact kind', 64),
        ref: text(value.ref, 'artifact ref', 2048),
        summary: text(value.summary, 'artifact summary', 2048),
        at,
      });
      break;
    }
    case 'NEXT_ACTIONS_SET':
      next.nextActions = uniqueText(action.values, 'next actions');
      break;
    case 'OBJECTIVE_REVISE':
      next.objective = text(action.objective, 'objective');
      next.epoch += 1;
      timelineType = 'SCOPE_CHANGE';
      timelineReason = text(action.reason, 'scope change reason', 2048);
      break;
    case 'CONSTRAINTS_SET':
      next.constraints = uniqueText(action.values, 'constraints');
      next.epoch += 1;
      timelineType = 'SCOPE_CHANGE';
      timelineReason = text(action.reason, 'scope change reason', 2048);
      break;
    case 'HANDOFF':
      if (next.handoffs.length >= MAX_LIST) fail('handoff limit', RangeError);
      next.handoffs.push({
        id: text(uuid(), 'handoff id', 160),
        at,
        to: text(action.to, 'handoff to', 160),
        reason: text(action.reason, 'handoff reason', 2048),
        invariantHash: agentInvariantHash(next),
      });
      break;
    default:
      fail('unsupported action');
  }

  next.revision += 1;
  next.updatedAt = at;
  addTimeline(next, { id: text(uuid(), 'timeline id', 160), at, type: timelineType, reason: timelineReason });
  next.checkpoint = { at, revision: next.revision, invariantHash: agentInvariantHash(next), stateHash: agentStateHash(next) };
  if (action.type === 'HANDOFF') next.handoffs[next.handoffs.length - 1].invariantHash = next.checkpoint.invariantHash;
  return importAgentState(next);
}

function same(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

export function detectAgentDrift(baselineInput, candidateInput) {
  const baseline = clone(baselineInput);
  const candidate = clone(candidateInput);
  const fields = [];
  for (const field of ['objective', 'taskClass', 'risk', 'constraints']) {
    if (!same(baseline[field], candidate[field])) fields.push(field);
  }
  const decisionLoss = Array.isArray(baseline.decisions) && Array.isArray(candidate.decisions)
    && baseline.decisions.some(value => !candidate.decisions.includes(value));
  if (decisionLoss) fields.push('decisions');

  let severity = 'none';
  if (fields.some(field => ['objective', 'taskClass', 'risk', 'constraints'].includes(field))) severity = 'critical';
  else if (decisionLoss) severity = 'high';

  return {
    drifted: fields.length > 0,
    severity,
    fields,
    expectedHash: agentInvariantHash(baseline),
    actualHash: agentInvariantHash(candidate),
  };
}

export function createHandoffEnvelope(current, { to, reason, contextRefs = [] } = {}) {
  const state = importAgentState(current);
  const envelope = {
    schemaVersion: HANDOFF_SCHEMA_VERSION,
    stateId: state.id,
    revision: state.revision,
    epoch: state.epoch,
    to: text(to, 'handoff to', 160),
    reason: text(reason, 'handoff reason', 2048),
    objective: state.objective,
    taskClass: state.taskClass,
    risk: state.risk,
    constraints: [...state.constraints],
    decisions: [...state.decisions],
    artifacts: clone(state.artifacts),
    nextActions: [...state.nextActions],
    contextRefs: uniqueText(contextRefs, 'context refs'),
    invariantHash: state.checkpoint.invariantHash,
    sourceStateHash: state.checkpoint.stateHash,
    handoffHash: null,
  };
  envelope.handoffHash = agentHandoffHash(envelope);
  return importHandoffEnvelope(envelope);
}

export function importHandoffEnvelope(input) {
  let value = input;
  if (typeof input === 'string') {
    try { value = JSON.parse(input); } catch { handoffFail('malformed JSON'); }
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) handoffFail('object');

  const expectedKeys = [
    'schemaVersion', 'stateId', 'revision', 'epoch', 'to', 'reason', 'objective', 'taskClass', 'risk', 'constraints',
    'decisions', 'artifacts', 'nextActions', 'contextRefs', 'invariantHash', 'sourceStateHash', 'handoffHash',
  ].sort();
  if (canonicalJson(Object.keys(value).sort()) !== canonicalJson(expectedKeys)) handoffFail('top-level keys');
  if (value.schemaVersion !== HANDOFF_SCHEMA_VERSION) handoffFail('schema version');
  if (!Number.isSafeInteger(value.revision) || value.revision < 0) handoffFail('revision');
  if (!Number.isSafeInteger(value.epoch) || value.epoch < 0) handoffFail('epoch');
  if (!isAgentTaskClass(value.taskClass)) handoffFail('task class');
  if (!isAgentRiskLevel(value.risk)) handoffFail('risk');

  const normalized = {
    schemaVersion: HANDOFF_SCHEMA_VERSION,
    stateId: handoffText(value.stateId, 'state id', 160),
    revision: value.revision,
    epoch: value.epoch,
    to: handoffText(value.to, 'to', 160),
    reason: handoffText(value.reason, 'reason', 2048),
    objective: handoffText(value.objective, 'objective'),
    taskClass: value.taskClass,
    risk: value.risk,
    constraints: handoffUniqueText(value.constraints, 'constraints'),
    decisions: handoffUniqueText(value.decisions, 'decisions'),
    artifacts: Array.isArray(value.artifacts) && value.artifacts.length <= MAX_LIST ? value.artifacts.map(validateHandoffArtifact) : handoffFail('artifacts'),
    nextActions: handoffUniqueText(value.nextActions, 'next actions'),
    contextRefs: handoffUniqueText(value.contextRefs, 'context refs'),
    invariantHash: handoffText(value.invariantHash, 'invariant hash', 64),
    sourceStateHash: handoffText(value.sourceStateHash, 'source state hash', 64),
    handoffHash: handoffText(value.handoffHash, 'handoff hash', 64),
  };
  ensureUniqueIds(normalized.artifacts, 'artifacts', handoffFail);
  for (const field of ['invariantHash', 'sourceStateHash', 'handoffHash']) {
    if (!/^[a-f0-9]{64}$/.test(normalized[field])) handoffFail(field);
  }
  if (normalized.invariantHash !== agentInvariantHash(normalized)) handoffFail('invariant mismatch');
  if (normalized.handoffHash !== agentHandoffHash(normalized)) handoffFail('handoff hash mismatch');
  return deepFreeze(normalized);
}
