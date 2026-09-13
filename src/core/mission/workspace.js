import { normalizeClientProfile } from './client-profile.js';
import { assessClientRelevance } from './relevance.js';
import { validateMissionKql } from './kql-validator.js';
import { buildHuntPackage } from './hunt-package.js';
import { analyzeMissionResults } from './result-analysis.js';
import { buildServiceNowProjection } from '../../report/render-servicenow.js';
import {
  createAgentState,
  createHandoffEnvelope,
  importAgentState,
  importHandoffEnvelope,
  reduceAgentState,
} from '../agent-state.js';

export const MISSION_WORKSPACE_SCHEMA_VERSION = 'mission-workspace-v1.1';
const LEGACY_MISSION_WORKSPACE_SCHEMA_VERSION = 'mission-workspace-v1.0';
const MAX_BUNDLE_BYTES = 2 * 1024 * 1024;
const DOMAIN_KEYS = Object.freeze([
  'revision',
  'profile',
  'context',
  'relevance',
  'hunt',
  'kqlValidations',
  'result',
  'serviceNow',
]);
const LEGACY_WORKSPACE_KEYS = Object.freeze(['schemaVersion', ...DOMAIN_KEYS]);
const WORKSPACE_KEYS = Object.freeze(['schemaVersion', ...DOMAIN_KEYS, 'agentState', 'handoff']);
const CONTEXT_KEYS = Object.freeze([
  'technologies',
  'industries',
  'geographies',
  'attackPaths',
  'actors',
  'requiredTelemetry',
  'observedExploitation',
  'evidenceConfidence',
]);
const CONTEXT_LIST_KEYS = new Set([
  'technologies',
  'industries',
  'geographies',
  'attackPaths',
  'actors',
  'requiredTelemetry',
]);
const RESULT_KEYS = Object.freeze([
  'schemaVersion',
  'format',
  'state',
  'rowCount',
  'columnCount',
  'columns',
  'nonEmptyRowCount',
  'formulaLikeCellCount',
  'limitations',
]);
const CONTROL = /[\u0000-\u001F\u007F]/;
const MISSION_AGENT_TIME = '1970-01-01T00:00:00.000Z';
const MISSION_AGENT_OBJECTIVE = 'Complete the PARA11AX mission workflow while preserving canonical state, provenance, and fail-closed evidence semantics.';
const MISSION_AGENT_CONSTRAINTS = Object.freeze([
  'Preserve canonical mission workspace state and provenance.',
  'Do not treat missing or empty results as benign evidence.',
  'Only continue from validated mission and handoff state.',
]);

function fail(message) {
  throw new TypeError(`invalid mission workspace: ${message}`);
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const item of Object.values(value)) deepFreeze(item);
  return Object.freeze(value);
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonicalize(value[key])]));
}

function exactKeys(value, keys) {
  const actual = Object.keys(value).sort((a, b) => a.localeCompare(b));
  const expected = [...keys].sort((a, b) => a.localeCompare(b));
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function hasOnlyKeys(value, keys) {
  const allowed = new Set(keys);
  return Object.keys(value).every(key => allowed.has(key));
}

function sameJson(left, right) {
  return JSON.stringify(canonicalize(left)) === JSON.stringify(canonicalize(right));
}

function assertJsonTree(value, stack = new WeakSet()) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('non-finite number');
    return;
  }
  if (typeof value !== 'object') fail('non-JSON value');
  if (stack.has(value)) fail('cyclic value');
  stack.add(value);

  const isArray = Array.isArray(value);
  const prototype = Object.getPrototypeOf(value);
  if ((!isArray && prototype !== Object.prototype) || (isArray && prototype !== Array.prototype)) fail('plain object required');
  if (Object.getOwnPropertySymbols(value).length) fail('symbol key');

  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Object.keys(descriptors).filter(key => key !== 'length');
  if (isArray) {
    if (keys.length !== value.length || keys.some((key, index) => key !== String(index))) fail('sparse array');
  }
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) fail('accessor property');
    assertJsonTree(descriptor.value, stack);
  }
  stack.delete(value);
}

function normalizeContext(value, profile) {
  if (value === null) return null;
  if (!value || typeof value !== 'object' || Array.isArray(value) || !hasOnlyKeys(value, CONTEXT_KEYS)) fail('context');
  const normalized = {};
  for (const key of Object.keys(value)) {
    const item = value[key];
    if (CONTEXT_LIST_KEYS.has(key)) {
      if (!Array.isArray(item) || item.length > 64) fail(`context ${key}`);
      const list = item.map((entry, index) => {
        if (typeof entry !== 'string') fail(`context ${key}[${index}]`);
        const text = entry.trim().toLowerCase();
        if (!text || text.length > 256 || CONTROL.test(text)) fail(`context ${key}[${index}]`);
        return text;
      });
      normalized[key] = [...new Set(list)].sort((a, b) => a.localeCompare(b));
    } else {
      normalized[key] = item;
    }
  }
  assessClientRelevance(profile ?? { id: 'validation', name: 'Validation' }, normalized);
  return normalized;
}

function validateProfile(value) {
  if (value === null) return null;
  const normalized = normalizeClientProfile(value);
  if (!sameJson(value, normalized)) fail('profile is not canonical');
  return normalized;
}

function validateRelevance(value, profile, context) {
  if (value === null) return null;
  if (!profile) fail('relevance requires profile');
  if (context === null) fail('relevance requires context');
  const expected = assessClientRelevance(profile, context);
  if (!sameJson(value, expected)) fail('relevance mismatch');
  return expected;
}

function validateHunt(value, profile, context) {
  if (value === null) return null;
  if (!profile) fail('hunt requires profile');
  if (context === null) fail('hunt requires context');
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('hunt');
  const expected = buildHuntPackage({
    profile,
    context,
    subject: value.subject,
    hypothesis: value.hypothesis,
    attackIds: value.attackIds,
    evidenceFingerprints: value.evidenceFingerprints,
    sourceReferences: value.sourceReferences,
    kqlCandidates: Array.isArray(value.kqlCandidates) ? value.kqlCandidates.map(candidate => candidate?.query) : value.kqlCandidates,
  });
  if (!sameJson(value, expected)) fail('hunt mismatch');
  return expected;
}

function validateKqlValidations(value) {
  if (!Array.isArray(value) || value.length > 8) fail('KQL validations');
  const normalized = value.map(item => {
    if (!item || typeof item !== 'object' || Array.isArray(item) || !exactKeys(item, ['query', 'validation'])) fail('KQL validation');
    if (typeof item.query !== 'string') fail('KQL query');
    const expected = Object.freeze({ query: item.query, validation: validateMissionKql(item.query) });
    if (!sameJson(item, expected)) fail('KQL validation mismatch');
    return expected;
  });
  const queries = normalized.map(item => item.query);
  const sorted = [...new Set(queries)].sort((a, b) => a.localeCompare(b));
  if (!sameJson(queries, sorted)) fail('KQL validations must be sorted and unique');
  return normalized;
}

function nonNegativeInteger(value, maximum, field) {
  if (!Number.isInteger(value) || value < 0 || value > maximum) fail(`result ${field}`);
  return value;
}

function validateResult(value) {
  if (value === null) return null;
  if (!value || typeof value !== 'object' || Array.isArray(value) || !exactKeys(value, RESULT_KEYS)) fail('result');
  if (value.schemaVersion !== 'mission-result-v1.0') fail('result version');
  if (!['json', 'csv', 'text'].includes(value.format)) fail('result format');
  if (!['IMPORT_EMPTY', 'NO_RESULTS', 'RESULTS_PRESENT'].includes(value.state)) fail('result state');
  const rowCount = nonNegativeInteger(value.rowCount, 5_000, 'rowCount');
  const columnCount = nonNegativeInteger(value.columnCount, 128, 'columnCount');
  const nonEmptyRowCount = nonNegativeInteger(value.nonEmptyRowCount, rowCount, 'nonEmptyRowCount');
  const formulaLikeCellCount = nonNegativeInteger(value.formulaLikeCellCount, 5_000 * 128, 'formulaLikeCellCount');
  if (!Array.isArray(value.columns) || value.columns.length !== columnCount) fail('result columns');
  const columns = value.columns.map((column, index) => {
    if (typeof column !== 'string' || !column || column.length > 256 || CONTROL.test(column)) fail(`result columns[${index}]`);
    return column;
  });
  if (!sameJson(columns, [...new Set(columns)].sort((a, b) => a.localeCompare(b)))) fail('result columns must be sorted and unique');
  if (!Array.isArray(value.limitations) || value.limitations.some(item => typeof item !== 'string')) fail('result limitations');
  if (formulaLikeCellCount > rowCount * columnCount) fail('result formulaLikeCellCount');

  if (value.state === 'IMPORT_EMPTY') {
    if (value.format !== 'text' || rowCount !== 0 || columnCount !== 0 || nonEmptyRowCount !== 0 || formulaLikeCellCount !== 0 || !sameJson(value.limitations, ['input_empty'])) fail('result IMPORT_EMPTY');
  } else if (value.state === 'NO_RESULTS') {
    if (!['json', 'csv'].includes(value.format) || rowCount !== 0 || columnCount !== 0 || nonEmptyRowCount !== 0 || formulaLikeCellCount !== 0 || !sameJson(value.limitations, ['no_results_is_not_benign_evidence'])) fail('result NO_RESULTS');
  } else if (value.format === 'text' || rowCount === 0 || !sameJson(value.limitations, [])) {
    fail('result RESULTS_PRESENT');
  }
  return {
    schemaVersion: 'mission-result-v1.0',
    format: value.format,
    state: value.state,
    rowCount,
    columnCount,
    columns,
    nonEmptyRowCount,
    formulaLikeCellCount,
    limitations: [...value.limitations],
  };
}

function validateServiceNow(value, hunt, result) {
  if (value === null) return null;
  if (!hunt) fail('ServiceNow requires hunt');
  const expected = buildServiceNowProjection(hunt, result);
  if (!sameJson(value, expected)) fail('ServiceNow mismatch');
  return expected;
}

function normalizeDomain(value) {
  if (!Number.isSafeInteger(value.revision) || value.revision < 0) fail('revision');
  const profile = validateProfile(value.profile);
  const context = normalizeContext(value.context, profile);
  const relevance = validateRelevance(value.relevance, profile, context);
  const hunt = validateHunt(value.hunt, profile, context);
  const kqlValidations = validateKqlValidations(value.kqlValidations);
  const result = validateResult(value.result);
  const serviceNow = validateServiceNow(value.serviceNow, hunt, result);
  return { revision: value.revision, profile, context, relevance, hunt, kqlValidations, result, serviceNow };
}

function nextMissionActions(domain) {
  if (!domain.profile) return ['mission-profile-set'];
  if (domain.context === null) return ['mission-context-set'];
  if (domain.relevance === null) return ['mission-relevance'];
  if (domain.hunt === null) return ['mission-hunt-build'];
  if (domain.result === null) return ['mission-result-analyze'];
  if (domain.serviceNow === null) return ['mission-servicenow'];
  return [];
}

function actionSlug(actionType) {
  return String(actionType).trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

function missionAgentDeps(missionRevision, actionType) {
  let sequence = 0;
  const slug = actionSlug(actionType);
  return Object.freeze({
    now: () => MISSION_AGENT_TIME,
    uuid: () => `mission-${missionRevision}-${slug}-${++sequence}`,
  });
}

function missionReason(actionType, revision) {
  return `Mission ${actionSlug(actionType)} completed; continue from canonical workspace revision ${revision}.`;
}

function buildMissionContinuation(domain, previousAgentState, actionType) {
  const deps = missionAgentDeps(domain.revision, actionType);
  let agentState = previousAgentState
    ? importAgentState(previousAgentState)
    : createAgentState({
      objective: MISSION_AGENT_OBJECTIVE,
      constraints: MISSION_AGENT_CONSTRAINTS,
      taskClass: 'security_analysis',
      risk: 'medium',
      ...deps,
    });

  agentState = reduceAgentState(agentState, { type: 'NEXT_ACTIONS_SET', values: nextMissionActions(domain) }, deps);
  const reason = missionReason(actionType, domain.revision);
  agentState = reduceAgentState(agentState, { type: 'HANDOFF', to: 'next-agent', reason }, deps);
  const handoff = createHandoffEnvelope(agentState, {
    to: 'next-agent',
    reason,
    contextRefs: [
      `mission:revision:${domain.revision}`,
      `mission:action:${actionSlug(actionType)}`,
    ],
  });
  return { agentState, handoff };
}

function validateMissionContinuation(domain, agentStateInput, handoffInput) {
  let agentState;
  let handoff;
  try {
    agentState = importAgentState(agentStateInput);
    handoff = importHandoffEnvelope(handoffInput);
  } catch {
    fail('handoff validation failed');
  }
  if (agentState.objective !== MISSION_AGENT_OBJECTIVE) fail('agent objective');
  if (agentState.taskClass !== 'security_analysis' || agentState.risk !== 'medium') fail('agent routing contract');
  if (!sameJson(agentState.constraints, MISSION_AGENT_CONSTRAINTS)) fail('agent constraints');
  const expectedNextActions = nextMissionActions(domain);
  if (!sameJson(agentState.nextActions, expectedNextActions)) fail('agent next actions');
  if (handoff.stateId !== agentState.id || handoff.revision !== agentState.revision || handoff.epoch !== agentState.epoch) fail('handoff state mismatch');
  if (handoff.invariantHash !== agentState.checkpoint.invariantHash || handoff.sourceStateHash !== agentState.checkpoint.stateHash) fail('handoff checkpoint mismatch');
  if (!sameJson(handoff.nextActions, expectedNextActions)) fail('handoff next actions');
  if (handoff.to !== 'next-agent') fail('handoff recipient');
  if (!handoff.contextRefs.includes(`mission:revision:${domain.revision}`)) fail('handoff mission revision');
  const actionRefs = handoff.contextRefs.filter(item => item.startsWith('mission:action:'));
  if (actionRefs.length !== 1) fail('handoff mission action');
  return { agentState, handoff };
}

function assembleWorkspace(domain, continuation) {
  return deepFreeze({
    schemaVersion: MISSION_WORKSPACE_SCHEMA_VERSION,
    ...domain,
    agentState: continuation.agentState,
    handoff: continuation.handoff,
  });
}

function blankDomain(revision = 0) {
  return {
    revision,
    profile: null,
    context: null,
    relevance: null,
    hunt: null,
    kqlValidations: [],
    result: null,
    serviceNow: null,
  };
}

export function createMissionWorkspace() {
  const domain = blankDomain(0);
  return assembleWorkspace(domain, buildMissionContinuation(domain, null, 'new'));
}

export function importMissionWorkspace(input) {
  let value = input;
  if (typeof input === 'string') {
    if (new TextEncoder().encode(input).byteLength > MAX_BUNDLE_BYTES) throw new RangeError('invalid mission workspace: input too large');
    try { value = JSON.parse(input); }
    catch { fail('malformed JSON'); }
  }
  assertJsonTree(value);
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) fail('plain object required');

  if (value.schemaVersion === LEGACY_MISSION_WORKSPACE_SCHEMA_VERSION) {
    if (!exactKeys(value, LEGACY_WORKSPACE_KEYS)) fail('top-level keys');
    const domain = normalizeDomain(value);
    return assembleWorkspace(domain, buildMissionContinuation(domain, null, 'legacy-import'));
  }

  if (value.schemaVersion !== MISSION_WORKSPACE_SCHEMA_VERSION) fail('unsupported version');
  if (!exactKeys(value, WORKSPACE_KEYS)) fail('top-level keys');
  const domain = normalizeDomain(value);
  return assembleWorkspace(domain, validateMissionContinuation(domain, value.agentState, value.handoff));
}

export function exportMissionWorkspace(workspace) {
  const validated = importMissionWorkspace(workspace);
  return `${JSON.stringify(canonicalize(validated), null, 2)}\n`;
}

function requireProfile(current) {
  if (!current.profile) fail('profile required');
}

function requireContext(current) {
  if (current.context === null) fail('context required');
}

function domainFromWorkspace(workspace) {
  return Object.fromEntries(DOMAIN_KEYS.map(key => [key, workspace[key]]));
}

function advance(current, patch, actionType, { resetAgent = false } = {}) {
  if (current.revision === Number.MAX_SAFE_INTEGER) throw new RangeError('invalid mission workspace: revision limit');
  const domain = { ...domainFromWorkspace(current), ...patch, revision: current.revision + 1 };
  const continuation = buildMissionContinuation(domain, resetAgent ? null : current.agentState, actionType);
  return assembleWorkspace(domain, continuation);
}

const TRANSITIONS = Object.freeze({
  PROFILE_SET(current, action) {
    const profile = normalizeClientProfile(action.value);
    return advance(current, {
      profile,
      relevance: null,
      hunt: null,
      kqlValidations: [],
      result: null,
      serviceNow: null,
    }, 'PROFILE_SET');
  },
  CONTEXT_SET(current, action) {
    const context = normalizeContext(action.value, current.profile);
    if (context === null) fail('context required');
    return advance(current, {
      context,
      relevance: null,
      hunt: null,
      kqlValidations: [],
      result: null,
      serviceNow: null,
    }, 'CONTEXT_SET');
  },
  RELEVANCE_ASSESS(current) {
    requireProfile(current);
    requireContext(current);
    return advance(current, {
      relevance: assessClientRelevance(current.profile, current.context),
      hunt: null,
      kqlValidations: [],
      result: null,
      serviceNow: null,
    }, 'RELEVANCE_ASSESS');
  },
  HUNT_BUILD(current, action) {
    requireProfile(current);
    requireContext(current);
    if (!action.value || typeof action.value !== 'object' || Array.isArray(action.value)) fail('hunt input required');
    if (Object.hasOwn(action.value, 'profile') || Object.hasOwn(action.value, 'context')) fail('hunt input cannot override profile or context');
    const hunt = buildHuntPackage({ ...action.value, profile: current.profile, context: current.context });
    return advance(current, {
      hunt,
      kqlValidations: hunt.kqlCandidates,
      result: null,
      serviceNow: null,
    }, 'HUNT_BUILD');
  },
  KQL_VALIDATE(current, action) {
    if (typeof action.value !== 'string') fail('KQL query required');
    const candidate = Object.freeze({ query: action.value, validation: validateMissionKql(action.value) });
    const byQuery = new Map(current.kqlValidations.map(item => [item.query, item]));
    byQuery.set(candidate.query, candidate);
    if (byQuery.size > 8) throw new RangeError('invalid mission workspace: KQL validation limit is 8');
    return advance(current, {
      kqlValidations: [...byQuery.values()].sort((left, right) => left.query.localeCompare(right.query)),
    }, 'KQL_VALIDATE');
  },
  RESULT_ANALYZE(current, action) {
    return advance(current, {
      result: analyzeMissionResults(action.value),
      serviceNow: null,
    }, 'RESULT_ANALYZE');
  },
  SERVICENOW_BUILD(current) {
    if (!current.hunt) fail('hunt required for ServiceNow projection');
    return advance(current, { serviceNow: buildServiceNowProjection(current.hunt, current.result) }, 'SERVICENOW_BUILD');
  },
  CLEAR(current) {
    return advance(current, blankDomain(current.revision + 1), 'CLEAR', { resetAgent: true });
  },
});

export function reduceMissionWorkspace(workspace, action) {
  if (!action || typeof action !== 'object' || Array.isArray(action) || typeof action.type !== 'string') fail('action required');
  if (action.type === 'IMPORT') return importMissionWorkspace(action.value);
  const current = importMissionWorkspace(workspace);
  const transition = TRANSITIONS[action.type];
  if (!transition) fail('unsupported action');
  return transition(current, action);
}
