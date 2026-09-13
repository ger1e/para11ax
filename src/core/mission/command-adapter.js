import { ShellCommandError, shellError } from '../../../app/shell-core/errors.js';
import {
  createMissionWorkspace,
  exportMissionWorkspace,
  importMissionWorkspace,
  reduceMissionWorkspace,
} from './workspace.js';
import {
  DOMAIN_INVESTIGATION_HANDLERS,
  executeDomainInvestigationCommand,
} from '../domain-investigation-command-adapter.js';

const CORE_MISSION_HANDLERS = Object.freeze([
  'mission-new', 'mission-show', 'mission-profile-set', 'mission-context-set',
  'mission-relevance', 'mission-hunt-build', 'mission-kql-validate',
  'mission-result-analyze', 'mission-servicenow', 'mission-export', 'mission-import', 'mission-clear',
]);

export const WORKFLOW_HANDLERS = Object.freeze([...CORE_MISSION_HANDLERS, ...DOMAIN_INVESTIGATION_HANDLERS]);
// Compatibility export for the Node executor on the long-lived Intelligence Fabric branch.
// Both handler families are safe here because executeMissionCommand preserves them in one
// explicit volatile envelope rather than overwriting either workflow state.
export const MISSION_HANDLERS = WORKFLOW_HANDLERS;

const ACTIONS = Object.freeze({
  'mission-profile-set': Object.freeze({ type: 'PROFILE_SET', kind: 'profile', format: 'json' }),
  'mission-context-set': Object.freeze({ type: 'CONTEXT_SET', kind: 'context', format: 'json' }),
  'mission-hunt-build': Object.freeze({ type: 'HUNT_BUILD', kind: 'hunt', format: 'json' }),
  'mission-result-analyze': Object.freeze({ type: 'RESULT_ANALYZE', kind: 'result', format: 'raw' }),
});

function typedRecord(value) { return Object.freeze({ type: 'record', value }); }
function noArgs(args, usage) { if (args.length) throw shellError('INVALID_ARGUMENT', `usage: ${usage}`); }

function safeDomainMessage(error) {
  const message = String(error?.message ?? '').toLowerCase();
  if (message.includes('domain investigation')) return 'invalid Domain Investigation input';
  if (message.includes('profile required')) return 'mission profile required';
  if (message.includes('context required')) return 'mission context required';
  if (message.includes('hunt required')) return 'mission hunt required';
  if (message.includes('version')) return 'unsupported mission version';
  if (message.includes('profile')) return 'invalid mission profile';
  if (message.includes('context')) return 'invalid mission context';
  if (message.includes('hunt')) return 'invalid mission hunt';
  if (message.includes('kql') || message.includes('query')) return 'invalid mission KQL';
  if (message.includes('result') || message.includes('csv')) return 'invalid mission result';
  if (message.includes('servicenow')) return 'invalid ServiceNow projection';
  return 'invalid mission input';
}

function normalizeError(error) {
  if (error instanceof ShellCommandError) return error;
  if (error instanceof RangeError && /too large|limit|oversized|too many|exceed|budget/i.test(error.message)) {
    return shellError('OUTPUT_LIMIT', 'mission input exceeds a fixed limit');
  }
  if (error instanceof TypeError || error instanceof RangeError || error instanceof SyntaxError) {
    return shellError('INVALID_ARGUMENT', safeDomainMessage(error));
  }
  return shellError('INVALID_ARGUMENT', 'invalid mission input');
}

function parseJson(content) { try { return JSON.parse(content); } catch { throw new TypeError('invalid mission input: malformed JSON'); } }

function isEnvelope(value) {
  return Boolean(value && value.__para11axShellWorkflows === 'v1');
}

function splitWorkspace(workspace) {
  if (isEnvelope(workspace)) return { mission: workspace.mission ?? null, domainInvestigation: workspace.domainInvestigation ?? null };
  return { mission: workspace ?? null, domainInvestigation: null };
}

function joinWorkspace({ mission, domainInvestigation }) {
  if (!domainInvestigation) return mission;
  return Object.freeze({ __para11axShellWorkflows: 'v1', mission: mission ?? null, domainInvestigation });
}

function currentWorkspace(input, workspace) {
  if (input?.type === 'record') return importMissionWorkspace(input.value);
  if (!workspace) throw new TypeError('invalid mission workspace: mission new or import required');
  return importMissionWorkspace(workspace);
}

async function loadRequestedContent(loadContent, kind, args) {
  if (typeof loadContent !== 'function') throw shellError('POLICY_DENIED', 'mission content transport unavailable');
  const content = await loadContent({ kind, args: [...args] });
  if (content === null) throw shellError('OPERATION_ABORTED', 'file selection cancelled');
  if (typeof content !== 'string') throw new TypeError('invalid mission input: transport must return text');
  return content;
}

async function actionValue(definition, args, loadContent) {
  const transport = args.length === 0 || String(args[0]).startsWith('--');
  let content;
  if (transport) content = await loadRequestedContent(loadContent, definition.kind, args);
  else content = args.join(' ');
  if (!content && definition.kind !== 'result') throw new TypeError(`invalid mission ${definition.kind}: content required`);
  return definition.format === 'json' ? parseJson(content) : content;
}

export async function executeMissionCommand({
  handler, args = [], input = { type: 'void', value: null }, workspace = null, loadContent = null,
} = {}) {
  try {
    if (!WORKFLOW_HANDLERS.includes(handler)) throw new TypeError('invalid mission input: unsupported handler');
    if (!Array.isArray(args)) throw new TypeError('invalid mission input: arguments required');

    const state = splitWorkspace(workspace);
    if (DOMAIN_INVESTIGATION_HANDLERS.includes(handler)) {
      const outcome = await executeDomainInvestigationCommand({
        handler, args, artifact: state.domainInvestigation, loadContent,
      });
      return Object.freeze({
        output: outcome.output,
        workspace: joinWorkspace({ mission: state.mission, domainInvestigation: outcome.artifact }),
      });
    }

    const missionWorkspace = state.mission;
    if (handler === 'mission-new') {
      noArgs(args, 'mission new');
      const next = createMissionWorkspace();
      return Object.freeze({ output: typedRecord(next), workspace: joinWorkspace({ mission: next, domainInvestigation: state.domainInvestigation }) });
    }

    if (handler === 'mission-import') {
      const content = await loadRequestedContent(loadContent, 'workspace', args);
      const next = reduceMissionWorkspace(missionWorkspace, { type: 'IMPORT', value: content });
      return Object.freeze({ output: typedRecord(next), workspace: joinWorkspace({ mission: next, domainInvestigation: state.domainInvestigation }) });
    }

    const current = currentWorkspace(input, missionWorkspace);
    if (handler === 'mission-show') {
      noArgs(args, 'mission show');
      return Object.freeze({ output: typedRecord(current), workspace: joinWorkspace({ mission: current, domainInvestigation: state.domainInvestigation }) });
    }
    if (handler === 'mission-export') {
      noArgs(args, 'mission export');
      const artifact = Object.freeze({ filename: 'para11ax-mission.json', mimeType: 'application/json;charset=utf-8', encoding: 'utf8', content: exportMissionWorkspace(current) });
      return Object.freeze({ output: Object.freeze({ type: 'artifact', value: artifact }), workspace: joinWorkspace({ mission: current, domainInvestigation: state.domainInvestigation }) });
    }
    if (handler === 'mission-relevance') {
      noArgs(args, 'mission relevance');
      const next = reduceMissionWorkspace(current, { type: 'RELEVANCE_ASSESS' });
      return Object.freeze({ output: typedRecord(next), workspace: joinWorkspace({ mission: next, domainInvestigation: state.domainInvestigation }) });
    }
    if (handler === 'mission-kql-validate') {
      if (!args.length) throw new TypeError('invalid mission KQL: query required');
      const next = reduceMissionWorkspace(current, { type: 'KQL_VALIDATE', value: args.join(' ') });
      return Object.freeze({ output: typedRecord(next), workspace: joinWorkspace({ mission: next, domainInvestigation: state.domainInvestigation }) });
    }
    if (handler === 'mission-servicenow') {
      noArgs(args, 'mission servicenow');
      const next = reduceMissionWorkspace(current, { type: 'SERVICENOW_BUILD' });
      return Object.freeze({ output: typedRecord(next), workspace: joinWorkspace({ mission: next, domainInvestigation: state.domainInvestigation }) });
    }
    if (handler === 'mission-clear') {
      noArgs(args, 'mission clear');
      const next = reduceMissionWorkspace(current, { type: 'CLEAR' });
      return Object.freeze({ output: typedRecord(next), workspace: joinWorkspace({ mission: next, domainInvestigation: state.domainInvestigation }) });
    }

    const definition = ACTIONS[handler];
    if (!definition) throw new TypeError('invalid mission input: unsupported handler');
    const value = await actionValue(definition, args, loadContent);
    const next = reduceMissionWorkspace(current, { type: definition.type, value });
    return Object.freeze({ output: typedRecord(next), workspace: joinWorkspace({ mission: next, domainInvestigation: state.domainInvestigation }) });
  } catch (error) {
    throw normalizeError(error);
  }
}
