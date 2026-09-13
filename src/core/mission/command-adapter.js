import { ShellCommandError, shellError } from '../../../app/shell-core/errors.js';
import {
  createMissionWorkspace,
  exportMissionWorkspace,
  importMissionWorkspace,
  reduceMissionWorkspace,
} from './workspace.js';

export const MISSION_HANDLERS = Object.freeze([
  'mission-new',
  'mission-show',
  'mission-profile-set',
  'mission-context-set',
  'mission-relevance',
  'mission-hunt-build',
  'mission-kql-validate',
  'mission-result-analyze',
  'mission-servicenow',
  'mission-export',
  'mission-import',
  'mission-clear',
]);

// Backward-compatible alias retained for the browser shell introduced on main.
// Both names point at the same frozen handler set so command admission cannot drift.
export const WORKFLOW_HANDLERS = MISSION_HANDLERS;

const ACTIONS = Object.freeze({
  'mission-profile-set': Object.freeze({ type: 'PROFILE_SET', kind: 'profile', format: 'json' }),
  'mission-context-set': Object.freeze({ type: 'CONTEXT_SET', kind: 'context', format: 'json' }),
  'mission-hunt-build': Object.freeze({ type: 'HUNT_BUILD', kind: 'hunt', format: 'json' }),
  'mission-result-analyze': Object.freeze({ type: 'RESULT_ANALYZE', kind: 'result', format: 'raw' }),
});

function typedRecord(value) {
  return Object.freeze({ type: 'record', value });
}

function noArgs(args, usage) {
  if (args.length) throw shellError('INVALID_ARGUMENT', `usage: ${usage}`);
}

function safeDomainMessage(error) {
  const message = String(error?.message ?? '').toLowerCase();
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
  if (error instanceof RangeError && /too large|limit|oversized|too many/i.test(error.message)) {
    return shellError('OUTPUT_LIMIT', 'mission input exceeds a fixed limit');
  }
  if (error instanceof TypeError || error instanceof RangeError || error instanceof SyntaxError) {
    return shellError('INVALID_ARGUMENT', safeDomainMessage(error));
  }
  return shellError('INVALID_ARGUMENT', 'invalid mission input');
}

function parseJson(content) {
  try { return JSON.parse(content); }
  catch { throw new TypeError('invalid mission input: malformed JSON'); }
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
  handler,
  args = [],
  input = { type: 'void', value: null },
  workspace = null,
  loadContent = null,
} = {}) {
  try {
    if (!MISSION_HANDLERS.includes(handler)) throw new TypeError('invalid mission input: unsupported handler');
    if (!Array.isArray(args)) throw new TypeError('invalid mission input: arguments required');

    if (handler === 'mission-new') {
      noArgs(args, 'mission new');
      const next = createMissionWorkspace();
      return Object.freeze({ output: typedRecord(next), workspace: next });
    }

    if (handler === 'mission-import') {
      const content = await loadRequestedContent(loadContent, 'workspace', args);
      const next = reduceMissionWorkspace(workspace, { type: 'IMPORT', value: content });
      return Object.freeze({ output: typedRecord(next), workspace: next });
    }

    const current = currentWorkspace(input, workspace);

    if (handler === 'mission-show') {
      noArgs(args, 'mission show');
      return Object.freeze({ output: typedRecord(current), workspace: current });
    }

    if (handler === 'mission-export') {
      noArgs(args, 'mission export');
      const artifact = Object.freeze({
        filename: 'para11ax-mission.json',
        mimeType: 'application/json;charset=utf-8',
        encoding: 'utf8',
        content: exportMissionWorkspace(current),
      });
      return Object.freeze({ output: Object.freeze({ type: 'artifact', value: artifact }), workspace: current });
    }

    if (handler === 'mission-relevance') {
      noArgs(args, 'mission relevance');
      const next = reduceMissionWorkspace(current, { type: 'RELEVANCE_ASSESS' });
      return Object.freeze({ output: typedRecord(next), workspace: next });
    }

    if (handler === 'mission-kql-validate') {
      if (!args.length) throw new TypeError('invalid mission KQL: query required');
      const next = reduceMissionWorkspace(current, { type: 'KQL_VALIDATE', value: args.join(' ') });
      return Object.freeze({ output: typedRecord(next), workspace: next });
    }

    if (handler === 'mission-servicenow') {
      noArgs(args, 'mission servicenow');
      const next = reduceMissionWorkspace(current, { type: 'SERVICENOW_BUILD' });
      return Object.freeze({ output: typedRecord(next), workspace: next });
    }

    if (handler === 'mission-clear') {
      noArgs(args, 'mission clear');
      const next = reduceMissionWorkspace(current, { type: 'CLEAR' });
      return Object.freeze({ output: typedRecord(next), workspace: next });
    }

    const definition = ACTIONS[handler];
    if (!definition) throw new TypeError('invalid mission input: unsupported handler');
    const value = await actionValue(definition, args, loadContent);
    const next = reduceMissionWorkspace(current, { type: definition.type, value });
    return Object.freeze({ output: typedRecord(next), workspace: next });
  } catch (error) {
    throw normalizeError(error);
  }
}
