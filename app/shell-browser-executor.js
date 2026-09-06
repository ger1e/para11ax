import { classifyBrowserObservable, SUPPORTED_OBSERVABLE_TYPES, validateTypedBrowserObservable } from './observable-input.js';
import {
  buildCorrelation,
  buildCoverage,
  buildEvidence,
  buildIpAnalystReport,
  buildOverview,
  buildRelationships,
  renderIpAnalystReportText,
} from './view-model.js';
import { shellError } from './shell-core/errors.js';
import {
  listAliases,
  renderCapabilities,
  renderCommandIndex,
  renderLimits,
  renderManual,
  searchCommands,
  whichCommand,
} from './shell-core/help.js';
import {
  decodeBrowserArtifact,
  inspectBrowserReportQuality,
  projectBrowserReport,
  renderBrowserReportText,
} from './shell-report-browser.js';
import { parseSwarmArgs } from './swarm-command.js';
import { MISSION_HANDLERS, executeMissionCommand } from '../src/core/mission/command-adapter.js';
import { importMissionWorkspace } from '../src/core/mission/workspace.js';

const PROFILES = new Set(['fast', 'standard', 'full']);
const SHODAN_COMMANDS = new Set(['host', 'search', 'count', 'stats', 'domain', 'info']);
const REPORT_FORMAT_HANDLERS = new Set(['report-text', 'report-html', 'report-pdf', 'report-csv', 'report-kql', 'report-navigator', 'report-stix', 'report-evidence']);
const RESULT_REQUIRED = new Set([
  'result-summary','result-request','result-evidence','result-facts','result-providers','result-failures',
  'result-contradictions','result-corroboration','result-references','result-relationships','result-coverage',
  'result-correlation','result-graph','result-guidance','result-decision','result-attacks','result-hunts',
  'result-telemetry','result-freshness','result-raw','view','json','stix','copy',
  'report-show','report-quality',...REPORT_FORMAT_HANDLERS,
]);

function text(value) { return { type: 'text', value: String(value ?? '') }; }
function record(value) { return { type: 'record', value }; }
function records(value) { return { type: 'records', value: Array.isArray(value) ? value : [] }; }

function invalid(message, context = undefined) {
  throw shellError('INVALID_ARGUMENT', message, context);
}

function classifyObservable(value) {
  try { return classifyBrowserObservable(String(value ?? '')); }
  catch { invalid('invalid observable'); }
}

function validateTypedObservable(type, value) {
  try { return validateTypedBrowserObservable(type, String(value ?? '')); }
  catch { invalid(`invalid ${type} observable`, { type }); }
}

function parseProfile(args, fallback) {
  if (!args.length) return fallback;
  if (args.length !== 1) invalid('profile accepts one value');
  const raw = String(args[0]);
  const value = raw.startsWith('--') ? raw.slice(2) : raw;
  if (!PROFILES.has(value)) invalid('profile must be fast, standard, or full');
  return value;
}

function parseEnrichArgs(args, fallbackProfile) {
  if (!args.length || args.length > 2) invalid('usage: enrich <observable> [--fast|--standard|--full]');
  const indicator = String(args[0] ?? '').trim();
  if (!indicator) invalid('observable required');
  return { indicator, profile: args.length === 2 ? parseProfile([args[1]], fallbackProfile) : fallbackProfile };
}

function parseUserScannerArgs(args) {
  if (args.length < 2) invalid('usage: user-scanner <email|username> <target> [options]');
  const scanType = String(args[0]).toLowerCase();
  const target = String(args[1] ?? '').trim();
  if (!['email', 'username'].includes(scanType) || !target) invalid('user-scanner requires email or username target');
  let category = null;
  let module = null;
  let crossScan = false;
  let noNsfw = true;
  for (let index = 2; index < args.length; index += 1) {
    const token = args[index];
    if (token === '--cross-scan') { crossScan = true; continue; }
    if (token === '--include-nsfw') { noNsfw = false; continue; }
    if (token === '--category' || token === '--module') {
      const value = args[index + 1];
      if (!value || String(value).startsWith('--') || !/^[a-z0-9._-]{1,64}$/i.test(String(value))) invalid(`${token} requires a safe value`);
      if (token === '--category') category = String(value);
      else module = String(value).replace(/\./g, '_');
      index += 1;
      continue;
    }
    invalid(`unsupported user-scanner option: ${token}`);
  }
  if (category && module) invalid('user-scanner category and module are mutually exclusive');
  return { scanType, target, category, module, crossScan, noNsfw };
}

function parseShodanArgs(args) {
  const command = String(args[0] ?? '').toLowerCase();
  if (!SHODAN_COMMANDS.has(command)) invalid('usage: shodan <host|search|count|stats|domain|info> ...');
  if (command === 'info') {
    if (args.length !== 1) invalid('usage: shodan info');
    return { command, target: null, query: null, facets: null };
  }
  if (command === 'host') {
    const target = String(args[1] ?? '').trim();
    if (args.length !== 2 || !target || target.length > 64 || !/^[0-9a-f:.]+$/i.test(target) || (!target.includes('.') && !target.includes(':'))) invalid('usage: shodan host <ip>');
    return { command, target, query: null, facets: null };
  }
  if (command === 'domain') {
    const target = String(args[1] ?? '').trim().toLowerCase().replace(/\.$/, '');
    if (args.length !== 2 || !target || target.length > 253 || !/^[a-z0-9.-]+$/i.test(target) || !target.includes('.') || target.includes('..')) invalid('usage: shodan domain <domain>');
    return { command, target, query: null, facets: null };
  }
  if (command === 'search' || command === 'count') {
    const parts = args.slice(1);
    if (!parts.length || parts.some(token => String(token).startsWith('--'))) invalid(`usage: shodan ${command} <query>`);
    const query = parts.join(' ').trim();
    if (!query || query.length > 1024) invalid('Shodan query must be 1..1024 characters');
    return { command, target: null, query, facets: null };
  }
  const queryParts = [];
  let facets = null;
  for (let index = 1; index < args.length; index += 1) {
    const token = args[index];
    if (token === '--facets') {
      if (facets !== null || index + 1 >= args.length || index + 2 !== args.length) invalid('usage: shodan stats <query> [--facets <fields>]');
      facets = String(args[index + 1]);
      if (!/^[a-z0-9_.-]+(?::[1-9]\d{0,2})?(?:,[a-z0-9_.-]+(?::[1-9]\d{0,2})?)*$/i.test(facets) || facets.length > 256) invalid('invalid Shodan facets');
      index += 1;
      continue;
    }
    if (String(token).startsWith('--')) invalid(`unsupported Shodan option: ${token}`);
    queryParts.push(token);
  }
  const query = queryParts.join(' ').trim();
  if (!query || query.length > 1024) invalid('usage: shodan stats <query> [--facets <fields>]');
  return { command, target: null, query, facets };
}

function providerEntries(meta) {
  const providers = meta?.providers;
  if (!providers || Array.isArray(providers) || typeof providers !== 'object') return [];
  return Object.entries(providers).map(([name, value]) => ({ name, ...(value && typeof value === 'object' ? value : {}) }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

function resultOrInput(state, input) {
  if (input && input.type === 'enrichment') return input.value;
  return state.currentResult;
}

function parseCaseAction(handler, args) {
  if (handler === 'case-new') {
    const title = args.join(' ').trim();
    if (!title) invalid('usage: case new <title>');
    return { action: handler, title };
  }
  if (handler === 'case-open') {
    if (args.length !== 1 || !String(args[0]).trim()) invalid('usage: case open <id>');
    return { action: handler, caseId: String(args[0]) };
  }
  if (['case-close','case-list','case-show','case-import','case-export','case-pin','case-diff','case-pins','case-notes','case-timeline','case-graph'].includes(handler)) {
    if (args.length) invalid(`usage: ${handler.replace('case-', 'case ')}`);
    return { action: handler };
  }
  if (handler === 'case-refresh') {
    if (!args.length) return { action: handler, staleOnly: false };
    if (args.length === 1 && args[0] === '--stale') return { action: handler, staleOnly: true };
    invalid('usage: case refresh [--stale]');
  }
  if (handler === 'case-find' || handler === 'case-unpin') {
    if (args.length !== 2) invalid(`usage: case ${handler === 'case-find' ? 'find' : 'unpin'} <type> <value>`);
    const type = String(args[0]).toLowerCase();
    if (!SUPPORTED_OBSERVABLE_TYPES.includes(type)) invalid('unsupported observable type');
    const observable = validateTypedObservable(type, args[1]);
    return { action: handler, observable: { type: observable.type, value: observable.value } };
  }
  if (handler === 'case-note') {
    const value = args.join(' ').trim();
    if (!value) invalid('usage: case note <text>');
    return { action: handler, text: value };
  }
  invalid('unsupported case command');
}

function caseOutput(handler, action, outcome) {
  if (outcome && typeof outcome === 'object' && typeof outcome.type === 'string' && Object.hasOwn(outcome, 'value')) return outcome;
  if (handler === 'case-new' || handler === 'case-open' || handler === 'case-import') {
    if (outcome?.cancelled) return text('[ CASE ] import cancelled');
    return text(`[ CASE ] ${outcome?.case?.title ?? 'case'} // ${outcome?.case?.id ?? 'unknown'}`);
  }
  if (handler === 'case-close') return text('[ CASE ] active case closed');
  if (handler === 'case-list') return records(outcome?.cases ?? []);
  if (handler === 'case-show') return record(outcome?.case ?? {});
  if (handler === 'case-pins') return records(outcome?.pins ?? []);
  if (handler === 'case-notes') return records(outcome?.notes ?? []);
  if (handler === 'case-timeline') return records(outcome?.timeline ?? []);
  if (handler === 'case-graph') return { type: 'graph', value: outcome?.graph ?? { nodes: [], edges: [] } };
  if (handler === 'case-pin') return text('[ CASE ] current observable pinned');
  if (handler === 'case-unpin') return text(`[ CASE ] unpinned ${action.observable.type}:${action.observable.value}`);
  if (handler === 'case-note') return text('[ CASE ] note appended');
  if (handler === 'case-diff') return records(outcome?.diff ? [outcome.diff] : []);
  if (handler === 'case-find') return records(outcome?.sightings ?? []);
  if (handler === 'case-refresh') return records([outcome ?? { selected: 0, captured: 0, failures: [] }]);
  if (handler === 'case-export') return { type: 'artifact', value: outcome ?? {} };
  invalid('unsupported case output');
}

const INVESTIGATION_NO_ARG_HANDLERS = new Set([
  'investigation-close', 'investigation-list', 'investigation-show', 'investigation-status',
  'investigation-capture-evidence', 'investigation-capture-operator', 'investigation-relevance',
  'investigation-result-import', 'investigation-report', 'investigation-servicenow',
  'investigation-timeline', 'investigation-export', 'investigation-import', 'investigation-clear',
]);

function parseInvestigationJson(args, usage) {
  if (args.length !== 1 || new TextEncoder().encode(String(args[0])).byteLength > 4 * 1024 * 1024) invalid(`usage: ${usage}`);
  try {
    const value = JSON.parse(String(args[0]));
    if (!value || typeof value !== 'object' || Array.isArray(value)) invalid(`usage: ${usage}`);
    return value;
  } catch (error) {
    if (error?.code === 'INVALID_ARGUMENT') throw error;
    invalid(`usage: ${usage}`);
  }
}

function parseInvestigationAction(handler, args) {
  if (handler === 'investigation-new') {
    const title = args.join(' ').trim();
    if (!title) invalid('usage: investigation new <title>');
    return { type: 'NEW', title };
  }
  if (handler === 'investigation-open') {
    if (args.length !== 1 || !String(args[0]).trim()) invalid('usage: investigation open <id>');
    return { type: 'OPEN', id: String(args[0]) };
  }
  if (INVESTIGATION_NO_ARG_HANDLERS.has(handler)) {
    if (args.length) invalid(`usage: ${handler.replaceAll('-', ' ')}`);
    return { type: handler.slice('investigation-'.length).replaceAll('-', '_').toUpperCase() };
  }
  if (handler === 'investigation-scope-set') {
    const value = parseInvestigationJson(args, 'investigation scope set <json>');
    if (!Object.hasOwn(value, 'profile') || !Object.hasOwn(value, 'context')) invalid('usage: investigation scope set <json>');
    return { type: 'SCOPE_SET', profile: value.profile, context: value.context };
  }
  if (handler === 'investigation-observable-add' || handler === 'investigation-observable-remove') {
    if (args.length !== 2) invalid(`usage: investigation observable ${handler.endsWith('add') ? 'add' : 'remove'} <type> <value>`);
    const observable = validateTypedObservable(String(args[0]).toLowerCase(), args[1]);
    return { type: handler.endsWith('add') ? 'OBSERVABLE_ADD' : 'OBSERVABLE_REMOVE', observable: { type: observable.type, value: observable.value } };
  }
  if (handler === 'investigation-hunt-build') return { type: 'HUNT_BUILD', value: parseInvestigationJson(args, 'investigation hunt build <json>') };
  if (handler === 'investigation-kql-validate') {
    const query = args.join(' ').trim();
    if (!query) invalid('usage: investigation kql validate <query>');
    return { type: 'KQL_VALIDATE', query };
  }
  if (handler === 'investigation-disposition-set') return { type: 'DISPOSITION_SET', value: parseInvestigationJson(args, 'investigation disposition set <json>') };
  invalid('unsupported investigation command');
}

function investigationReceipt(outcome, fallbackAction) {
  const investigation = outcome?.investigation;
  return record({
    investigationId: investigation?.id ?? null,
    revision: investigation?.revision ?? null,
    action: outcome?.action ?? fallbackAction,
    invalidated: outcome?.invalidated ?? [],
    phase: investigation?.status?.phase ?? null,
    readiness: investigation?.status?.readiness ?? null,
  });
}

function investigationOutput(handler, action, outcome) {
  if (handler === 'investigation-list') return records(outcome?.investigations ?? []);
  if (handler === 'investigation-show') return record(outcome?.investigation ?? {});
  if (handler === 'investigation-status') return record(outcome?.status ?? {});
  if (handler === 'investigation-timeline') return records(outcome?.timeline ?? []);
  if (handler === 'investigation-export') return { type: 'artifact', value: { filename: outcome?.filename, mediaType: 'application/vnd.para11ax.investigation+json', bytes: new TextEncoder().encode(outcome?.text ?? '').byteLength } };
  if (handler === 'investigation-close') return record({ closed: true });
  if (outcome?.cancelled) return record({ cancelled: true });
  return investigationReceipt(outcome, action.type);
}

function commandListArgs(args) {
  let namespace = null;
  let all = false;
  for (const value of args) {
    if (value === '--all') { all = true; continue; }
    if (namespace !== null) invalid('usage: commands [namespace] [--all]');
    namespace = String(value);
  }
  return { namespace, all };
}

export function createBrowserShellExecutor({
  client,
  session,
  cases = null,
  investigations = null,
  history = null,
  ui = null,
  downloads = { save: () => {} },
  missionFiles = null,
  clipboard = { writeText: async () => {} },
  audio = {},
  now = () => new Date(),
  monotonicNow = () => 0,
  version = 'unknown',
  initialState = {},
} = {}) {
  if (!client || typeof client !== 'object') throw new TypeError('browser shell client required');
  if (!session || typeof session !== 'object') throw new TypeError('browser shell session required');
  const startedAt = Number(monotonicNow()) || 0;
  const state = {
    profile: PROFILES.has(initialState.profile) ? initialState.profile : 'standard',
    currentResult: initialState.currentResult ?? null,
    missionWorkspace: initialState.missionWorkspace == null ? null : importMissionWorkspace(initialState.missionWorkspace),
    currentOperatorResult: initialState.currentOperatorResult ?? null,
  };

  const snapshot = () => Object.freeze({
    profile: state.profile,
    currentResult: state.currentResult,
    missionWorkspace: state.missionWorkspace,
    currentOperatorResult: state.currentOperatorResult,
    investigation: investigations?.state?.() ?? { activeInvestigationId: null, available: false },
    startedAt,
    version,
  });

  async function execute({ descriptor, args = [], input = { type: 'void', value: null }, context = {}, signal } = {}) {
    if (!descriptor || typeof descriptor.handler !== 'string') throw new TypeError('command descriptor required');
    const handler = descriptor.handler;
    const surface = context.surface ?? 'web';
    if (MISSION_HANDLERS.includes(handler)) {
      const outcome = await executeMissionCommand({
        handler,
        args,
        input,
        workspace: state.missionWorkspace,
        loadContent: request => missionFiles?.select?.(request),
      });
      state.missionWorkspace = outcome.workspace;
      return outcome.output;
    }
    if (RESULT_REQUIRED.has(handler) && !resultOrInput(state, input)) invalid('no current enrichment result');

    if (handler === 'help') {
      if (args.length > 1) invalid('usage: help [command]');
      return text(args.length ? renderManual(args) : `PARA11AX COMMAND INDEX\n\n${renderCommandIndex()}`);
    }
    if (handler === 'man') {
      if (!args.length) invalid('usage: man <command>');
      return text(renderManual(args));
    }
    if (handler === 'commands') {
      const { namespace } = commandListArgs(args);
      return text(renderCommandIndex(namespace));
    }
    if (handler === 'apropos') {
      if (!args.length) invalid('usage: apropos <term>');
      return text(searchCommands(args.join(' ')).map(item => `${item.command} — ${item.summary}`).join('\n'));
    }
    if (handler === 'which') {
      if (!args.length) invalid('usage: which <command>');
      return text(whichCommand(args));
    }
    if (handler === 'aliases') return records(listAliases());
    if (handler === 'capabilities') return records(renderCapabilities({ surface }));
    if (handler === 'limits') return record(renderLimits());
    if (handler === 'system-policy') return record({
      surface,
      commandExecution: 'registered-only',
      hostShell: false,
      arbitraryFetch: false,
      arbitraryFilesystem: false,
      credentialPersistence: false,
    });
    if (handler === 'history') return text(history?.entries?.().join('\n') ?? '');
    if (handler === 'history-clear') {
      history?.clear?.();
      return text('history cleared');
    }

    if (handler === 'enrich') {
      const request = parseEnrichArgs(args, state.profile);
      const value = await client.enrich(request.indicator, request.profile, signal);
      state.currentResult = value;
      return { type: 'enrichment', value };
    }
    if (handler === 'intel-typed') {
      const expectedType = descriptor.tokens[1];
      if (!SUPPORTED_OBSERVABLE_TYPES.includes(expectedType) || args.length !== 1) invalid(`usage: intel ${expectedType} <observable>`);
      const classified = validateTypedObservable(expectedType, args[0]);
      const value = await client.enrich(classified.value, state.profile, signal);
      state.currentResult = value;
      return { type: 'enrichment', value };
    }
    if (handler === 'normalize') {
      if (args.length !== 1) invalid('usage: normalize <observable>');
      return record(classifyObservable(args[0]));
    }
    if (handler === 'type') {
      if (args.length !== 1) invalid('usage: type <observable>');
      return { type: 'scalar', value: classifyObservable(args[0]).type };
    }
    if (handler === 'validate') {
      if (args.length !== 1) invalid('usage: validate <observable>');
      const classified = classifyObservable(args[0]);
      return record({ valid: true, ...classified });
    }
    if (handler === 'profile') {
      if (!args.length) return text(`profile: ${state.profile}`);
      state.profile = parseProfile(args, state.profile);
      return text(`profile: ${state.profile}`);
    }
    if (handler === 'batch') {
      if (args.length < 1 || args.length > 20) invalid('batch accepts 1..20 observables');
      const value = await client.batch(args.map(String), state.profile, signal);
      return record(value);
    }
    if (handler === 'health') return record(await client.health(signal));
    if (handler === 'status') return record(await client.status(signal));
    if (handler === 'meta') return record(await client.meta(signal));

    if (handler === 'provider-run') {
      let providerName;
      let indicator;
      if (descriptor.provider) {
        providerName = descriptor.provider;
        if (args.length !== 1) invalid(`usage: ${descriptor.tokens.join(' ')} <observable>`);
        indicator = String(args[0] ?? '').trim();
      } else {
        if (args.length !== 2) invalid('usage: provider run <provider> <observable>');
        providerName = String(args[0] ?? '').trim().toLowerCase();
        indicator = String(args[1] ?? '').trim();
      }
      if (!providerName || !indicator) invalid('provider and observable required');
      const value = await client.provider(providerName, indicator, signal);
      state.currentResult = value;
      return { type: 'enrichment', value };
    }
    if (handler === 'provider-list') return records(providerEntries(await client.meta(signal)));
    if (handler === 'provider-show' || handler === 'provider-capabilities') {
      if (args.length !== 1) invalid(`usage: provider ${handler === 'provider-show' ? 'show' : 'capabilities'} <provider>`);
      const found = providerEntries(await client.meta(signal)).find(item => item.name === String(args[0]).toLowerCase());
      if (!found) invalid('unknown provider', { provider: args[0] });
      return record(found);
    }
    if (handler === 'provider-coverage') {
      if (args.length !== 1 || !SUPPORTED_OBSERVABLE_TYPES.includes(String(args[0]).toLowerCase())) invalid('usage: provider coverage <observable-type>');
      const type = String(args[0]).toLowerCase();
      return records(providerEntries(await client.meta(signal)).filter(item => Array.isArray(item.types) && item.types.includes(type)));
    }
    if (handler === 'provider-status') {
      if (args.length > 1) invalid('usage: provider status [provider]');
      const status = await client.status(signal);
      const entries = providerEntries({ providers: status?.providers ?? {} });
      if (!args.length) return records(entries);
      const name = String(args[0]).toLowerCase();
      const found = entries.find(item => item.name === name);
      if (!found) invalid('unknown provider', { provider: name });
      return records([found]);
    }

    if (handler === 'shodan') {
      const value = await client.shodan(parseShodanArgs(args), signal);
      state.currentOperatorResult = { kind: 'shodan', source: 'current-result', summary: JSON.stringify(value).slice(0, 4000), references: [] };
      return record(value);
    }
    if (handler === 'swarm') {
      let request;
      try { request = parseSwarmArgs(args); }
      catch (error) { invalid(error?.message || 'invalid swarm command'); }
      const value = await client.swarm(request, signal);
      if (value?.command === 'export') {
        downloads.save(value.data, value.mediaType, value.filename);
        const { data: _data, ...receipt } = value;
        return record(receipt);
      }
      state.currentOperatorResult = { kind: 'greynoise-swarm', source: 'current-result', summary: JSON.stringify(value).slice(0, 4000), references: [] };
      return record(value);
    }
    if (handler === 'user-scanner') {
      const value = await client.userScanner(parseUserScannerArgs(args), signal);
      state.currentOperatorResult = { kind: 'user-scanner', source: 'current-result', summary: JSON.stringify(value).slice(0, 4000), references: [] };
      return record(value);
    }

    if (handler === 'result-summary') return text(JSON.stringify(resultOrInput(state, input)));
    if (handler === 'result-request') {
      const value = resultOrInput(state, input);
      return record({ requestId: value.requestId, indicator: value.indicator, type: value.type, profile: value.profile, status: value.status, queriedAt: value.queriedAt, durationMs: value.durationMs });
    }
    if (handler === 'result-evidence') return { type: 'evidence', value: resultOrInput(state, input).evidence ?? [] };
    if (handler === 'result-failures') return records(resultOrInput(state, input).failures);
    if (handler === 'result-relationships') return { type: 'relationships', value: resultOrInput(state, input).relationships ?? [] };
    if (handler === 'result-coverage') return record(resultOrInput(state, input).coverage ?? {});
    if (handler === 'result-correlation') return record(resultOrInput(state, input).correlation ?? {});
    if (handler === 'result-graph') return { type: 'graph', value: resultOrInput(state, input).evidenceGraph ?? { nodes: [], edges: [] } };
    if (handler === 'result-guidance') return { type: 'guidance', value: resultOrInput(state, input).guidance ?? {} };
    if (handler === 'result-decision') return record(resultOrInput(state, input).decision ?? {});
    if (handler === 'result-contradictions') return records(resultOrInput(state, input).correlation?.contradictions ?? []);
    if (handler === 'result-corroboration') return records(resultOrInput(state, input).correlation?.corroboration ?? []);
    if (handler === 'result-references') {
      const refs = [];
      for (const evidence of resultOrInput(state, input).evidence ?? []) for (const reference of evidence.references ?? []) refs.push(reference);
      return records(refs);
    }
    if (handler === 'result-providers') {
      const names = [...new Set((resultOrInput(state, input).evidence ?? []).map(item => item.provider).filter(Boolean))].sort();
      return { type: 'provider-list', value: names.map(name => ({ name })) };
    }
    if (handler === 'result-facts') return records(resultOrInput(state, input).evidence ?? []);
    if (handler === 'result-attacks') return records(resultOrInput(state, input).guidance?.attackMappings ?? []);
    if (handler === 'result-hunts') return records(resultOrInput(state, input).guidance?.hunts ?? resultOrInput(state, input).decision?.hunts ?? []);
    if (handler === 'result-telemetry') return record(resultOrInput(state, input).guidance?.telemetry ?? {});
    if (handler === 'result-freshness') return records(resultOrInput(state, input).guidance?.freshness ?? []);
    if (handler === 'result-raw') return { type: 'enrichment', value: resultOrInput(state, input) };
    if (handler === 'view') return text(JSON.stringify(resultOrInput(state, input)));

    if (handler === 'report-show') {
      if (args.length) invalid('usage: report show');
      return text(renderBrowserReportText(resultOrInput(state, input)));
    }
    if (handler === 'report-quality') {
      if (args.length) invalid('usage: report quality');
      return record(inspectBrowserReportQuality(resultOrInput(state, input), { generatedAt: now().toISOString() }));
    }
    if (REPORT_FORMAT_HANDLERS.has(handler)) {
      const format = handler.slice('report-'.length);
      if (args.length) invalid(`usage: report ${format}`);
      return { type: 'artifact', value: projectBrowserReport(resultOrInput(state, input), format, { generatedAt: now().toISOString() }) };
    }
    if (handler === 'download') {
      if (args.length) invalid('usage: download <artifact>');
      if (input?.type !== 'artifact') invalid('download requires an artifact');
      let payload;
      try { payload = decodeBrowserArtifact(input.value); }
      catch { invalid('download requires a registered artifact'); }
      downloads.save(payload, input.value.mimeType, input.value.filename);
      return input;
    }

    if (handler === 'json') {
      const serialized = JSON.stringify(resultOrInput(state, input), null, 2);
      if (args[0] === 'save') downloads.save(serialized, 'application/json', 'para11ax-evidence.json');
      return text(serialized);
    }
    if (handler === 'stix') {
      const current = resultOrInput(state, input);
      const value = await client.stix(current.indicator, current.profile ?? state.profile, signal);
      return { type: 'artifact', value };
    }
    if (handler === 'copy') {
      const current = resultOrInput(state, input);
      const target = String(args[0] ?? 'observable');
      let value;
      if (target === 'observable') value = current.indicator;
      else if (target === 'json') value = JSON.stringify(current, null, 2);
      else if (target === 'request-id') value = current.requestId;
      else if (target === 'report') {
        if (current.type !== 'ip') invalid('copy report currently requires an IP enrichment result');
        value = renderIpAnalystReportText(buildIpAnalystReport({
          overview: buildOverview(current),
          evidence: buildEvidence(current),
          correlation: buildCorrelation(current),
          relationships: buildRelationships(current),
          coverage: buildCoverage(current),
        }));
      } else invalid('copy target must be observable, report, json, or request-id');
      await clipboard.writeText(String(value ?? ''));
      return text(`copied ${target}`);
    }

    if (handler === 'sound') {
      if (args.length !== 1 || !['on', 'off'].includes(args[0])) invalid('sound must be on or off');
      if (typeof audio.mute === 'function') audio.mute(args[0] === 'off');
      if (args[0] === 'on' && typeof audio.enable === 'function') await audio.enable();
      return text(`sound: ${args[0]}`);
    }
    if (handler === 'volume') {
      if (args.length !== 1 || !/^\d{1,3}$/.test(String(args[0]))) invalid('volume must be 0..100');
      const percent = Number(args[0]);
      if (percent < 0 || percent > 100) invalid('volume must be 0..100');
      if (typeof audio.setVolume === 'function') audio.setVolume(percent / 100);
      return text(`volume: ${percent}`);
    }
    if (handler === 'theme') return text('green-black CRT');
    if (handler === 'pwd') return text('/para11ax');
    if (handler === 'hostname') return text('para11ax');
    if (handler === 'date') return text(now().toString());
    if (handler === 'echo' || handler === 'printf') return text(args.join(' '));
    if (handler === 'uname') return text(`PARA11AX ${version}`);
    if (handler === 'id') return text('analyst@para11ax');
    if (handler === 'uptime') return text(String(Math.max(0, Number(monotonicNow()) - startedAt)));
    if (handler === 'version') return text(version);

    if (handler === 'disconnect' || handler === 'auth-clear') {
      cases?.reset?.();
      investigations?.reset?.();
      session.disconnect?.();
      state.currentResult = null;
      if (handler === 'disconnect') state.missionWorkspace = null;
      return text('disconnected');
    }
    if (handler === 'auth-status') return text(session.snapshot?.().hasToken ? 'authenticated' : 'locked');
    if (handler === 'whoami' || handler === 'session') return record(session.snapshot?.() ?? {});
    if (handler === 'reboot') {
      cases?.reset?.();
      investigations?.reset?.();
      session.reset?.();
      state.currentResult = null;
      state.missionWorkspace = null;
      await ui?.reboot?.();
      return text('reboot');
    }
    if (handler === 'login') {
      if (args.length) invalid('login accepts no inline bearer; use the hidden prompt');
      ui?.requestLogin?.();
      return text('hidden bearer prompt required');
    }
    if (handler === 'clear') {
      if (args.length) invalid('usage: clear');
      ui?.clear?.();
      return text('');
    }

    if (handler.startsWith('case-')) {
      if (!cases?.handle) throw shellError('CAPABILITY_UNAVAILABLE', 'case workspace unavailable');
      const action = parseCaseAction(handler, args);
      const outcome = await cases.handle(action, { currentResult: state.currentResult, profile: state.profile, signal });
      return caseOutput(handler, action, outcome);
    }

    if (handler.startsWith('investigation-')) {
      if (!investigations?.handle) throw shellError('CAPABILITY_UNAVAILABLE', 'investigation workspace unavailable');
      const action = parseInvestigationAction(handler, args);
      let outcome;
      if (handler === 'investigation-capture-evidence') {
        if (!state.currentResult) invalid('no current enrichment result');
        outcome = await investigations.captureEvidence(state.currentResult);
      } else if (handler === 'investigation-capture-operator') {
        if (!state.currentOperatorResult) invalid('no current operator result');
        outcome = await investigations.captureOperator(state.currentOperatorResult);
      } else {
        outcome = await investigations.handle(action);
      }
      return investigationOutput(handler, action, outcome);
    }

    throw shellError('CAPABILITY_UNAVAILABLE', 'browser command handler unavailable', { handler, surface });
  }

  return Object.freeze({ execute, state: snapshot });
}
