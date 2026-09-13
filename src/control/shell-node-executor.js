import { createApp } from '../app.js';
import { classifyIndicator } from '../core/validate.js';
import { GATEWAY_VERSION } from '../core/version.js';
import { createShodanCommandHandler } from '../shodan-command.js';
import { createUserScannerHandler } from '../user-scanner.js';
import { PROVIDER_MANIFEST, providerSecretNames } from '../providers/manifest.js';
import { collectDoctorState } from './doctor.js';
import { runMaltegoCheck, runReleaseVerify, runSetup } from './commands.js';
import { probeProviders } from './provider-probe.js';
import { compileReportCommand, diffReportCommand } from './report-commands.js';
import {
  buildNodeReportManifest,
  inspectNodeReportQuality,
  projectNodeReport,
} from './shell-report-node.js';
import { shellError } from '../../app/shell-core/errors.js';
import {
  listAliases,
  renderCapabilities,
  renderCommandIndex,
  renderLimits,
  renderManual,
  searchCommands,
  whichCommand,
} from '../../app/shell-core/help.js';
import { MISSION_HANDLERS, executeMissionCommand } from '../core/mission/command-adapter.js';
import { createMissionContentLoader } from './mission-content-loader.js';
import { createInvestigationContentLoader } from './investigation-content-loader.js';
import { deriveInvestigationStatus, exportInvestigation, importInvestigation } from '../core/investigation/index.js';

const PROFILES = new Set(['fast', 'standard', 'full']);
const LOCAL_BEARER = 'para11ax-local-cli-runtime';
const SHODAN_COMMANDS = new Set(['host', 'search', 'count', 'stats', 'domain', 'info']);
const REPORT_FORMAT_HANDLERS = new Set(['report-text', 'report-html', 'report-pdf', 'report-csv', 'report-kql', 'report-navigator', 'report-stix', 'report-evidence']);
const RESULT_REQUIRED = new Set([
  'result-summary','result-request','result-evidence','result-facts','result-providers','result-failures',
  'result-contradictions','result-corroboration','result-references','result-relationships','result-coverage',
  'result-correlation','result-graph','result-guidance','result-decision','result-attacks','result-hunts',
  'result-telemetry','result-freshness','result-raw','view','json','stix','copy',
  'report-show','report-quality','report-manifest',...REPORT_FORMAT_HANDLERS,
]);

const text = value => ({ type: 'text', value: String(value ?? '') });
const record = value => ({ type: 'record', value });
const records = value => ({ type: 'records', value: Array.isArray(value) ? value : [] });

function invalid(message, context) {
  throw shellError('INVALID_ARGUMENT', message, context);
}

function safeUpstreamError(result) {
  const message = typeof result?.body?.error === 'string' ? result.body.error : `operation_failed_${result?.status ?? 500}`;
  throw shellError('UPSTREAM_ERROR', message, { status: Number(result?.status) || 500 });
}

function classified(value) {
  try { return classifyIndicator(String(value ?? '')); }
  catch { invalid('invalid observable'); }
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

function parseIntelligenceArgs(args, operation, fallbackProfile) {
  if (!args.length || args.length > 2) invalid(`usage: intel ${operation} <observable> [--fast|--standard|--full]`);
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
    if (args.length !== 2 || !target) invalid('usage: shodan host <ip>');
    return { command, target, query: null, facets: null };
  }
  if (command === 'domain') {
    const target = String(args[1] ?? '').trim();
    if (args.length !== 2 || !target) invalid('usage: shodan domain <domain>');
    return { command, target, query: null, facets: null };
  }
  if (command === 'search' || command === 'count') {
    const query = args.slice(1).join(' ').trim();
    if (!query || args.slice(1).some(token => String(token).startsWith('--'))) invalid(`usage: shodan ${command} <query>`);
    return { command, target: null, query, facets: null };
  }
  const queryParts = [];
  let facets = null;
  for (let index = 1; index < args.length; index += 1) {
    const token = args[index];
    if (token === '--facets') {
      if (facets !== null || index + 1 >= args.length || index + 2 !== args.length) invalid('usage: shodan stats <query> [--facets <fields>]');
      facets = String(args[index + 1]);
      index += 1;
      continue;
    }
    if (String(token).startsWith('--')) invalid(`unsupported Shodan option: ${token}`);
    queryParts.push(token);
  }
  const query = queryParts.join(' ').trim();
  if (!query) invalid('usage: shodan stats <query> [--facets <fields>]');
  return { command, target: null, query, facets };
}

function providerRows() {
  return Object.entries(PROVIDER_MANIFEST)
    .map(([name, policy]) => ({
      name,
      displayName: policy.displayName,
      types: [...policy.types],
      costClass: policy.costClass,
      tier: policy.tier,
      active: policy.active !== false,
      credentialMode: policy.credentialMode ?? (policy.credentialEnv ? 'secret' : 'none'),
      fixedHosts: [...(policy.fixedHosts ?? [])],
      methods: [...(policy.methods ?? ['GET'])],
      maxResponseBytes: policy.maxResponseBytes,
      timeoutMs: policy.timeoutMs,
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

function resultOrInput(state, input) {
  if (input?.type === 'enrichment') return input.value;
  return state.currentResult;
}

function cliUsageLines(registry) {
  const lines = new Set();
  for (const descriptor of registry.list({ surface: 'cli' })) {
    lines.add(descriptor.usage);
    const canonical = descriptor.tokens.join(' ');
    const suffix = descriptor.usage.startsWith(canonical) ? descriptor.usage.slice(canonical.length) : '';
    for (const alias of descriptor.aliases) lines.add(`${alias.join(' ')}${suffix}`);
  }
  return [...lines].sort((a, b) => a.localeCompare(b));
}

export function renderNodeCliHelp(registry) {
  return `PARA11AX operator CLI\n\nUsage:\n${cliUsageLines(registry).map(usage => `  para11ax ${usage}`).join('\n')}\n`;
}

function parseProbeArgs(args) {
  if (!args.length) return { includeCredentialed: false, providerName: null };
  if (args.length === 1 && args[0] === 'all') return { includeCredentialed: true, providerName: null };
  if (args.length === 1 && !String(args[0]).startsWith('--')) return { includeCredentialed: true, providerName: String(args[0]) };
  let includeCredentialed = false;
  let providerName = null;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--all') { includeCredentialed = true; continue; }
    if (arg === '--provider') {
      const value = args[index + 1];
      if (!value || String(value).startsWith('--')) invalid('--provider requires a provider name');
      providerName = String(value);
      index += 1;
      continue;
    }
    invalid(`unknown provider probe argument: ${arg}`);
  }
  return { includeCredentialed, providerName };
}

function runAdmin(fn, ...args) {
  const exitCode = fn(...args);
  return { type: 'void', value: null, exitCode: Number.isInteger(exitCode) ? exitCode : 1 };
}

export function createNodeShellExecutor({
  env = process.env,
  fetchImpl = fetch,
  now = () => new Date(),
  nowMs = () => Date.now(),
  monotonicNow = () => performance.now(),
  version = GATEWAY_VERSION,
  registry,
  missionReadFile = undefined,
  missionStdin = null,
  investigationReadFile = undefined,
  investigationStdin = null,
} = {}) {
  if (!registry) throw new TypeError('Node shell registry required');
  const startedAt = Number(monotonicNow()) || 0;
  const runtimeEnv = { ...env, PARA11AX_TOKEN: LOCAL_BEARER };
  const app = createApp({ env: runtimeEnv, fetchImpl, now: () => now().toISOString(), nowMs });
  const shodan = createShodanCommandHandler({ env: runtimeEnv, fetchImpl, nowMs });
  const userScanner = createUserScannerHandler({ env: runtimeEnv, fetchImpl, nowMs });
  const state = { profile: 'standard', currentResult: null, missionWorkspace: null };
  const missionContent = createMissionContentLoader({ readFile: missionReadFile, stdinContent: missionStdin });
  const investigationContent = createInvestigationContentLoader({ readFile: investigationReadFile, stdinContent: investigationStdin });

  const request = body => ({
    method: 'POST',
    headers: { authorization: `Bearer ${LOCAL_BEARER}`, 'content-type': 'application/json' },
    body,
  });
  const getRequest = () => ({ method: 'GET', headers: { authorization: `Bearer ${LOCAL_BEARER}` } });
  const unwrap = async promise => {
    const result = await promise;
    if (!result || result.status < 200 || result.status >= 300) safeUpstreamError(result);
    return result.body;
  };

  async function execute({ descriptor, args = [], input = { type: 'void', value: null }, context = {} } = {}) {
    if (!descriptor || typeof descriptor.handler !== 'string') throw new TypeError('command descriptor required');
    const handler = descriptor.handler;
    if (MISSION_HANDLERS.includes(handler)) {
      const outcome = await executeMissionCommand({
        handler,
        args,
        input,
        workspace: state.missionWorkspace,
        loadContent: missionContent,
      });
      state.missionWorkspace = outcome.workspace;
      return outcome.output;
    }
    if (['investigation-show', 'investigation-status', 'investigation-import', 'investigation-export'].includes(handler)) {
      let investigation;
      try { investigation = importInvestigation(await investigationContent(args)); }
      catch (error) {
        if (error?.code) throw error;
        invalid(error instanceof Error && /^invalid investigation:/.test(error.message) ? error.message : 'invalid investigation bundle');
      }
      if (handler === 'investigation-status') return record(deriveInvestigationStatus(investigation));
      if (handler === 'investigation-export') return text(exportInvestigation(investigation));
      return record(investigation);
    }
    if (RESULT_REQUIRED.has(handler) && !resultOrInput(state, input)) invalid('no current enrichment result');

    if (handler === 'help') {
      if (args.length > 1) invalid('usage: help [command]');
      return text(args.length ? renderManual(args) : renderNodeCliHelp(registry));
    }
    if (handler === 'man') {
      if (!args.length) invalid('usage: man <command>');
      return text(renderManual(args));
    }
    if (handler === 'commands') {
      const namespace = args.find(arg => arg !== '--all') ?? null;
      if (args.filter(arg => arg !== '--all').length > 1) invalid('usage: commands [namespace] [--all]');
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
    if (handler === 'capabilities') return records(renderCapabilities({ surface: 'cli' }));
    if (handler === 'limits') return record(renderLimits());
    if (handler === 'system-policy') return record({
      surface: 'cli',
      commandExecution: 'registered-only',
      hostShell: false,
      arbitraryFetch: false,
      arbitraryFilesystem: false,
      credentialPersistence: false,
    });

    if (handler === 'doctor') return record(collectDoctorState(env));
    if (handler === 'setup') return runAdmin(runSetup);
    if (handler === 'repair') return runAdmin(runSetup, { repair: true });
    if (handler === 'release-verify') return runAdmin(runReleaseVerify);
    if (handler === 'maltego-check') return runAdmin(runMaltegoCheck);

    if (handler === 'health') return record(await unwrap(app.handleHealth(getRequest())));
    if (handler === 'status') return record(await unwrap(app.handleStatus(getRequest())));
    if (handler === 'meta') return record(await unwrap(app.handleMeta({ method: 'GET', headers: {} })));

    if (handler === 'enrich') {
      const options = parseEnrichArgs(args, state.profile);
      const value = await unwrap(app.handleEnrich(request({ indicator: options.indicator, profile: options.profile })));
      state.currentResult = value;
      return { type: 'enrichment', value };
    }
    if (handler === 'intelligence') {
      const operation = String(descriptor.tokens[1] ?? '');
      const options = parseIntelligenceArgs(args, operation, state.profile);
      const value = await unwrap(app.handleIntelligence(request({ operation, indicator: options.indicator, profile: options.profile })));
      return record(value);
    }
    if (handler === 'intel-typed') {
      if (args.length !== 1) invalid(`usage: ${descriptor.tokens.join(' ')} <observable>`);
      const value = classified(args[0]);
      const expected = descriptor.tokens[1];
      if (value.type !== expected) invalid(`observable is ${value.type}, expected ${expected}`);
      const result = await unwrap(app.handleEnrich(request({ indicator: value.value, type: expected, profile: state.profile })));
      state.currentResult = result;
      return { type: 'enrichment', value: result };
    }
    if (handler === 'normalize') {
      if (args.length !== 1) invalid('usage: normalize <observable>');
      return record(classified(args[0]));
    }
    if (handler === 'type') {
      if (args.length !== 1) invalid('usage: type <observable>');
      return { type: 'scalar', value: classified(args[0]).type };
    }
    if (handler === 'validate') {
      if (args.length !== 1) invalid('usage: validate <observable>');
      return record({ valid: true, ...classified(args[0]) });
    }
    if (handler === 'profile') {
      if (!args.length) return text(`profile: ${state.profile}`);
      state.profile = parseProfile(args, state.profile);
      return text(`profile: ${state.profile}`);
    }
    if (handler === 'batch') {
      if (args.length < 1 || args.length > 20) invalid('batch accepts 1..20 observables');
      return record(await unwrap(app.handleBatch(request({ indicators: args.map(String), profile: state.profile }))));
    }

    if (handler === 'provider-list') return records(providerRows());
    if (handler === 'provider-show' || handler === 'provider-capabilities') {
      if (args.length !== 1) invalid(`usage: provider ${handler === 'provider-show' ? 'show' : 'capabilities'} <provider>`);
      const found = providerRows().find(item => item.name === String(args[0]).toLowerCase());
      if (!found) invalid('unknown provider', { provider: args[0] });
      return record(found);
    }
    if (handler === 'provider-coverage') {
      if (args.length !== 1) invalid('usage: provider coverage <observable-type>');
      const type = String(args[0]).toLowerCase();
      return records(providerRows().filter(item => item.types.includes(type)));
    }
    if (handler === 'provider-status') {
      if (args.length > 1) invalid('usage: provider status [provider]');
      const status = await unwrap(app.handleStatus(getRequest()));
      const rows = Object.entries(status.providers ?? {}).map(([name, value]) => ({ name, ...value })).sort((a, b) => a.name.localeCompare(b.name));
      if (!args.length) return records(rows);
      const found = rows.find(item => item.name === String(args[0]).toLowerCase());
      if (!found) invalid('unknown provider', { provider: args[0] });
      return records([found]);
    }
    if (handler === 'provider-probe') {
      const options = parseProbeArgs(args);
      const value = await probeProviders({ ...options, env, fetchImpl });
      const exitCode = value.some(item => !['ok', 'unconfigured'].includes(item.status)) ? 1 : 0;
      return { type: 'records', value, exitCode };
    }
    if (handler === 'provider-env-template') return text(providerSecretNames().map(name => `${name}=`).join('\n'));
    if (handler === 'provider-run') {
      let provider;
      let indicator;
      if (descriptor.provider) {
        if (args.length !== 1) invalid(`usage: ${descriptor.tokens.join(' ')} <observable>`);
        provider = descriptor.provider;
        indicator = String(args[0]);
      } else {
        if (args.length !== 2) invalid('usage: provider run <provider> <observable>');
        provider = String(args[0]).toLowerCase();
        indicator = String(args[1]);
      }
      const value = await unwrap(app.handleProvider(request({ provider, indicator })));
      state.currentResult = value;
      return { type: 'enrichment', value };
    }

    if (handler === 'shodan') return record(await unwrap(shodan(request(parseShodanArgs(args)))));
    if (handler === 'user-scanner') return record(await unwrap(userScanner(request(parseUserScannerArgs(args)))));

    if (handler === 'result-summary') return text(JSON.stringify(resultOrInput(state, input)));
    if (handler === 'result-request') {
      const value = resultOrInput(state, input);
      return record({ requestId: value.requestId, indicator: value.indicator, type: value.type, profile: value.profile, status: value.status, queriedAt: value.queriedAt, durationMs: value.durationMs });
    }
    if (handler === 'result-evidence') return { type: 'evidence', value: resultOrInput(state, input).evidence ?? [] };
    if (handler === 'result-failures') return records(resultOrInput(state, input).failures ?? []);
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
    if (handler === 'view') return text(JSON.stringify(resultOrInput(state, input), null, 2));

    if (handler === 'json') return text(JSON.stringify(resultOrInput(state, input), null, 2));
    if (handler === 'stix') {
      const current = resultOrInput(state, input);
      return { type: 'artifact', value: await unwrap(app.handleStix(request({ indicator: current.indicator, profile: current.profile ?? state.profile }))) };
    }
    if (handler === 'copy') {
      const current = resultOrInput(state, input);
      const target = String(args[0] ?? 'observable');
      if (target === 'observable') return text(current.indicator);
      if (target === 'json') return text(JSON.stringify(current, null, 2));
      if (target === 'request-id') return text(current.requestId);
      invalid('Node copy supports observable, json, or request-id; use report text for reports');
    }

    if (handler === 'report-show') {
      if (args.length) invalid('usage: report show');
      return text(projectNodeReport(resultOrInput(state, input), 'text', { generatedAt: now().toISOString() }).artifact.content);
    }
    if (handler === 'report-quality') {
      if (args.length) invalid('usage: report quality');
      return record(inspectNodeReportQuality(resultOrInput(state, input), { generatedAt: now().toISOString() }));
    }
    if (REPORT_FORMAT_HANDLERS.has(handler)) {
      const format = handler.slice('report-'.length);
      if (args.length) invalid(`usage: report ${format}`);
      return { type: 'artifact', value: projectNodeReport(resultOrInput(state, input), format, { generatedAt: now().toISOString() }).artifact };
    }
    if (handler === 'report-manifest') {
      if (args.length) invalid('usage: report manifest');
      return record(buildNodeReportManifest(resultOrInput(state, input), { generatedAt: now().toISOString(), preset: 'all' }));
    }
    if (handler === 'report-compile') return { type: 'artifact', value: compileReportCommand(args) };
    if (handler === 'report-diff') return record(diffReportCommand(args));

    if (handler === 'echo' || handler === 'printf') return text(args.join(' '));
    if (handler === 'date') return text(now().toString());
    if (handler === 'hostname') return text('para11ax');
    if (handler === 'pwd') return text('/para11ax');
    if (handler === 'uname') return text(`PARA11AX ${version}`);
    if (handler === 'id') return text('analyst@para11ax');
    if (handler === 'uptime') return text(String(Math.max(0, Number(monotonicNow()) - startedAt)));
    if (handler === 'version') return text(version);
    if (handler === 'theme') return text('green-black CRT');
    if (handler === 'clear') return text('');
    if (handler === 'sound' || handler === 'volume') return text(`${handler}: unavailable on CLI`);

    if (handler === 'auth-status') return text('local-cli');
    if (handler === 'auth-clear' || handler === 'disconnect') {
      state.currentResult = null;
      if (handler === 'disconnect') state.missionWorkspace = null;
      return text('local session cleared');
    }
    if (handler === 'whoami' || handler === 'session') return record({ surface: 'cli', authenticated: true, profile: state.profile });
    if (handler === 'history') return text('');
    if (handler === 'history-clear') return text('history cleared');

    throw shellError('CAPABILITY_UNAVAILABLE', 'CLI command handler unavailable', { handler, surface: context.surface ?? 'cli' });
  }

  return Object.freeze({ execute, state: () => Object.freeze({ ...state, startedAt, version }) });
}

function providerListText(rows) {
  return rows.map(row => `${row.name}\t${row.displayName}\t${row.types.join(',')}\t${row.costClass}\ttier=${row.tier}`).join('\n');
}

export function renderNodeShellOutput(output, { descriptor = null, pipelineLength = 1 } = {}) {
  if (!output || output.type === 'void') return '';
  if (descriptor?.id === 'provider.list' && pipelineLength === 1 && output.type === 'records') return `${providerListText(output.value)}\n`;
  if (descriptor?.id === 'mission.export' && output.type === 'artifact' && output.value?.encoding === 'utf8') {
    return String(output.value.content ?? '');
  }
  if (output.type === 'text' || output.type === 'scalar') {
    const value = String(output.value ?? '');
    return value.endsWith('\n') ? value : `${value}\n`;
  }
  return `${JSON.stringify(output.value, null, 2)}\n`;
}
