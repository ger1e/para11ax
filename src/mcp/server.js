import { requireGatewayAuth } from '../core/auth.js';
import { securityHeaders } from '../core/http.js';
import { createApp } from '../app.js';
import { createShodanCommandHandler } from '../shodan-command.js';
import { createUserScannerHandler } from '../user-scanner.js';
import { createGreyNoiseSwarmCommandHandler } from '../greynoise-swarm-command.js';
import { executeMissionCommand } from '../core/mission/command-adapter.js';
import {
  createInvestigation,
  deriveInvestigationStatus,
  exportInvestigation,
  importInvestigation,
  reduceInvestigation,
} from '../core/investigation/index.js';
import { buildInvestigationReport, renderInvestigationText } from '../report/render-investigation.js';
import {
  createCase,
  validateCaseValue,
  addNote as addCaseNote,
  addPin as addCasePin,
  removePin as removeCasePin,
  appendSnapshot,
} from '../../app/case-model.js';
import { buildCaseEvidenceGraph } from '../../app/case-evidence-graph.js';
import { COMMAND_REGISTRY } from '../../app/shell-core/catalog.js';
import { createNodeShellExecutor } from '../control/shell-node-executor.js';
import {
  buildNodeReportManifest,
  inspectNodeReportQuality,
  projectNodeReport,
} from '../control/shell-report-node.js';
import { GATEWAY_VERSION } from '../core/version.js';

export const MCP_PROTOCOL_VERSION = '2026-07-28';
const LEGACY_PROTOCOL_VERSION = '2025-06-18';
const MAX_BODY_BYTES = 128 * 1024;
const DENIED_COMMAND_IDS = new Set([
  'system.doctor', 'system.setup', 'system.repair', 'system.release-verify', 'system.maltego-check',
  'provider.probe', 'provider.env-template', 'report.compile', 'report.diff',
]);
const DENIED_COMMAND_NAMESPACES = new Set(['session', 'terminal', 'case', 'investigation']);

const schema = (properties = {}, required = []) => ({
  type: 'object',
  properties,
  required,
  additionalProperties: false,
});
const string = (description, extra = {}) => ({ type: 'string', description, ...extra });
const object = description => ({ type: 'object', description, additionalProperties: true });
const array = (description, items = {}) => ({ type: 'array', description, items });

const TOOLS = Object.freeze([
  {
    name: 'para11ax_capabilities',
    title: 'PARA11AX capabilities',
    description: 'Inspect authenticated gateway health, status, metadata, MCP tools, or remotely exposed registered commands.',
    inputSchema: schema({ view: string('View to return.', { enum: ['catalog', 'health', 'status', 'meta', 'commands'] }) }),
    annotations: { readOnlyHint: true },
  },
  {
    name: 'para11ax_enrich',
    title: 'PARA11AX enrichment',
    description: 'Run policy-bound Evidence v2 enrichment for one observable.',
    inputSchema: schema({
      indicator: string('Observable to classify and enrich.'),
      type: string('Optional asserted observable type.'),
      profile: string('Enrichment profile.', { enum: ['fast', 'standard', 'full'] }),
    }, ['indicator']),
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  {
    name: 'para11ax_batch',
    title: 'PARA11AX batch enrichment',
    description: 'Run bounded Evidence v2 enrichment for 1..20 observables.',
    inputSchema: schema({
      indicators: array('Observables to enrich.', { type: 'string' }),
      profile: string('Enrichment profile.', { enum: ['fast', 'standard', 'full'] }),
    }, ['indicators']),
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  {
    name: 'para11ax_provider',
    title: 'PARA11AX provider',
    description: 'Run one registered provider through the bounded provider gateway.',
    inputSchema: schema({
      provider: string('Registered provider name.'),
      indicator: string('Observable.'),
      type: string('Optional asserted observable type.'),
    }, ['provider', 'indicator']),
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  {
    name: 'para11ax_shodan',
    title: 'PARA11AX Shodan',
    description: 'Run the existing bounded Shodan operator surface.',
    inputSchema: schema({
      command: string('Shodan operation.', { enum: ['host', 'search', 'count', 'stats', 'domain', 'info'] }),
      target: string('Host or domain target where required.'),
      query: string('Search query where required.'),
      facets: string('Optional stats facets.'),
    }, ['command']),
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  {
    name: 'para11ax_swarm',
    title: 'PARA11AX GreyNoise Project Swarm',
    description: 'Run bounded Project Swarm session search, retrieval, pivot, timeseries, diff, or export operations.',
    inputSchema: { type: 'object', additionalProperties: true, properties: { command: string('Swarm operation.', { enum: ['search', 'get', 'export', 'unique', 'timeseries', 'diff'] }) }, required: ['command'] },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  {
    name: 'para11ax_user_scan',
    title: 'PARA11AX User Scanner',
    description: 'Run the existing isolated identity OSINT scanner with its bounded policy controls.',
    inputSchema: { type: 'object', additionalProperties: true, properties: { scanType: string('Identity target type.', { enum: ['email', 'username'] }), target: string('Identity target.') }, required: ['scanType', 'target'] },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  {
    name: 'para11ax_stix',
    title: 'PARA11AX STIX export',
    description: 'Generate a deterministic STIX 2.1 bundle for an observable using PARA11AX enrichment.',
    inputSchema: schema({ indicator: string('Observable.'), type: string('Optional asserted type.'), profile: string('Enrichment profile.', { enum: ['fast', 'standard', 'full'] }) }, ['indicator']),
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  {
    name: 'para11ax_mission',
    title: 'PARA11AX mission workflow',
    description: 'Operate the complete mission/hunt/KQL workflow using an explicit workspace handle returned on every call.',
    inputSchema: schema({
      operation: string('Mission operation.', { enum: ['new', 'show', 'profile_set', 'context_set', 'relevance', 'hunt_build', 'kql_validate', 'result_analyze', 'servicenow', 'export', 'import', 'clear'] }),
      workspace: object('Existing mission workspace for stateful operations.'),
      payload: object('Structured profile/context/hunt/import payload.'),
      content: string('Raw JSON/CSV/text input for import or result analysis.'),
      query: string('KQL for kql_validate.'),
    }, ['operation']),
    annotations: { readOnlyHint: false },
  },
  {
    name: 'para11ax_investigation',
    title: 'PARA11AX investigation workflow',
    description: 'Create, inspect, mutate, report, import, or export Investigation Workspace v2 using explicit state-in/state-out.',
    inputSchema: schema({
      operation: string('Investigation operation.', { enum: ['create', 'status', 'dispatch', 'report', 'report_text', 'export', 'import'] }),
      title: string('Title for create.'),
      investigation: object('Existing investigation state.'),
      action: object('Reducer action for dispatch.'),
      bundle: string('Canonical investigation JSON for import.'),
    }, ['operation']),
    annotations: { readOnlyHint: false },
  },
  {
    name: 'para11ax_case',
    title: 'PARA11AX analyst case',
    description: 'Create and operate analyst cases with explicit portable case state rather than hidden browser/server persistence.',
    inputSchema: schema({
      operation: string('Case operation.', { enum: ['create', 'show', 'note', 'pin', 'unpin', 'capture', 'graph', 'diffs', 'export'] }),
      title: string('Case title.'),
      case: object('Existing case state.'),
      text: string('Analyst note.'),
      observable: object('Observable {type,value}.'),
      enrichment: object('Evidence v2 enrichment result to capture.'),
      sightings: array('Optional cross-case sightings.', { type: 'object' }),
    }, ['operation']),
    annotations: { readOnlyHint: false },
  },
  {
    name: 'para11ax_report',
    title: 'PARA11AX report engine',
    description: 'Render or quality-check deterministic enrichment and investigation reports without filesystem access.',
    inputSchema: schema({
      kind: string('Report input kind.', { enum: ['enrichment', 'investigation'] }),
      operation: string('Report operation.', { enum: ['render', 'quality', 'manifest'] }),
      format: string('Enrichment render format.', { enum: ['text', 'html', 'pdf', 'csv', 'kql', 'navigator', 'stix', 'evidence'] }),
      snapshot: object('Evidence v2 enrichment snapshot.'),
      investigation: object('Investigation Workspace v2 state.'),
    }, ['kind', 'operation']),
    annotations: { readOnlyHint: true },
  },
  {
    name: 'para11ax_command',
    title: 'PARA11AX registered command',
    description: 'Execute a server-safe registered PARA11AX command by exact command id. Local-admin, filesystem, credential-template, browser-session, and host-shell capabilities are not exposed.',
    inputSchema: schema({
      commandId: string('Exact registered command id.'),
      args: array('Command arguments.', {}),
      input: object('Optional typed pipeline input, e.g. {type:"enrichment",value:{...}}.'),
    }, ['commandId']),
    annotations: { readOnlyHint: false },
  },
]);

function response(status, body, extraHeaders = {}) {
  return {
    status,
    headers: {
      ...securityHeaders(),
      'cache-control': 'no-store',
      'content-type': 'application/json; charset=utf-8',
      'mcp-protocol-version': MCP_PROTOCOL_VERSION,
      ...extraHeaders,
    },
    body,
  };
}

function headerValue(headers, name) {
  if (!headers) return undefined;
  if (typeof headers.get === 'function') return headers.get(name) ?? undefined;
  return headers[name] ?? headers[name.toLowerCase()] ?? headers[name.toUpperCase()];
}

function parseBody(request) {
  const declared = Number(headerValue(request?.headers, 'content-length'));
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) throw Object.assign(new Error('payload_too_large'), { status: 413 });
  let body = request?.body;
  if (typeof body === 'string') {
    if (Buffer.byteLength(body, 'utf8') > MAX_BODY_BYTES) throw Object.assign(new Error('payload_too_large'), { status: 413 });
    try { body = JSON.parse(body); } catch { throw Object.assign(new Error('parse_error'), { status: 400 }); }
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw Object.assign(new Error('invalid_request'), { status: 400 });
  if (Buffer.byteLength(JSON.stringify(body), 'utf8') > MAX_BODY_BYTES) throw Object.assign(new Error('payload_too_large'), { status: 413 });
  return body;
}

function rpcResult(id, result) {
  return { jsonrpc: '2.0', id: id ?? null, result };
}

function rpcError(id, code, message, data = undefined) {
  return { jsonrpc: '2.0', id: id ?? null, error: { code, message, ...(data === undefined ? {} : { data }) } };
}

function safeMessage(error) {
  const message = typeof error?.message === 'string' ? error.message : 'operation failed';
  return message.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 500) || 'operation failed';
}

function jsonText(value) {
  return JSON.stringify(value, null, 2);
}

function toolSuccess(value) {
  const structuredContent = value && typeof value === 'object' && !Array.isArray(value) ? value : { value };
  return {
    content: [{ type: 'text', text: jsonText(structuredContent) }],
    structuredContent,
    isError: false,
  };
}

function toolFailure(error) {
  const message = safeMessage(error);
  return { content: [{ type: 'text', text: message }], structuredContent: { error: message }, isError: true };
}

function remoteCommandAllowed(descriptor) {
  if (!descriptor || !descriptor.surfaces.includes('cli')) return false;
  if (DENIED_COMMAND_IDS.has(descriptor.id)) return false;
  if (DENIED_COMMAND_NAMESPACES.has(descriptor.namespace)) return false;
  if (descriptor.sideEffect === 'filesystem' || descriptor.sideEffect === 'local-admin') return false;
  return true;
}

function remoteCommandCatalog() {
  return COMMAND_REGISTRY.all().filter(remoteCommandAllowed).map(descriptor => ({
    id: descriptor.id,
    command: descriptor.tokens.join(' '),
    namespace: descriptor.namespace,
    auth: descriptor.auth,
    inputTypes: [...descriptor.inputTypes],
    outputType: descriptor.outputType,
    egressClass: descriptor.egressClass,
    sideEffect: descriptor.sideEffect,
    capabilities: [...descriptor.capabilities],
    usage: descriptor.usage,
    summary: descriptor.summary,
  }));
}

function innerRequest(env, body = undefined, method = 'POST') {
  return {
    method,
    headers: {
      authorization: `Bearer ${env.PARA11AX_TOKEN}`,
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(body === undefined ? {} : { body }),
  };
}

async function unwrap(result) {
  if (!result || result.status < 200 || result.status >= 300) {
    const message = typeof result?.body?.error === 'string' ? result.body.error : `operation_failed_${result?.status ?? 500}`;
    throw new Error(message);
  }
  return result.body;
}

function missionInput(args) {
  if (typeof args.content === 'string') return args.content;
  if (args.payload !== undefined) return JSON.stringify(args.payload);
  return null;
}

async function runMission(args) {
  const map = {
    new: 'mission-new', show: 'mission-show', profile_set: 'mission-profile-set', context_set: 'mission-context-set',
    relevance: 'mission-relevance', hunt_build: 'mission-hunt-build', kql_validate: 'mission-kql-validate',
    result_analyze: 'mission-result-analyze', servicenow: 'mission-servicenow', export: 'mission-export',
    import: 'mission-import', clear: 'mission-clear',
  };
  const handler = map[args.operation];
  if (!handler) throw new Error('unsupported mission operation');
  const content = missionInput(args);
  const commandArgs = handler === 'mission-kql-validate' ? [String(args.query ?? '')] : [];
  const outcome = await executeMissionCommand({
    handler,
    args: commandArgs,
    workspace: args.workspace ?? null,
    loadContent: async () => content,
  });
  return { workspace: outcome.workspace, output: outcome.output };
}

function runInvestigation(args, now) {
  if (args.operation === 'create') return { investigation: createInvestigation({ title: args.title, now }) };
  if (args.operation === 'import') return { investigation: importInvestigation(args.bundle) };
  const investigation = importInvestigation(args.investigation);
  if (args.operation === 'status') return { status: deriveInvestigationStatus(investigation), investigation };
  if (args.operation === 'export') return { bundle: exportInvestigation(investigation), investigation };
  if (args.operation === 'report') return { report: buildInvestigationReport(investigation), investigation };
  if (args.operation === 'report_text') return { artifact: { filename: 'investigation-report.txt', mimeType: 'text/plain;charset=utf-8', encoding: 'utf8', content: renderInvestigationText(investigation) }, investigation };
  if (args.operation === 'dispatch') {
    if (!args.action || typeof args.action !== 'object' || Array.isArray(args.action)) throw new Error('investigation action required');
    const next = reduceInvestigation(investigation, args.action, { now, buildReport: buildInvestigationReport });
    return { investigation: next, status: deriveInvestigationStatus(next) };
  }
  throw new Error('unsupported investigation operation');
}

function runCase(args, now) {
  if (args.operation === 'create') return { case: createCase({ title: args.title, now }) };
  const caseValue = structuredClone(args.case);
  validateCaseValue(caseValue);
  if (args.operation === 'show') return { case: caseValue };
  if (args.operation === 'note') return { case: addCaseNote(caseValue, args.text, { now }) };
  if (args.operation === 'pin') return { case: addCasePin(caseValue, args.observable, { now }) };
  if (args.operation === 'unpin') return { case: removeCasePin(caseValue, args.observable, { now }) };
  if (args.operation === 'capture') return { case: appendSnapshot(caseValue, args.enrichment, { now }) };
  if (args.operation === 'graph') return { case: caseValue, graph: buildCaseEvidenceGraph(caseValue, { sightings: args.sightings ?? [] }) };
  if (args.operation === 'diffs') return { case: caseValue, diffs: structuredClone(caseValue.diffs) };
  if (args.operation === 'export') return { case: caseValue, artifact: { filename: 'para11ax-case.json', mimeType: 'application/json;charset=utf-8', encoding: 'utf8', content: `${JSON.stringify(caseValue, null, 2)}\n` } };
  throw new Error('unsupported case operation');
}

function runReport(args, now) {
  if (args.kind === 'investigation') {
    const investigation = importInvestigation(args.investigation);
    if (args.operation === 'render') return { artifact: { filename: 'investigation-report.txt', mimeType: 'text/plain;charset=utf-8', encoding: 'utf8', content: renderInvestigationText(investigation) }, report: buildInvestigationReport(investigation) };
    if (args.operation === 'quality') return { ok: true, report: buildInvestigationReport(investigation) };
    if (args.operation === 'manifest') throw new Error('investigation manifest is not a registered in-memory report capability');
    throw new Error('unsupported investigation report operation');
  }
  const snapshot = args.snapshot;
  const generatedAt = now();
  if (args.operation === 'quality') return { quality: inspectNodeReportQuality(snapshot, { generatedAt }) };
  if (args.operation === 'manifest') return { manifest: buildNodeReportManifest(snapshot, { generatedAt, preset: 'all' }) };
  if (args.operation === 'render') return projectNodeReport(snapshot, args.format ?? 'text', { generatedAt });
  throw new Error('unsupported report operation');
}

export function createMcpHttpHandler({
  env = process.env,
  fetchImpl = fetch,
  now = () => new Date().toISOString(),
  nowMs = () => Date.now(),
} = {}) {
  const app = createApp({ env, fetchImpl, now, nowMs });
  const shodan = createShodanCommandHandler({ env, fetchImpl, nowMs });
  const userScanner = createUserScannerHandler({ env, fetchImpl, nowMs });
  const swarm = createGreyNoiseSwarmCommandHandler({ env, fetchImpl, nowMs });

  async function invokeTool(name, args = {}) {
    if (name === 'para11ax_capabilities') {
      const view = args.view ?? 'catalog';
      if (view === 'catalog') return { protocolVersion: MCP_PROTOCOL_VERSION, gatewayVersion: GATEWAY_VERSION, tools: TOOLS.map(({ name: toolName, title, description }) => ({ name: toolName, title, description })), commands: remoteCommandCatalog() };
      if (view === 'commands') return { commands: remoteCommandCatalog() };
      if (view === 'health') return { health: await unwrap(app.handleHealth(innerRequest(env, undefined, 'GET'))) };
      if (view === 'status') return { status: await unwrap(app.handleStatus(innerRequest(env, undefined, 'GET'))) };
      if (view === 'meta') return { meta: await unwrap(app.handleMeta({ method: 'GET', headers: {} })) };
      throw new Error('unsupported capabilities view');
    }
    if (name === 'para11ax_enrich') return { enrichment: await unwrap(app.handleEnrich(innerRequest(env, { indicator: args.indicator, ...(args.type ? { type: args.type } : {}), ...(args.profile ? { profile: args.profile } : {}) }))) };
    if (name === 'para11ax_batch') return { batch: await unwrap(app.handleBatch(innerRequest(env, { indicators: args.indicators, ...(args.profile ? { profile: args.profile } : {}) }))) };
    if (name === 'para11ax_provider') return { enrichment: await unwrap(app.handleProvider(innerRequest(env, { provider: args.provider, indicator: args.indicator, ...(args.type ? { type: args.type } : {}) }))) };
    if (name === 'para11ax_stix') return { bundle: await unwrap(app.handleStix(innerRequest(env, { indicator: args.indicator, ...(args.type ? { type: args.type } : {}), ...(args.profile ? { profile: args.profile } : {}) }))) };
    if (name === 'para11ax_shodan') return { result: await unwrap(shodan(innerRequest(env, args))) };
    if (name === 'para11ax_user_scan') return { result: await unwrap(userScanner(innerRequest(env, args))) };
    if (name === 'para11ax_swarm') {
      const result = await swarm(innerRequest(env, args));
      if (!result || result.status < 200 || result.status >= 300) return { result: await unwrap(result) };
      if (!result.binary) return { result: result.body };
      return {
        artifact: {
          filename: String(result.headers?.['content-disposition'] ?? '').match(/filename="([^"]+)"/)?.[1] ?? 'swarm-export.bin',
          mimeType: result.headers?.['content-type'] ?? 'application/octet-stream',
          encoding: 'base64',
          content: Buffer.from(result.body).toString('base64'),
        },
      };
    }
    if (name === 'para11ax_mission') return runMission(args);
    if (name === 'para11ax_investigation') return runInvestigation(args, now);
    if (name === 'para11ax_case') return runCase(args, now);
    if (name === 'para11ax_report') return runReport(args, now);
    if (name === 'para11ax_command') {
      const descriptor = COMMAND_REGISTRY.get(String(args.commandId ?? ''));
      if (!remoteCommandAllowed(descriptor)) throw new Error('registered command is not exposed over MCP');
      const executor = createNodeShellExecutor({ env, fetchImpl, now: () => new Date(now()), nowMs, registry: COMMAND_REGISTRY });
      const output = await executor.execute({
        descriptor,
        args: Array.isArray(args.args) ? args.args : [],
        input: args.input && typeof args.input === 'object' ? args.input : { type: 'void', value: null },
        context: { surface: 'mcp' },
      });
      return { command: descriptor.id, output };
    }
    throw new Error('unknown tool');
  }

  return async function handleMcp(request) {
    if (request?.method !== 'POST') return response(405, { error: 'method_not_allowed' }, { allow: 'POST' });
    if (!requireGatewayAuth(request, env.PARA11AX_TOKEN)) return response(401, { error: 'unauthorized' });
    const contentType = headerValue(request.headers, 'content-type');
    if (contentType && !String(contentType).toLowerCase().startsWith('application/json')) return response(415, { error: 'unsupported_media_type' });

    let body;
    try { body = parseBody(request); }
    catch (error) { return response(error.status ?? 400, rpcError(null, -32700, error.message === 'payload_too_large' ? 'Payload too large' : 'Parse error')); }

    const id = body.id ?? null;
    if (body.jsonrpc !== '2.0' || typeof body.method !== 'string') return response(400, rpcError(id, -32600, 'Invalid Request'));

    const requestedVersion = headerValue(request.headers, 'mcp-protocol-version');
    if (requestedVersion && ![MCP_PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION].includes(String(requestedVersion))) {
      return response(400, rpcError(id, -32602, 'Unsupported MCP protocol version', { supported: [MCP_PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION] }));
    }

    if (body.method === 'server/discover' || body.method === 'initialize') {
      return response(200, rpcResult(id, {
        protocolVersion: body.method === 'initialize' && body.params?.protocolVersion === LEGACY_PROTOCOL_VERSION ? LEGACY_PROTOCOL_VERSION : MCP_PROTOCOL_VERSION,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'para11ax', version: GATEWAY_VERSION },
        instructions: 'Authenticated PARA11AX cybersecurity control plane. Use explicit state handles for mission, investigation, and case workflows.',
      }));
    }
    if (body.method === 'notifications/initialized') return response(202, null);
    if (body.method === 'ping') return response(200, rpcResult(id, {}));
    if (body.method === 'tools/list') return response(200, rpcResult(id, { tools: TOOLS }));
    if (body.method === 'tools/call') {
      const name = body.params?.name;
      const args = body.params?.arguments ?? {};
      if (typeof name !== 'string' || !args || typeof args !== 'object' || Array.isArray(args)) return response(200, rpcResult(id, toolFailure(new Error('invalid tool call'))));
      try { return response(200, rpcResult(id, toolSuccess(await invokeTool(name, args)))); }
      catch (error) { return response(200, rpcResult(id, toolFailure(error))); }
    }
    return response(200, rpcError(id, -32601, 'Method not found'));
  };
}

export const MCP_TOOLS = TOOLS;
