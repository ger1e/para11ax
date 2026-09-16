import test from 'node:test';
import assert from 'node:assert/strict';

import { createMcpHttpHandler, MCP_PROTOCOL_VERSION } from '../src/mcp/transport.js';
import { runFullMcpConformance } from '../src/mcp/ga-conformance.js';

const TOKEN = 'test-mcp-token';
const TOOL_NAMES = [
  'para11ax_capabilities', 'para11ax_enrich', 'para11ax_batch', 'para11ax_provider',
  'para11ax_shodan', 'para11ax_swarm', 'para11ax_user_scan', 'para11ax_stix',
  'para11ax_mission', 'para11ax_investigation', 'para11ax_case', 'para11ax_report',
  'para11ax_command',
];

const NOW = '2026-09-11T19:00:00.000Z';
const PROFILE = { id: 'client', name: 'Example Client', technologies: ['fortinet'], telemetry: ['DeviceNetworkEvents'] };
const CONTEXT = { technologies: ['fortinet'], requiredTelemetry: ['devicenetworkevents'], observedExploitation: true };
const KQL = 'DeviceNetworkEvents | where Timestamp > ago(24h) | project Timestamp, DeviceName, RemoteIP';
const HUNT = {
  subject: 'Remote-access credential abuse',
  hypothesis: 'Valid-account abuse may produce anomalous endpoint activity.',
  attackIds: ['T1078'], evidenceFingerprints: ['a'.repeat(64)],
  sourceReferences: ['https://example.test/research'], kqlCandidates: [KQL],
};
const ENRICHMENT = {
  schemaVersion: '2.0', gatewayVersion: '2.0.0', requestId: 'request-1',
  type: 'ip', indicator: '1.1.1.1', queriedAt: NOW, status: 'ok',
  evidence: [{ provider: 'fixture', references: ['https://example.test/research'] }],
  relationships: [], failures: [],
};

function request(method, params = {}, id = 1) {
  return {
    method: 'POST',
    headers: {
      authorization: `Bearer ${TOKEN}`,
      'content-type': 'application/json',
      'mcp-protocol-version': MCP_PROTOCOL_VERSION,
      'mcp-method': method,
      ...(method === 'tools/call' ? { 'mcp-name': params.name } : {}),
    },
    body: { jsonrpc: '2.0', id, method, params },
  };
}

function fakeInvokeRecorder() {
  const calls = [];
  let missionRevision = 0;
  let investigationRevision = 0;
  let caseRevision = 0;

  async function invoke(name, args = {}) {
    calls.push({ name, args: structuredClone(args) });
    if (name === 'para11ax_capabilities') {
      if (args.view === 'catalog') return { protocolVersion: MCP_PROTOCOL_VERSION, tools: TOOL_NAMES.map(toolName => ({ name: toolName })), commands: [{ id: 'intel.validate' }] };
      if (args.view === 'commands') return { commands: [{ id: 'intel.validate' }] };
      if (args.view === 'health') return { health: { status: 'ok' } };
      if (args.view === 'status') return { status: { gatewayVersion: '2.0.0' } };
      if (args.view === 'meta') return { meta: { gatewayVersion: '2.0.0' } };
    }
    if (name === 'para11ax_batch') return { batch: { inputCount: 2, uniqueIndicators: 2, results: [{ status: 'ok' }, { status: 'partial' }] } };
    if (name === 'para11ax_provider') return { enrichment: { ...ENRICHMENT, indicator: 'example.com', type: 'domain' } };
    if (name === 'para11ax_shodan') return { result: { plan: 'dev', queryCredits: 100 } };
    if (name === 'para11ax_swarm') return { result: { source: 'greynoise-swarm', command: 'search', data: { sessions: [] } } };
    if (name === 'para11ax_stix') return { bundle: { type: 'bundle', id: 'bundle--stable', objects: [{ type: 'indicator', id: 'indicator--stable' }] } };
    if (name === 'para11ax_mission') {
      if (args.operation === 'new') missionRevision = 0;
      else missionRevision += 1;
      const workspace = { schemaVersion: 'mission-workspace-v1.0', revision: missionRevision, hunt: { state: missionRevision >= 4 ? 'READY' : 'EMPTY' }, result: { state: missionRevision >= 6 ? 'RESULTS_PRESENT' : 'EMPTY' } };
      if (args.operation === 'export') return { workspace, output: { value: { content: JSON.stringify(workspace) } } };
      return { workspace, output: { value: {} } };
    }
    if (name === 'para11ax_investigation') {
      if (args.operation === 'create') investigationRevision = 0;
      else if (args.operation === 'dispatch') investigationRevision += 1;
      const investigation = { schemaVersion: 'investigation-workspace-v2.0', id: 'inv-1', title: 'GA', revision: investigationRevision };
      if (args.operation === 'status') return { investigation, status: { phase: 'REPORT_READY' } };
      if (args.operation === 'report') return { investigation, report: { title: 'GA' } };
      if (args.operation === 'report_text') return { investigation, artifact: { filename: 'investigation-report.txt', mimeType: 'text/plain;charset=utf-8', encoding: 'utf8', content: 'GA' } };
      if (args.operation === 'export') return { investigation, bundle: JSON.stringify(investigation) };
      return { investigation };
    }
    if (name === 'para11ax_case') {
      if (args.operation === 'create') caseRevision = 0;
      else caseRevision += 1;
      const caseValue = { schemaVersion: 'analyst-case-v1.0', id: 'case-1', title: 'GA', revision: caseRevision, notes: args.operation === 'note' ? [{ text: args.text }] : [], pins: [], snapshots: [], diffs: [] };
      if (args.operation === 'graph') return { case: caseValue, graph: { nodes: [], edges: [] } };
      if (args.operation === 'diffs') return { case: caseValue, diffs: [] };
      if (args.operation === 'export') return { case: caseValue, artifact: { filename: 'para11ax-case.json', mimeType: 'application/json;charset=utf-8', encoding: 'utf8', content: JSON.stringify(caseValue) } };
      return { case: caseValue };
    }
    if (name === 'para11ax_report') {
      if (args.operation === 'quality') return args.kind === 'investigation' ? { ok: true, report: { title: 'GA' } } : { quality: { ok: true } };
      if (args.operation === 'manifest') return { manifest: { manifestVersion: '1.0', files: [] } };
      return { artifact: { filename: `report.${args.format ?? 'txt'}`, mimeType: 'text/plain', encoding: 'utf8', content: 'ok' }, report: { title: 'GA' } };
    }
    if (name === 'para11ax_command') return { command: 'intel.validate', output: { value: { valid: true, type: 'ip', value: '1.1.1.1' } } };
    throw new Error(`unexpected tool ${name}`);
  }

  return { invoke, calls };
}

async function toolCall(handle, name, args, id) {
  const response = await handle(request('tools/call', { name, arguments: args }, id));
  assert.equal(response.body.result.isError, false, response.body.result.content?.[0]?.text);
  return response.body.result.structuredContent;
}

test('full GA conformance exercises all 13 MCP tools and every local stateful/report operation', async () => {
  const { invoke, calls } = fakeInvokeRecorder();
  const result = await runFullMcpConformance({
    invoke,
    enrichment: ENRICHMENT,
    userScanner: { totalScanned: 260, found: 10, notFound: 220, errors: 30, skipped: 0 },
    now: () => NOW,
  });

  assert.equal(result.status, 'pass', JSON.stringify(result, null, 2));
  assert.deepEqual(Object.keys(result.surfaces).sort(), [...TOOL_NAMES].sort());
  assert.ok(Object.values(result.surfaces).every(surface => surface.status === 'pass'));
  assert.deepEqual(new Set(calls.map(call => call.name)), new Set(TOOL_NAMES.filter(name => !['para11ax_enrich', 'para11ax_user_scan'].includes(name))));

  const capabilityViews = calls.filter(call => call.name === 'para11ax_capabilities').map(call => call.args.view);
  assert.deepEqual(capabilityViews, ['catalog', 'health', 'status', 'meta', 'commands']);

  const missionOps = calls.filter(call => call.name === 'para11ax_mission').map(call => call.args.operation);
  for (const op of ['new', 'show', 'profile_set', 'context_set', 'relevance', 'hunt_build', 'kql_validate', 'result_analyze', 'servicenow', 'export', 'import', 'clear']) assert.ok(missionOps.includes(op), op);

  const investigationOps = calls.filter(call => call.name === 'para11ax_investigation').map(call => call.args.operation);
  for (const op of ['create', 'status', 'dispatch', 'report', 'report_text', 'export', 'import']) assert.ok(investigationOps.includes(op), op);

  const caseOps = calls.filter(call => call.name === 'para11ax_case').map(call => call.args.operation);
  for (const op of ['create', 'show', 'note', 'pin', 'unpin', 'capture', 'graph', 'diffs', 'export']) assert.ok(caseOps.includes(op), op);

  const enrichmentFormats = calls
    .filter(call => call.name === 'para11ax_report' && call.args.kind === 'enrichment' && call.args.operation === 'render')
    .map(call => call.args.format);
  assert.deepEqual(enrichmentFormats, ['text', 'html', 'pdf', 'csv', 'kql', 'navigator', 'stix', 'evidence']);
  assert.ok(calls.some(call => call.name === 'para11ax_report' && call.args.kind === 'investigation' && call.args.operation === 'manifest'));
});

test('investigation report manifest is an advertised in-memory MCP capability', async () => {
  const handle = createMcpHttpHandler({ env: { PARA11AX_TOKEN: TOKEN }, now: () => NOW });
  let id = 1;
  let state = await toolCall(handle, 'para11ax_investigation', { operation: 'create', title: 'GA manifest' }, id++);
  let investigation = state.investigation;

  const dispatch = async action => {
    state = await toolCall(handle, 'para11ax_investigation', { operation: 'dispatch', investigation, action }, id++);
    investigation = state.investigation;
  };

  await dispatch({ type: 'SCOPE_SET', profile: PROFILE, context: CONTEXT });
  await dispatch({ type: 'OBSERVABLE_ADD', observable: { type: 'ip', value: ENRICHMENT.indicator } });
  await dispatch({ type: 'EVIDENCE_CAPTURE', value: ENRICHMENT });
  await dispatch({ type: 'RELEVANCE_BUILD' });
  await dispatch({ type: 'HUNT_BUILD', value: HUNT });
  await dispatch({ type: 'KQL_VALIDATE', query: KQL });
  await dispatch({ type: 'RESULT_SET', value: '[]' });
  await dispatch({
    type: 'DISPOSITION_SET',
    value: {
      state: 'NO_EVIDENCE_IDENTIFIED', confidence: 'MEDIUM',
      rationale: 'No related activity was identified in the reviewed telemetry.',
      artifactIds: [], limitations: ['telemetry_scope_limited'],
    },
  });
  await dispatch({ type: 'SERVICENOW_BUILD' });
  await dispatch({ type: 'REPORT_BUILD' });

  const manifest = await toolCall(handle, 'para11ax_report', {
    kind: 'investigation', operation: 'manifest', investigation,
  }, id++);
  assert.equal(manifest.manifest.manifestVersion, '1.0');
  assert.equal(manifest.manifest.investigationId, investigation.id);
  assert.equal(manifest.manifest.investigationRevision, investigation.revision);
  assert.match(manifest.manifest.reportSha256, /^[a-f0-9]{64}$/);
  assert.equal(manifest.manifest.files.length, 1);
  assert.equal(manifest.manifest.files[0].sha256, manifest.manifest.reportSha256);
});
