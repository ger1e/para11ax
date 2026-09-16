const EXPECTED_TOOL_NAMES = Object.freeze([
  'para11ax_capabilities', 'para11ax_enrich', 'para11ax_batch', 'para11ax_provider',
  'para11ax_shodan', 'para11ax_swarm', 'para11ax_user_scan', 'para11ax_stix',
  'para11ax_mission', 'para11ax_investigation', 'para11ax_case', 'para11ax_report',
  'para11ax_command',
]);

const REPORT_FORMATS = Object.freeze(['text', 'html', 'pdf', 'csv', 'kql', 'navigator', 'stix', 'evidence']);
const KQL = 'DeviceNetworkEvents | where Timestamp > ago(24h) | project Timestamp, DeviceName, RemoteIP';
const PROFILE = Object.freeze({
  id: 'ga',
  name: 'PARA11AX GA Fixture',
  technologies: ['fortinet'],
  telemetry: ['DeviceNetworkEvents'],
});
const CONTEXT = Object.freeze({
  technologies: ['fortinet'],
  observedExploitation: true,
  requiredTelemetry: ['DeviceNetworkEvents'],
  evidenceConfidence: 0.8,
});
const HUNT = Object.freeze({
  subject: 'Remote-access credential abuse',
  hypothesis: 'Valid-account abuse may produce anomalous endpoint activity.',
  attackIds: ['T1078'],
  evidenceFingerprints: ['a'.repeat(64)],
  sourceReferences: ['https://example.org/research'],
  kqlCandidates: [KQL],
});
const CSV = 'DeviceName,RemoteIP\nhost-1,1.1.1.1\n';

function fail(code) {
  throw new Error(code);
}

function requireObject(value, code) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(code);
  return value;
}

function safeCode(error, fallback) {
  const value = String(error?.message ?? fallback).toLowerCase().replace(/[^a-z0-9_:-]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 64);
  return value || fallback;
}

function passed(extra = {}) {
  return Object.freeze({ status: 'pass', ...extra });
}

async function checked(fn, fallback) {
  try {
    return await fn();
  } catch (error) {
    return Object.freeze({ status: 'fail', error: safeCode(error, fallback) });
  }
}

function statusOk(value) {
  return value && value.status !== 'error' && value.status !== 'fail';
}

function evidenceCount(enrichment) {
  return Array.isArray(enrichment?.evidence) ? enrichment.evidence.length : 0;
}

function failureCount(enrichment) {
  return Array.isArray(enrichment?.failures) ? enrichment.failures.length : 0;
}

function scannerSummaryValid(summary) {
  return summary
    && Number.isFinite(Number(summary.totalScanned))
    && Number.isFinite(Number(summary.found))
    && Number.isFinite(Number(summary.errors));
}

function rangeFrom(nowIso) {
  const endMs = Date.parse(nowIso);
  if (!Number.isFinite(endMs)) fail('invalid_conformance_clock');
  return {
    startTime: new Date(endMs - 10 * 60_000).toISOString(),
    endTime: new Date(endMs - 60_000).toISOString(),
  };
}

async function capabilitiesCheck(invoke) {
  const views = ['catalog', 'health', 'status', 'meta', 'commands'];
  let catalog;
  for (const view of views) {
    const value = requireObject(await invoke('para11ax_capabilities', { view }), `capabilities_${view}_shape`);
    if (view === 'catalog') catalog = value;
    if (view === 'health' && value.health?.status !== 'ok') fail('capabilities_health_not_ok');
    if (view === 'status') requireObject(value.status, 'capabilities_status_shape');
    if (view === 'meta') requireObject(value.meta, 'capabilities_meta_shape');
    if (view === 'commands' && !Array.isArray(value.commands)) fail('capabilities_commands_shape');
  }
  const names = (catalog?.tools ?? []).map(tool => tool?.name).filter(Boolean).sort();
  if (names.length !== EXPECTED_TOOL_NAMES.length || names.some((name, index) => name !== [...EXPECTED_TOOL_NAMES].sort()[index])) fail('capabilities_catalog_mismatch');
  return passed({ checks: views.length, toolCount: names.length, commandCount: Array.isArray(catalog.commands) ? catalog.commands.length : 0 });
}

async function batchCheck(invoke) {
  const value = requireObject(await invoke('para11ax_batch', { indicators: ['1.1.1.1', 'example.com'], profile: 'fast' }), 'batch_shape');
  const batch = requireObject(value.batch, 'batch_result_shape');
  if (batch.inputCount !== 2 || !Array.isArray(batch.results) || batch.results.length !== 2) fail('batch_result_count');
  if (batch.results.some(item => !['ok', 'partial'].includes(item?.status))) fail('batch_item_failed');
  return passed({ inputCount: batch.inputCount, uniqueIndicators: Number(batch.uniqueIndicators ?? 0) });
}

async function providerCheck(invoke) {
  const value = requireObject(await invoke('para11ax_provider', { provider: 'cloudflare-dns', indicator: 'example.com', type: 'domain' }), 'provider_shape');
  const enrichment = requireObject(value.enrichment, 'provider_enrichment_shape');
  if (!statusOk(enrichment) || failureCount(enrichment) > 0) fail('provider_cloudflare_dns_failed');
  return passed({ provider: 'cloudflare-dns', evidenceCount: evidenceCount(enrichment) });
}

async function shodanCheck(invoke) {
  const value = requireObject(await invoke('para11ax_shodan', { command: 'info' }), 'shodan_shape');
  requireObject(value.result, 'shodan_info_shape');
  return passed({ command: 'info' });
}

async function swarmCheck(invoke, now) {
  const range = rangeFrom(now);
  const value = requireObject(await invoke('para11ax_swarm', {
    command: 'search', scope: 'demo', ...range, page: 1, pageSize: 1,
  }), 'swarm_shape');
  const result = requireObject(value.result, 'swarm_result_shape');
  if (result.command !== 'search' || result.source !== 'greynoise-swarm') fail('swarm_search_shape');
  requireObject(result.data, 'swarm_data_shape');
  return passed({ command: 'search', scope: 'demo' });
}

async function stixCheck(invoke) {
  const first = requireObject((await invoke('para11ax_stix', { indicator: '1.1.1.1', type: 'ip', profile: 'fast' })).bundle, 'stix_first_shape');
  const second = requireObject((await invoke('para11ax_stix', { indicator: '1.1.1.1', type: 'ip', profile: 'fast' })).bundle, 'stix_second_shape');
  if (first.type !== 'bundle' || second.type !== 'bundle' || first.id !== second.id) fail('stix_bundle_not_deterministic');
  const firstIds = (first.objects ?? []).map(item => item?.id).filter(Boolean).sort();
  const secondIds = (second.objects ?? []).map(item => item?.id).filter(Boolean).sort();
  if (JSON.stringify(firstIds) !== JSON.stringify(secondIds)) fail('stix_objects_not_deterministic');
  return passed({ objectCount: firstIds.length });
}

async function missionCheck(invoke) {
  let calls = 0;
  const call = async (operation, args = {}) => {
    calls += 1;
    const value = requireObject(await invoke('para11ax_mission', { operation, ...args }), `mission_${operation}_shape`);
    requireObject(value.workspace, `mission_${operation}_workspace`);
    return value;
  };

  let value = await call('new');
  let workspace = value.workspace;
  value = await call('show', { workspace }); workspace = value.workspace;
  value = await call('profile_set', { workspace, payload: PROFILE }); workspace = value.workspace;
  value = await call('context_set', { workspace, payload: CONTEXT }); workspace = value.workspace;
  value = await call('relevance', { workspace }); workspace = value.workspace;
  value = await call('hunt_build', { workspace, payload: HUNT }); workspace = value.workspace;
  value = await call('kql_validate', { workspace, query: KQL }); workspace = value.workspace;
  value = await call('result_analyze', { workspace, content: CSV }); workspace = value.workspace;
  value = await call('servicenow', { workspace }); workspace = value.workspace;
  value = await call('export', { workspace }); workspace = value.workspace;
  const content = value.output?.value?.content;
  if (typeof content !== 'string' || !content) fail('mission_export_content');
  value = await call('import', { workspace, content }); workspace = value.workspace;
  value = await call('clear', { workspace }); workspace = value.workspace;
  return passed({ checks: calls, finalRevision: Number(workspace.revision ?? 0) });
}

async function investigationCheck(invoke, enrichment) {
  requireObject(enrichment, 'investigation_enrichment_missing');
  let calls = 0;
  const invocationCode = (operation, args, error) => {
    const message = String(error?.message ?? '');
    const kind = message.endsWith('_transport_failed')
      ? 'transport'
      : message.endsWith('_failed')
        ? 'tool'
        : 'exception';
    const action = operation === 'dispatch'
      ? String(args?.action?.type ?? 'unknown').toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 24) || 'unknown'
      : null;
    return safeCode(new Error(['investigation', operation, action, kind].filter(Boolean).join('_')), 'investigation_invoke_failed');
  };
  const call = async (operation, args = {}) => {
    calls += 1;
    let result;
    try {
      result = await invoke('para11ax_investigation', { operation, ...args });
    } catch (error) {
      fail(invocationCode(operation, args, error));
    }
    return requireObject(result, `investigation_${operation}_shape`);
  };

  let value = await call('create', { title: 'PARA11AX GA Investigation' });
  let investigation = requireObject(value.investigation, 'investigation_create_state');
  const dispatch = async action => {
    value = await call('dispatch', { investigation, action });
    investigation = requireObject(value.investigation, 'investigation_dispatch_state');
  };

  await dispatch({ type: 'SCOPE_SET', profile: PROFILE, context: CONTEXT });
  await dispatch({ type: 'OBSERVABLE_ADD', observable: { type: enrichment.type, value: enrichment.indicator } });
  await dispatch({ type: 'EVIDENCE_CAPTURE', value: enrichment });
  await dispatch({ type: 'RELEVANCE_BUILD' });
  await dispatch({ type: 'HUNT_BUILD', value: HUNT });
  await dispatch({ type: 'KQL_VALIDATE', query: KQL });
  await dispatch({ type: 'RESULT_SET', value: '[]' });
  await dispatch({
    type: 'DISPOSITION_SET',
    value: {
      state: 'NO_EVIDENCE_IDENTIFIED', confidence: 'MEDIUM',
      rationale: 'No related activity was identified in the reviewed GA telemetry.',
      artifactIds: [], limitations: ['ga_fixture_scope'],
    },
  });
  await dispatch({ type: 'SERVICENOW_BUILD' });
  await dispatch({ type: 'REPORT_BUILD' });

  value = await call('status', { investigation });
  if (!value.status?.phase) fail('investigation_status_missing');
  value = await call('report', { investigation });
  requireObject(value.report, 'investigation_report_missing');
  value = await call('report_text', { investigation });
  if (typeof value.artifact?.content !== 'string' || !value.artifact.content) fail('investigation_report_text_missing');
  value = await call('export', { investigation });
  if (typeof value.bundle !== 'string' || !value.bundle) fail('investigation_export_missing');
  value = await call('import', { bundle: value.bundle });
  investigation = requireObject(value.investigation, 'investigation_import_state');
  return { surface: passed({ checks: calls, revision: Number(investigation.revision ?? 0) }), investigation };
}

async function caseCheck(invoke, enrichment) {
  requireObject(enrichment, 'case_enrichment_missing');
  let calls = 0;
  const call = async (operation, args = {}) => {
    calls += 1;
    return requireObject(await invoke('para11ax_case', { operation, ...args }), `case_${operation}_shape`);
  };

  let value = await call('create', { title: 'PARA11AX GA Case' });
  let caseValue = requireObject(value.case, 'case_create_state');
  value = await call('show', { case: caseValue }); caseValue = requireObject(value.case, 'case_show_state');
  value = await call('note', { case: caseValue, text: 'GA conformance note' }); caseValue = requireObject(value.case, 'case_note_state');
  const observable = { type: enrichment.type, value: enrichment.indicator };
  value = await call('pin', { case: caseValue, observable }); caseValue = requireObject(value.case, 'case_pin_state');
  value = await call('capture', { case: caseValue, enrichment }); caseValue = requireObject(value.case, 'case_capture_state');
  value = await call('graph', { case: caseValue }); requireObject(value.graph, 'case_graph_missing'); caseValue = requireObject(value.case, 'case_graph_state');
  value = await call('diffs', { case: caseValue }); if (!Array.isArray(value.diffs)) fail('case_diffs_missing'); caseValue = requireObject(value.case, 'case_diffs_state');
  value = await call('export', { case: caseValue }); if (typeof value.artifact?.content !== 'string' || !value.artifact.content) fail('case_export_missing'); caseValue = requireObject(value.case, 'case_export_state');
  value = await call('unpin', { case: caseValue, observable }); caseValue = requireObject(value.case, 'case_unpin_state');
  return passed({ checks: calls, snapshotCount: Array.isArray(caseValue.snapshots) ? caseValue.snapshots.length : 0 });
}

async function reportCheck(invoke, enrichment, investigation) {
  requireObject(enrichment, 'report_enrichment_missing');
  requireObject(investigation, 'report_investigation_missing');
  let calls = 0;
  const call = async args => {
    calls += 1;
    return requireObject(await invoke('para11ax_report', args), 'report_shape');
  };

  let value = await call({ kind: 'enrichment', operation: 'quality', snapshot: enrichment });
  if (value.quality?.ok !== true) fail('report_enrichment_quality');
  value = await call({ kind: 'enrichment', operation: 'manifest', snapshot: enrichment });
  requireObject(value.manifest, 'report_enrichment_manifest');
  for (const format of REPORT_FORMATS) {
    value = await call({ kind: 'enrichment', operation: 'render', format, snapshot: enrichment });
    if (typeof value.artifact?.content !== 'string' || !value.artifact.content) fail(`report_render_${format}`);
  }
  value = await call({ kind: 'investigation', operation: 'quality', investigation });
  if (value.ok !== true) fail('report_investigation_quality');
  value = await call({ kind: 'investigation', operation: 'render', investigation });
  if (typeof value.artifact?.content !== 'string' || !value.artifact.content) fail('report_investigation_render');
  value = await call({ kind: 'investigation', operation: 'manifest', investigation });
  requireObject(value.manifest, 'report_investigation_manifest');
  return passed({ checks: calls, enrichmentFormats: REPORT_FORMATS.length });
}

async function commandCheck(invoke) {
  const value = requireObject(await invoke('para11ax_command', { commandId: 'intel.validate', args: ['1.1.1.1'] }), 'command_shape');
  if (value.command !== 'intel.validate' || value.output?.value?.valid !== true || value.output?.value?.type !== 'ip') fail('command_validate_failed');
  return passed({ command: 'intel.validate' });
}

export async function runFullMcpConformance({
  invoke,
  enrichment,
  userScanner,
  now = () => new Date().toISOString(),
} = {}) {
  if (typeof invoke !== 'function') throw new TypeError('invoke required');
  const surfaces = {};

  surfaces.para11ax_enrich = statusOk(enrichment)
    ? passed({ evidenceCount: evidenceCount(enrichment), failureCount: failureCount(enrichment) })
    : Object.freeze({ status: 'fail', error: 'enrichment_preflight_failed' });
  surfaces.para11ax_user_scan = scannerSummaryValid(userScanner)
    ? passed({ totalScanned: Number(userScanner.totalScanned), found: Number(userScanner.found), errors: Number(userScanner.errors), skipped: Number(userScanner.skipped ?? 0) })
    : Object.freeze({ status: 'fail', error: 'user_scanner_preflight_failed' });

  const fixedNow = now();
  const independent = await Promise.all([
    checked(() => capabilitiesCheck(invoke), 'capabilities_failed'),
    checked(() => batchCheck(invoke), 'batch_failed'),
    checked(() => providerCheck(invoke), 'provider_failed'),
    checked(() => shodanCheck(invoke), 'shodan_failed'),
    checked(() => swarmCheck(invoke, fixedNow), 'swarm_failed'),
    checked(() => stixCheck(invoke), 'stix_failed'),
    checked(() => missionCheck(invoke), 'mission_failed'),
    checked(() => caseCheck(invoke, enrichment), 'case_failed'),
    checked(() => commandCheck(invoke), 'command_failed'),
  ]);

  [
    'para11ax_capabilities', 'para11ax_batch', 'para11ax_provider', 'para11ax_shodan',
    'para11ax_swarm', 'para11ax_stix', 'para11ax_mission', 'para11ax_case', 'para11ax_command',
  ].forEach((name, index) => { surfaces[name] = independent[index]; });

  let investigation = null;
  const investigationResult = await checked(async () => {
    const result = await investigationCheck(invoke, enrichment);
    investigation = result.investigation;
    return result.surface;
  }, 'investigation_failed');
  surfaces.para11ax_investigation = investigationResult;
  surfaces.para11ax_report = await checked(() => reportCheck(invoke, enrichment, investigation), 'report_failed');

  const ordered = Object.fromEntries(EXPECTED_TOOL_NAMES.map(name => [name, surfaces[name] ?? { status: 'fail', error: 'surface_missing' }]));
  const failed = Object.entries(ordered).filter(([, value]) => value.status !== 'pass').map(([name]) => name);
  return Object.freeze({
    status: failed.length ? 'fail' : 'pass',
    toolCount: EXPECTED_TOOL_NAMES.length,
    failed,
    surfaces: Object.freeze(ordered),
  });
}

export { EXPECTED_TOOL_NAMES, REPORT_FORMATS };
