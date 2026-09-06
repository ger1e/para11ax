const SCOPES = new Set(['workspace', 'demo']);
const EXPORT_TYPES = Object.freeze({ pcap: 'pcap', 'raw-source': 'rawSource', 'raw-destination': 'rawDestination' });
const PIVOT_FIELDS = new Set([
  'source.ip', 'destination.ip', 'source.port', 'destination.port', 'classification', 'protocol', 'ipProtocol',
  'sourceMetadata.asn', 'sourceMetadata.org', 'sourceMetadata.country_code',
  'destinationMetadata.asn', 'destinationMetadata.org', 'destinationMetadata.country_code',
  'gnTagMetadata.name', 'gnTagMetadata.slug', 'gnTagMetadata.category', 'gnTagMetadata.intention', 'gnTagMetadata.cves',
  'tls.ja3', 'tls.ja4', 'tcp.ja4t', 'suricata.signature', 'suricata.category', 'suricata.severity',
]);
const TIMESERIES_INTERVALS = new Set(['auto', '1s', '1m', '1h', '1d']);
const DIFF_WORKSPACES = new Set(['personal', 'community', 'greynoise']);
const DIFF_MODES = new Set(['source-only', 'both', 'all']);
const SESSION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const ISO8601 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;

function fail(message) { throw new TypeError(message); }
function validTime(value) { return ISO8601.test(value) && Number.isFinite(Date.parse(value)); }
function validRange(startTime, endTime) {
  return Boolean(startTime && endTime && validTime(startTime) && validTime(endTime) && Date.parse(startTime) < Date.parse(endTime));
}
function validQuery(value) {
  return Boolean(value && value.length <= 2048 && !/[\u0000-\u001f\u007f]/.test(value));
}
function validOpaque(value, max = 4096) {
  return Boolean(value && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value));
}

export function parseSwarmArgs(args) {
  const command = String(args[0] ?? '').toLowerCase();
  if (!['search', 'get', 'export', 'unique', 'timeseries', 'diff'].includes(command)) fail('usage: swarm <search|get|export|unique|timeseries|diff> ...');

  if (command === 'diff') {
    let query = null;
    let sourceWorkspace = 'personal';
    let targetWorkspace = 'greynoise';
    let mode = 'source-only';
    let size = 10;
    let nextToken = null;
    const valueFlags = new Set(['--query', '--source', '--target', '--mode', '--size', '--next-token']);
    for (let index = 1; index < args.length; index += 1) {
      const flag = String(args[index]);
      if (!valueFlags.has(flag)) fail(`unsupported swarm option: ${flag}`);
      const raw = args[index + 1];
      if (raw === undefined || String(raw).startsWith('--')) fail(`${flag} requires a value`);
      const value = String(raw).trim();
      if (flag === '--query') {
        if (!validQuery(value)) fail('swarm diff query must be 1..2048 printable characters');
        query = value;
      } else if (flag === '--source') {
        sourceWorkspace = value.toLowerCase();
        if (!DIFF_WORKSPACES.has(sourceWorkspace)) fail('swarm diff workspace must be personal, community, or greynoise');
      } else if (flag === '--target') {
        targetWorkspace = value.toLowerCase();
        if (!DIFF_WORKSPACES.has(targetWorkspace)) fail('swarm diff workspace must be personal, community, or greynoise');
      } else if (flag === '--mode') {
        mode = value.toLowerCase();
        if (!DIFF_MODES.has(mode)) fail('swarm diff mode must be source-only, both, or all');
      } else if (flag === '--size') {
        size = Number(value);
        if (!Number.isSafeInteger(size) || size < 1 || size > 100) fail('swarm diff size must be 1..100');
      } else if (flag === '--next-token') {
        if (!validOpaque(value)) fail('swarm diff next-token must be 1..4096 printable characters');
        nextToken = value;
      }
      index += 1;
    }
    if (!query) fail('swarm diff requires --query');
    if (sourceWorkspace === targetWorkspace) fail('swarm diff source and target must differ');
    return { command, query, sourceWorkspace, targetWorkspace, mode, size, nextToken };
  }

  let scope = 'workspace';

  if (command === 'get') {
    const sessionId = String(args[1] ?? '').trim();
    if (!SESSION_ID.test(sessionId)) fail('usage: swarm get <session-id> [--scope <workspace|demo>]');
    if (args.length === 2) return { command, sessionId, scope, startTime: null, endTime: null, query: null, page: null, pageSize: null, exportType: null };
    if (args.length !== 4 || args[2] !== '--scope') fail('usage: swarm get <session-id> [--scope <workspace|demo>]');
    scope = String(args[3] ?? '').toLowerCase();
    if (!SCOPES.has(scope)) fail('swarm scope must be workspace or demo');
    return { command, sessionId, scope, startTime: null, endTime: null, query: null, page: null, pageSize: null, exportType: null };
  }

  if (command === 'export') {
    const sessionId = String(args[1] ?? '').trim();
    const exportType = EXPORT_TYPES[String(args[2] ?? '').toLowerCase()];
    if (args.length !== 3 || !SESSION_ID.test(sessionId) || !exportType) fail('usage: swarm export <session-id> <pcap|raw-source|raw-destination>');
    return { command, sessionId, scope, startTime: null, endTime: null, query: null, page: null, pageSize: null, exportType };
  }

  let startTime = null;
  let endTime = null;
  let query = null;
  let page = command === 'search' ? 1 : null;
  let pageSize = command === 'search' ? 25 : null;
  let field = null;
  let includeCounts = command === 'unique' ? false : null;
  let interval = command === 'timeseries' ? 'auto' : null;
  let size = command === 'timeseries' ? 10 : null;

  const valueFlags = command === 'search'
    ? new Set(['--from', '--to', '--scope', '--query', '--page', '--page-size'])
    : command === 'unique'
      ? new Set(['--from', '--to', '--scope', '--query', '--field'])
      : new Set(['--from', '--to', '--scope', '--query', '--field', '--size', '--interval']);

  for (let index = 1; index < args.length; index += 1) {
    const flag = String(args[index]);
    if (command === 'unique' && flag === '--include-counts') {
      includeCounts = true;
      continue;
    }
    if (!valueFlags.has(flag)) fail(`unsupported swarm option: ${flag}`);
    const raw = args[index + 1];
    if (raw === undefined || String(raw).startsWith('--')) fail(`${flag} requires a value`);
    const value = String(raw).trim();
    if (flag === '--from') startTime = value;
    else if (flag === '--to') endTime = value;
    else if (flag === '--scope') {
      scope = value.toLowerCase();
      if (!SCOPES.has(scope)) fail('swarm scope must be workspace or demo');
    } else if (flag === '--query') {
      if (!validQuery(value)) fail('swarm query must be 1..2048 printable characters');
      query = value;
    } else if (flag === '--page') {
      page = Number(value);
      if (!Number.isSafeInteger(page) || page < 1 || page > 10000) fail('swarm page must be 1..10000');
    } else if (flag === '--page-size') {
      pageSize = Number(value);
      if (!Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > 100) fail('swarm page-size must be 1..100');
    } else if (flag === '--field') {
      if (!PIVOT_FIELDS.has(value)) fail('unsupported swarm pivot field');
      field = value;
    } else if (flag === '--size') {
      size = Number(value);
      if (!Number.isSafeInteger(size) || size < 1 || size > 100) fail('swarm timeseries size must be 1..100');
    } else if (flag === '--interval') {
      interval = value;
      if (!TIMESERIES_INTERVALS.has(interval)) fail('swarm timeseries interval must be auto, 1s, 1m, 1h, or 1d');
    }
    index += 1;
  }

  if (!validRange(startTime, endTime)) fail(`swarm ${command} requires valid --from and --to ISO-8601 timestamps with from < to`);
  if (command === 'search') return { command, sessionId: null, scope, startTime, endTime, query, page, pageSize, exportType: null };
  if (command === 'unique') {
    if (!field) fail('swarm unique requires --field');
    return { command, sessionId: null, scope, startTime, endTime, query, page: null, pageSize: null, exportType: null, field, includeCounts, interval: null, size: null };
  }
  return { command, sessionId: null, scope, startTime, endTime, query, page: null, pageSize: null, exportType: null, field, includeCounts: null, interval, size };
}

export const SWARM_COMPLETIONS = Object.freeze(['search', 'get', 'export', 'unique', 'timeseries', 'diff']);
