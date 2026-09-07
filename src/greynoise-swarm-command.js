import { randomUUID } from 'node:crypto';
import { requireGatewayAuth } from './core/auth.js';
import { securityHeaders } from './core/http.js';

const MAX_BODY_BYTES = 8 * 1024;
const MAX_JSON_RESPONSE_BYTES = 4 * 1024 * 1024;
const MAX_EXPORT_BYTES = 4 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_QUERY_LENGTH = 2048;
const MAX_DIFF_TOKEN_LENGTH = 4096;
const MAX_PAGE = 10_000;
const MAX_PAGE_SIZE = 100;
const DEFAULT_PAGE_SIZE = 25;
const MAX_TIMESERIES_SIZE = 100;
const DEFAULT_TIMESERIES_SIZE = 10;
const MAX_DIFF_SIZE = 100;
const DEFAULT_DIFF_SIZE = 10;
const SCOPES = new Set(['workspace', 'demo']);
const COMMANDS = new Set(['search', 'get', 'export', 'unique', 'timeseries', 'diff']);
const EXPORT_TYPES = new Set(['pcap', 'rawSource', 'rawDestination']);
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
const CONTROL = /[\u0000-\u001f\u007f]/g;

function response(status, body, extraHeaders = {}, binary = false) {
  return {
    status,
    headers: { ...securityHeaders(), 'cache-control': 'no-store', ...extraHeaders },
    body,
    ...(binary ? { binary: true } : {}),
  };
}

function errorResponse(status, error, requestId = null) {
  return response(status, { error, ...(requestId ? { requestId } : {}) });
}

function headerValue(headers, name) {
  if (!headers) return undefined;
  if (typeof headers.get === 'function') return headers.get(name) ?? undefined;
  return headers[name] ?? headers[name.toLowerCase()] ?? headers[name.toUpperCase()];
}

function isJsonMediaType(value) {
  const mediaType = String(value || '').split(';', 1)[0].trim().toLowerCase();
  return mediaType === 'application/json' || mediaType.endsWith('+json');
}

function parseBody(request) {
  const contentLength = Number(headerValue(request.headers, 'content-length'));
  if (Number.isFinite(contentLength) && contentLength > MAX_BODY_BYTES) throw Object.assign(new Error('payload_too_large'), { status: 413 });
  let body = request.body;
  if (typeof body === 'string') {
    if (Buffer.byteLength(body, 'utf8') > MAX_BODY_BYTES) throw Object.assign(new Error('payload_too_large'), { status: 413 });
    try { body = JSON.parse(body); } catch { throw Object.assign(new Error('invalid_request'), { status: 400 }); }
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw Object.assign(new Error('invalid_request'), { status: 400 });
  if (Buffer.byteLength(JSON.stringify(body), 'utf8') > MAX_BODY_BYTES) throw Object.assign(new Error('payload_too_large'), { status: 413 });
  return body;
}

function validTimestamp(value) {
  return typeof value === 'string' && ISO8601.test(value) && Number.isFinite(Date.parse(value));
}

function validRange(startTime, endTime) {
  return validTimestamp(startTime) && validTimestamp(endTime) && Date.parse(startTime) < Date.parse(endTime);
}

function validPrintable(value, max) {
  return typeof value === 'string' && value.length >= 1 && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value);
}

function cleanString(value, max = 4096) {
  return String(value).replace(CONTROL, ' ').trim().slice(0, max);
}

function sanitize(value, depth = 0) {
  if (depth > 6 || value === undefined) return null;
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'string') return cleanString(value);
  if (Array.isArray(value)) return value.slice(0, 100).map(item => sanitize(item, depth + 1));
  if (typeof value !== 'object') return null;
  const output = {};
  for (const [rawKey, rawValue] of Object.entries(value).slice(0, 128)) {
    const key = cleanString(rawKey, 128);
    if (!key || key === '__proto__' || key === 'prototype' || key === 'constructor') continue;
    output[key] = sanitize(rawValue, depth + 1);
  }
  return output;
}

function validateRequest(body) {
  const allowed = new Set([
    'command', 'sessionId', 'scope', 'startTime', 'endTime', 'query', 'page', 'pageSize', 'exportType',
    'field', 'includeCounts', 'interval', 'size', 'sourceWorkspace', 'targetWorkspace', 'mode', 'nextToken',
  ]);
  if (Object.keys(body).some(key => !allowed.has(key))) throw new Error('unsupported_request_field');

  const command = typeof body.command === 'string' ? body.command.trim().toLowerCase() : '';
  if (!COMMANDS.has(command)) throw new Error('invalid_swarm_command');
  const scope = command === 'diff' ? null : (body.scope === undefined || body.scope === null ? 'workspace' : String(body.scope).trim().toLowerCase());
  if (scope !== null && !SCOPES.has(scope)) throw new Error('invalid_swarm_scope');
  const sessionId = body.sessionId === undefined || body.sessionId === null ? null : String(body.sessionId).trim();
  const startTime = body.startTime === undefined || body.startTime === null ? null : String(body.startTime).trim();
  const endTime = body.endTime === undefined || body.endTime === null ? null : String(body.endTime).trim();
  const query = body.query === undefined || body.query === null ? null : String(body.query).trim();
  const page = body.page === undefined || body.page === null ? 1 : Number(body.page);
  const pageSize = body.pageSize === undefined || body.pageSize === null ? DEFAULT_PAGE_SIZE : Number(body.pageSize);
  const exportType = body.exportType === undefined || body.exportType === null ? null : String(body.exportType).trim();
  const field = body.field === undefined || body.field === null ? null : String(body.field).trim();
  const includeCounts = body.includeCounts === undefined || body.includeCounts === null ? false : body.includeCounts;
  const interval = body.interval === undefined || body.interval === null ? 'auto' : String(body.interval).trim();
  const size = body.size === undefined || body.size === null ? (command === 'diff' ? DEFAULT_DIFF_SIZE : DEFAULT_TIMESERIES_SIZE) : Number(body.size);
  const sourceWorkspace = body.sourceWorkspace === undefined || body.sourceWorkspace === null ? 'personal' : String(body.sourceWorkspace).trim().toLowerCase();
  const targetWorkspace = body.targetWorkspace === undefined || body.targetWorkspace === null ? 'greynoise' : String(body.targetWorkspace).trim().toLowerCase();
  const mode = body.mode === undefined || body.mode === null ? 'source-only' : String(body.mode).trim().toLowerCase();
  const nextToken = body.nextToken === undefined || body.nextToken === null ? null : String(body.nextToken).trim();

  if (sessionId && !SESSION_ID.test(sessionId)) throw new Error('invalid_swarm_session_id');
  if (query && !validPrintable(query, MAX_QUERY_LENGTH)) throw new Error('invalid_swarm_query');

  if (command === 'search') {
    if (sessionId || exportType || field || body.includeCounts !== undefined || body.interval !== undefined || body.size !== undefined || body.sourceWorkspace !== undefined || body.targetWorkspace !== undefined || body.mode !== undefined || body.nextToken !== undefined || !validRange(startTime, endTime)) throw new Error('invalid_swarm_search_request');
    if (!Number.isSafeInteger(page) || page < 1 || page > MAX_PAGE) throw new Error('invalid_swarm_page');
    if (!Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > MAX_PAGE_SIZE) throw new Error('invalid_swarm_page_size');
  } else if (command === 'get') {
    if (!sessionId || startTime || endTime || query || body.page !== undefined || body.pageSize !== undefined || exportType || field || body.includeCounts !== undefined || body.interval !== undefined || body.size !== undefined || body.sourceWorkspace !== undefined || body.targetWorkspace !== undefined || body.mode !== undefined || body.nextToken !== undefined) throw new Error('invalid_swarm_get_request');
  } else if (command === 'export') {
    if (!sessionId || startTime || endTime || query || body.page !== undefined || body.pageSize !== undefined || !EXPORT_TYPES.has(exportType) || field || body.includeCounts !== undefined || body.interval !== undefined || body.size !== undefined || body.sourceWorkspace !== undefined || body.targetWorkspace !== undefined || body.mode !== undefined || body.nextToken !== undefined) throw new Error('invalid_swarm_export_request');
    if (scope === 'demo') throw new Error('swarm_demo_export_unsupported');
  } else if (command === 'unique') {
    if (sessionId || exportType || body.page !== undefined || body.pageSize !== undefined || body.interval !== undefined || body.size !== undefined || body.sourceWorkspace !== undefined || body.targetWorkspace !== undefined || body.mode !== undefined || body.nextToken !== undefined || !validRange(startTime, endTime)) throw new Error('invalid_swarm_unique_request');
    if (!field || !PIVOT_FIELDS.has(field)) throw new Error('invalid_swarm_field');
    if (typeof includeCounts !== 'boolean') throw new Error('invalid_swarm_include_counts');
  } else if (command === 'timeseries') {
    if (sessionId || exportType || body.page !== undefined || body.pageSize !== undefined || body.includeCounts !== undefined || body.sourceWorkspace !== undefined || body.targetWorkspace !== undefined || body.mode !== undefined || body.nextToken !== undefined || !validRange(startTime, endTime)) throw new Error('invalid_swarm_timeseries_request');
    if (field && !PIVOT_FIELDS.has(field)) throw new Error('invalid_swarm_field');
    if (!Number.isSafeInteger(size) || size < 1 || size > MAX_TIMESERIES_SIZE) throw new Error('invalid_swarm_size');
    if (!TIMESERIES_INTERVALS.has(interval)) throw new Error('invalid_swarm_interval');
  } else {
    if (body.scope !== undefined || sessionId || startTime || endTime || body.page !== undefined || body.pageSize !== undefined || exportType || field || body.includeCounts !== undefined || body.interval !== undefined) throw new Error('invalid_swarm_diff_request');
    if (!query) throw new Error('invalid_swarm_query');
    if (!DIFF_WORKSPACES.has(sourceWorkspace) || !DIFF_WORKSPACES.has(targetWorkspace)) throw new Error('invalid_swarm_diff_workspace');
    if (sourceWorkspace === targetWorkspace) throw new Error('invalid_swarm_diff_workspace_pair');
    if (!DIFF_MODES.has(mode)) throw new Error('invalid_swarm_diff_mode');
    if (!Number.isSafeInteger(size) || size < 1 || size > MAX_DIFF_SIZE) throw new Error('invalid_swarm_diff_size');
    if (nextToken !== null && !validPrintable(nextToken, MAX_DIFF_TOKEN_LENGTH)) throw new Error('invalid_swarm_diff_next_token');
  }

  return { command, sessionId, scope, startTime, endTime, query, page, pageSize, exportType, field, includeCounts, interval, size, sourceWorkspace, targetWorkspace, mode, nextToken };
}

function addRangeQuery(url, scan) {
  url.searchParams.set('scope', scan.scope);
  url.searchParams.set('start_time', scan.startTime);
  url.searchParams.set('end_time', scan.endTime);
  if (scan.query) url.searchParams.set('query', scan.query);
}

function buildUpstream(scan) {
  const url = new URL('https://api.greynoise.io');
  if (scan.command === 'diff') {
    url.pathname = '/v3/workspaces/diff';
    const body = JSON.stringify({
      query: scan.query,
      source_workspace: scan.sourceWorkspace,
      target_workspace: scan.targetWorkspace,
      size: scan.size,
      ...(scan.nextToken ? { next_token: scan.nextToken } : {}),
      ips_from_source: scan.mode === 'source-only',
      require_both_workspaces: scan.mode === 'both',
    });
    if (Buffer.byteLength(body, 'utf8') > MAX_BODY_BYTES) throw new Error('invalid_swarm_diff_request');
    return { url, method: 'POST', body };
  }
  if (scan.command === 'search') {
    url.pathname = '/v3/sessions';
    addRangeQuery(url, scan);
    url.searchParams.set('page', String(scan.page));
    url.searchParams.set('page_size', String(scan.pageSize));
    url.searchParams.set('sort_by', 'lastPacket');
    url.searchParams.set('sort_desc', 'true');
  } else if (scan.command === 'unique') {
    url.pathname = '/v3/sessions/unique';
    addRangeQuery(url, scan);
    url.searchParams.set('field', scan.field);
    url.searchParams.set('include_counts', String(scan.includeCounts));
  } else if (scan.command === 'timeseries') {
    url.pathname = '/v3/sessions/timeseries';
    addRangeQuery(url, scan);
    if (scan.field) url.searchParams.set('field', scan.field);
    url.searchParams.set('size', String(scan.size));
    url.searchParams.set('interval', scan.interval);
  } else {
    url.pathname = `/v3/sessions/${encodeURIComponent(scan.sessionId)}${scan.command === 'export' ? '/export' : ''}`;
    url.searchParams.set('scope', scan.scope);
    if (scan.command === 'export') url.searchParams.set('type', scan.exportType);
  }
  return { url, method: 'GET', body: undefined };
}

async function readJson(upstream) {
  const declared = Number(upstream.headers?.get?.('content-length'));
  if (Number.isFinite(declared) && declared > MAX_JSON_RESPONSE_BYTES) throw new Error('swarm_response_too_large');
  const bytes = new Uint8Array(await upstream.arrayBuffer());
  if (bytes.byteLength > MAX_JSON_RESPONSE_BYTES) throw new Error('swarm_response_too_large');
  let parsed;
  try { parsed = JSON.parse(new TextDecoder().decode(bytes)); }
  catch { throw new Error('invalid_swarm_response'); }
  const data = sanitize(parsed);
  if (Buffer.byteLength(JSON.stringify(data), 'utf8') > MAX_JSON_RESPONSE_BYTES) throw new Error('swarm_response_too_large');
  return data;
}

async function readBinary(upstream) {
  const declared = Number(upstream.headers?.get?.('content-length'));
  if (Number.isFinite(declared) && declared > MAX_EXPORT_BYTES) throw new Error('swarm_export_too_large');
  const bytes = new Uint8Array(await upstream.arrayBuffer());
  if (bytes.byteLength > MAX_EXPORT_BYTES) throw new Error('swarm_export_too_large');
  return bytes;
}

function filenameFor(scan) {
  if (scan.exportType === 'pcap') return `${scan.sessionId}.pcap`;
  if (scan.exportType === 'rawSource') return `${scan.sessionId}-raw-source.bin`;
  return `${scan.sessionId}-raw-destination.bin`;
}

function mapUpstreamError(status, requestId) {
  if (status === 400) return errorResponse(400, 'swarm_query_rejected', requestId);
  if (status === 401 || status === 403) return errorResponse(502, 'swarm_auth_or_entitlement_failed', requestId);
  if (status === 404) return errorResponse(404, 'swarm_no_result', requestId);
  if (status === 429) return errorResponse(429, 'swarm_rate_limited', requestId);
  return errorResponse(502, 'swarm_upstream_error', requestId);
}

function resultInput(scan) {
  if (scan.command === 'diff') {
    return {
      query: scan.query,
      sourceWorkspace: scan.sourceWorkspace,
      targetWorkspace: scan.targetWorkspace,
      mode: scan.mode,
      size: scan.size,
      ...(scan.nextToken ? { nextToken: scan.nextToken } : {}),
    };
  }
  return {
    scope: scan.scope,
    ...(scan.sessionId ? { sessionId: scan.sessionId } : {}),
    ...(scan.startTime ? { startTime: scan.startTime, endTime: scan.endTime } : {}),
    ...(scan.query ? { query: scan.query } : {}),
    ...(scan.command === 'search' ? { page: scan.page, pageSize: scan.pageSize } : {}),
    ...(scan.field ? { field: scan.field } : {}),
    ...(scan.command === 'unique' ? { includeCounts: scan.includeCounts } : {}),
    ...(scan.command === 'timeseries' ? { size: scan.size, interval: scan.interval } : {}),
  };
}

export function createGreyNoiseSwarmCommandHandler({
  env = process.env,
  fetchImpl = fetch,
  nowMs = () => Date.now(),
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  return async function handleGreyNoiseSwarmCommand(request) {
    if (request?.method !== 'POST') return errorResponse(405, 'method_not_allowed');
    if (!requireGatewayAuth(request, env.PARA11AX_TOKEN)) return errorResponse(401, 'unauthorized');
    const contentType = headerValue(request.headers, 'content-type');
    if (contentType && !isJsonMediaType(contentType)) return errorResponse(415, 'unsupported_media_type');
    if (!env.GREYNOISE_API_KEY) return errorResponse(503, 'greynoise_unconfigured');

    let body;
    try { body = parseBody(request); }
    catch (error) { return errorResponse(error.status ?? 400, error.message === 'payload_too_large' ? 'payload_too_large' : 'invalid_request'); }

    let scan;
    try { scan = validateRequest(body); }
    catch (error) { return errorResponse(400, error.message); }

    const requestId = randomUUID();
    let upstreamRequest;
    try { upstreamRequest = buildUpstream(scan); }
    catch { return errorResponse(400, 'invalid_swarm_diff_request', requestId); }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.max(1000, Math.min(30_000, timeoutMs)));
    const started = nowMs();
    try {
      const upstream = await fetchImpl(upstreamRequest.url.toString(), {
        method: upstreamRequest.method,
        headers: {
          key: env.GREYNOISE_API_KEY,
          accept: scan.command === 'export' ? 'application/octet-stream' : 'application/json',
          ...(upstreamRequest.body ? { 'content-type': 'application/json' } : {}),
        },
        ...(upstreamRequest.body ? { body: upstreamRequest.body } : {}),
        redirect: 'error',
        cache: 'no-store',
        signal: controller.signal,
      });
      if (!upstream.ok) return mapUpstreamError(upstream.status, requestId);

      const durationMs = Math.max(0, Math.round(nowMs() - started));
      if (scan.command === 'export') {
        const bytes = await readBinary(upstream);
        const filename = filenameFor(scan);
        return response(200, bytes, {
          'content-type': 'application/octet-stream',
          'content-disposition': `attachment; filename="${filename}"`,
          'x-para11ax-request-id': requestId,
          'x-para11ax-swarm-export-type': scan.exportType,
          'x-para11ax-duration-ms': String(durationMs),
        }, true);
      }

      const data = await readJson(upstream);
      return response(200, {
        requestId,
        source: 'greynoise-swarm',
        command: scan.command,
        input: resultInput(scan),
        data,
        durationMs,
      });
    } catch (error) {
      if (error?.name === 'AbortError') return errorResponse(504, 'swarm_timeout', requestId);
      if (error?.message === 'swarm_response_too_large') return errorResponse(502, 'swarm_response_too_large', requestId);
      if (error?.message === 'swarm_export_too_large') return errorResponse(502, 'swarm_export_too_large', requestId);
      if (error?.message === 'invalid_swarm_response') return errorResponse(502, 'invalid_swarm_response', requestId);
      return errorResponse(502, 'swarm_transport_error', requestId);
    } finally {
      clearTimeout(timer);
    }
  };
}
