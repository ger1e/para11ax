import { randomUUID } from 'node:crypto';
import { requireGatewayAuth } from './core/auth.js';
import { securityHeaders } from './core/http.js';

const MAX_BODY_BYTES = 4 * 1024;
const MAX_WORKER_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_RESULTS = 1000;
const MAX_ERRORED_SITES = 512;
const DEFAULT_TIMEOUT_MS = 55_000;
const SAFE_NAME = /^[a-z0-9._-]{1,64}$/i;
// Use the canonical production domain. Branch aliases can inherit Vercel
// deployment protection and reject service-to-service calls before the worker
// gets a chance to verify the gateway's workload identity.
const DEFAULT_PRODUCTION_WORKER_URL = 'https://user-scanner-kappa.vercel.app/scan';

function response(status, body, extraHeaders = {}) {
  return {
    status,
    headers: { ...securityHeaders(), 'cache-control': 'no-store', ...extraHeaders },
    body,
  };
}

function headerValue(headers, name) {
  if (!headers) return undefined;
  if (typeof headers.get === 'function') return headers.get(name) ?? undefined;
  return headers[name] ?? headers[name.toLowerCase()] ?? headers[name.toUpperCase()];
}

function errorResponse(status, error, requestId = null) {
  return response(status, { error, ...(requestId ? { requestId } : {}) });
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

function validateRequest(body) {
  const allowed = new Set(['scanType', 'target', 'category', 'module', 'crossScan', 'noNsfw']);
  if (Object.keys(body).some(key => !allowed.has(key))) throw new Error('unsupported_request_field');
  if (!['email', 'username'].includes(body.scanType)) throw new Error('invalid_scan_type');
  if (typeof body.target !== 'string') throw new Error('invalid_target');
  const target = body.target.trim();
  if (!target || target.length > 320 || /[\u0000-\u001f\u007f]/.test(target)) throw new Error('invalid_target');
  if (body.category !== undefined && (typeof body.category !== 'string' || !SAFE_NAME.test(body.category))) throw new Error('invalid_category');
  if (body.module !== undefined && (typeof body.module !== 'string' || !SAFE_NAME.test(body.module))) throw new Error('invalid_module');
  if (body.category && body.module) throw new Error('category_module_conflict');
  if (body.crossScan !== undefined && typeof body.crossScan !== 'boolean') throw new Error('invalid_cross_scan');
  if (body.noNsfw !== undefined && typeof body.noNsfw !== 'boolean') throw new Error('invalid_no_nsfw');
  return {
    scanType: body.scanType,
    target,
    category: body.category || null,
    module: body.module || null,
    crossScan: body.crossScan === true,
    noNsfw: body.noNsfw !== false,
  };
}

function workerUrl(value) {
  if (!value) return null;
  let parsed;
  try { parsed = new URL(value); } catch { throw new Error('invalid_user_scanner_worker_url'); }
  const localhost = ['127.0.0.1', 'localhost', '::1'].includes(parsed.hostname);
  if (parsed.protocol !== 'https:' && !(localhost && parsed.protocol === 'http:')) throw new Error('invalid_user_scanner_worker_url');
  parsed.hash = '';
  return parsed.toString();
}

function resolveWorkerUrl(env) {
  const configured = workerUrl(env.PARA11AX_USER_SCANNER_URL);
  if (configured) return configured;
  if (env.VERCEL === '1' && env.VERCEL_ENV === 'production') return DEFAULT_PRODUCTION_WORKER_URL;
  return null;
}

function boundedString(value, max = 2048) {
  if (value === undefined || value === null) return '';
  return String(value).slice(0, max);
}

function boundedExtra(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  try {
    const serialized = JSON.stringify(value);
    if (Buffer.byteLength(serialized, 'utf8') > 32 * 1024) return { truncated: true };
    return value;
  } catch {
    return {};
  }
}

function normalizeWorkerPayload(payload, scan, durationMs) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('invalid_worker_response');
  const rawSummary = payload.summary;
  if (!rawSummary || typeof rawSummary !== 'object') throw new Error('invalid_worker_response');
  const int = (camel, snake) => {
    const value = rawSummary[camel] ?? rawSummary[snake];
    if (!Number.isSafeInteger(value) || value < 0) throw new Error('invalid_worker_response');
    return value;
  };
  const summary = {
    totalScanned: int('totalScanned', 'total_scanned'),
    found: int('found', 'found'),
    notFound: int('notFound', 'not_found'),
    errors: int('errors', 'errors'),
    skipped: int('skipped', 'skipped'),
  };
  if (!Array.isArray(payload.results)) throw new Error('invalid_worker_response');
  const results = payload.results.slice(0, MAX_RESULTS).map(item => ({
    status: boundedString(item?.status, 32),
    siteName: boundedString(item?.siteName ?? item?.site_name, 128),
    category: boundedString(item?.category, 128),
    url: boundedString(item?.url, 2048),
    extra: boundedExtra(item?.extra),
  }));
  const errored = payload.erroredSites ?? payload.errored_sites ?? [];
  const erroredSites = Array.isArray(errored) ? errored.slice(0, MAX_ERRORED_SITES).map(value => boundedString(value, 128)).filter(Boolean) : [];
  return {
    scanId: randomUUID(),
    scanType: scan.scanType,
    target: scan.target,
    summary,
    results,
    erroredSites,
    durationMs: Math.max(0, Math.round(durationMs)),
    source: 'user-scanner',
  };
}

async function readWorkerJson(res) {
  const declared = Number(res.headers?.get?.('content-length'));
  if (Number.isFinite(declared) && declared > MAX_WORKER_RESPONSE_BYTES) throw new Error('worker_response_too_large');
  const bytes = new Uint8Array(await res.arrayBuffer());
  if (bytes.byteLength > MAX_WORKER_RESPONSE_BYTES) throw new Error('worker_response_too_large');
  let payload;
  try { payload = JSON.parse(new TextDecoder().decode(bytes)); }
  catch { throw new Error('invalid_worker_response'); }
  return payload;
}

export function createUserScannerHandler({
  env = process.env,
  fetchImpl = fetch,
  nowMs = () => Date.now(),
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  return async function handleUserScanner(request) {
    if (request?.method !== 'POST') return errorResponse(405, 'method_not_allowed');
    if (!requireGatewayAuth(request, env.PARA11AX_TOKEN)) return errorResponse(401, 'unauthorized');
    const contentType = String(headerValue(request.headers, 'content-type') || '').split(';', 1)[0].trim().toLowerCase();
    if (contentType && contentType !== 'application/json' && !contentType.endsWith('+json')) return errorResponse(415, 'unsupported_media_type');

    let body;
    try { body = parseBody(request); }
    catch (error) { return errorResponse(error.status ?? 400, error.message === 'payload_too_large' ? 'payload_too_large' : 'invalid_request'); }

    let scan;
    try { scan = validateRequest(body); }
    catch (error) { return errorResponse(400, error.message); }

    let url;
    try { url = resolveWorkerUrl(env); }
    catch { return errorResponse(503, 'user_scanner_misconfigured'); }
    if (!url) return errorResponse(503, 'user_scanner_unconfigured');

    const workerBody = {
      scan_type: scan.scanType,
      target: scan.target,
      ...(scan.category ? { category: scan.category } : {}),
      ...(scan.module ? { module: scan.module } : {}),
      cross_scan: scan.crossScan,
      no_nsfw: scan.noNsfw,
    };
    const headers = { 'Content-Type': 'application/json' };
    const staticWorkerToken = typeof env.PARA11AX_USER_SCANNER_TOKEN === 'string' ? env.PARA11AX_USER_SCANNER_TOKEN.trim() : '';
    const workloadToken = String(headerValue(request.headers, 'x-vercel-oidc-token') ?? env.VERCEL_OIDC_TOKEN ?? '').trim();
    if (staticWorkerToken) {
      headers.Authorization = `Bearer ${staticWorkerToken}`;
    } else if (workloadToken) {
      headers.Authorization = `Bearer ${workloadToken}`;
      headers['x-vercel-trusted-oidc-idp-token'] = workloadToken;
    } else {
      return errorResponse(503, 'user_scanner_auth_unconfigured');
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.max(1000, Math.min(120_000, timeoutMs)));
    const started = nowMs();
    try {
      const upstream = await fetchImpl(url, {
        method: 'POST',
        headers,
        redirect: 'error',
        cache: 'no-store',
        signal: controller.signal,
        body: JSON.stringify(workerBody),
      });
      if (!upstream.ok) return errorResponse(502, upstream.status === 429 ? 'user_scanner_rate_limited' : 'user_scanner_worker_error');
      const payload = await readWorkerJson(upstream);
      return response(200, normalizeWorkerPayload(payload, scan, nowMs() - started));
    } catch (error) {
      if (error?.name === 'AbortError') return errorResponse(504, 'user_scanner_timeout');
      if (error?.message === 'worker_response_too_large') return errorResponse(502, 'user_scanner_response_too_large');
      if (error?.message === 'invalid_worker_response') return errorResponse(502, 'invalid_user_scanner_worker_response');
      return errorResponse(502, 'user_scanner_unavailable');
    } finally {
      clearTimeout(timer);
    }
  };
}
