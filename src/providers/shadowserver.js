import { createHmac } from 'node:crypto';
import { fetchJson } from '../core/fetch-json.js';

const API_URL = 'https://transform.shadowserver.org/api2/reports/query';
const SOURCE_URL = 'https://www.shadowserver.org/what-we-do/network-reporting/api-reports-query/';
const MAX_EVENTS = 50;
const MAX_TEXT = 512;
const MARKUP_RE = /<\/?[a-z][^>]*>/i;

function failSchema() {
  throw new Error('provider_schema_invalid');
}

function safeText(value, { required = false, pattern = null } = {}) {
  if (value === undefined || value === null || value === '') {
    if (required) failSchema();
    return null;
  }
  if (typeof value !== 'string' && typeof value !== 'number') failSchema();
  const text = String(value);
  if (!text || text.length > MAX_TEXT || /[\u0000-\u001f\u007f]/.test(text) || MARKUP_RE.test(text)) failSchema();
  if (pattern && !pattern.test(text)) failSchema();
  return text;
}

function normalizePort(value) {
  if (value === undefined || value === null || value === '') return null;
  const port = Number(value);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) failSchema();
  return port;
}

function normalizeEvent(row) {
  if (!row || typeof row !== 'object' || Array.isArray(row)) failSchema();
  const type = safeText(row.type ?? row.report_type, { required: true, pattern: /^[a-z0-9_+-]{1,128}$/i });
  const event = { type };
  const timestamp = safeText(row.timestamp);
  const ip = safeText(row.ip, { pattern: /^[0-9a-f:.]{2,64}$/i });
  const hostname = safeText(row.hostname, { pattern: /^[a-z0-9._-]{1,253}$/i });
  const protocol = safeText(row.protocol, { pattern: /^[a-z0-9_-]{1,32}$/i });
  const port = normalizePort(row.port);
  if (timestamp !== null) event.timestamp = timestamp;
  if (ip !== null) event.ip = ip;
  if (hostname !== null) event.hostname = hostname;
  if (protocol !== null) event.protocol = protocol;
  if (port !== null) event.port = port;
  return Object.freeze(event);
}

function credentials(env) {
  const key = typeof env?.SHADOWSERVER_API_KEY === 'string' ? env.SHADOWSERVER_API_KEY.trim() : '';
  const secret = typeof env?.SHADOWSERVER_API_SECRET === 'string' ? env.SHADOWSERVER_API_SECRET.trim() : '';
  if (!key || !secret) throw new Error('Shadowserver is not configured');
  return { key, secret };
}

function queryFor(input) {
  if (input?.type === 'ip' && typeof input.value === 'string' && input.value) return { ip: input.value };
  if (input?.type === 'cidr' && typeof input.value === 'string' && input.value) return { network: input.value };
  throw new TypeError('unsupported Shadowserver input');
}

export const shadowserverProvider = Object.freeze({
  name: 'shadowserver',
  types: Object.freeze(['ip', 'cidr']),
  observationTypes: Object.freeze(['internet_exposure']),
  requiredEnvs: Object.freeze(['SHADOWSERVER_API_KEY', 'SHADOWSERVER_API_SECRET']),
  tier: 4,
  costClass: 'scarce',
  timeoutMs: 7000,
  cacheTtlMs: 3600000,
  negativeCacheTtlMs: 900000,
  maxResponseBytes: 2 * 1024 * 1024,
  fixedHosts: Object.freeze(['transform.shadowserver.org']),
  methods: Object.freeze(['POST']),
  protocols: Object.freeze(['https:']),
  parserVersion: 'reports-query-2026-09-13.1',
  sourceUrl: SOURCE_URL,
  sourceRole: 'first_party',
  distribution: 'internal_only',
  async run(input, { env = {}, signal, fetchImpl = fetch } = {}) {
    const { key, secret } = credentials(env);
    const body = JSON.stringify({
      query: queryFor(input),
      date: '-1:now',
      limit: MAX_EVENTS,
      page: 1,
      apikey: key,
    });
    const hmac = createHmac('sha256', secret).update(body).digest('hex');
    const raw = await fetchJson(API_URL, {
      fetchImpl,
      signal,
      maxBytes: shadowserverProvider.maxResponseBytes,
      method: 'POST',
      headers: { 'content-type': 'application/json', HMAC2: hmac },
      body,
      redirect: 'error',
    });
    if (!Array.isArray(raw) || raw.length > MAX_EVENTS) failSchema();
    const events = raw.map(normalizeEvent);
    const reportTypes = [...new Set(events.map(event => event.type))].sort();
    return {
      observationType: 'internet_exposure',
      verdict: events.length ? 'observed' : 'no_result',
      confidence: events.length ? 85 : 0,
      attributes: {
        scope: 'account_authorized_owned_assets',
        requestedScope: input.value,
        eventCount: events.length,
        reportTypes,
        events,
      },
      relationships: [],
      references: [SOURCE_URL],
    };
  },
});
