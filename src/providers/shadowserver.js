import { createHmac } from 'node:crypto';
import { domainToASCII } from 'node:url';
import { fetchJson } from '../core/fetch-json.js';
import { parseCanonicalCidr, parseIp } from '../core/network.js';

const API_URL = 'https://transform.shadowserver.org/api2/reports/query';
const DOC_URL = 'https://www.shadowserver.org/what-we-do/network-reporting/api-reports-query/';
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_EVENTS = 100;
const MAX_TAGS = 16;
const EVENT_FIELDS = Object.freeze([
  'timestamp', 'severity', 'ip', 'protocol', 'port', 'hostname', 'domain', 'asn', 'geo', 'region', 'city',
  'type', 'infection', 'device_vendor', 'device_type', 'device_model', 'network', 'public_source', 'application', 'version',
]);

function schemaError() {
  return new Error('provider_schema_invalid');
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function safeText(value, max = 512) {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value === 'number' && Number.isFinite(value)) value = String(value);
  if (typeof value !== 'string' || value.length > max || /[\u0000-\u001f\u007f<>]/.test(value)) throw schemaError();
  return value;
}

function canonicalDomain(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 253 || /\s/.test(value)) return null;
  const ascii = domainToASCII(value.toLowerCase());
  if (!ascii || !ascii.includes('.') || ascii.length > 253) return null;
  const labels = ascii.split('.');
  if (labels.some(label => !label || label.length > 63 || !/^[a-z0-9-]+$/.test(label) || label.startsWith('-') || label.endsWith('-'))) return null;
  return ascii;
}

function queryFor(input) {
  if (input?.type === 'ip' && parseIp(input.value)) return { ip: input.value };
  if (input?.type === 'cidr' && parseCanonicalCidr(input.value)?.cidr === input.value) return { network: input.value };
  if (input?.type === 'domain') {
    const domain = canonicalDomain(input.value);
    if (domain === input.value) return { domain };
  }
  throw new Error('unsupported Shadowserver input');
}

function normalizeTags(value) {
  if (value === undefined || value === null) return [];
  const values = Array.isArray(value) ? value : [value];
  if (values.length > MAX_TAGS) throw schemaError();
  const output = [];
  for (const item of values) {
    const normalized = safeText(item, 128);
    if (normalized && !output.includes(normalized)) output.push(normalized);
  }
  return output.sort();
}

function normalizeEvent(record) {
  if (!isPlainObject(record)) throw schemaError();
  const event = {};
  for (const field of EVENT_FIELDS) {
    const value = safeText(record[field]);
    if (value !== null) event[field] = value;
  }
  const tags = normalizeTags(record.tag);
  if (tags.length) event.tag = tags;
  if (!Object.keys(event).length) throw schemaError();
  return event;
}

function eventTimes(events) {
  const timestamps = events.map(event => event.timestamp).filter(value => typeof value === 'string').sort();
  return {
    firstSeen: timestamps[0] ?? null,
    lastSeen: timestamps[timestamps.length - 1] ?? null,
  };
}

export const shadowserverProvider = Object.freeze({
  name: 'shadowserver',
  types: ['ip', 'cidr', 'domain'],
  observationType: 'internet_exposure',
  cacheTtlMs: 60 * 60 * 1000,
  negativeCacheTtlMs: 15 * 60 * 1000,
  costClass: 'quota',
  timeoutMs: 8000,
  parserVersion: 'shadowserver-reports-2026-09-13.1',
  requiredEnv: 'SHADOWSERVER_API_SECRET',
  requiredConfigEnv: 'SHADOWSERVER_API_KEY',
  async run(input, { env = process.env, signal, fetchImpl = fetch } = {}) {
    const query = queryFor(input);
    const apiKey = env.SHADOWSERVER_API_KEY;
    const secret = env.SHADOWSERVER_API_SECRET;
    if (!apiKey || !secret) throw new Error('Shadowserver is not configured');

    const request = {
      query,
      sort: 'descending',
      date: '-1:now',
      limit: MAX_EVENTS,
      page: 1,
      apikey: apiKey,
    };
    const body = JSON.stringify(request);
    // Shadowserver requires HMAC-SHA256(secret, request body) for API authentication:
    // https://github.com/The-Shadowserver-Foundation/api_utils/wiki/call_api-Documentation
    // codeql[js/insufficient-password-hash]
    const hmac2 = createHmac('sha256', secret).update(body).digest('hex');
    const raw = await fetchJson(API_URL, {
      fetchImpl,
      signal,
      maxBytes: MAX_RESPONSE_BYTES,
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        HMAC2: hmac2,
      },
      body,
      redirect: 'error',
    });

    if (!Array.isArray(raw) || raw.length > MAX_EVENTS) throw schemaError();
    const events = raw.map(normalizeEvent);
    const { firstSeen, lastSeen } = eventTimes(events);

    return {
      observationType: 'internet_exposure',
      verdict: events.length ? 'observed' : 'no_result',
      confidence: null,
      firstSeen,
      lastSeen,
      attributes: {
        queryType: input.type,
        eventCount: events.length,
        events,
      },
      relationships: [],
      references: [DOC_URL],
    };
  },
});
