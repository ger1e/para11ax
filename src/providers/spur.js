import { fetchJson } from '../core/fetch-json.js';

const API_BASE = 'https://api.spur.us/v2/context';
const SOURCE_URL = 'https://docs.spur.us/';
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

function validIp(value) {
  return typeof value === 'string' && value.length > 2 && value.length <= 64 && /^[0-9a-f:.]+$/i.test(value);
}

function dateFromHeader(value) {
  return /^\d{8}$/.test(value ?? '') ? `${value.slice(0, 4)}-${value.slice(4, 6)}-${value.slice(6, 8)}` : null;
}

function list(value, max = 64) {
  return Array.isArray(value) ? [...new Set(value.filter(item => typeof item === 'string' && item.length > 0 && item.length <= 256))].sort().slice(0, max) : [];
}

function noResult() {
  return {
    observationType: 'anonymization_infrastructure',
    verdict: 'no_result',
    confidence: null,
    attributes: {},
    relationships: [],
    references: [SOURCE_URL],
  };
}

export const spurProvider = Object.freeze({
  name: 'spur',
  types: ['ip'],
  observationType: 'anonymization_infrastructure',
  cacheTtlMs: 60 * 60 * 1000,
  negativeCacheTtlMs: 30 * 60 * 1000,
  costClass: 'scarce',
  timeoutMs: 5000,
  parserVersion: 'spur-context-v2-2026-09-14.1',
  requiredEnv: 'SPUR_TOKEN',
  async run(input, { signal, fetchImpl = fetch, env = process.env } = {}) {
    if (input?.type !== 'ip' || !validIp(input.value)) throw new Error('unsupported Spur input');
    const token = env.SPUR_TOKEN;
    if (!token) throw new Error('Spur is not configured');
    const requestUrl = `${API_BASE}/${encodeURIComponent(input.value)}`;
    let resultDate = null;
    let body;
    try {
      const response = await fetchImpl(requestUrl, {
        method: 'GET',
        signal,
        redirect: 'error',
        headers: { accept: 'application/json', token },
      });
      if (response.status === 404) return noResult();
      if (!response.ok) {
        const error = new Error(`provider HTTP ${response.status}`);
        error.status = response.status;
        error.retryAfter = response.headers.get('retry-after');
        throw error;
      }
      resultDate = dateFromHeader(response.headers.get('x-result-dt'));
      const declared = Number(response.headers.get('content-length'));
      if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) throw Object.assign(new Error('provider response too large'), { status: 502 });
      const text = await response.text();
      if (Buffer.byteLength(text, 'utf8') > MAX_RESPONSE_BYTES) throw Object.assign(new Error('provider response too large'), { status: 502 });
      body = text ? JSON.parse(text) : null;
    } catch (error) {
      throw error;
    }
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('provider_schema_invalid');
    const tunnels = Array.isArray(body.tunnels) ? body.tunnels : [];
    const operators = [...new Set(tunnels
      .filter(item => item && typeof item === 'object' && !Array.isArray(item) && item.anonymous === true)
      .map(item => typeof item.operator === 'string' ? item.operator : null)
      .filter(Boolean))].sort();
    return {
      observationType: 'anonymization_infrastructure',
      verdict: 'observed',
      confidence: null,
      attributes: {
        resultDate,
        asn: Number.isSafeInteger(body.as?.number) ? body.as.number : null,
        organization: typeof body.organization === 'string' ? body.organization : null,
        infrastructure: typeof body.infrastructure === 'string' ? body.infrastructure : null,
        risks: list(body.risks),
        services: list(body.services),
        anonymizationOperators: operators,
      },
      relationships: [],
      references: [SOURCE_URL],
    };
  },
});
