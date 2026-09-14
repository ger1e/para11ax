import { fetchJson } from '../core/fetch-json.js';

const API_BASE = 'https://api.spycloud.io/enterprise-v2/breach/data';
const SOURCE_URL = 'https://api.spycloud.io/enterprise-v2/breach/data';
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_RECORDS = 100;

function schemaError() {
  return new Error('provider_schema_invalid');
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function boundedText(value, max = 256) {
  return typeof value === 'string' && value.length > 0 && value.length <= max ? value : null;
}

function boundedNumber(value, min = 0, max = Number.MAX_SAFE_INTEGER) {
  return Number.isFinite(value) && value >= min && value <= max ? value : null;
}

export const spyCloudProvider = Object.freeze({
  name: 'spycloud',
  types: ['domain', 'email'],
  observationType: 'identity_exposure',
  cacheTtlMs: 300000,
  negativeCacheTtlMs: 300000,
  costClass: 'scarce',
  timeoutMs: 5000,
  parserVersion: 'spycloud-enterprise-v2-2026-09-14.1',
  requiredEnv: 'SPYCLOUD_API_KEY',
  async run(input, { signal, fetchImpl = fetch, env = process.env } = {}) {
    if (!input || !['domain', 'email'].includes(input.type) || typeof input.value !== 'string' || input.value.length < 1 || input.value.length > 512) {
      throw new Error('unsupported SpyCloud input');
    }
    const apiKey = env.SPYCLOUD_API_KEY;
    if (!apiKey) throw new Error('SpyCloud is not configured');

    const segment = input.type === 'domain' ? 'domains' : 'emails';
    const url = `${API_BASE}/${segment}/${encodeURIComponent(input.value)}`;
    const body = await fetchJson(url, {
      fetchImpl,
      signal,
      maxBytes: MAX_RESPONSE_BYTES,
      headers: { 'X-API-KEY': apiKey },
    });
    if (!isObject(body) || !Array.isArray(body.results)) throw schemaError();

    if (body.results.length === 0) {
      return {
        observationType: 'identity_exposure',
        verdict: 'no_result',
        confidence: null,
        attributes: {
          recordCount: 0,
          hitCount: boundedNumber(body.hits) ?? 0,
          truncated: Boolean(body.cursor),
        },
        relationships: [],
        references: [SOURCE_URL],
      };
    }

    const records = body.results.slice(0, MAX_RECORDS).map(item => {
      if (!isObject(item)) throw schemaError();
      return {
        sourceId: boundedNumber(item.source_id),
        severity: boundedNumber(item.severity, 0, 10),
        publishDate: boundedText(item.spycloud_publish_date, 64),
      };
    });

    return {
      observationType: 'identity_exposure',
      verdict: 'observed',
      confidence: null,
      attributes: {
        recordCount: body.results.length,
        hitCount: boundedNumber(body.hits) ?? body.results.length,
        records,
        truncated: Boolean(body.cursor) || body.results.length > MAX_RECORDS,
      },
      relationships: [],
      references: [SOURCE_URL],
    };
  },
});
