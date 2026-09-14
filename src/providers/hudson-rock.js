import { fetchJson } from '../core/fetch-json.js';

const ENDPOINT = 'https://api.hudsonrock.com/json/v3/search-by-domain';
const SOURCE_URL = 'https://docs.hudsonrock.com/';
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_RECORDS = 1000;

function schemaError() {
  return new Error('provider_schema_invalid');
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function boundedDate(value) {
  return typeof value === 'string' && value.length <= 64 && Number.isFinite(Date.parse(value)) ? new Date(value).toISOString() : null;
}

export const hudsonRockProvider = Object.freeze({
  name: 'hudson-rock',
  types: ['domain'],
  observationType: 'identity_exposure',
  cacheTtlMs: 300000,
  negativeCacheTtlMs: 300000,
  costClass: 'scarce',
  timeoutMs: 5000,
  parserVersion: 'hudson-rock-v3-2026-09-14.1',
  requiredEnv: 'HUDSONROCK_API_KEY',
  async run(input, { signal, fetchImpl = fetch, env = process.env } = {}) {
    if (input?.type !== 'domain' || typeof input.value !== 'string' || input.value.length < 1 || input.value.length > 253) {
      throw new Error('unsupported Hudson Rock input');
    }
    const apiKey = env.HUDSONROCK_API_KEY;
    if (!apiKey) throw new Error('Hudson Rock is not configured');

    const body = await fetchJson(ENDPOINT, {
      fetchImpl,
      signal,
      maxBytes: MAX_RESPONSE_BYTES,
      method: 'POST',
      headers: {
        'api-key': apiKey,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ domains: [input.value], filter_credentials: true }),
    });
    if (!isObject(body) || !Array.isArray(body.data)) throw schemaError();
    if (body.data.length > MAX_RECORDS) throw schemaError();
    if (body.data.length === 0) {
      return {
        observationType: 'identity_exposure',
        verdict: 'no_result',
        confidence: null,
        attributes: { recordCount: 0, truncated: Boolean(body.nextCursor) },
        relationships: [],
        references: [SOURCE_URL],
      };
    }

    let firstCompromised = null;
    let lastUploaded = null;
    for (const item of body.data) {
      if (!isObject(item)) throw schemaError();
      const compromised = boundedDate(item.date_compromised);
      const uploaded = boundedDate(item.date_uploaded);
      if (compromised && (!firstCompromised || compromised < firstCompromised)) firstCompromised = compromised;
      if (uploaded && (!lastUploaded || uploaded > lastUploaded)) lastUploaded = uploaded;
    }

    return {
      observationType: 'identity_exposure',
      verdict: 'observed',
      confidence: null,
      firstSeen: firstCompromised,
      lastSeen: lastUploaded,
      attributes: {
        recordCount: body.data.length,
        truncated: Boolean(body.nextCursor),
      },
      relationships: [],
      references: [SOURCE_URL],
    };
  },
});
