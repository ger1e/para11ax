import { fetchJson } from '../core/fetch-json.js';

const API_BASE = 'https://haveibeenpwned.com/api/v3';
const SOURCE_URL = 'https://haveibeenpwned.com/API/v3';
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_BREACHES = 100;
const MAX_DATA_CLASSES = 64;

function schemaError() {
  return new Error('provider_schema_invalid');
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function boundedText(value, max = 512) {
  return typeof value === 'string' && value.length > 0 && value.length <= max ? value : null;
}

function noResult(attributes = {}) {
  return {
    observationType: 'identity_exposure',
    verdict: 'no_result',
    confidence: null,
    attributes,
    relationships: [],
    references: [SOURCE_URL],
  };
}

function sanitizeBreach(item) {
  if (!isObject(item)) throw schemaError();
  if (item.DataClasses !== undefined && !Array.isArray(item.DataClasses)) throw schemaError();
  const dataClasses = (item.DataClasses ?? [])
    .slice(0, MAX_DATA_CLASSES)
    .map(value => boundedText(value, 256))
    .filter(Boolean);
  return {
    name: boundedText(item.Name, 256),
    title: boundedText(item.Title, 256),
    domain: boundedText(item.Domain, 253),
    breachDate: boundedText(item.BreachDate, 32),
    addedDate: boundedText(item.AddedDate, 64),
    dataClasses: [...new Set(dataClasses)].sort(),
  };
}

async function getJson(url, apiKey, { fetchImpl, signal }) {
  return fetchJson(url, {
    fetchImpl,
    signal,
    maxBytes: MAX_RESPONSE_BYTES,
    headers: {
      'hibp-api-key': apiKey,
      'user-agent': 'PARA11AX/2.0',
    },
  });
}

export const hibpProvider = Object.freeze({
  name: 'hibp',
  types: ['email', 'domain'],
  observationType: 'identity_exposure',
  cacheTtlMs: 300000,
  negativeCacheTtlMs: 300000,
  costClass: 'scarce',
  timeoutMs: 5000,
  parserVersion: 'hibp-v3-2026-09-14.1',
  requiredEnv: 'HIBP_API_KEY',
  async run(input, { signal, fetchImpl = fetch, env = process.env } = {}) {
    if (!input || !['email', 'domain'].includes(input.type) || typeof input.value !== 'string' || input.value.length < 1 || input.value.length > 512) {
      throw new Error('unsupported HIBP input');
    }
    const apiKey = env.HIBP_API_KEY;
    if (!apiKey) throw new Error('HIBP is not configured');

    if (input.type === 'email') {
      const url = `${API_BASE}/breachedaccount/${encodeURIComponent(input.value)}?truncateResponse=false`;
      let body;
      try {
        body = await getJson(url, apiKey, { fetchImpl, signal });
      } catch (error) {
        if (error?.status === 404) return noResult({ breachCount: 0, breaches: [], truncated: false });
        throw error;
      }
      if (!Array.isArray(body)) throw schemaError();
      if (body.length === 0) return noResult({ breachCount: 0, breaches: [], truncated: false });
      const breaches = body.slice(0, MAX_BREACHES).map(sanitizeBreach);
      return {
        observationType: 'identity_exposure',
        verdict: 'observed',
        confidence: null,
        attributes: {
          breachCount: body.length,
          breaches,
          truncated: body.length > MAX_BREACHES,
        },
        relationships: [],
        references: [SOURCE_URL],
      };
    }

    const url = `${API_BASE}/breacheddomain/${encodeURIComponent(input.value)}`;
    let body;
    try {
      body = await getJson(url, apiKey, { fetchImpl, signal });
    } catch (error) {
      if (error?.status === 404) return noResult({ accountCount: 0, breachNames: [] });
      throw error;
    }
    if (!isObject(body)) throw schemaError();
    const aliases = Object.entries(body);
    const breachNames = new Set();
    for (const [, names] of aliases) {
      if (!Array.isArray(names)) throw schemaError();
      for (const name of names.slice(0, MAX_BREACHES)) {
        const clean = boundedText(name, 256);
        if (clean) breachNames.add(clean);
      }
    }
    if (aliases.length === 0) return noResult({ accountCount: 0, breachNames: [] });
    return {
      observationType: 'identity_exposure',
      verdict: 'observed',
      confidence: null,
      attributes: {
        accountCount: aliases.length,
        breachNames: [...breachNames].sort().slice(0, MAX_BREACHES),
      },
      relationships: [],
      references: [SOURCE_URL],
    };
  },
});
