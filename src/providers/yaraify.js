import { fetchJson } from '../core/fetch-json.js';

const API_URL = 'https://yaraify-api.abuse.ch/api/v1/';
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const HASH_RE = /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{96})$/i;

function validRuleName(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 256 && !/[\u0000-\u001f\u007f]/.test(value);
}

function ruleNames(data) {
  const candidates = Array.isArray(data?.yara_rules) ? data.yara_rules : Array.isArray(data?.yara) ? data.yara : [];
  const names = [];
  for (const item of candidates.slice(0, 128)) {
    const name = typeof item === 'string' ? item : item?.rule_name ?? item?.rule ?? item?.name;
    if (validRuleName(name) && !names.includes(name)) names.push(name);
    if (names.length >= 64) break;
  }
  return names.sort();
}

export const yaraifyProvider = Object.freeze({
  name: 'yaraify',
  types: ['hash'],
  observationType: 'malware_similarity',
  cacheTtlMs: 6 * 60 * 60 * 1000,
  negativeCacheTtlMs: 60 * 60 * 1000,
  costClass: 'quota',
  timeoutMs: 5000,
  parserVersion: 'yaraify-2026-09-13.1',
  requiredEnv: 'ABUSECH_API_KEY',
  async run(input, { signal, fetchImpl = fetch, env = process.env } = {}) {
    if (input?.type !== 'hash' || typeof input.value !== 'string' || !HASH_RE.test(input.value)) throw new Error('unsupported YARAify hash input');
    const key = env.ABUSECH_API_KEY;
    if (!key) throw new Error('YARAify is not configured');
    const body = JSON.stringify({ query: 'lookup_hash', search_term: input.value.toLowerCase() });
    const raw = await fetchJson(API_URL, {
      fetchImpl,
      signal,
      maxBytes: MAX_RESPONSE_BYTES,
      method: 'POST',
      headers: { 'Auth-Key': key, 'content-type': 'application/json' },
      body,
    });
    if (!raw || typeof raw !== 'object' || Array.isArray(raw) || typeof raw.query_status !== 'string') throw new Error('provider_schema_invalid');
    if (['hash_not_found', 'no_results', 'not_found'].includes(raw.query_status)) {
      return {
        observationType: 'malware_similarity',
        verdict: 'not_found',
        confidence: 0,
        attributes: { hash: input.value.toLowerCase(), yaraRules: [], sightings: 0 },
        relationships: [],
        references: ['https://yaraify.abuse.ch/api/'],
      };
    }
    if (raw.query_status !== 'ok' || !raw.data || typeof raw.data !== 'object' || Array.isArray(raw.data)) throw new Error('provider_schema_invalid');
    const metadata = raw.data.metadata && typeof raw.data.metadata === 'object' && !Array.isArray(raw.data.metadata) ? raw.data.metadata : {};
    const yaraRules = ruleNames(raw.data);
    const sightings = Number(metadata.sightings);
    return {
      observationType: 'malware_similarity',
      verdict: 'observed',
      confidence: yaraRules.length ? 90 : 60,
      attributes: {
        hash: input.value.toLowerCase(),
        sha256: typeof metadata.sha256_hash === 'string' ? metadata.sha256_hash.toLowerCase() : null,
        md5: typeof metadata.md5_hash === 'string' ? metadata.md5_hash.toLowerCase() : null,
        sightings: Number.isFinite(sightings) && sightings >= 0 ? sightings : null,
        yaraRules,
      },
      relationships: [],
      references: ['https://yaraify.abuse.ch/api/'],
    };
  },
});
