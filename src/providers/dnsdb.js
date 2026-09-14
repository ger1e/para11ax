const API_BASE = 'https://api.dnsdb.info/dnsdb/v2/lookup/rrset/name';
const SOURCE_URL = 'https://docs.dnsdb.info/dnsdb-api/';
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_RECORDS = 100;

function httpError(response) {
  const error = new Error(`provider HTTP ${response.status}`);
  error.status = response.status;
  error.retryAfter = response.headers.get('retry-after');
  return error;
}

function toIso(value) {
  return Number.isFinite(value) && value >= 0 ? new Date(value * 1000).toISOString() : null;
}

function validDomain(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 253 && !/[/\\\s]/.test(value);
}

function noResult() {
  return {
    observationType: 'passive_dns_history',
    verdict: 'no_result',
    confidence: null,
    attributes: { recordCount: 0, truncated: false },
    relationships: [],
    references: [SOURCE_URL],
  };
}

async function fetchNdjson(url, apiKey, { fetchImpl, signal }) {
  const response = await fetchImpl(url, {
    method: 'GET',
    signal,
    redirect: 'error',
    headers: { 'x-api-key': apiKey, accept: 'application/x-ndjson' },
  });
  if (!response.ok) {
    if (response.status === 404) return '';
    throw httpError(response);
  }
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) throw Object.assign(new Error('provider response too large'), { status: 502 });
  const body = await response.text();
  if (Buffer.byteLength(body, 'utf8') > MAX_RESPONSE_BYTES) throw Object.assign(new Error('provider response too large'), { status: 502 });
  return body;
}

function parseStream(body) {
  const records = [];
  let truncated = false;
  for (const line of body.split(/\r?\n/)) {
    if (!line.trim()) continue;
    let item;
    try { item = JSON.parse(line); } catch { throw new Error('provider_schema_invalid'); }
    if (!item || typeof item !== 'object' || Array.isArray(item)) throw new Error('provider_schema_invalid');
    if (item.cond) {
      if (item.cond === 'limited') truncated = true;
      continue;
    }
    const obj = item.obj;
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) throw new Error('provider_schema_invalid');
    if (!Array.isArray(obj.rdata) || typeof obj.rrtype !== 'string') throw new Error('provider_schema_invalid');
    records.push(obj);
    if (records.length >= MAX_RECORDS) {
      truncated = true;
      break;
    }
  }
  return { records, truncated };
}

export const dnsdbProvider = Object.freeze({
  name: 'dnsdb',
  types: ['domain'],
  observationType: 'passive_dns_history',
  cacheTtlMs: 6 * 60 * 60 * 1000,
  negativeCacheTtlMs: 60 * 60 * 1000,
  costClass: 'scarce',
  timeoutMs: 5000,
  parserVersion: 'dnsdb-v2-2026-09-14.1',
  requiredEnv: 'DNSDB_API_KEY',
  async run(input, { signal, fetchImpl = fetch, env = process.env } = {}) {
    if (input?.type !== 'domain' || !validDomain(input.value)) throw new Error('unsupported DNSDB input');
    const apiKey = env.DNSDB_API_KEY;
    if (!apiKey) throw new Error('DNSDB is not configured');
    const domain = input.value.toLowerCase().replace(/\.$/, '');
    const requestUrl = `${API_BASE}/${encodeURIComponent(domain)}?limit=${MAX_RECORDS}`;
    const body = await fetchNdjson(requestUrl, apiKey, { fetchImpl, signal });
    if (!body) return noResult();
    const { records, truncated } = parseStream(body);
    if (!records.length) return noResult();

    let firstSeen = null;
    let lastSeen = null;
    const relationships = [];
    const seen = new Set();
    for (const record of records) {
      const first = toIso(record.time_first);
      const last = toIso(record.time_last);
      if (first && (!firstSeen || first < firstSeen)) firstSeen = first;
      if (last && (!lastSeen || last > lastSeen)) lastSeen = last;
      if (!['A', 'AAAA'].includes(record.rrtype)) continue;
      for (const raw of record.rdata) {
        if (typeof raw !== 'string' || raw.length < 2 || raw.length > 128) continue;
        const key = `${raw}|${first ?? ''}|${last ?? ''}`;
        if (seen.has(key)) continue;
        seen.add(key);
        relationships.push({
          targetType: 'ip',
          target: raw,
          relationship: 'historical_dns_resolution',
          firstSeen: first,
          lastSeen: last,
        });
        if (relationships.length >= MAX_RECORDS) break;
      }
      if (relationships.length >= MAX_RECORDS) break;
    }
    return {
      observationType: 'passive_dns_history',
      verdict: 'observed',
      confidence: null,
      firstSeen,
      lastSeen,
      attributes: { recordCount: records.length, truncated },
      relationships,
      references: [SOURCE_URL],
    };
  },
});
