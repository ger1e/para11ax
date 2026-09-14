import { fetchJson } from '../core/fetch-json.js';

const API_BASE = 'https://api.validin.com/api/axon/domain/dns/history';
const SOURCE_URL = 'https://www.validin.com/';
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_RECORDS = 100;

function validDomain(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 253 && !/[/\\\s]/.test(value);
}

function toIso(value) {
  return Number.isFinite(value) && value >= 0 ? new Date(value * 1000).toISOString() : null;
}

function noResult() {
  return {
    observationType: 'dns_history',
    verdict: 'no_result',
    confidence: null,
    attributes: { recordCount: 0, truncated: false },
    relationships: [],
    references: [SOURCE_URL],
  };
}

export const validinProvider = Object.freeze({
  name: 'validin',
  types: ['domain'],
  observationType: 'dns_history',
  cacheTtlMs: 6 * 60 * 60 * 1000,
  negativeCacheTtlMs: 60 * 60 * 1000,
  costClass: 'scarce',
  timeoutMs: 5000,
  parserVersion: 'validin-axon-2026-09-14.1',
  requiredEnv: 'VALIDIN_API_KEY',
  async run(input, { signal, fetchImpl = fetch, env = process.env } = {}) {
    if (input?.type !== 'domain' || !validDomain(input.value)) throw new Error('unsupported Validin input');
    const apiKey = env.VALIDIN_API_KEY;
    if (!apiKey) throw new Error('Validin is not configured');
    const domain = input.value.toLowerCase().replace(/\.$/, '');
    const requestUrl = `${API_BASE}/${encodeURIComponent(domain)}?exclude_nx=true&limit=${MAX_RECORDS}`;
    let body;
    try {
      body = await fetchJson(requestUrl, {
        fetchImpl,
        signal,
        maxBytes: MAX_RESPONSE_BYTES,
        headers: { authorization: `Bearer ${apiKey}` },
      });
    } catch (error) {
      if (error?.status === 404) return noResult();
      throw error;
    }
    if (!body || typeof body !== 'object' || Array.isArray(body) || !Array.isArray(body.records)) throw new Error('provider_schema_invalid');
    if (!body.records.length) return noResult();
    const records = body.records.slice(0, MAX_RECORDS);
    let firstSeen = null;
    let lastSeen = null;
    const relationships = [];
    const seen = new Set();
    for (const record of records) {
      if (!record || typeof record !== 'object' || Array.isArray(record)) throw new Error('provider_schema_invalid');
      const first = toIso(record.time_first);
      const last = toIso(record.time_last);
      if (first && (!firstSeen || first < firstSeen)) firstSeen = first;
      if (last && (!lastSeen || last > lastSeen)) lastSeen = last;
      if (!['A', 'AAAA'].includes(record.rrtype) || typeof record.rdata !== 'string') continue;
      const key = `${record.rdata}|${first ?? ''}|${last ?? ''}`;
      if (seen.has(key)) continue;
      seen.add(key);
      relationships.push({
        targetType: 'ip',
        target: record.rdata,
        relationship: 'historical_dns_resolution',
        firstSeen: first,
        lastSeen: last,
      });
    }
    return {
      observationType: 'dns_history',
      verdict: 'observed',
      confidence: null,
      firstSeen,
      lastSeen,
      attributes: { recordCount: records.length, truncated: body.records.length > MAX_RECORDS },
      relationships,
      references: [SOURCE_URL],
    };
  },
});
