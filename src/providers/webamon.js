import { fetchJson } from '../core/fetch-json.js';
import { compact, relation, requireEnv } from './helpers.js';

const SEARCH_FIELDS = Object.freeze({
  ip: 'server.ip,request.response.ip',
  domain: 'domain.name,resolved_domain,server.domain,submission_url,resolved_url',
  url: 'resolved_url,submission_url,request.response.url,resource.url,server.resource.url',
  hash: 'resource.sha256,server.resource.sha256',
});

function rowsFrom(raw) {
  if (Array.isArray(raw?.results)) return raw.results;
  if (Array.isArray(raw?.data)) return raw.data;
  if (Array.isArray(raw?.hits)) return raw.hits;
  if (Array.isArray(raw?.hits?.hits)) return raw.hits.hits.map(row => row?._source ?? row).filter(Boolean);
  return [];
}

function totalFrom(raw, rows) {
  for (const value of [raw?.total_hits, raw?.total, raw?.count, raw?.hits?.total?.value]) {
    const number = Number(value);
    if (Number.isFinite(number) && number >= 0) return number;
  }
  return rows.length;
}

function cleanObservedValue(value) {
  if (typeof value !== 'string') return value;
  return value.replace(/<\/?mark(?:\s[^>]*)?>/gi, '');
}

export const webamonProvider = Object.freeze({
  name: 'webamon', types: ['ip', 'domain', 'url', 'hash'], requiredEnv: 'WEBAMON_API_KEY', cacheTtlMs: 21600000, negativeCacheTtlMs: 3600000, costClass: 'free', timeoutMs: 12000, parserVersion: '2026-09-13.1',
  async run(input, context = {}) {
    const key = requireEnv(context, 'WEBAMON_API_KEY');
    const params = new URLSearchParams({ search: input.value, results: SEARCH_FIELDS[input.type], size: '10' });
    const url = `https://pro.webamon.com/search?${params}`;
    const raw = await fetchJson(url, { ...context, headers: { 'x-api-key': key }, maxBytes: 3_000_000 });
    const rows = rowsFrom(raw);
    const rels = [];
    for (const row of rows) {
      const r = row?._source ?? row ?? {};
      for (const ip of [r?.ip, r?.server?.ip, r?.request?.response?.ip]) {
        if (ip) rels.push(relation('ip', cleanObservedValue(ip), 'observed_ip'));
      }
      for (const domain of [typeof r?.domain === 'string' ? r.domain : r?.domain?.name, r?.resolved_domain, r?.server?.domain]) {
        if (domain) rels.push(relation('domain', cleanObservedValue(domain), 'observed_domain'));
      }
      for (const observedUrl of [r?.url, r?.resolved_url, r?.submission_url, r?.meta?.submission_url, r?.request?.response?.url, r?.resource?.url, r?.server?.resource?.url]) {
        if (observedUrl) rels.push(relation('url', cleanObservedValue(observedUrl), 'observed_url'));
      }
      for (const hash of [r?.resource?.sha256, r?.server?.resource?.sha256]) {
        if (hash) rels.push(relation('hash', cleanObservedValue(hash), 'observed_sha256'));
      }
    }
    const riskScores = rows.map(row => Number((row?._source ?? row)?.meta?.risk_score)).filter(Number.isFinite);
    return {
      observationType: 'web_intelligence',
      verdict: rows.length ? 'observed' : 'no_result',
      attributes: {
        resultCount: totalFrom(raw, rows),
        returnedCount: rows.length,
        maxRiskScore: riskScores.length ? Math.max(...riskScores) : null,
      },
      relationships: compact(rels),
      references: ['https://webamon.com/api'],
    };
  },
});
