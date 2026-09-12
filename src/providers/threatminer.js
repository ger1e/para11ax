import { isIP } from 'node:net';
import { fetchJson } from '../core/fetch-json.js';
import { compact, relation } from './helpers.js';

const COVERAGE_OBSERVATION_TYPES = Object.freeze({
  ip: Object.freeze(['passive_dns']),
  domain: Object.freeze(['passive_dns']),
  url: Object.freeze(['passive_dns']),
  hash: Object.freeze(['sample_hosts']),
});

function endpoint(input) {
  if (input.type === 'ip') return { url: `https://api.threatminer.org/v2/host.php?q=${encodeURIComponent(input.value)}&rt=2`, kind: 'passive_dns', pivot: input.value };
  if (input.type === 'domain') return { url: `https://api.threatminer.org/v2/domain.php?q=${encodeURIComponent(input.value)}&rt=2`, kind: 'passive_dns', pivot: input.value };
  if (input.type === 'url') {
    const host = new URL(input.value).hostname.toLowerCase();
    const endpointName = isIP(host) ? 'host' : 'domain';
    return { url: `https://api.threatminer.org/v2/${endpointName}.php?q=${encodeURIComponent(host)}&rt=2`, kind: 'passive_dns', pivot: host };
  }
  return { url: `https://api.threatminer.org/v2/sample.php?q=${encodeURIComponent(input.value)}&rt=3`, kind: 'sample_hosts', pivot: input.value };
}

function sameIndicator(type, value, input) {
  if (type !== input.type) return false;
  if (type === 'domain') return String(value).toLowerCase() === String(input.value).toLowerCase();
  return String(value) === String(input.value);
}

function relationshipsFor(results, input) {
  const out = [];
  const kind = input.type === 'hash' ? 'sample_contact' : 'passive_dns';
  const push = (type, value, relationKind = kind) => {
    if (!value || sameIndicator(type, value, input)) return;
    out.push(relation(type, value, relationKind));
  };

  for (const item of Array.isArray(results) ? results : []) {
    if (typeof item === 'string') {
      const type = isIP(item) ? 'ip' : 'domain';
      push(type, type === 'domain' ? item.toLowerCase() : item);
      continue;
    }
    if (!item || typeof item !== 'object') continue;
    if (item.domain) push('domain', String(item.domain).toLowerCase());
    if (item.ip) push('ip', item.ip);
    if (item.uri) push('url', item.uri, 'related');
  }
  return compact(out);
}

function seen(results, field) {
  const values = (Array.isArray(results) ? results : []).map(x => x && typeof x === 'object' ? x[field] : null).filter(Boolean).sort();
  return field === 'first_seen' ? values[0] ?? null : values.at(-1) ?? null;
}

export const threatminerProvider = Object.freeze({
  name: 'threatminer', types: ['ip', 'domain', 'url', 'hash'], cacheTtlMs: 6 * 60 * 60 * 1000, negativeCacheTtlMs: 60 * 60 * 1000, costClass: 'free', timeoutMs: 5000, parserVersion: '2026-08-22.1', fastProfileEligible: false,
  coverageObservationTypesByType: COVERAGE_OBSERVATION_TYPES,
  async run(input, context = {}) {
    const { url, kind, pivot } = endpoint(input);
    const raw = await fetchJson(url, { ...context, maxBytes: 2_000_000 });
    const results = Array.isArray(raw?.results) ? raw.results : [];
    const statusCode = Number.isFinite(Number(raw?.status_code)) ? Number(raw.status_code) : null;
    return {
      observationType: kind,
      verdict: statusCode === 404 ? 'no_result' : 'unknown',
      firstSeen: seen(results, 'first_seen'),
      lastSeen: seen(results, 'last_seen'),
      attributes: {
        pivot,
        resultCount: results.length,
        statusCode,
        statusMessage: raw?.status_message ?? null,
      },
      relationships: relationshipsFor(results, input),
      references: [url],
    };
  },
});
