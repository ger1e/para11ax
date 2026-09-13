import { fetchJson } from '../core/fetch-json.js';
import { requireEnv, relation } from './helpers.js';

const API_BASE = 'https://api.vulncheck.com/v3/search/cve';
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
const MAX_ROWS = 100;
const MAX_RELATIONSHIPS = 64;
const MAX_REFERENCES = 32;
const CVE = /^CVE-\d{4}-\d{4,}$/;

function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function strings(value, limit = 64) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value
    .filter(item => typeof item === 'string' && item.trim())
    .map(item => item.trim()))].slice(0, limit);
}

function safeHttps(value) {
  if (typeof value !== 'string' || value.length > 2048) return null;
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'https:' ? parsed.href : null;
  } catch {
    return null;
  }
}

function metadata(raw) {
  const meta = plain(raw?._meta) ? raw._meta : {};
  const number = key => Number.isSafeInteger(meta[key]) && meta[key] >= 0 ? meta[key] : null;
  return {
    queriedIndexCount: number('queried_index_count'),
    indicesWithHits: number('indices_with_hits'),
    totalCount: number('total_count'),
  };
}

function extract(raw, cve, requestUrl) {
  if (!plain(raw) || !Array.isArray(raw.data)) throw new Error('invalid VulnCheck response');
  const rows = raw.data.slice(0, MAX_ROWS);
  for (const row of rows) {
    if (!plain(row) || typeof row.index !== 'string' || !plain(row.source)) throw new Error('invalid VulnCheck response');
  }

  const meta = metadata(raw);
  const exploitKeys = new Set();
  const exploitTypes = new Set();
  const actors = new Set();
  const ransomware = new Set();
  const references = new Set([requestUrl]);
  let knownExploited = false;
  let knownRansomwareCampaignUse = null;

  for (const row of rows) {
    const index = row.index.toLowerCase();
    const source = row.source;
    const rowCves = strings(source.cve).map(value => value.toUpperCase());
    if (rowCves.length && !rowCves.includes(cve)) continue;

    if (index.includes('kev')) knownExploited = true;
    if (index === 'exploits' || index.includes('exploit')) {
      exploitKeys.add(`row:${row.id ?? exploitKeys.size}`);
      if (typeof source.exploit_type === 'string' && source.exploit_type.trim()) exploitTypes.add(source.exploit_type.trim());
    }

    const xdb = source.vulncheck_xdb;
    if (xdb !== undefined && !Array.isArray(xdb)) throw new Error('invalid VulnCheck response');
    for (const item of Array.isArray(xdb) ? xdb.slice(0, MAX_ROWS) : []) {
      if (!plain(item)) throw new Error('invalid VulnCheck response');
      const id = typeof item.xdb_id === 'string' && item.xdb_id.trim() ? item.xdb_id.trim() : null;
      if (id) exploitKeys.add(`xdb:${id}`);
      if (typeof item.exploit_type === 'string' && item.exploit_type.trim()) exploitTypes.add(item.exploit_type.trim());
      const ref = safeHttps(item.xdb_url);
      if (ref && references.size < MAX_REFERENCES) references.add(ref);
    }

    for (const actor of strings(source.threat_actors)) actors.add(actor);
    for (const family of strings(source.ransomware)) ransomware.add(family);
    if (knownRansomwareCampaignUse === null && typeof source.knownRansomwareCampaignUse === 'string' && source.knownRansomwareCampaignUse.trim()) {
      knownRansomwareCampaignUse = source.knownRansomwareCampaignUse.trim();
    }
  }

  const relationships = [];
  for (const actor of [...actors].sort()) {
    if (relationships.length >= MAX_RELATIONSHIPS) break;
    relationships.push(relation('actor', actor, 'threat_actor_context'));
  }
  for (const family of [...ransomware].sort()) {
    if (relationships.length >= MAX_RELATIONSHIPS) break;
    relationships.push(relation('ransomware', family, 'ransomware_context'));
  }

  const exploitCount = exploitKeys.size;
  const evidencePresent = knownExploited || exploitCount > 0;
  return {
    observationType: 'exploit_maturity',
    verdict: evidencePresent ? (knownExploited ? 'known_exploited' : 'exploit_available') : 'no_result',
    attributes: {
      cve,
      knownExploited: evidencePresent ? knownExploited : null,
      coverage: 'accessible_indices_only',
      queriedIndexCount: meta.queriedIndexCount,
      indicesWithHits: meta.indicesWithHits,
      totalCount: meta.totalCount,
      exploitCount,
      exploitTypes: [...exploitTypes].sort(),
      knownRansomwareCampaignUse,
      resultCount: rows.length,
      relationshipsTruncated: actors.size + ransomware.size > relationships.length,
    },
    relationships,
    references: [...references].slice(0, MAX_REFERENCES),
  };
}

export const vulncheckProvider = Object.freeze({
  name: 'vulncheck',
  types: ['cve'],
  cacheTtlMs: 6 * 60 * 60 * 1000,
  negativeCacheTtlMs: 60 * 60 * 1000,
  costClass: 'quota',
  timeoutMs: 7000,
  parserVersion: 'v3-search-cve-2026-09-13.1',
  async run(input, context = {}) {
    if (input?.type !== 'cve' || typeof input.value !== 'string' || !CVE.test(input.value)) throw new Error('unsupported VulnCheck input');
    const cve = input.value.toUpperCase();
    const token = requireEnv(context, 'VULNCHECK_API_TOKEN');
    const url = new URL(API_BASE);
    url.searchParams.set('cve', cve);
    url.searchParams.set('limit', String(MAX_ROWS));
    const requestUrl = url.toString();
    const raw = await fetchJson(requestUrl, {
      fetchImpl: context.fetchImpl,
      signal: context.signal,
      maxBytes: MAX_RESPONSE_BYTES,
      headers: { Authorization: `Bearer ${token}` },
    });
    return extract(raw, cve, requestUrl);
  },
});
