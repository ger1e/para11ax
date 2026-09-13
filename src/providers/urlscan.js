import { fetchJson } from '../core/fetch-json.js';
import { classifyIntelligenceIndicator } from '../core/intelligence-observables.js';
import { compact, relation, requireEnv } from './helpers.js';

const GRAPH_SEARCH_SIZE = 5;
const GRAPH_RELATIONSHIP_LIMIT = 64;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SHA256_RE = /^[a-f0-9]{64}$/i;

function query(input) {
  if (input.type === 'ip') return `ip:${input.value}`;
  if (input.type === 'domain') return `domain:${input.value}`;
  if (input.type === 'url') return `page.url:${JSON.stringify(input.value)}`;
  throw Object.assign(new Error('unsupported indicator type'), { status: 400 });
}

function schemaInvalid() {
  throw new Error('provider_schema_invalid');
}

function objectOrNull(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function rejectMarkup(value) {
  return typeof value === 'string' && value.trim() && !/[<>]/.test(value) ? value.trim() : null;
}

function canonicalTarget(targetType, rawValue) {
  let value = rejectMarkup(rawValue);
  if (!value) return null;
  if (targetType === 'certificate') {
    if (!SHA256_RE.test(value)) return null;
    value = `cert-sha256:${value.toLowerCase()}`;
  }
  try {
    const classified = classifyIntelligenceIndicator(value);
    if (classified.type !== targetType) return null;
    return classified.value;
  } catch {
    return null;
  }
}

function pushRelationship(output, seen, targetType, rawValue, relationship) {
  if (output.length >= GRAPH_RELATIONSHIP_LIMIT) return;
  const target = canonicalTarget(targetType, rawValue);
  if (!target) return;
  const key = `${targetType}\u0000${target}\u0000${relationship}`;
  if (seen.has(key)) return;
  seen.add(key);
  output.push({ targetType, target, relationship });
}

function assertOptionalArray(owner, key) {
  if (owner?.[key] != null && !Array.isArray(owner[key])) schemaInvalid();
  return Array.isArray(owner?.[key]) ? owner[key] : [];
}

function resultUuid(search) {
  if (!search || typeof search !== 'object' || Array.isArray(search)) schemaInvalid();
  if (!Array.isArray(search.results)) schemaInvalid();
  const first = search.results.find(row => UUID_RE.test(String(row?._id ?? '')));
  return first?._id ?? null;
}

function parseDeepResult(raw) {
  const root = objectOrNull(raw);
  if (!root) schemaInvalid();
  const page = root.page == null ? {} : objectOrNull(root.page);
  const task = root.task == null ? {} : objectOrNull(root.task);
  const data = root.data == null ? {} : objectOrNull(root.data);
  const lists = root.lists == null ? {} : objectOrNull(root.lists);
  const meta = root.meta == null ? {} : objectOrNull(root.meta);
  if (!page || !task || !data || !lists || !meta) schemaInvalid();

  const redirects = assertOptionalArray(data, 'redirects');
  const domains = assertOptionalArray(lists, 'domains');
  const ips = assertOptionalArray(lists, 'ips');
  const urls = assertOptionalArray(lists, 'urls');
  const hashes = assertOptionalArray(lists, 'hashes');
  const certificates = assertOptionalArray(lists, 'certificates');

  const processors = meta.processors == null ? {} : objectOrNull(meta.processors);
  if (!processors) schemaInvalid();
  const download = processors.download == null ? {} : objectOrNull(processors.download);
  const wappa = processors.wappa == null ? {} : objectOrNull(processors.wappa);
  if (!download || !wappa) schemaInvalid();
  const downloads = assertOptionalArray(download, 'data');
  const technologies = assertOptionalArray(wappa, 'data');

  const relationships = [];
  const seen = new Set();
  const finalUrl = canonicalTarget('url', page.url);
  if (finalUrl) pushRelationship(relationships, seen, 'url', finalUrl, 'final_destination');

  for (const row of redirects.slice(0, 32)) {
    const value = objectOrNull(row)?.url;
    const canonical = canonicalTarget('url', value);
    if (!canonical || canonical === finalUrl) continue;
    pushRelationship(relationships, seen, 'url', canonical, 'redirect_step');
  }
  for (const value of domains.slice(0, 32)) pushRelationship(relationships, seen, 'domain', value, 'request_host');
  for (const value of ips.slice(0, 32)) pushRelationship(relationships, seen, 'ip', value, 'contacted_ip');
  for (const value of urls.slice(0, 32)) pushRelationship(relationships, seen, 'url', value, 'requested_url');
  for (const value of hashes.slice(0, 32)) pushRelationship(relationships, seen, 'hash', value, 'response_body_hash');
  for (const item of certificates.slice(0, 32)) {
    const certificate = objectOrNull(item);
    if (!certificate) continue;
    pushRelationship(relationships, seen, 'certificate', certificate.sha256, 'tls_certificate');
  }
  for (const item of downloads.slice(0, 32)) {
    const downloadItem = objectOrNull(item);
    if (!downloadItem) continue;
    pushRelationship(relationships, seen, 'hash', downloadItem.sha256, 'downloaded_file');
  }

  const technologyNames = [...new Set(technologies
    .slice(0, 64)
    .map(item => rejectMarkup(objectOrNull(item)?.app))
    .filter(Boolean))]
    .sort()
    .slice(0, 32);

  if (!relationships.length && !technologyNames.length && !rejectMarkup(task.uuid) && !rejectMarkup(task.url) && !rejectMarkup(page.url)) {
    schemaInvalid();
  }

  return {
    observationType: 'web_scan_history',
    verdict: relationships.length || technologyNames.length ? 'observed' : 'no_result',
    attributes: { technologies: technologyNames },
    relationships,
    references: [UUID_RE.test(String(task.uuid ?? '')) ? `https://urlscan.io/result/${task.uuid}/` : 'https://urlscan.io/search/'],
  };
}

export const urlscanProvider = Object.freeze({
  name: 'urlscan', types: ['ip', 'domain', 'url'], requiredEnv: 'URLSCAN_API_KEY', cacheTtlMs: 21600000, negativeCacheTtlMs: 3600000, costClass: 'free', timeoutMs: 7000, parserVersion: '2026-08-20',
  async run(input, context = {}) {
    const key = requireEnv(context, 'URLSCAN_API_KEY');
    const url = `https://urlscan.io/api/v1/search?q=${encodeURIComponent(query(input))}&size=25`;
    const raw = await fetchJson(url, { ...context, headers: { 'api-key': key }, maxBytes: 3_000_000 });
    const rows = Array.isArray(raw?.results) ? raw.results : [];
    const malicious = rows.some(r => r?.verdicts?.overall?.malicious === true);
    const rels = [];
    for (const r of rows) {
      if (r?.page?.ip) rels.push(relation('ip', r.page.ip, 'resolved_ip'));
      if (r?.page?.domain) rels.push(relation('domain', r.page.domain, 'observed_domain'));
      if (r?.page?.url) rels.push(relation('url', r.page.url, 'observed_url'));
    }
    return {
      observationType: 'web_observation',
      verdict: malicious ? 'malicious' : rows.length ? 'observed' : 'no_result',
      firstSeen: rows.at(-1)?.indexedAt ?? null,
      lastSeen: rows[0]?.indexedAt ?? null,
      attributes: { resultCount: rows.length },
      relationships: compact(rels),
      references: ['https://urlscan.io/search/'],
    };
  },
});

export const urlscanGraphProvider = Object.freeze({
  name: 'urlscan-graph',
  types: ['ip', 'domain', 'url'],
  requiredEnv: 'URLSCAN_API_KEY',
  cacheTtlMs: 21600000,
  negativeCacheTtlMs: 3600000,
  costClass: 'quota',
  timeoutMs: 7000,
  parserVersion: '2026-09-13.1',
  mode: 'graph',
  fanoutEligible: false,
  async run(input, context = {}) {
    const key = requireEnv(context, 'URLSCAN_API_KEY');
    const searchUrl = `https://urlscan.io/api/v1/search?q=${encodeURIComponent(query(input))}&size=${GRAPH_SEARCH_SIZE}`;
    let search;
    try {
      search = await fetchJson(searchUrl, { ...context, headers: { 'api-key': key }, maxBytes: 1_000_000 });
    } catch (error) {
      if (error?.status === 404) {
        return { observationType: 'web_scan_history', verdict: 'no_result', attributes: { technologies: [] }, relationships: [], references: ['https://urlscan.io/search/'] };
      }
      throw error;
    }
    const uuid = resultUuid(search);
    if (!uuid) {
      return { observationType: 'web_scan_history', verdict: 'no_result', attributes: { technologies: [] }, relationships: [], references: ['https://urlscan.io/search/'] };
    }

    let detail;
    try {
      detail = await fetchJson(`https://urlscan.io/api/v1/result/${uuid}/`, {
        ...context,
        headers: { 'api-key': key },
        maxBytes: 4_000_000,
      });
    } catch (error) {
      if (error?.status === 404 || error?.status === 410) {
        return { observationType: 'web_scan_history', verdict: 'no_result', attributes: { technologies: [] }, relationships: [], references: [`https://urlscan.io/result/${uuid}/`] };
      }
      throw error;
    }
    return parseDeepResult(detail);
  },
});
