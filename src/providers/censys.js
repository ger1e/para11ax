import { fetchJson } from '../core/fetch-json.js';
import { classifyIntelligenceIndicator } from '../core/intelligence-observables.js';
import { compact, relation, requireEnv } from './helpers.js';

const SEARCH_PAGE_SIZE = 25;
const SEARCH_RELATIONSHIP_LIMIT = 75;
const HISTORY_PAGE_SIZE = 50;
const HISTORY_RELATIONSHIP_LIMIT = 50;
const SHA256_RE = /^[a-f0-9]{64}$/;
const ORG_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function certificateFingerprint(value) {
  return typeof value === 'string' && /^cert-sha256:[a-f0-9]{64}$/.test(value)
    ? value.slice('cert-sha256:'.length)
    : null;
}

function schemaInvalid() {
  throw new Error('provider_schema_invalid');
}

function objectOrNull(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function cleanString(value, maxLength = 4096) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > maxLength || /[<>]/.test(trimmed)) return null;
  return trimmed;
}

function canonicalTarget(targetType, rawValue) {
  let value = cleanString(rawValue);
  if (!value) return null;
  if (targetType === 'certificate') {
    if (!SHA256_RE.test(value.toLowerCase())) return null;
    value = `cert-sha256:${value.toLowerCase()}`;
  } else if (targetType === 'asn' && /^\d+$/.test(value)) {
    value = `AS${value}`;
  }
  try {
    const classified = classifyIntelligenceIndicator(value);
    if (classified.type !== targetType) return null;
    return classified.value;
  } catch {
    return null;
  }
}

function pushRelationship(output, seen, targetType, rawValue, relationship, extra = {}, limit = SEARCH_RELATIONSHIP_LIMIT) {
  if (output.length >= limit) return;
  const target = canonicalTarget(targetType, rawValue);
  if (!target) return;
  const key = `${targetType}\u0000${target}\u0000${relationship}`;
  if (seen.has(key)) return;
  seen.add(key);
  output.push({ targetType, target, relationship, ...extra });
}

function certificateResult(input, raw) {
  const requested = certificateFingerprint(input.value);
  if (!requested) throw Object.assign(new Error('unsupported indicator type'), { status: 400 });
  const resource = raw?.result?.resource;
  if (!resource || typeof resource !== 'object' || Array.isArray(resource)) schemaInvalid();

  const returned = resource.fingerprint_sha256 ?? resource.sha256 ?? resource.fingerprint?.sha256 ?? null;
  if (returned != null && (typeof returned !== 'string' || returned.toLowerCase() !== requested)) schemaInvalid();
  if (resource.names != null && !Array.isArray(resource.names)) schemaInvalid();

  const names = Array.isArray(resource.names)
    ? resource.names.filter(value => typeof value === 'string' && value.length > 0).slice(0, 100)
    : [];
  const subject = typeof resource.subject_dn === 'string' ? resource.subject_dn : null;
  const issuer = typeof resource.issuer_dn === 'string' ? resource.issuer_dn : null;
  const validity = resource.validity && typeof resource.validity === 'object' && !Array.isArray(resource.validity)
    ? {
        notBefore: resource.validity.start ?? resource.validity.not_before ?? null,
        notAfter: resource.validity.end ?? resource.validity.not_after ?? null,
      }
    : null;
  if (!returned && names.length === 0 && !subject && !issuer && !validity) schemaInvalid();

  return {
    observationType: 'certificate_metadata',
    verdict: 'observed',
    attributes: { sha256: requested, names, subject, issuer, validity },
    relationships: names.map(name => relation('domain', name, 'certificate_name')).filter(Boolean),
    references: [`https://search.censys.io/certificates/${requested}`],
  };
}

function searchQuery(input) {
  if (input.type === 'ip') return `host.ip=${JSON.stringify(input.value)}`;
  if (input.type === 'domain') return `web.hostname=${JSON.stringify(input.value)}`;
  if (input.type === 'certificate') {
    const fingerprint = certificateFingerprint(input.value);
    if (!fingerprint) throw Object.assign(new Error('unsupported indicator type'), { status: 400 });
    return `cert.fingerprint_sha256=${JSON.stringify(fingerprint)}`;
  }
  throw Object.assign(new Error('unsupported indicator type'), { status: 400 });
}

function searchFields(type) {
  if (type === 'ip') return ['host.ip', 'host.autonomous_system.asn', 'host.dns.names'];
  if (type === 'domain') return ['web.hostname', 'web.endpoints.ip', 'web.cert.fingerprint_sha256'];
  return ['cert.fingerprint_sha256', 'cert.names'];
}

function parseSearchResult(input, raw) {
  const result = objectOrNull(raw?.result);
  if (!result || !Array.isArray(result.hits)) schemaInvalid();
  const relationships = [];
  const seen = new Set();

  for (const hit of result.hits.slice(0, SEARCH_PAGE_SIZE)) {
    if (input.type === 'ip') {
      const resource = objectOrNull(objectOrNull(hit)?.host_v1)?.resource;
      if (!objectOrNull(resource)) continue;
      const ip = canonicalTarget('ip', resource.ip);
      if (!ip) continue;
      pushRelationship(relationships, seen, 'ip', ip, 'search_hit');
      const asn = resource.autonomous_system?.asn;
      if (asn != null) pushRelationship(relationships, seen, 'asn', String(asn), 'asn');
      if (resource.dns?.names != null && !Array.isArray(resource.dns.names)) schemaInvalid();
      for (const name of (resource.dns?.names ?? []).slice(0, 25)) pushRelationship(relationships, seen, 'domain', name, 'dns_name');
      continue;
    }

    if (input.type === 'certificate') {
      const resource = objectOrNull(objectOrNull(hit)?.certificate_v1)?.resource;
      if (!objectOrNull(resource)) continue;
      const fingerprint = canonicalTarget('certificate', resource.fingerprint_sha256);
      if (!fingerprint) continue;
      pushRelationship(relationships, seen, 'certificate', resource.fingerprint_sha256, 'search_hit');
      if (resource.names != null && !Array.isArray(resource.names)) schemaInvalid();
      for (const name of (resource.names ?? []).slice(0, 25)) pushRelationship(relationships, seen, 'domain', name, 'certificate_name');
      continue;
    }

    const resource = objectOrNull(objectOrNull(hit)?.webproperty_v1)?.resource;
    if (!objectOrNull(resource)) continue;
    const hostname = canonicalTarget('domain', resource.hostname);
    if (!hostname) continue;
    pushRelationship(relationships, seen, 'domain', hostname, 'search_hit');
    if (resource.endpoints != null && !Array.isArray(resource.endpoints)) schemaInvalid();
    for (const endpoint of (resource.endpoints ?? []).slice(0, 25)) {
      const item = objectOrNull(endpoint);
      if (!item) continue;
      pushRelationship(relationships, seen, 'ip', item.ip, 'resolved_ip');
    }
    if (resource.cert?.fingerprint_sha256) pushRelationship(relationships, seen, 'certificate', resource.cert.fingerprint_sha256, 'tls_certificate');
  }

  return {
    observationType: input.type === 'certificate' ? 'certificate_metadata' : 'internet_exposure',
    verdict: relationships.length ? 'observed' : 'no_result',
    attributes: {
      totalHits: Number.isSafeInteger(result.total_hits) && result.total_hits >= 0 ? result.total_hits : relationships.length,
      returnedHits: Math.min(result.hits.length, SEARCH_PAGE_SIZE),
    },
    relationships,
    references: ['https://search.censys.io/'],
  };
}

function historyRelationship(row) {
  const item = objectOrNull(row);
  if (!item) return null;
  const ip = canonicalTarget('ip', item.ip);
  if (!ip) return null;
  const extra = {};
  for (const [source, target] of [['start_time', 'startTime'], ['end_time', 'endTime']]) {
    const value = cleanString(item[source], 128);
    if (value) extra[target] = value;
  }
  if (Number.isSafeInteger(item.port) && item.port >= 1 && item.port <= 65535) extra.port = item.port;
  const transportProtocol = cleanString(item.transport_protocol, 32);
  if (transportProtocol) extra.transportProtocol = transportProtocol;
  if (item.protocols != null && !Array.isArray(item.protocols)) schemaInvalid();
  const protocols = [...new Set((item.protocols ?? []).map(value => cleanString(value, 64)).filter(Boolean))].sort().slice(0, 16);
  if (protocols.length) extra.protocols = protocols;
  return { ip, extra };
}

export const censysProvider = Object.freeze({
  name: 'censys', types: ['ip', 'certificate'], requiredEnv: 'CENSYS_PAT', cacheTtlMs: 86400000, negativeCacheTtlMs: 21600000, costClass: 'scarce', timeoutMs: 7000, parserVersion: 'v3-2026-08-29.1',
  async run(input, context = {}) {
    const token = requireEnv(context, 'CENSYS_PAT');
    if (input.type === 'certificate') {
      const fingerprint = certificateFingerprint(input.value);
      if (!fingerprint) throw Object.assign(new Error('unsupported indicator type'), { status: 400 });
      let raw;
      try {
        raw = await fetchJson(`https://api.platform.censys.io/v3/global/asset/certificate/${fingerprint}`, {
          ...context,
          method: 'GET',
          headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.censys.api.v3.certificate.v1+json' },
          maxBytes: 3_000_000,
        });
      } catch (error) {
        if (error?.status === 404) {
          return { observationType: 'certificate_metadata', verdict: 'no_result', attributes: { sha256: fingerprint, names: [], subject: null, issuer: null, validity: null }, relationships: [], references: [`https://search.censys.io/certificates/${fingerprint}`] };
        }
        throw error;
      }
      return certificateResult(input, raw);
    }

    if (input.type !== 'ip') throw Object.assign(new Error('unsupported indicator type'), { status: 400 });
    const url = `https://api.platform.censys.io/v3/global/asset/host/${encodeURIComponent(input.value)}`;
    let raw;
    try {
      raw = await fetchJson(url, { ...context, method: 'GET', headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.censys.api.v3.host.v1+json' }, maxBytes: 3_000_000 });
    } catch (error) {
      if (error?.status === 404) {
        return { observationType: 'internet_exposure', verdict: 'no_result', attributes: { ip: input.value, asn: null, organization: null, country: null, services: [], serviceCount: 0 }, relationships: [], references: [`https://search.censys.io/hosts/${encodeURIComponent(input.value)}`] };
      }
      throw error;
    }
    const d = raw?.result?.resource ?? raw?.result ?? {};
    const asn = d?.autonomous_system?.asn;
    const services = Array.isArray(d?.services) ? d.services : [];
    return { observationType: 'internet_exposure', verdict: 'observed', attributes: { ip: d?.ip ?? input.value, asn: asn != null ? `AS${asn}` : null, organization: d?.autonomous_system?.name ?? null, country: d?.location?.country ?? d?.location?.country_code ?? null, services: services.slice(0, 100).map(s => ({ port: s?.port ?? null, service: s?.service_name ?? s?.service?.name ?? null })), serviceCount: services.length }, relationships: compact([relation('asn', asn != null ? `AS${asn}` : null, 'asn')]), references: [`https://search.censys.io/hosts/${encodeURIComponent(input.value)}`] };
  },
});

export const censysSearchProvider = Object.freeze({
  name: 'censys-search',
  types: ['ip', 'domain', 'certificate'],
  requiredEnv: 'CENSYS_PAT',
  cacheTtlMs: 21600000,
  negativeCacheTtlMs: 3600000,
  costClass: 'scarce',
  timeoutMs: 7000,
  parserVersion: 'v3-search-2026-09-13.1',
  mode: 'search',
  fanoutEligible: false,
  async run(input, context = {}) {
    const token = requireEnv(context, 'CENSYS_PAT');
    const body = {
      query: searchQuery(input),
      fields: searchFields(input.type),
      page_size: SEARCH_PAGE_SIZE,
    };
    let raw;
    try {
      raw = await fetchJson('https://api.platform.censys.io/v3/global/search/query', {
        ...context,
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        maxBytes: 3_000_000,
      });
    } catch (error) {
      if (error?.status === 404) return { observationType: 'internet_exposure', verdict: 'no_result', attributes: { totalHits: 0, returnedHits: 0 }, relationships: [], references: ['https://search.censys.io/'] };
      throw error;
    }
    return parseSearchResult(input, raw);
  },
});

export const censysHistoryProvider = Object.freeze({
  name: 'censys-history',
  types: ['certificate'],
  requiredEnv: 'CENSYS_PAT',
  cacheTtlMs: 21600000,
  negativeCacheTtlMs: 3600000,
  costClass: 'scarce',
  timeoutMs: 7000,
  parserVersion: 'v3-history-2026-09-13.1',
  mode: 'graph',
  fanoutEligible: false,
  async run(input, context = {}) {
    const token = requireEnv(context, 'CENSYS_PAT');
    const organizationId = cleanString(context?.env?.CENSYS_ORG_ID, 64);
    if (!organizationId || !ORG_ID_RE.test(organizationId)) {
      throw Object.assign(new Error('Censys organization id required'), { status: 503 });
    }
    const fingerprint = certificateFingerprint(input.value);
    if (!fingerprint) throw Object.assign(new Error('unsupported indicator type'), { status: 400 });
    const params = new URLSearchParams({ organization_id: organizationId, page_size: String(HISTORY_PAGE_SIZE) });
    let raw;
    try {
      raw = await fetchJson(`https://api.platform.censys.io/v3/threat-hunting/certificate/${fingerprint}/observations/hosts?${params}`, {
        ...context,
        method: 'GET',
        headers: { Authorization: `Bearer ${token}` },
        maxBytes: 3_000_000,
      });
    } catch (error) {
      if (error?.status === 404) return { observationType: 'certificate_metadata', verdict: 'no_result', attributes: { totalResults: 0 }, relationships: [], references: [`https://search.censys.io/certificates/${fingerprint}`] };
      throw error;
    }
    const result = objectOrNull(raw?.result);
    if (!result || !Array.isArray(result.ranges)) schemaInvalid();
    const relationships = [];
    const seen = new Set();
    for (const row of result.ranges.slice(0, HISTORY_PAGE_SIZE)) {
      const parsed = historyRelationship(row);
      if (!parsed) continue;
      pushRelationship(relationships, seen, 'ip', parsed.ip, 'historically_presented_certificate', parsed.extra, HISTORY_RELATIONSHIP_LIMIT);
    }
    return {
      observationType: 'certificate_metadata',
      verdict: relationships.length ? 'observed' : 'no_result',
      attributes: { totalResults: Number.isSafeInteger(result.total_results) && result.total_results >= 0 ? result.total_results : relationships.length },
      relationships,
      references: [`https://search.censys.io/certificates/${fingerprint}`],
    };
  },
});
