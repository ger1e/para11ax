import { fetchJson } from '../core/fetch-json.js';
import { classifyIndicator } from '../core/validate.js';
import { compact, isoFromUnix, relation, requireEnv, vtVerdict } from './helpers.js';

const COVERAGE_OBSERVATION_TYPES = Object.freeze({
  ip: Object.freeze(['multi_engine_reputation']),
  domain: Object.freeze(['multi_engine_reputation']),
  url: Object.freeze(['multi_engine_reputation']),
  hash: Object.freeze(['multi_engine_reputation']),
  certificate: Object.freeze(['certificate_metadata']),
});

const GRAPH_PAGE_LIMIT = 20;
const GRAPH_SPECS = Object.freeze({
  domain: Object.freeze([
    Object.freeze({ name: 'resolutions', targetType: 'ip', relationship: 'resolves_to', value: item => item?.attributes?.ip_address }),
    Object.freeze({ name: 'communicating_files', targetType: 'hash', relationship: 'communicating_file', value: item => item?.id }),
    Object.freeze({ name: 'historical_ssl_certificates', targetType: 'certificate', relationship: 'historical_ssl_certificate', value: item => item?.id ? `cert-sha256:${item.id}` : null }),
  ]),
  ip: Object.freeze([
    Object.freeze({ name: 'resolutions', targetType: 'domain', relationship: 'resolved_domain', value: item => item?.attributes?.host_name }),
    Object.freeze({ name: 'communicating_files', targetType: 'hash', relationship: 'communicating_file', value: item => item?.id }),
    Object.freeze({ name: 'historical_ssl_certificates', targetType: 'certificate', relationship: 'historical_ssl_certificate', value: item => item?.id ? `cert-sha256:${item.id}` : null }),
  ]),
  hash: Object.freeze([
    Object.freeze({ name: 'contacted_domains', targetType: 'domain', relationship: 'contacted_domain', value: item => item?.id }),
    Object.freeze({ name: 'contacted_ips', targetType: 'ip', relationship: 'contacted_ip', value: item => item?.id }),
    Object.freeze({ name: 'contacted_urls', targetType: 'url', relationship: 'contacted_url', value: item => item?.attributes?.url }),
  ]),
});

function certificateFingerprint(value) {
  return typeof value === 'string' && /^cert-sha256:[a-f0-9]{64}$/.test(value)
    ? value.slice('cert-sha256:'.length)
    : null;
}

function vtPath(input) {
  if (input.type === 'ip') return `ip_addresses/${encodeURIComponent(input.value)}`;
  if (input.type === 'domain') return `domains/${encodeURIComponent(input.value)}`;
  if (input.type === 'hash') return `files/${encodeURIComponent(input.value)}`;
  if (input.type === 'url') return `urls/${Buffer.from(input.value).toString('base64url').replace(/=+$/, '')}`;
  if (input.type === 'certificate') {
    const fingerprint = certificateFingerprint(input.value);
    if (fingerprint) return `ssl_certs/${fingerprint}`;
  }
  throw Object.assign(new Error('unsupported indicator type'), { status: 400 });
}

function graphRoot(input) {
  if (input.type === 'ip') return `ip_addresses/${encodeURIComponent(input.value)}`;
  if (input.type === 'domain') return `domains/${encodeURIComponent(input.value)}`;
  if (input.type === 'hash') return `files/${encodeURIComponent(input.value)}`;
  throw Object.assign(new Error('unsupported indicator type'), { status: 400 });
}

function noResult(input) {
  if (input?.type === 'certificate') {
    const fingerprint = certificateFingerprint(input.value);
    return {
      observationType: 'certificate_metadata',
      verdict: 'no_result',
      lastSeen: null,
      tags: [],
      attributes: { sha256: fingerprint, names: [], subject: null, issuer: null, validity: null },
      relationships: [],
      references: ['https://www.virustotal.com/gui/home/search'],
    };
  }
  return {
    observationType: 'multi_engine_reputation',
    verdict: 'no_result',
    lastSeen: null,
    tags: [],
    attributes: {
      reputation: null,
      lastAnalysisStats: {},
      typeDescription: null,
      meaningfulName: null,
    },
    relationships: [],
    references: ['https://www.virustotal.com/gui/home/search'],
  };
}

function graphResult(relationships, classes) {
  return {
    observationType: 'infrastructure_relationship',
    verdict: relationships.length ? 'observed' : 'no_result',
    lastSeen: null,
    tags: [],
    attributes: {
      relationshipClasses: classes,
      relationshipCount: relationships.length,
      pageLimit: GRAPH_PAGE_LIMIT,
      pagination: 'first_page_only',
    },
    relationships,
    references: ['https://docs.virustotal.com/reference/relationships'],
  };
}

function schemaInvalid() {
  throw new Error('provider_schema_invalid');
}

function canonicalRelationship(spec, item) {
  const raw = spec.value(item);
  if (typeof raw !== 'string' || !raw.trim() || /[<>]/.test(raw)) return null;
  try {
    const classified = classifyIndicator(raw);
    if (classified.type !== spec.targetType) return null;
    return relation(spec.targetType, classified.value, spec.relationship);
  } catch {
    return null;
  }
}

async function graphRelationships(input, context, key) {
  const specs = GRAPH_SPECS[input.type];
  if (!specs) throw Object.assign(new Error('unsupported indicator type'), { status: 400 });
  const root = graphRoot(input);
  const relationships = [];
  const seen = new Set();

  for (const spec of specs) {
    let raw;
    try {
      raw = await fetchJson(`https://www.virustotal.com/api/v3/${root}/${spec.name}?limit=${GRAPH_PAGE_LIMIT}`, {
        ...context,
        method: 'GET',
        headers: { 'x-apikey': key },
        maxBytes: 1_000_000,
      });
    } catch (error) {
      if (error?.status === 404) continue;
      throw error;
    }
    if (!raw || !Array.isArray(raw.data)) schemaInvalid();
    for (const item of raw.data.slice(0, GRAPH_PAGE_LIMIT)) {
      const mapped = canonicalRelationship(spec, item);
      if (!mapped) continue;
      const dedupeKey = `${mapped.targetType}\u0000${mapped.target}\u0000${mapped.relationship}`;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);
      relationships.push(mapped);
    }
  }
  return graphResult(relationships, specs.map(spec => spec.name));
}

function certificateResult(input, raw) {
  const requested = certificateFingerprint(input.value);
  if (!requested) throw Object.assign(new Error('unsupported indicator type'), { status: 400 });
  const data = raw?.data;
  if (!data || typeof data !== 'object' || Array.isArray(data)) schemaInvalid();
  if (data.type != null && data.type !== 'ssl_cert') schemaInvalid();
  const attributes = data.attributes;
  if (!attributes || typeof attributes !== 'object' || Array.isArray(attributes)) schemaInvalid();

  for (const returned of [data.id, attributes.thumbprint_sha256, attributes.sha256, attributes.fingerprint_sha256]) {
    if (returned != null && (typeof returned !== 'string' || returned.toLowerCase() !== requested)) schemaInvalid();
  }

  const san = attributes.extensions?.subject_alternative_name ?? attributes.subject_alternative_name ?? [];
  if (san != null && !Array.isArray(san)) schemaInvalid();
  const names = Array.isArray(san) ? san.filter(value => typeof value === 'string' && value.length > 0).slice(0, 100) : [];
  const subject = attributes.subject && typeof attributes.subject === 'object' && !Array.isArray(attributes.subject)
    ? attributes.subject.CN ?? attributes.subject.common_name ?? null
    : null;
  const issuer = attributes.issuer && typeof attributes.issuer === 'object' && !Array.isArray(attributes.issuer)
    ? attributes.issuer.CN ?? attributes.issuer.common_name ?? null
    : null;
  const validity = attributes.validity && typeof attributes.validity === 'object' && !Array.isArray(attributes.validity)
    ? { notBefore: attributes.validity.not_before ?? null, notAfter: attributes.validity.not_after ?? null }
    : null;

  return {
    observationType: 'certificate_metadata',
    verdict: 'observed',
    lastSeen: null,
    tags: [],
    attributes: { sha256: requested, names, subject, issuer, validity },
    relationships: [],
    references: ['https://www.virustotal.com/gui/home/search'],
  };
}

export const virustotalProvider = Object.freeze({
  name: 'virustotal', types: ['ip', 'domain', 'url', 'hash', 'certificate'], requiredEnv: 'VIRUSTOTAL_API_KEY', cacheTtlMs: 21600000, negativeCacheTtlMs: 3600000, costClass: 'scarce', timeoutMs: 7000, parserVersion: 'v3-2026-08-29.1',
  coverageObservationTypesByType: COVERAGE_OBSERVATION_TYPES,
  async run(input, context = {}) {
    const key = requireEnv(context, 'VIRUSTOTAL_API_KEY');
    let raw;
    try {
      raw = await fetchJson(`https://www.virustotal.com/api/v3/${vtPath(input)}`, {
        ...context,
        method: 'GET',
        headers: { 'x-apikey': key },
        maxBytes: 3_000_000,
      });
    } catch (error) {
      if (error?.status === 404) return noResult(input);
      throw error;
    }
    if (input.type === 'certificate') return certificateResult(input, raw);
    const a = raw?.data?.attributes ?? {};
    const stats = a.last_analysis_stats ?? {};
    return {
      observationType: 'multi_engine_reputation',
      verdict: vtVerdict(stats),
      lastSeen: isoFromUnix(a.last_analysis_date),
      tags: compact(a.tags),
      attributes: {
        reputation: a.reputation ?? null,
        lastAnalysisStats: stats,
        typeDescription: a.type_description ?? null,
        meaningfulName: a.meaningful_name ?? null,
      },
      relationships: [],
      references: ['https://www.virustotal.com/gui/home/search'],
    };
  },
});

export const virustotalGraphProvider = Object.freeze({
  name: 'virustotal-graph',
  types: ['ip', 'domain', 'hash'],
  requiredEnv: 'VIRUSTOTAL_API_KEY',
  cacheTtlMs: 21600000,
  negativeCacheTtlMs: 3600000,
  costClass: 'scarce',
  timeoutMs: 7000,
  parserVersion: 'v3-2026-09-13.1',
  mode: 'graph',
  fanoutEligible: false,
  sensitivity: 'public',
  authorization: 'none',
  retentionClass: 'normal',
  distribution: 'internal',
  providerFamily: 'virustotal',
  maxPages: 1,
  maxRelationships: 60,
  async run(input, context = {}) {
    const key = requireEnv(context, 'VIRUSTOTAL_API_KEY');
    return graphRelationships(input, context, key);
  },
});
