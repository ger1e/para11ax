import { fetchJson } from '../core/fetch-json.js';
import { requireEnv } from './helpers.js';

const API_BASE = 'https://api.vulncheck.com/v3/index/exploits';
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function schemaError() {
  return new Error('provider_schema_invalid');
}

function optionalBoolean(record, key) {
  const value = record[key];
  if (value === undefined || value === null) return false;
  if (typeof value !== 'boolean') throw schemaError();
  return value;
}

function optionalString(record, key, max = 128) {
  const value = record[key];
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string' || value.length === 0 || value.length > max) throw schemaError();
  return value;
}

function optionalCount(counts, key) {
  const value = counts?.[key];
  if (value === undefined || value === null) return 0;
  if (!Number.isSafeInteger(value) || value < 0) throw schemaError();
  return value;
}

function normalizeCounts(value) {
  if (value === undefined || value === null) value = {};
  if (!isPlainObject(value)) throw schemaError();
  return {
    exploits: optionalCount(value, 'exploits'),
    threatActors: optionalCount(value, 'threat_actors'),
    botnets: optionalCount(value, 'botnets'),
    ransomwareFamilies: optionalCount(value, 'ransomware_families'),
  };
}

function validatedExploitCount(value) {
  if (value === undefined || value === null) return 0;
  if (!Array.isArray(value)) throw schemaError();
  let count = 0;
  for (const exploit of value) {
    if (!isPlainObject(exploit)) throw schemaError();
    const validation = exploit.validation_level;
    if (validation !== undefined && validation !== null) {
      if (typeof validation !== 'string' || validation.length === 0 || validation.length > 128) throw schemaError();
      count += 1;
    }
  }
  return count;
}

function emptyAttributes() {
  return {
    maxExploitMaturity: null,
    publicExploitFound: false,
    commercialExploitFound: false,
    weaponizedExploitFound: false,
    reportedExploited: false,
    reportedExploitedByThreatActors: false,
    reportedExploitedByRansomware: false,
    reportedExploitedByBotnets: false,
    reportedExploitedByHoneypotService: false,
    reportedExploitedByVulncheckCanaries: false,
    inKev: false,
    inVcKev: false,
    counts: { exploits: 0, threatActors: 0, botnets: 0, ransomwareFamilies: 0 },
    validatedExploitCount: 0,
  };
}

function noResult(reference) {
  return {
    observationType: 'exploit_maturity',
    verdict: 'no_result',
    confidence: 100,
    attributes: emptyAttributes(),
    relationships: [],
    references: [reference],
  };
}

export const vulncheckProvider = Object.freeze({
  name: 'vulncheck',
  types: ['cve'],
  observationType: 'exploit_maturity',
  cacheTtlMs: 60 * 60 * 1000,
  negativeCacheTtlMs: 15 * 60 * 1000,
  costClass: 'scarce',
  timeoutMs: 5000,
  parserVersion: 'v3-exploits-2026-09-13.1',
  async run(input, { env = {}, signal, fetchImpl = fetch } = {}) {
    if (input?.type !== 'cve' || typeof input.value !== 'string' || !/^CVE-\d{4}-\d{4,}$/i.test(input.value)) {
      throw new Error('unsupported VulnCheck input');
    }

    const cve = input.value.toUpperCase();
    const token = requireEnv({ env }, 'VULNCHECK_API_TOKEN');
    const url = new URL(API_BASE);
    url.searchParams.set('cve', cve);
    url.searchParams.set('limit', '1');
    const reference = url.toString();

    const raw = await fetchJson(reference, {
      fetchImpl,
      signal,
      maxBytes: MAX_RESPONSE_BYTES,
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!isPlainObject(raw) || !Array.isArray(raw.data)) throw schemaError();
    if (raw.data.length === 0) return noResult(reference);
    if (raw.data.length !== 1 || !isPlainObject(raw.data[0])) throw schemaError();

    const record = raw.data[0];
    if (record.id !== cve) throw schemaError();
    const maturity = optionalString(record, 'max_exploit_maturity', 64);
    const attributes = {
      maxExploitMaturity: maturity,
      publicExploitFound: optionalBoolean(record, 'public_exploit_found'),
      commercialExploitFound: optionalBoolean(record, 'commercial_exploit_found'),
      weaponizedExploitFound: optionalBoolean(record, 'weaponized_exploit_found'),
      reportedExploited: optionalBoolean(record, 'reported_exploited'),
      reportedExploitedByThreatActors: optionalBoolean(record, 'reported_exploited_by_threat_actors'),
      reportedExploitedByRansomware: optionalBoolean(record, 'reported_exploited_by_ransomware'),
      reportedExploitedByBotnets: optionalBoolean(record, 'reported_exploited_by_botnets'),
      reportedExploitedByHoneypotService: optionalBoolean(record, 'reported_exploited_by_honeypot_service'),
      reportedExploitedByVulncheckCanaries: optionalBoolean(record, 'reported_exploited_by_vulncheck_canaries'),
      inKev: optionalBoolean(record, 'inKEV'),
      inVcKev: optionalBoolean(record, 'inVCKEV'),
      counts: normalizeCounts(record.counts),
      validatedExploitCount: validatedExploitCount(record.exploits),
    };

    return {
      observationType: 'exploit_maturity',
      verdict: maturity ?? (attributes.reportedExploited ? 'exploited' : 'observed'),
      confidence: 100,
      attributes,
      relationships: [],
      references: [reference],
    };
  },
});
