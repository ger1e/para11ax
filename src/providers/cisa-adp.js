import { fetchJson } from '../core/fetch-json.js';

const CVE_API_BASE = 'https://cveawg.mitre.org/api/cve/';
const CISA_ADP_ORG_ID = '134c704f-9b21-4f2e-91b3-4a467353bcc0';
const CISA_ADP_SHORT_NAME = 'CISA-ADP';
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const EXPLOITATION = new Set(['none', 'poc', 'active']);
const AUTOMATABLE = new Set(['no', 'yes']);
const TECHNICAL_IMPACT = new Set(['partial', 'total']);

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isTimestamp(value) {
  return typeof value === 'string' && value.length <= 64 && Number.isFinite(Date.parse(value));
}

function emptyAttributes() {
  return {
    exploitation: null,
    automatable: null,
    technicalImpact: null,
    ssvcVersion: null,
    assessedAt: null,
    cisaAdpUpdatedAt: null,
    kevCataloged: false,
  };
}

function noResult(reference) {
  return {
    observationType: 'ssvc_assessment',
    verdict: 'no_result',
    confidence: 100,
    attributes: emptyAttributes(),
    references: [reference],
  };
}

function findCisaContainer(record) {
  const adp = record?.containers?.adp;
  if (adp === undefined) return null;
  if (!Array.isArray(adp)) throw new Error('invalid CVE ADP container');
  return adp.find(container => {
    const metadata = container?.providerMetadata;
    return isPlainObject(metadata)
      && metadata.shortName === CISA_ADP_SHORT_NAME
      && metadata.orgId === CISA_ADP_ORG_ID;
  }) ?? null;
}

function optionValue(options, key) {
  const matches = options
    .filter(option => isPlainObject(option) && Object.prototype.hasOwnProperty.call(option, key))
    .map(option => option[key]);
  if (matches.length !== 1 || typeof matches[0] !== 'string') throw new Error('invalid CISA ADP SSVC record');
  return matches[0].toLowerCase();
}

function parseSsvc(container, expectedCve) {
  const metrics = container?.metrics;
  if (metrics === undefined) return null;
  if (!Array.isArray(metrics)) throw new Error('invalid CISA ADP SSVC record');
  const metric = metrics.find(item => item?.other?.type === 'ssvc');
  if (!metric) return null;
  const content = metric?.other?.content;
  if (!isPlainObject(content)
    || content.id !== expectedCve
    || content.role !== 'CISA Coordinator'
    || !Array.isArray(content.options)
    || typeof content.version !== 'string'
    || content.version.length === 0
    || content.version.length > 32
    || !isTimestamp(content.timestamp)) {
    throw new Error('invalid CISA ADP SSVC record');
  }

  const exploitation = optionValue(content.options, 'Exploitation');
  const automatable = optionValue(content.options, 'Automatable');
  const technicalImpact = optionValue(content.options, 'Technical Impact');
  if (!EXPLOITATION.has(exploitation)
    || !AUTOMATABLE.has(automatable)
    || !TECHNICAL_IMPACT.has(technicalImpact)) {
    throw new Error('invalid CISA ADP SSVC record');
  }

  return {
    exploitation,
    automatable,
    technicalImpact,
    ssvcVersion: content.version,
    assessedAt: content.timestamp,
  };
}

function hasKevMetric(container) {
  const metrics = Array.isArray(container?.metrics) ? container.metrics : [];
  return metrics.some(item => item?.other?.type === 'kev' && isPlainObject(item?.other?.content));
}

export const cisaAdpProvider = Object.freeze({
  name: 'cisa-adp',
  types: ['cve'],
  cacheTtlMs: 6 * 60 * 60 * 1000,
  negativeCacheTtlMs: 60 * 60 * 1000,
  costClass: 'free',
  timeoutMs: 5000,
  parserVersion: '5.2-cisa-adp-2026-09-12.1',
  async run(input, { signal, fetchImpl = fetch } = {}) {
    if (input?.type !== 'cve' || typeof input.value !== 'string') throw new Error('unsupported CISA ADP input');
    const reference = `${CVE_API_BASE}${encodeURIComponent(input.value)}`;
    let raw;
    try {
      raw = await fetchJson(reference, { fetchImpl, signal, maxBytes: MAX_RESPONSE_BYTES });
    } catch (error) {
      if (error?.status === 404) return noResult(reference);
      throw error;
    }

    if (!isPlainObject(raw)
      || raw.dataType !== 'CVE_RECORD'
      || !isPlainObject(raw.cveMetadata)
      || raw.cveMetadata.cveId !== input.value
      || !isPlainObject(raw.containers)) {
      throw new Error('invalid CVE record');
    }

    const container = findCisaContainer(raw);
    if (!container) return noResult(reference);
    const ssvc = parseSsvc(container, input.value);
    if (!ssvc) return noResult(reference);

    const dateUpdated = container?.providerMetadata?.dateUpdated;
    if (dateUpdated !== undefined && !isTimestamp(dateUpdated)) throw new Error('invalid CISA ADP SSVC record');

    return {
      observationType: 'ssvc_assessment',
      verdict: 'assessed',
      confidence: 100,
      firstSeen: ssvc.assessedAt,
      attributes: {
        ...ssvc,
        cisaAdpUpdatedAt: dateUpdated ?? null,
        kevCataloged: hasKevMetric(container),
      },
      references: [reference],
    };
  },
});
