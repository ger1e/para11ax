import { fetchJson } from '../core/fetch-json.js';
import { arr, compact, envValue, relation, requireEnv, uniq } from './helpers.js';

const LOOKUP_DOC = 'https://docs.greynoise.io/reference/v3ip';
const SWARM_DOC = 'https://docs.greynoise.io/docs/using-the-greynoise-community-dataset';
const DEFAULT_DATASET_SCOPES = Object.freeze(['greynoise']);
const ALLOWED_DATASET_SCOPES = new Set(['greynoise', 'community', 'personal']);

function datasetScopes(context) {
  const configured = envValue(context, 'GREYNOISE_WORKSPACE_LABELS');
  if (!configured) return { scopes: [...DEFAULT_DATASET_SCOPES], explicit: false };
  const scopes = uniq(configured.split(',').map(value => value.trim().toLowerCase()))
    .filter(value => ALLOWED_DATASET_SCOPES.has(value));
  return { scopes: scopes.length ? scopes : [...DEFAULT_DATASET_SCOPES], explicit: scopes.length > 0 };
}

function tagNames(value) {
  return uniq(arr(value).map(tag => typeof tag === 'string' ? tag : tag?.name ?? tag?.slug ?? null)).slice(0, 64);
}

function scannedPorts(value) {
  return uniq(arr(value).map(scan => scan?.port === undefined || scan?.port === null
    ? null
    : `${scan.port}/${String(scan?.protocol ?? 'unknown').toUpperCase()}`)).slice(0, 64);
}

function observedScopes(raw) {
  return uniq([
    ...arr(raw?.workspace_labels),
    raw?.workspace_label,
  ]).map(value => value.toLowerCase()).filter(value => ALLOWED_DATASET_SCOPES.has(value));
}

function verdictFor(raw) {
  if (raw?.seen === false) return 'no_result';
  if (raw?.classification === 'malicious') return 'malicious';
  if (raw?.classification === 'suspicious') return 'suspicious';
  if (raw?.classification === 'benign') return 'benign';
  if (raw?.seen === true || raw?.last_seen) return 'internet_noise';
  return 'unknown';
}

function noResult(ip, scopes) {
  return {
    observationType: 'internet_noise',
    verdict: 'no_result',
    attributes: {
      ip,
      name: null,
      noise: false,
      riot: false,
      classification: null,
      datasetScopes: scopes,
      observedDatasetScopes: [],
    },
    relationships: [],
    references: [LOOKUP_DOC, SWARM_DOC],
  };
}

export const greynoiseProvider = Object.freeze({
  name: 'greynoise', types: ['ip'], requiredEnv: 'GREYNOISE_API_KEY', cacheTtlMs: 86400000, negativeCacheTtlMs: 21600000, costClass: 'scarce', timeoutMs: 5000, parserVersion: '2026-09-11.1',
  async run(input, context = {}) {
    const key = requireEnv(context, 'GREYNOISE_API_KEY');
    const { scopes, explicit } = datasetScopes(context);
    const url = new URL(`https://api.greynoise.io/v3/ip/${encodeURIComponent(input.value)}`);
    // GreyNoise treats workspace_labels as an entitlement-bearing request. Omitting
    // it uses the default global dataset and works with ordinary API keys.
    if (explicit) url.searchParams.set('workspace_labels', scopes.join(','));
    let raw;
    try {
      raw = await fetchJson(url, { ...context, headers: { key } });
    } catch (error) {
      if (error?.status === 404) return noResult(input.value, scopes);
      throw error;
    }
    if (raw?.seen === false) return noResult(raw?.ip ?? input.value, scopes);

    const tags = tagNames(raw?.tags ?? raw?.tag);
    const cves = uniq(arr(raw?.cve)).slice(0, 64);
    const ports = scannedPorts(raw?.raw_data?.scan);
    const observedDatasetScopes = observedScopes(raw);
    const name = raw?.actor ?? raw?.metadata?.rdns ?? null;
    const noise = raw?.seen === true || Boolean(raw?.last_seen || raw?.classification || tags.length);

    return {
      observationType: 'internet_noise',
      verdict: verdictFor(raw),
      lastSeen: raw?.last_seen ?? null,
      tags: compact([raw?.classification, ...tags]),
      attributes: {
        ip: raw?.ip ?? input.value,
        name,
        noise,
        riot: Boolean(raw?.riot),
        classification: raw?.classification ?? null,
        actor: raw?.actor ?? null,
        firstSeen: raw?.first_seen ?? null,
        spoofable: raw?.spoofable ?? null,
        asn: raw?.metadata?.asn ?? null,
        organization: raw?.metadata?.organization ?? null,
        rdns: raw?.metadata?.rdns ?? null,
        countryCode: raw?.metadata?.source_country_code ?? raw?.metadata?.country_code ?? null,
        cves,
        scannedPorts: ports,
        datasetScopes: scopes,
        observedDatasetScopes,
      },
      relationships: compact([relation('url', raw?.link, 'greynoise_profile')]),
      references: compact([raw?.link, LOOKUP_DOC, SWARM_DOC]),
    };
  },
});
