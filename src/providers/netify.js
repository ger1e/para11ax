import { fetchJson } from '../core/fetch-json.js';

const API_BASE = 'https://feeds.netify.ai/api/v2/ips';
const SOURCE_URL = 'https://www.netify.ai/resources/api';
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_ITEMS = 64;

function validIp(value) {
  return typeof value === 'string' && value.length > 2 && value.length <= 64 && /^[0-9a-f:.]+$/i.test(value);
}

function uniqueStrings(value) {
  return Array.isArray(value)
    ? [...new Set(value.filter(item => typeof item === 'string' && item.length > 0 && item.length <= 512))].sort().slice(0, MAX_ITEMS)
    : [];
}

function noResult() {
  return {
    observationType: 'network_identity',
    verdict: 'no_result',
    confidence: null,
    attributes: {},
    relationships: [],
    references: [SOURCE_URL],
  };
}

export const netifyProvider = Object.freeze({
  name: 'netify',
  types: ['ip'],
  observationType: 'network_identity',
  cacheTtlMs: 6 * 60 * 60 * 1000,
  negativeCacheTtlMs: 60 * 60 * 1000,
  costClass: 'quota',
  timeoutMs: 5000,
  parserVersion: 'netify-ip-v2-2026-09-14.1',
  requiredEnv: 'NETIFY_API_KEY',
  async run(input, { signal, fetchImpl = fetch, env = process.env } = {}) {
    if (input?.type !== 'ip' || !validIp(input.value)) throw new Error('unsupported Netify input');
    const apiKey = env.NETIFY_API_KEY;
    if (!apiKey) throw new Error('Netify is not configured');
    const requestUrl = `${API_BASE}/${encodeURIComponent(input.value)}`;
    let body;
    try {
      body = await fetchJson(requestUrl, {
        fetchImpl,
        signal,
        maxBytes: MAX_RESPONSE_BYTES,
        headers: { 'x-api-key': apiKey },
      });
    } catch (error) {
      if (error?.status === 404) return noResult();
      throw error;
    }
    if (!body || typeof body !== 'object' || Array.isArray(body) || !body.data || typeof body.data !== 'object' || Array.isArray(body.data)) throw new Error('provider_schema_invalid');
    const data = body.data;
    const applications = Array.isArray(data.application_list)
      ? [...new Set(data.application_list.map(item => item && typeof item === 'object' && typeof item.tag === 'string' ? item.tag : null).filter(Boolean))].sort().slice(0, MAX_ITEMS)
      : [];
    const hostnames = uniqueStrings(data.hostnames);
    const relationships = hostnames.map(target => ({ targetType: 'domain', target, relationship: 'network_hostname' }));
    return {
      observationType: 'network_identity',
      verdict: 'observed',
      confidence: null,
      attributes: {
        asn: typeof data.asn?.tag === 'string' ? data.asn.tag : null,
        asnName: typeof data.asn?.label === 'string' ? data.asn.label : null,
        asnRoute: typeof data.asn_route === 'string' ? data.asn_route : null,
        network: typeof data.network?.tag === 'string' ? data.network.tag : null,
        platform: typeof data.platform?.tag === 'string' ? data.platform.tag : null,
        applications,
        anycast: data.is_anycast === true,
        sharedScore: Number.isFinite(data.shared_score) ? data.shared_score : null,
      },
      relationships,
      references: [SOURCE_URL],
    };
  },
});
