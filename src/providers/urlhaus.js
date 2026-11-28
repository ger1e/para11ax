import { fetchJson } from '../core/fetch-json.js';
import { compact, relation, requireEnv } from './helpers.js';
export const urlhausProvider = Object.freeze({
  name: 'urlhaus', types: ['url'], methods: ['POST'], requiredEnv: 'ABUSECH_API_KEY', cacheTtlMs: 3600000, negativeCacheTtlMs: 1800000, costClass: 'free', timeoutMs: 7000, parserVersion: '2026-11-28.1',
  async run(input, context = {}) {
    const key = requireEnv(context, 'ABUSECH_API_KEY'); const body = new URLSearchParams({ url: input.value }).toString();
    const raw = await fetchJson('https://urlhaus-api.abuse.ch/v1/url/', { ...context, method: 'POST', headers: { 'Auth-Key': key, 'Content-Type': 'application/x-www-form-urlencoded' }, body, maxBytes: 3_000_000 }); const payloads = Array.isArray(raw?.payloads) ? raw.payloads : [];
    const label = value => typeof value === 'string' ? value.trim().slice(0,160) || null : null;
    const signatures = [...new Set(payloads.map(p => label(p?.signature)).filter(Boolean))].sort();
    const recordId = /^\d{1,20}$/.test(String(raw?.id ?? '')) ? String(raw.id) : null;
    return { observationType: 'malware_distribution', verdict: raw?.query_status === 'ok' ? 'associated' : 'no_association', firstSeen: raw?.date_added ?? null, lastSeen: raw?.last_online ?? null, tags: compact(raw?.tags), attributes: { urlStatus: raw?.url_status ?? null, threat: raw?.threat ?? null, queryStatus: raw?.query_status ?? null, payloadCount: payloads.length, reportedPayloadSignatures: signatures.slice(0,25), recordId, payloadRecords: payloads.slice(0,8).map(p => ({signature:label(p?.signature), fileType:label(p?.file_type), firstSeen:label(p?.firstseen ?? p?.first_seen)})), omittedPayloadRecords:Math.max(0,payloads.length-8) }, relationships: compact(payloads.map(p => relation('hash', p?.response_sha256 ?? p?.sha256_hash, 'payload_sha256'))), references: compact(['https://urlhaus.abuse.ch/', recordId ? 'https://urlhaus.abuse.ch/url/' + recordId + '/' : null]) };
  },
});
