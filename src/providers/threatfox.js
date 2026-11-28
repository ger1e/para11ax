import { fetchJson } from '../core/fetch-json.js';
import { compact, relation, requireEnv } from './helpers.js';

export const threatfoxProvider = Object.freeze({
  name: 'threatfox', types: ['ip', 'domain', 'url', 'hash'], methods: ['POST'], requiredEnv: 'ABUSECH_API_KEY', cacheTtlMs: 3600000, negativeCacheTtlMs: 1800000, costClass: 'free', timeoutMs: 7000, parserVersion: '2026-11-28.1',
  async run(input, context = {}) {
    const key = requireEnv(context, 'ABUSECH_API_KEY');
    const body = input.type === 'hash'
      ? { query: 'search_hash', hash: input.value }
      : { query: 'search_ioc', search_term: input.value, exact_match: true };
    const raw = await fetchJson('https://threatfox-api.abuse.ch/api/v1/', {
      ...context,
      method: 'POST',
      headers: { 'Auth-Key': key, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      maxBytes: 3_000_000,
    });
    const rows = Array.isArray(raw?.data) ? raw.data : [];
    const first = rows[0] ?? {};
    // Keep competing feed assertions separate; multiple rows are not independent sources.
    const clean = value => typeof value === 'string'
      ? value.replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, ' ').trim().slice(0, 160) || null : null;
    const family = row => clean(row?.malware_printable) ?? clean(row?.malware);
    const families = [...new Set(rows.map(family).filter(Boolean))].sort();
    const associations = rows.slice(0, 8).map(row => ({
      recordId: /^\d{1,20}$/.test(String(row?.id ?? '')) ? String(row.id) : null,
      family: family(row),
      alias: clean(row?.malware_alias),
      threatType: clean(row?.threat_type),
      confidence: row?.confidence_level != null && Number.isFinite(Number(row.confidence_level))
        ? Number(row.confidence_level) : null,
      firstSeen: clean(row?.first_seen),
      lastSeen: clean(row?.last_seen),
    }));
    const sourceRefs = associations.filter(row => row.recordId)
      .map(row => 'https://threatfox.abuse.ch/ioc/' + row.recordId + '/');

    const rels = rows.map(row => relation(
      row?.ioc_type?.includes('ip') ? 'ip'
        : row?.ioc_type?.includes('domain') ? 'domain'
          : row?.ioc_type?.includes('url') ? 'url'
            : null,
      row?.ioc,
      'threatfox_ioc',
    )).filter(item => item?.targetType);
    return {
      observationType: 'threat_intelligence',
      verdict: rows.length ? 'associated' : 'no_association',
      confidence: families.length <= 1 && first?.confidence_level != null && Number.isFinite(Number(first.confidence_level)) ? Number(first.confidence_level) : null,
      firstSeen: first?.first_seen ?? null,
      lastSeen: first?.last_seen ?? null,
      tags: compact(rows.flatMap(row => Array.isArray(row?.tags) ? row.tags : [])),
      malwareFamily: families.length === 1 ? families[0] : null,
      attributes: {
        queryStatus: raw?.query_status ?? null,
        threatType: first?.threat_type ?? null,
        resultCount: rows.length,
        reportedMalwareFamilies: families.slice(0, 25),
        conflictingFamilyLabels: families.length > 1,
        reportedAssociations: associations,
        omittedAssociations: Math.max(0, rows.length - associations.length),
      },
      relationships: rels,
      references: [...new Set(['https://threatfox.abuse.ch/', ...sourceRefs])],
    };
  },
});
