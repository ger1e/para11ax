import { fetchJson } from '../core/fetch-json.js';
import { compact, relation } from './helpers.js';

const CVE = /^CVE-\d{4}-\d{4,}$/i;

export const osvProvider = Object.freeze({
  name: 'osv', types: ['cve'], cacheTtlMs: 86400000, negativeCacheTtlMs: 21600000, costClass: 'free', timeoutMs: 5000, parserVersion: '2026-09-11.1',
  async run(input, context = {}) {
    const url = `https://api.osv.dev/v1/vulns/${encodeURIComponent(input.value)}`; let raw;
    try { raw = await fetchJson(url, { ...context, maxBytes: 2_000_000 }); }
    catch (error) { if (error?.status === 404) return { observationType: 'open_source_vulnerability', verdict: 'no_result', attributes: { id: input.value, aliases: [] }, relationships: [], references: [`https://osv.dev/vulnerability/${encodeURIComponent(input.value)}`] }; throw error; }
    const aliases = Array.isArray(raw?.aliases) ? [...new Set(raw.aliases.filter(value => typeof value === 'string' && value.trim()).map(value => value.trim()))].slice(0, 64) : [];
    const cveAliases = aliases.filter(alias => CVE.test(alias) && alias.toUpperCase() !== String(input.value).toUpperCase());
    return {
      observationType: 'open_source_vulnerability',
      verdict: 'cataloged',
      firstSeen: raw?.published ?? null,
      lastSeen: raw?.modified ?? null,
      attributes: {
        id: raw?.id ?? input.value,
        summary: raw?.summary ?? null,
        affectedCount: Array.isArray(raw?.affected) ? raw.affected.length : 0,
        aliases,
      },
      relationships: compact(cveAliases.map(alias => relation('cve', alias.toUpperCase(), 'alias'))),
      references: [`https://osv.dev/vulnerability/${encodeURIComponent(raw?.id ?? input.value)}`],
    };
  },
});
