import { fetchJson } from '../core/fetch-json.js';
import { compact, relation, requireEnv } from './helpers.js';

const API_ROOT = 'https://hybrid-analysis.com/api/v2';

function noResult() {
  return {
    observationType: 'sandbox_report_index',
    verdict: 'no_result',
    attributes: { reportCount: 0, reports: [] },
    relationships: [],
    references: ['https://hybrid-analysis.com/'],
  };
}

function reportRows(raw) {
  if (Array.isArray(raw)) return raw;
  if (Array.isArray(raw?.reports)) return raw.reports;
  return [];
}

export const hybridAnalysisProvider = Object.freeze({
  name: 'hybrid-analysis',
  types: ['hash'],
  requiredEnv: 'HYBRID_ANALYSIS_API_KEY',
  cacheTtlMs: 86400000,
  negativeCacheTtlMs: 3600000,
  costClass: 'scarce',
  timeoutMs: 10000,
  parserVersion: 'v2.38.0-2026-11-28.1',
  async run(input, context = {}) {
    const key = requireEnv(context, 'HYBRID_ANALYSIS_API_KEY');
    const url = `${API_ROOT}/search/hash?hash=${encodeURIComponent(input.value)}`;
    let raw;
    try {
      raw = await fetchJson(url, {
        ...context,
        headers: { 'api-key': key, 'User-Agent': 'Falcon Sandbox' },
        maxBytes: 3_000_000,
      });
    } catch (error) {
      if (error?.status === 404) return noResult();
      throw error;
    }

    const reports = reportRows(raw);
    const families = [...new Set(reports.map(report => typeof report?.vx_family === 'string' ? report.vx_family.trim().slice(0,160) : '').filter(Boolean))].sort();
    const verdicts = reports.map(report => String(report?.verdict ?? '').toLowerCase());
    const verdict = verdicts.includes('malicious')
      ? 'malicious'
      : verdicts.includes('suspicious')
        ? 'suspicious'
        : reports.length
          ? 'observed'
          : 'no_result';
    const hashes = compact([
      ...(Array.isArray(raw?.sha256s) ? raw.sha256s : []),
      ...reports.flatMap(report => [report?.sha256, report?.sha256_hash]),
    ]);

    return {
      observationType: 'sandbox_report_index',
      verdict,
      malwareFamily: families.length === 1 ? families[0] : null,
      attributes: {
        reportCount: reports.length,
        reportedMalwareFamilies: families.slice(0,25),
        conflictingFamilyLabels: families.length > 1,
        sandboxVerdicts: [...new Set(verdicts.filter(Boolean))].sort(),
        omittedReports: Math.max(0, reports.length - 20),
        reports: reports.slice(0, 20).map(report => ({
          id: report?.id ?? null,
          environmentId: report?.environment_id ?? null,
          state: report?.state ?? null,
          verdict: report?.verdict ?? null,
          threatScore: report?.threat_score != null && Number.isFinite(Number(report.threat_score)) ? Number(report.threat_score) : null,
          family: report?.vx_family ?? null,
        })),
      },
      relationships: compact(hashes.map(hash => relation('hash', hash, 'related_sha256'))),
      references: ['https://hybrid-analysis.com/', ...[...new Set(hashes.filter(hash => typeof hash === 'string' && /^[a-f0-9]{64}$/i.test(hash)))].slice(0,8).map(hash => 'https://hybrid-analysis.com/sample/' + hash.toLowerCase())],
    };
  },
});
