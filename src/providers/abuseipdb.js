import { fetchJson } from '../core/fetch-json.js';
import { compact, relation, requireEnv } from './helpers.js';
export const abuseipdbProvider = Object.freeze({
  name: 'abuseipdb', types: ['ip'], requiredEnv: 'ABUSEIPDB_API_KEY', cacheTtlMs: 21600000, negativeCacheTtlMs: 3600000, costClass: 'free', timeoutMs: 5000, parserVersion: '2026-11-28.1',
  async run(input, context = {}) {
    const key = requireEnv(context, 'ABUSEIPDB_API_KEY'); const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(input.value)}&maxAgeInDays=90&verbose`;
    const raw = await fetchJson(url, { ...context, headers: { Key: key, Accept: 'application/json' } }); const d = raw?.data ?? {};
    const reports = Array.isArray(d.reports) ? d.reports : [];
    const counts = new Map();
    for (const report of reports) {
      for (const category of new Set(Array.isArray(report?.categories) ? report.categories : [])) {
        if (Number.isInteger(category) && category >= 1 && category <= 23) counts.set(category, (counts.get(category) ?? 0) + 1);
      }
    }
    const communityCategoryCounts = [...counts].sort((a,b) => b[1]-a[1] || a[0]-b[0])
      .map(([category, count]) => ({category, count}));
    const cleanComment = value => typeof value === 'string' ? value
      .replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, ' ')
      .replace(/https?:\/\/\S+/gi, '[URL omitted]')
      .replace(/\b(?:password|passwd|token|api[_-]?key|authorization|secret)\s*[:=]\s*\S+/gi, '[REDACTED]')
      .trim().slice(0, 300) : '';
    const communityRecentReports = reports.filter(report => typeof report?.reportedAt === 'string')
      .sort((a,b) => b.reportedAt.localeCompare(a.reportedAt)).slice(0, 3)
      .map(report => ({reportedAt: report.reportedAt.slice(0,40),
        categories: (Array.isArray(report.categories) ? report.categories : []).filter(Number.isInteger).slice(0,23),
        comment: cleanComment(report.comment)}));
    const score = d.abuseConfidenceScore == null ? NaN : Number(d.abuseConfidenceScore); const verdict = score >= 75 ? 'malicious' : score >= 25 ? 'suspicious' : Number.isFinite(score) ? 'low_reported_abuse' : 'unknown';
    return { observationType: 'reported_abuse', verdict, confidence: Number.isFinite(score) ? score : null, lastSeen: d.lastReportedAt ?? null, attributes: { ip: d.ipAddress ?? input.value, country: d.countryCode ?? null, organization: d.isp ?? null, domain: d.domain ?? null, usageType: d.usageType ?? null, totalReports: d.totalReports ?? null, abuseConfidenceScore: d.abuseConfidenceScore ?? null, communityReturnedReportCount: reports.length, communityDistinctReporterCount: d.numDistinctUsers ?? null, communityCategoryCounts, communityRecentReports, communityReportScope: 'returned reports only; unverified community claims' }, relationships: compact([relation('domain', d.domain, 'reported_domain')]), references: [`https://www.abuseipdb.com/check/${encodeURIComponent(input.value)}`] };
  },
});
