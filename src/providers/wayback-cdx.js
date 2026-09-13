import { fetchJson } from '../core/fetch-json.js';

const API_URL = 'https://web.archive.org/cdx/search/cdx';
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_CAPTURES = 25;

function validHttpUrl(value) {
  try {
    const url = new URL(value);
    return (url.protocol === 'http:' || url.protocol === 'https:') && url.href.length <= 2048 ? url.href : null;
  } catch {
    return null;
  }
}

function parseRows(raw) {
  if (!Array.isArray(raw) || raw.length < 1 || raw.length > MAX_CAPTURES + 1) throw new Error('provider_schema_invalid');
  const header = raw[0];
  if (!Array.isArray(header) || header.join(',') !== 'timestamp,original,statuscode,digest') throw new Error('provider_schema_invalid');
  const rows = [];
  for (const row of raw.slice(1)) {
    if (!Array.isArray(row) || row.length !== 4 || typeof row[0] !== 'string' || typeof row[1] !== 'string' || typeof row[2] !== 'string' || typeof row[3] !== 'string') throw new Error('provider_schema_invalid');
    if (!/^\d{14}$/.test(row[0]) || row[2] !== '200' || row[3].length > 256) throw new Error('provider_schema_invalid');
    const url = validHttpUrl(row[1]);
    if (!url) throw new Error('provider_schema_invalid');
    rows.push({ timestamp: row[0], original: url, digest: row[3] });
  }
  return rows;
}

export const waybackCdxProvider = Object.freeze({
  name: 'wayback-cdx',
  types: ['domain', 'url'],
  observationType: 'web_archive_observation',
  cacheTtlMs: 12 * 60 * 60 * 1000,
  negativeCacheTtlMs: 60 * 60 * 1000,
  costClass: 'free',
  timeoutMs: 5000,
  parserVersion: 'wayback-cdx-2026-09-13.1',
  async run(input, { signal, fetchImpl = fetch } = {}) {
    if (!['domain', 'url'].includes(input?.type) || typeof input.value !== 'string' || input.value.length < 1 || input.value.length > 2048) throw new Error('unsupported Wayback input');
    const queryValue = input.type === 'domain' ? `${input.value}/*` : input.value;
    const params = new URLSearchParams({
      url: queryValue,
      output: 'json',
      fl: 'timestamp,original,statuscode,digest',
      filter: 'statuscode:200',
      collapse: 'digest',
      limit: String(MAX_CAPTURES),
      gzip: 'false',
    });
    const requestUrl = `${API_URL}?${params.toString()}`;
    const raw = await fetchJson(requestUrl, { fetchImpl, signal, maxBytes: MAX_RESPONSE_BYTES });
    const rows = parseRows(raw);
    const seen = new Set();
    const relationships = [];
    for (const row of rows) {
      if (seen.has(row.original)) continue;
      seen.add(row.original);
      relationships.push({ targetType: 'url', target: row.original, relationship: 'archived_capture' });
      if (relationships.length >= MAX_CAPTURES) break;
    }
    return {
      observationType: 'web_archive_observation',
      verdict: rows.length ? 'observed' : 'not_found',
      confidence: rows.length ? 100 : 0,
      attributes: {
        captureCount: rows.length,
        firstSeen: rows.length ? rows[0].timestamp : null,
        lastSeen: rows.length ? rows[rows.length - 1].timestamp : null,
      },
      relationships,
      references: [requestUrl],
    };
  },
});
