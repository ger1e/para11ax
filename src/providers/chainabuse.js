import { fetchJson } from '../core/fetch-json.js';

const API_URL = 'https://api.chainabuse.com/v0/reports';
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_REPORTS = 50;

function schemaError() {
  return new Error('provider_schema_invalid');
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function safeText(value, max = 256) {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string' || value.length < 1 || value.length > max || /[\u0000-\u001f\u007f<>]/.test(value)) throw schemaError();
  return value;
}

function normalizeAddress(value) {
  if (typeof value !== 'string') return null;
  if (/^eth:[a-f0-9]{40}$/i.test(value)) return { network: 'eth', address: value.slice(4).toLowerCase() };
  if (/^btc:[A-Za-z0-9]{12,90}$/.test(value)) return { network: 'btc', address: value.slice(4) };
  return null;
}

function normalizeReport(record) {
  if (!isPlainObject(record)) throw schemaError();
  const id = safeText(record.id, 128);
  if (!id) throw schemaError();
  if (record.trusted !== undefined && typeof record.trusted !== 'boolean') throw schemaError();
  if (record.checked !== undefined && typeof record.checked !== 'boolean') throw schemaError();
  return {
    id,
    category: safeText(record.scamCategory, 128),
    createdAt: safeText(record.createdAt, 128),
    trusted: record.trusted === true,
    checked: record.checked === true,
  };
}

export const chainabuseProvider = Object.freeze({
  name: 'chainabuse',
  types: ['crypto-address'],
  observationType: 'crypto_abuse',
  cacheTtlMs: 6 * 60 * 60 * 1000,
  negativeCacheTtlMs: 60 * 60 * 1000,
  costClass: 'scarce',
  timeoutMs: 5000,
  parserVersion: 'chainabuse-v0-2026-09-13.1',
  requiredEnv: 'CHAINABUSE_API_KEY',
  async run(input, { env = process.env, signal, fetchImpl = fetch } = {}) {
    if (input?.type !== 'crypto-address') throw new Error('unsupported Chainabuse input');
    const normalized = normalizeAddress(input.value);
    if (!normalized) throw new Error('unsupported Chainabuse crypto address');
    const key = env.CHAINABUSE_API_KEY;
    if (!key) throw new Error('Chainabuse is not configured');

    const url = new URL(API_URL);
    url.searchParams.set('address', normalized.address);
    url.searchParams.set('page', '1');
    url.searchParams.set('perPage', String(MAX_REPORTS));
    const requestUrl = url.toString();
    const authorization = `Basic ${Buffer.from(`${key}:${key}`).toString('base64')}`;
    const raw = await fetchJson(requestUrl, {
      fetchImpl,
      signal,
      maxBytes: MAX_RESPONSE_BYTES,
      method: 'GET',
      headers: { Authorization: authorization },
    });

    if (!isPlainObject(raw) || !Array.isArray(raw.reports) || raw.reports.length > MAX_REPORTS) throw schemaError();
    if (raw.count !== undefined && (!Number.isSafeInteger(raw.count) || raw.count < 0)) throw schemaError();
    const reports = raw.reports.map(normalizeReport).sort((a, b) => {
      const dateOrder = String(a.createdAt ?? '').localeCompare(String(b.createdAt ?? ''));
      return dateOrder || a.id.localeCompare(b.id);
    });

    return {
      observationType: 'crypto_abuse',
      verdict: reports.length ? 'reported' : 'not_found',
      confidence: reports.length ? 70 : 0,
      attributes: {
        network: normalized.network,
        reportCount: reports.length,
        reports,
      },
      relationships: [],
      references: [requestUrl],
    };
  },
});
