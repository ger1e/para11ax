import { loadTextFeed } from './public-feed.js';

const FEED_URL = 'https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv';
const JA3_RE = /^[a-f0-9]{32}$/;

function unsupported() {
  return new Error('unsupported SSLBL TLS fingerprint');
}

function parseFeed(text) {
  const rows = [];
  for (const line of String(text).split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const parts = trimmed.split(',');
    if (parts.length < 4) throw new Error('invalid SSLBL JA3 feed');
    const fingerprint = parts[0].trim().toLowerCase();
    if (!JA3_RE.test(fingerprint)) throw new Error('invalid SSLBL JA3 feed');
    rows.push(Object.freeze({
      fingerprint,
      firstSeen: parts[1].trim(),
      lastSeen: parts[2].trim(),
      listingReason: parts.slice(3).join(',').trim(),
    }));
    if (rows.length > 100_000) throw new Error('invalid SSLBL JA3 feed');
  }
  return rows;
}

export const sslblProvider = Object.freeze({
  name: 'sslbl',
  types: ['tls-fingerprint'],
  observationType: 'tls_malware_infrastructure',
  cacheTtlMs: 60 * 60 * 1000,
  negativeCacheTtlMs: 30 * 60 * 1000,
  costClass: 'free',
  timeoutMs: 5000,
  parserVersion: 'sslbl-ja3-2026-09-13.1',
  async run(input, context = {}) {
    if (input?.type !== 'tls-fingerprint' || typeof input.value !== 'string' || !input.value.startsWith('ja3:')) throw unsupported();
    const fingerprint = input.value.slice(4).toLowerCase();
    if (!JA3_RE.test(fingerprint)) throw unsupported();
    const text = await loadTextFeed(FEED_URL, context, { ttlMs: 60 * 60 * 1000, maxBytes: 8 * 1024 * 1024 });
    const match = parseFeed(text).find(row => row.fingerprint === fingerprint) ?? null;
    return {
      observationType: 'tls_malware_infrastructure',
      verdict: match ? 'listed' : 'not_listed',
      confidence: match ? 95 : 0,
      attributes: {
        fingerprint,
        family: 'ja3',
        listed: Boolean(match),
        firstSeen: match?.firstSeen ?? null,
        lastSeen: match?.lastSeen ?? null,
        listingReason: match?.listingReason ?? null,
      },
      relationships: [],
      references: [FEED_URL],
    };
  },
});
