import { fetchJson } from '../core/fetch-json.js';

const API_URL = 'https://api.hasmysecretleaked.com/v1/hashes';
const MAX_RESPONSE_BYTES = 512 * 1024;
const FINGERPRINT_RE = /^hmsl-sha256:([a-f0-9]{64})$/;

function schemaError() {
  return new Error('provider_schema_invalid');
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export const gitguardianHmslProvider = Object.freeze({
  name: 'gitguardian-hmsl',
  types: ['secret-fingerprint'],
  observationType: 'secret_exposure',
  cacheTtlMs: 0,
  negativeCacheTtlMs: 0,
  costClass: 'quota',
  timeoutMs: 5000,
  parserVersion: 'gitguardian-hmsl-2026-09-13.1',
  async run(input, { signal, fetchImpl = fetch } = {}) {
    if (input?.type !== 'secret-fingerprint' || typeof input.value !== 'string') throw new Error('unsupported GitGuardian HMSL input');
    const match = FINGERPRINT_RE.exec(input.value);
    if (!match) throw new Error('unsupported GitGuardian HMSL fingerprint');
    const hash = match[1];

    const raw = await fetchJson(API_URL, {
      fetchImpl,
      signal,
      maxBytes: MAX_RESPONSE_BYTES,
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ hashes: [hash] }),
    });
    if (!isPlainObject(raw) || !Array.isArray(raw.secrets) || raw.secrets.length > 100) throw schemaError();

    let exposureCount = 0;
    let locationAvailable = false;
    for (const record of raw.secrets) {
      if (!isPlainObject(record) || typeof record.hash !== 'string' || !/^[a-f0-9]{64}$/i.test(record.hash)) throw schemaError();
      if (record.hash.toLowerCase() !== hash) continue;
      if (!Number.isSafeInteger(record.count) || record.count < 0) throw schemaError();
      exposureCount = Math.max(exposureCount, record.count);
      locationAvailable ||= record.location !== undefined && record.location !== null;
    }

    const matched = exposureCount > 0;
    return {
      observationType: 'secret_exposure',
      verdict: matched ? 'observed' : 'not_found',
      confidence: matched ? 100 : 0,
      attributes: { matched, exposureCount, locationAvailable },
      relationships: [],
      references: ['https://docs.gitguardian.com/ggshield-docs/reference/hmsl/overview'],
    };
  },
});
