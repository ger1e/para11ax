import { fetchJson } from '../core/fetch-json.js';
import { classifyIndicator } from '../core/validate.js';

const API_BASE = 'https://mwdb.cert.pl/api';
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_RELATIONSHIPS = 50;
const HASH_RE = /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i;
const C2_KEYS = new Set(['c2', 'c&c', 'cnc', 'host', 'hostname', 'domain', 'server', 'url', 'gate']);

function schemaError() {
  return new Error('provider_schema_invalid');
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function normalizeTarget(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 2048 || /[\u0000-\u001f\u007f<>]/.test(value)) return null;
  const candidate = value.trim().replace(/^hxxps:/i, 'https:').replace(/^hxxp:/i, 'http:');
  try {
    const classified = classifyIndicator(candidate);
    if (['ip', 'domain', 'url'].includes(classified.type)) return { targetType: classified.type, target: classified.value };
  } catch {}
  const hostPort = candidate.match(/^([^:/\s]+):(\d{1,5})$/);
  if (hostPort) {
    try {
      const classified = classifyIndicator(hostPort[1]);
      if (['ip', 'domain'].includes(classified.type)) return { targetType: classified.type, target: classified.value };
    } catch {}
  }
  return null;
}

function extractC2(config) {
  const output = [];
  const seen = new Set();
  const walk = (value, key = '', depth = 0) => {
    if (depth > 8 || output.length >= MAX_RELATIONSHIPS) return;
    if (typeof value === 'string') {
      if (!C2_KEYS.has(key.toLowerCase())) return;
      const target = normalizeTarget(value);
      if (!target) return;
      const id = `${target.targetType}:${target.target}`;
      if (!seen.has(id)) {
        seen.add(id);
        output.push({ ...target, relationship: 'malware_config_c2' });
      }
      return;
    }
    if (Array.isArray(value)) {
      for (const item of value.slice(0, 100)) walk(item, key, depth + 1);
      return;
    }
    if (!isObject(value)) return;
    for (const [childKey, child] of Object.entries(value).slice(0, 100)) walk(child, childKey, depth + 1);
  };
  walk(config);
  return output;
}

async function getJson(url, token, options) {
  return fetchJson(url, {
    fetchImpl: options.fetchImpl,
    signal: options.signal,
    maxBytes: MAX_RESPONSE_BYTES,
    headers: { Authorization: `Bearer ${token}` },
  });
}

export const mwdbProvider = Object.freeze({
  name: 'mwdb',
  types: ['hash'],
  observationType: 'malware_configuration',
  cacheTtlMs: 6 * 60 * 60 * 1000,
  negativeCacheTtlMs: 60 * 60 * 1000,
  costClass: 'quota',
  timeoutMs: 5000,
  parserVersion: 'mwdb-2026-09-13.1',
  requiredEnv: 'MWDB_API_TOKEN',
  async run(input, { signal, fetchImpl = fetch, env = process.env } = {}) {
    if (input?.type !== 'hash' || typeof input.value !== 'string' || !HASH_RE.test(input.value)) throw new Error('unsupported MWDB hash input');
    const token = env.MWDB_API_TOKEN;
    if (!token) throw new Error('MWDB is not configured');
    const hash = input.value.toLowerCase();
    const fileUrl = `${API_BASE}/file/${encodeURIComponent(hash)}`;
    const file = await getJson(fileUrl, token, { fetchImpl, signal });
    if (!isObject(file) || file.type !== 'file' || typeof file.id !== 'string') throw schemaError();
    if (file.tags !== undefined && !Array.isArray(file.tags)) throw schemaError();
    const tagNames = Array.isArray(file.tags)
      ? file.tags.slice(0, 100).map(item => typeof item === 'string' ? item : item?.tag).filter(item => typeof item === 'string' && item.length <= 256)
      : [];
    let config = null;
    let relationships = [];
    const references = [fileUrl];
    if (typeof file.latest_config === 'string' && file.latest_config.length > 0 && file.latest_config.length <= 128) {
      const configUrl = `${API_BASE}/config/${encodeURIComponent(file.latest_config)}`;
      config = await getJson(configUrl, token, { fetchImpl, signal });
      if (!isObject(config) || config.type !== 'config' || !isObject(config.config)) throw schemaError();
      relationships = extractC2(config.config);
      references.push(configUrl);
    }
    return {
      observationType: 'malware_configuration',
      verdict: 'observed',
      confidence: config ? 95 : 65,
      attributes: {
        hash,
        sha256: typeof file.sha256 === 'string' ? file.sha256.toLowerCase() : null,
        tags: [...new Set(tagNames)].sort(),
        family: typeof config?.family === 'string' && config.family.length <= 256 ? config.family : null,
        configId: typeof config?.id === 'string' ? config.id : null,
        c2Count: relationships.length,
      },
      relationships,
      references,
    };
  },
});
