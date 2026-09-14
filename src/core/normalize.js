import { createHash } from 'node:crypto';
import { semanticClass } from './semantics.js';
import { evidenceRole } from './evidence-semantics.js';

function array(value) {
  return Array.isArray(value) ? value : [];
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonicalize(value[key])]));
  }
  return value;
}

function fingerprint(value) {
  return createHash('sha256').update(JSON.stringify(canonicalize(value))).digest('hex');
}

function evidencePolicy(meta) {
  const fields = ['mode', 'sensitivity', 'retentionClass', 'distribution'];
  if (!fields.some(field => meta[field] !== undefined)) return null;
  return Object.freeze({
    mode: typeof meta.mode === 'string' ? meta.mode : 'enrich',
    sensitivity: typeof meta.sensitivity === 'string' ? meta.sensitivity : 'public',
    retentionClass: typeof meta.retentionClass === 'string' ? meta.retentionClass : 'normal',
    distribution: typeof meta.distribution === 'string' ? meta.distribution : 'internal',
  });
}

export function normalizeEvidence(provider, indicator, type, data = {}, meta = {}) {
  const observation = {
    kind: data.observationType ?? 'enrichment',
    verdict: data.verdict ?? 'unknown',
    confidence: Number.isFinite(data.confidence) ? data.confidence : null,
    firstSeen: data.firstSeen ?? null,
    lastSeen: data.lastSeen ?? null,
    tags: array(data.tags),
    malwareFamily: data.malwareFamily ?? null,
    actor: data.actor ?? null,
    attributes: data.attributes && typeof data.attributes === 'object' ? data.attributes : {},
  };
  const relationships = array(data.relationships);
  const references = array(data.references);
  const parserVersion = meta.parserVersion ?? '1';
  const retrievedAt = meta.retrievedAt ?? null;
  const integrityFingerprint = fingerprint({
    provider,
    parserVersion,
    indicator,
    type,
    observation,
    relationships,
    references,
  });
  const semantic = semanticClass(observation.kind);
  const sourceRole = meta.sourceRole ?? 'community';
  const semantics = Object.freeze({
    class: evidenceRole({ semanticClass: semantic, sourceRole }),
    semanticClass: semantic,
    sourceRole,
  });
  const policy = evidencePolicy(meta);

  return {
    provider,
    indicator,
    type,
    observation,
    relationships,
    references,
    retrievedAt,
    cacheState: meta.cacheState ?? 'miss',
    durationMs: Number.isFinite(meta.durationMs) ? Math.max(0, meta.durationMs) : 0,
    integrity: {
      rawHash: meta.rawHash ?? null,
      parserVersion,
      fingerprint: integrityFingerprint,
    },
    semantics,
    ...(policy ? { policy } : {}),
  };
}
