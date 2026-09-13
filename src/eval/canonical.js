import { createHash } from 'node:crypto';

export function roundScore(value) {
  if (!Number.isFinite(value)) throw new TypeError('score must be finite');
  return Number(value.toFixed(6));
}

export function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map(key => [key, canonicalize(value[key])]),
    );
  }
  if (typeof value === 'number' && !Number.isFinite(value)) {
    throw new TypeError('canonical JSON cannot encode non-finite numbers');
  }
  return value;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

export function sha256Canonical(value) {
  const hex = createHash('sha256')
    .update(canonicalJson(value), 'utf8')
    .digest('hex');
  return `sha256:${hex}`;
}
