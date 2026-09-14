import { fetchJson } from '../core/fetch-json.js';

const API_BASE = 'https://d3fend.mitre.org/api/offensive-technique/attack';
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_BINDINGS = 1000;
const MAX_TECHNIQUES = 100;
const ATTACK_RE = /^T\d{4}(?:\.\d{3})?$/;

function schemaError() {
  return new Error('provider_schema_invalid');
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function safeText(value, max = 256) {
  if (typeof value !== 'string' || value.length < 1 || value.length > max || /[\u0000-\u001f\u007f<>]/.test(value)) return null;
  return value;
}

function bindingValue(binding, key, max = 256) {
  const field = binding?.[key];
  if (!isPlainObject(field)) return null;
  return safeText(field.value, max);
}

export const d3fendProvider = Object.freeze({
  name: 'd3fend',
  types: ['attack'],
  observationType: 'defensive_knowledge',
  cacheTtlMs: 24 * 60 * 60 * 1000,
  negativeCacheTtlMs: 6 * 60 * 60 * 1000,
  costClass: 'free',
  timeoutMs: 5000,
  parserVersion: 'd3fend-2026-09-13.1',
  async run(input, { signal, fetchImpl = fetch } = {}) {
    if (input?.type !== 'attack' || typeof input.value !== 'string' || !ATTACK_RE.test(input.value)) {
      throw new Error('unsupported D3FEND ATT&CK input');
    }

    const attackId = input.value;
    const requestUrl = `${API_BASE}/${encodeURIComponent(attackId)}.json`;
    const raw = await fetchJson(requestUrl, {
      fetchImpl,
      signal,
      maxBytes: MAX_RESPONSE_BYTES,
      method: 'GET',
    });

    if (!isPlainObject(raw) || !isPlainObject(raw.off_to_def) || !isPlainObject(raw.off_to_def.results) || !Array.isArray(raw.off_to_def.results.bindings)) {
      throw schemaError();
    }
    const bindings = raw.off_to_def.results.bindings;
    if (bindings.length > MAX_BINDINGS) throw schemaError();

    let attackTechnique = null;
    const techniques = new Map();
    for (const binding of bindings) {
      if (!isPlainObject(binding)) throw schemaError();
      const offensiveLabel = bindingValue(binding, 'off_tech_label');
      if (!attackTechnique && offensiveLabel) attackTechnique = offensiveLabel;

      const id = bindingValue(binding, 'def_tech_id', 64);
      const label = bindingValue(binding, 'def_tech_label');
      const tactic = bindingValue(binding, 'def_tactic_label');
      if (!id || !label || !tactic) continue;
      if (!/^D3-[A-Z0-9-]{1,32}$/i.test(id)) continue;
      const canonicalId = id.toUpperCase();
      if (!techniques.has(canonicalId)) techniques.set(canonicalId, { id: canonicalId, label, tactic });
      if (techniques.size > MAX_TECHNIQUES) throw schemaError();
    }

    const defensiveTechniques = [...techniques.values()].sort((a, b) => a.id.localeCompare(b.id));
    return {
      observationType: 'defensive_knowledge',
      verdict: defensiveTechniques.length ? 'reference' : 'not_found',
      confidence: defensiveTechniques.length ? 100 : 0,
      attributes: { attackId, attackTechnique, defensiveTechniques },
      relationships: [],
      references: [requestUrl],
    };
  },
});
