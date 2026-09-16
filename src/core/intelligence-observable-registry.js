import rawIntelligenceManifest from '../../config/intelligence-observables.json' with { type: 'json' };
import { OBSERVABLE_MANIFEST } from './observable-registry.js';

const CATEGORIES = new Set(['infrastructure', 'artifact', 'identity', 'supply_chain', 'financial_context']);
const CANONICALIZATION = new Set(['email', 'purl', 'tls-fingerprint', 'crypto-address', 'privacy-fingerprint', 'legal-entity', 'username']);
const STIX_EXPORT = new Set(['unsupported']);

function fail(message) {
  throw new Error(`invalid intelligence observable manifest: ${message}`);
}

function validate(type, input) {
  if (!/^[a-z][a-z0-9-]{1,31}$/.test(type)) fail(`type ${type}`);
  if (Object.hasOwn(OBSERVABLE_MANIFEST, type)) fail(`${type} duplicates legacy observable`);
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail(type);
  if (typeof input.displayName !== 'string' || input.displayName.length < 1 || input.displayName.length > 80) fail(`${type}.displayName`);
  if (!CATEGORIES.has(input.category)) fail(`${type}.category`);
  if (!CANONICALIZATION.has(input.canonicalization)) fail(`${type}.canonicalization`);
  if (!Number.isSafeInteger(input.maxLength) || input.maxLength < 1 || input.maxLength > 4096) fail(`${type}.maxLength`);
  if (!STIX_EXPORT.has(input.stixExport)) fail(`${type}.stixExport`);
  if (input.active !== true) fail(`${type}.active`);
  return Object.freeze({ ...input });
}

export const INTELLIGENCE_ONLY_OBSERVABLE_MANIFEST = Object.freeze(Object.fromEntries(
  Object.entries(rawIntelligenceManifest).map(([type, policy]) => [type, validate(type, policy)]),
));

export const INTELLIGENCE_OBSERVABLE_MANIFEST = Object.freeze({
  ...OBSERVABLE_MANIFEST,
  ...INTELLIGENCE_ONLY_OBSERVABLE_MANIFEST,
});

export function intelligenceObservablePolicy(type) {
  const policy = INTELLIGENCE_OBSERVABLE_MANIFEST[type];
  if (!policy) throw new Error(`unknown intelligence observable type: ${String(type)}`);
  return policy;
}

export function intelligenceObservableTypes() {
  return Object.freeze(Object.keys(INTELLIGENCE_OBSERVABLE_MANIFEST).sort());
}

export function isIntelligenceObservableType(type) {
  return typeof type === 'string' && Object.hasOwn(INTELLIGENCE_OBSERVABLE_MANIFEST, type);
}
