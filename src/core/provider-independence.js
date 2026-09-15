const MAX_ENTRIES = 256;
const MAX_TEXT = 256;
const MAX_REFERENCES = 16;
const MAX_REFERENCE_LENGTH = 2048;
const CONFIDENCES = new Set(['confirmed', 'probable', 'unknown']);
const BASES = new Set(['declared', 'documented_upstream', 'maintained_mapping', 'fallback']);
const ENTRY_KEYS = new Set([
  'provider',
  'independenceGroup',
  'lineageConfidence',
  'basis',
  'references',
  'updatedAt',
]);

function boundedText(value, label) {
  if (typeof value !== 'string') throw new TypeError(`${label} must be a string`);
  const normalized = value.trim();
  if (!normalized || normalized.length > MAX_TEXT) {
    throw new RangeError(`${label} must be 1-${MAX_TEXT} characters`);
  }
  return normalized;
}

function validateExactKeys(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  for (const key of Object.keys(value)) {
    if (!ENTRY_KEYS.has(key)) throw new TypeError(`${label} contains unsupported field: ${key}`);
  }
}

function normalizeReference(value) {
  if (typeof value !== 'string' || value.length > MAX_REFERENCE_LENGTH) {
    throw new TypeError('reference must be a bounded string');
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError('reference must be a valid HTTP(S) URL');
  }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) {
    throw new TypeError('reference must be a safe HTTP(S) URL without credentials');
  }
  return parsed.toString();
}

function normalizeUpdatedAt(value) {
  if (typeof value !== 'string' || !value.trim()) throw new TypeError('updatedAt must be an ISO timestamp');
  const millis = Date.parse(value);
  if (!Number.isFinite(millis)) throw new TypeError('updatedAt must be an ISO timestamp');
  return new Date(millis).toISOString();
}

function normalizeEntry(entry, index) {
  validateExactKeys(entry, `entry[${index}]`);
  const provider = boundedText(entry.provider, 'provider');
  const independenceGroup = boundedText(entry.independenceGroup, 'independenceGroup');
  if (!CONFIDENCES.has(entry.lineageConfidence)) {
    throw new TypeError('lineageConfidence must be confirmed, probable, or unknown');
  }
  if (!BASES.has(entry.basis) || entry.basis === 'fallback') {
    throw new TypeError('basis must be declared, documented_upstream, or maintained_mapping for registry entries');
  }
  if (!Array.isArray(entry.references) || entry.references.length > MAX_REFERENCES) {
    throw new TypeError(`references must be an array of at most ${MAX_REFERENCES} URLs`);
  }
  const references = [...new Set(entry.references.map(normalizeReference))].sort();
  const updatedAt = normalizeUpdatedAt(entry.updatedAt);
  const quorumEligible = entry.lineageConfidence !== 'unknown';
  return Object.freeze({
    provider,
    independenceGroup,
    lineageConfidence: entry.lineageConfidence,
    basis: entry.basis,
    references: Object.freeze(references),
    updatedAt,
    quorumEligible,
  });
}

function providerKey(provider) {
  return provider.toLocaleLowerCase('en-US');
}

export function createProviderIndependenceRegistry(entries = []) {
  if (!Array.isArray(entries) || entries.length > MAX_ENTRIES) {
    throw new TypeError(`entries must be an array of at most ${MAX_ENTRIES} records`);
  }
  const normalized = entries.map(normalizeEntry).sort((a, b) =>
    a.provider.localeCompare(b.provider) || a.independenceGroup.localeCompare(b.independenceGroup));
  const seen = new Set();
  for (const entry of normalized) {
    const key = providerKey(entry.provider);
    if (seen.has(key)) throw new TypeError(`duplicate provider mapping: ${entry.provider}`);
    seen.add(key);
  }
  return Object.freeze({
    version: 'provider-independence-v1.0',
    entries: Object.freeze(normalized),
  });
}

export const DEFAULT_PROVIDER_INDEPENDENCE_ENTRIES = Object.freeze([
  Object.freeze({ provider: 'virustotal', independenceGroup: 'google-virustotal', lineageConfidence: 'confirmed', basis: 'maintained_mapping', references: [], updatedAt: '2026-09-13T00:00:00.000Z' }),
  Object.freeze({ provider: 'urlhaus', independenceGroup: 'abuse-ch', lineageConfidence: 'confirmed', basis: 'maintained_mapping', references: [], updatedAt: '2026-09-13T00:00:00.000Z' }),
  Object.freeze({ provider: 'otx', independenceGroup: 'levelblue-otx', lineageConfidence: 'confirmed', basis: 'maintained_mapping', references: [], updatedAt: '2026-09-13T00:00:00.000Z' }),
  Object.freeze({ provider: 'openphish', independenceGroup: 'openphish', lineageConfidence: 'confirmed', basis: 'maintained_mapping', references: [], updatedAt: '2026-09-13T00:00:00.000Z' }),
]);

export const DEFAULT_PROVIDER_INDEPENDENCE_REGISTRY = createProviderIndependenceRegistry(DEFAULT_PROVIDER_INDEPENDENCE_ENTRIES);

export function resolveProviderIndependence(provider, registry = DEFAULT_PROVIDER_INDEPENDENCE_REGISTRY) {
  const normalizedProvider = boundedText(provider, 'provider');
  if (!registry || registry.version !== 'provider-independence-v1.0' || !Array.isArray(registry.entries)) {
    throw new TypeError('registry must be a provider-independence-v1.0 registry');
  }
  const match = registry.entries.find((entry) => providerKey(entry.provider) === providerKey(normalizedProvider));
  if (match) return match;
  return Object.freeze({
    provider: normalizedProvider,
    independenceGroup: `provider:${normalizedProvider}`,
    lineageConfidence: 'unknown',
    basis: 'fallback',
    references: Object.freeze([]),
    updatedAt: null,
    quorumEligible: false,
  });
}

export function summarizeProviderIndependence(providers = [], registry = DEFAULT_PROVIDER_INDEPENDENCE_REGISTRY) {
  if (!Array.isArray(providers) || providers.length > MAX_ENTRIES) {
    throw new TypeError(`providers must be an array of at most ${MAX_ENTRIES} values`);
  }
  const uniqueProviders = [...new Set(providers.map((provider) => boundedText(provider, 'provider')))];
  const resolved = uniqueProviders.map((provider) => resolveProviderIndependence(provider, registry));
  const quorumGroups = [...new Set(
    resolved.filter((entry) => entry.quorumEligible).map((entry) => entry.independenceGroup),
  )].sort();
  const unknownProviders = resolved
    .filter((entry) => !entry.quorumEligible)
    .map((entry) => entry.provider)
    .sort();
  return Object.freeze({
    registryVersion: registry.version,
    rawProviderCount: uniqueProviders.length,
    quorumEligibleGroupCount: quorumGroups.length,
    quorumGroups: Object.freeze(quorumGroups),
    unknownProviders: Object.freeze(unknownProviders),
    resolved: Object.freeze([...resolved].sort((a, b) => a.provider.localeCompare(b.provider))),
  });
}
