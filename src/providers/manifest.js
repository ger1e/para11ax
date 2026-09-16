import rawManifest from '../../config/providers.json' with { type: 'json' };
import rawIntelligenceManifest from '../../config/intelligence-providers.json' with { type: 'json' };
import { EXECUTION_POLICY_VERSION } from '../core/execution-policy.js';

const MAX_PROVIDERS = 64;
const MAX_TEXT = 512;
const REQUIRED_ARRAYS = ['types','observationTypes','fixedHosts','methods','protocols'];
const REQUIRED_NUMBERS = ['tier','timeoutMs','cacheTtlMs','negativeCacheTtlMs','maxResponseBytes'];
const COST_CLASSES = new Set(['free','quota','scarce']);
const AUTH_TYPES = new Set(['none','api_key','bearer','basic','token']);
const DISTRIBUTIONS = new Set(['internal','shareable','internal_only']);
const SOURCE_ROLES = new Set(['authoritative','first_party','aggregator','community','contextual']);
const FRESHNESS_CLASSES = new Set(['live','near_real_time','periodic','reference']);
const ADMISSION_VERSIONS = new Set(['v8.1']);
const SCHEDULER_ENUMS = Object.freeze({
  authorityClass: new Set(['authoritative','first_party','specialist','aggregator','community','contextual']),
  semanticUniqueness: new Set(['unique','complementary','duplicative']),
  intelligenceValue: new Set(['direct','supporting','contextual']),
  pivotValue: new Set(['high','medium','low','none']),
  latencyClass: new Set(['fast','normal','slow']),
});
const SCHEDULER_FIELDS = Object.freeze(Object.keys(SCHEDULER_ENUMS));

function fail(message) {
  throw new Error(`invalid provider manifest: ${message}`);
}

function boundedText(value, field, { nullable = false } = {}) {
  if (nullable && value === null) return null;
  if (typeof value !== 'string' || value.length < 1 || value.length > MAX_TEXT) fail(field);
  return value;
}

function boundedArray(value, field) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 32) fail(field);
  const out = value.map((item, index) => boundedText(item, `${field}[${index}]`));
  if (new Set(out).size !== out.length) fail(`${field} duplicate`);
  return Object.freeze(out);
}

function frozenObject(entries) {
  return Object.freeze(Object.fromEntries(entries));
}

export function sanitizeSchedulerMetadata(types, schedulerByType) {
  const supported = Array.isArray(types) ? [...new Set(types.filter(type => typeof type === 'string'))] : [];
  const supportedSet = new Set(supported);
  if (schedulerByType === undefined) {
    return Object.freeze({
      schedulerByType: frozenObject([]),
      schedulerMetadataInvalidTypes: Object.freeze([]),
    });
  }
  if (!schedulerByType || typeof schedulerByType !== 'object' || Array.isArray(schedulerByType)) {
    return Object.freeze({
      schedulerByType: frozenObject([]),
      schedulerMetadataInvalidTypes: Object.freeze([...supported].sort()),
    });
  }

  const normalized = [];
  const invalid = new Set();
  for (const [type, descriptor] of Object.entries(schedulerByType)) {
    if (!supportedSet.has(type)) {
      invalid.add(type);
      continue;
    }
    if (!descriptor || typeof descriptor !== 'object' || Array.isArray(descriptor)) {
      invalid.add(type);
      continue;
    }
    const values = [];
    let valid = true;
    for (const field of SCHEDULER_FIELDS) {
      const value = descriptor[field];
      if (!SCHEDULER_ENUMS[field].has(value)) {
        valid = false;
        break;
      }
      values.push([field, value]);
    }
    if (!valid) {
      invalid.add(type);
      continue;
    }
    normalized.push([type, frozenObject(values)]);
  }

  normalized.sort(([left], [right]) => left.localeCompare(right));
  return Object.freeze({
    schedulerByType: frozenObject(normalized),
    schedulerMetadataInvalidTypes: Object.freeze([...invalid].sort()),
  });
}

function validatePolicy(name, input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail(name);
  const output = { ...input };
  output.displayName = boundedText(input.displayName, `${name}.displayName`);
  if (input.credentialEnv !== null && (typeof input.credentialEnv !== 'string' || !/^[A-Z0-9_]{3,80}$/.test(input.credentialEnv))) fail(`${name}.credentialEnv`);
  output.credentialEnv = input.credentialEnv;
  if (typeof input.optionalCredential !== 'boolean') fail(`${name}.optionalCredential`);
  if (!AUTH_TYPES.has(input.authType)) fail(`${name}.authType`);
  if (input.credentialEnv === null && input.authType !== 'none') fail(`${name}.authType without credential`);
  if (input.credentialEnv !== null && input.authType === 'none') fail(`${name}.credential auth`);
  if (!COST_CLASSES.has(input.costClass)) fail(`${name}.costClass`);
  if (!DISTRIBUTIONS.has(input.distribution)) fail(`${name}.distribution`);
  if (!SOURCE_ROLES.has(input.sourceRole)) fail(`${name}.sourceRole`);
  if (!FRESHNESS_CLASSES.has(input.freshnessClass)) fail(`${name}.freshnessClass`);
  if (!ADMISSION_VERSIONS.has(input.admissionVersion)) fail(`${name}.admissionVersion`);
  if (input.executionPolicy !== EXECUTION_POLICY_VERSION) fail(`${name}.executionPolicy`);
  output.sourceRole = input.sourceRole;
  output.freshnessClass = input.freshnessClass;
  output.admissionVersion = input.admissionVersion;
  output.executionPolicy = input.executionPolicy;
  if (typeof input.active !== 'boolean') fail(`${name}.active`);
  for (const field of REQUIRED_NUMBERS) {
    if (!Number.isSafeInteger(input[field]) || input[field] < 1) fail(`${name}.${field}`);
  }
  if (input.probeIntervalMs !== undefined) {
    if (!Number.isSafeInteger(input.probeIntervalMs) || input.probeIntervalMs < 0 || input.probeIntervalMs > 60_000) fail(`${name}.probeIntervalMs`);
    output.probeIntervalMs = input.probeIntervalMs;
  }
  for (const field of REQUIRED_ARRAYS) output[field] = boundedArray(input[field], `${name}.${field}`);
  output.semanticClassHints = Array.isArray(input.semanticClassHints) && input.semanticClassHints.length
    ? boundedArray(input.semanticClassHints, `${name}.semanticClassHints`)
    : Object.freeze([]);
  if (input.schedulerByType !== undefined) {
    const scheduler = sanitizeSchedulerMetadata(output.types, input.schedulerByType);
    output.schedulerByType = scheduler.schedulerByType;
    if (scheduler.schedulerMetadataInvalidTypes.length) {
      output.schedulerMetadataInvalidTypes = scheduler.schedulerMetadataInvalidTypes;
    } else {
      delete output.schedulerMetadataInvalidTypes;
    }
  } else {
    delete output.schedulerByType;
    delete output.schedulerMetadataInvalidTypes;
  }
  output.parserVersion = boundedText(input.parserVersion, `${name}.parserVersion`);
  output.sourceUrl = boundedText(input.sourceUrl, `${name}.sourceUrl`);
  try {
    const source = new URL(output.sourceUrl);
    if (source.protocol !== 'https:') fail(`${name}.sourceUrl protocol`);
  } catch {
    fail(`${name}.sourceUrl`);
  }
  for (const host of output.fixedHosts) {
    if (!/^[a-z0-9.-]+$/i.test(host) || host.includes('..')) fail(`${name}.fixedHosts`);
  }
  for (const protocol of output.protocols) if (protocol !== 'https:') fail(`${name}.protocols`);
  for (const method of output.methods) if (!['GET','POST'].includes(method)) fail(`${name}.methods`);
  return Object.freeze(output);
}

export function validateProviderPolicy(name, input) {
  return validatePolicy(name, input);
}

for (const [label, manifest] of [['legacy', rawManifest], ['intelligence', rawIntelligenceManifest]]) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) fail(`${label} root`);
}
const legacyEntries = Object.entries(rawManifest);
const intelligenceEntries = Object.entries(rawIntelligenceManifest);
const entries = [...legacyEntries, ...intelligenceEntries];
if (entries.length < 1 || entries.length > MAX_PROVIDERS) fail('provider count');
if (new Set(entries.map(([name]) => name)).size !== entries.length) fail('duplicate provider name across manifests');

export const PROVIDER_MANIFEST = Object.freeze(Object.fromEntries(entries.map(([name, policy]) => {
  if (!/^[a-z0-9-]{1,64}$/.test(name)) fail(`provider name ${name}`);
  return [name, validatePolicy(name, policy)];
})));

export function providerPolicy(name) {
  const policy = PROVIDER_MANIFEST[name];
  if (!policy) throw new Error(`missing provider manifest policy: ${String(name ?? 'unknown')}`);
  return policy;
}

export function providerSecretNames() {
  return Object.freeze([...new Set(Object.values(PROVIDER_MANIFEST)
    .map(policy => policy.credentialEnv)
    .filter(Boolean))].sort());
}
