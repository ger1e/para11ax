import { INTELLIGENCE_PROVIDER_MANIFEST, intelligenceProviderPolicy } from './intelligence-manifest.js';

export const PROVIDER_METADATA = INTELLIGENCE_PROVIDER_MANIFEST;

function schedulerByType(policy) {
  return Object.freeze(Object.fromEntries(Object.entries(policy.schedulerByType ?? {}).map(([type, descriptor]) => [
    type,
    Object.freeze({ ...descriptor }),
  ])));
}

export function withProviderMetadata(adapter) {
  const policy = intelligenceProviderPolicy(adapter?.name);
  const credentialFields = policy.credentialEnv
    ? policy.optionalCredential
      ? { requiredEnv: undefined, optionalEnv: policy.credentialEnv }
      : { requiredEnv: policy.credentialEnv, optionalEnv: undefined }
    : { requiredEnv: undefined, optionalEnv: undefined };

  return Object.freeze({
    ...adapter,
    name: adapter.name,
    ...credentialFields,
    types: Object.freeze([...policy.types]),
    observationTypes: Object.freeze([...policy.observationTypes]),
    tier: policy.tier,
    costClass: policy.costClass,
    timeoutMs: policy.timeoutMs,
    probeIntervalMs: policy.probeIntervalMs ?? 0,
    cacheTtlMs: policy.cacheTtlMs,
    negativeCacheTtlMs: policy.negativeCacheTtlMs,
    maxResponseBytes: policy.maxResponseBytes,
    fixedHosts: Object.freeze([...policy.fixedHosts]),
    methods: Object.freeze([...policy.methods]),
    protocols: Object.freeze([...policy.protocols]),
    parserVersion: policy.parserVersion,
    sourceUrl: policy.sourceUrl,
    active: policy.active,
    distribution: policy.distribution,
    displayName: policy.displayName,
    authType: policy.authType,
    semanticClassHints: Object.freeze([...policy.semanticClassHints]),
    sourceRole: policy.sourceRole,
    freshnessClass: policy.freshnessClass,
    admissionVersion: policy.admissionVersion,
    executionPolicy: policy.executionPolicy,
    mode: policy.mode,
    fanoutEligible: policy.fanoutEligible,
    sensitivity: policy.sensitivity,
    authorization: policy.authorization,
    retentionClass: policy.retentionClass,
    providerFamily: policy.providerFamily,
    maxPages: policy.maxPages,
    maxRelationships: policy.maxRelationships,
    schedulerByType: schedulerByType(policy),
    schedulerMetadataInvalidTypes: Object.freeze([...(policy.schedulerMetadataInvalidTypes ?? [])]),
  });
}
