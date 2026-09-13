import { EXECUTION_POLICY } from './execution-policy.js';
import { PROVIDER_SCHEDULER_POLICY_VERSION } from './provider-priority.js';
import { WORKFLOW_CALL_LIMITS } from '../workflows.js';

function frozenObjects(values) {
  return Object.freeze(values.map(value => Object.freeze(value)));
}

function credentialMode(provider) {
  if (provider.requiredEnv) return 'required';
  if (provider.optionalEnv) return 'optional';
  return 'none';
}

function schedulerMetadata(provider) {
  const invalid = new Set(provider.schedulerMetadataInvalidTypes ?? []);
  const byType = Object.fromEntries([...provider.types].sort().map(type => {
    const descriptor = invalid.has(type) ? null : provider.schedulerByType?.[type];
    if (!descriptor) {
      return [type, Object.freeze({ fallback: true, rationale: 'legacy_priority_fallback' })];
    }
    return [type, Object.freeze({ ...descriptor, fallback: false })];
  }));
  return Object.freeze({
    version: PROVIDER_SCHEDULER_POLICY_VERSION,
    byType: Object.freeze(byType),
  });
}

export function buildCapabilityRegistry({ providerRegistry, observableRegistry }) {
  if (!providerRegistry || typeof providerRegistry.values !== 'function') throw new TypeError('providerRegistry is required');
  if (!observableRegistry || typeof observableRegistry !== 'object') throw new TypeError('observableRegistry is required');

  const observableTypes = Object.keys(observableRegistry).sort().map(type => Object.freeze({
    type,
    displayName: observableRegistry[type].displayName,
    category: observableRegistry[type].category,
    canonicalization: observableRegistry[type].canonicalization,
    stixExport: observableRegistry[type].stixExport,
    active: observableRegistry[type].active,
  }));

  const providers = providerRegistry.values().map(provider => Object.freeze({
    name: provider.name,
    displayName: provider.displayName ?? provider.name,
    types: Object.freeze([...provider.types].sort()),
    sourceRole: provider.sourceRole ?? null,
    freshnessClass: provider.freshnessClass ?? null,
    admissionVersion: provider.admissionVersion ?? null,
    executionPolicy: provider.executionPolicy ?? null,
    distribution: provider.distribution ?? null,
    mode: provider.mode ?? 'enrich',
    fanoutEligible: provider.fanoutEligible === true,
    sensitivity: provider.sensitivity ?? 'public',
    authorization: provider.authorization ?? 'none',
    retentionClass: provider.retentionClass ?? 'normal',
    providerFamily: provider.providerFamily ?? null,
    maxPages: provider.maxPages ?? null,
    maxRelationships: provider.maxRelationships ?? null,
    credentialMode: credentialMode(provider),
    active: provider.active !== false,
    scheduler: schedulerMetadata(provider),
  })).sort((a, b) => a.name.localeCompare(b.name));

  const byType = Object.fromEntries(observableTypes.map(({ type }) => {
    const matching = providers.filter(provider => provider.types.includes(type));
    return [type, Object.freeze({
      providers: Object.freeze(matching.map(provider => provider.name)),
      activeProviders: Object.freeze(matching.filter(provider => provider.active).map(provider => provider.name)),
    })];
  }));

  const execution = Object.freeze({
    version: EXECUTION_POLICY.version,
    providerConcurrencyMax: EXECUTION_POLICY.providerConcurrencyMax,
    providerMaxAttempts: EXECUTION_POLICY.providerMaxAttempts,
    requestDeadlineMs: EXECUTION_POLICY.requestDeadlineMs,
    workflowProviderCalls: Object.freeze({ ...WORKFLOW_CALL_LIMITS }),
  });

  return Object.freeze({
    observableTypes: frozenObjects(observableTypes),
    providers: frozenObjects(providers),
    byType: Object.freeze(byType),
    execution,
  });
}
