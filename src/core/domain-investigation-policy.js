import {
  DEFAULT_PROVIDER_INDEPENDENCE_REGISTRY,
  createProviderIndependenceRegistry,
  summarizeProviderIndependence,
} from './provider-independence.js';

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function normalizeRegistry(value) {
  if (value === undefined || value === null) return DEFAULT_PROVIDER_INDEPENDENCE_REGISTRY;
  if (Array.isArray(value)) return createProviderIndependenceRegistry(value);
  if (value?.version === 'provider-independence-v1.0' && Array.isArray(value.entries)) return value;
  throw new TypeError('provider independence registry must be a v1 registry or registry entry array');
}

function classify(rec, independence) {
  const knownGroups = independence.quorumEligibleGroupCount;
  const contradictions = Array.isArray(rec.contradictions) ? rec.contradictions : [];
  const contextSources = Array.isArray(rec.contextSources) ? rec.contextSources : [];
  const authority = Array.isArray(rec.authority) ? rec.authority : [];
  const hasOperatorContext = authority.includes('operator_context');
  const directSources = Array.isArray(rec.directSources) ? rec.directSources : [];

  if (knownGroups >= 2 && contradictions.length === 0) {
    return {
      disposition: 'BLOCK',
      ruleId: 'DI-BLOCK-2-INDEPENDENT-GROUPS',
      reasons: ['At least two known independent provider families directly support the exact IOC with no material contradiction.'],
    };
  }
  if (knownGroups >= 2 && contradictions.length > 0) {
    return {
      disposition: 'BLOCK_CANDIDATE',
      ruleId: 'DI-CANDIDATE-CONTRADICTION',
      reasons: ['Independent direct provider quorum exists, but explicit negative evidence requires analyst review before blocking.'],
    };
  }
  if (knownGroups >= 1 && (contextSources.length > 0 || hasOperatorContext)) {
    return {
      disposition: 'BLOCK_CANDIDATE',
      ruleId: contradictions.length ? 'DI-CANDIDATE-CONTRADICTION' : 'DI-CANDIDATE-DIRECT-CONTEXT',
      reasons: contradictions.length
        ? ['A known direct malicious provider family exists with corroborating context, but contradiction pressure requires analyst review.']
        : ['One known direct malicious provider family is corroborated by contextual or operator evidence; human approval remains required.'],
    };
  }
  if (directSources.length > 0) {
    return {
      disposition: 'MONITOR',
      ruleId: knownGroups === 1 ? 'DI-MONITOR-ONE-INDEPENDENT-GROUP' : 'DI-MONITOR-UNKNOWN-LINEAGE',
      reasons: [knownGroups === 1
        ? 'Only one known independent direct malicious provider family supports this IOC.'
        : 'Direct malicious evidence is present, but its provider lineage is unknown or non-quorum-eligible.'],
    };
  }
  if (contextSources.length > 0 || hasOperatorContext || (Array.isArray(rec.authority) && rec.authority.length > 0)) {
    return {
      disposition: 'MONITOR',
      ruleId: 'DI-MONITOR-CONTEXT',
      reasons: ['Only contextual or operator evidence is present; it does not satisfy direct provider-family quorum.'],
    };
  }
  return {
    disposition: 'DO_NOT_BLOCK',
    ruleId: 'DI-NO-DIRECT-EVIDENCE',
    reasons: ['No direct malicious Evidence v2 source supports blocking this IOC.'],
  };
}

export function applyProviderIndependencePolicy(artifact, registryInput) {
  if (!artifact || typeof artifact !== 'object' || !Array.isArray(artifact.recommendations)) {
    throw new TypeError('Domain Investigation artifact with recommendations is required');
  }
  const registry = normalizeRegistry(registryInput);
  const recommendations = artifact.recommendations.map((rec) => {
    const directSources = Array.isArray(rec.directSources) ? rec.directSources : [];
    const independence = summarizeProviderIndependence(directSources, registry);
    const decision = classify(rec, independence);
    return {
      ...rec,
      disposition: decision.disposition,
      ruleId: decision.ruleId,
      reasons: decision.reasons,
      independence: {
        registryVersion: independence.registryVersion,
        rawProviderCount: independence.rawProviderCount,
        quorumEligibleGroupCount: independence.quorumEligibleGroupCount,
        quorumGroups: independence.quorumGroups,
        unknownProviders: independence.unknownProviders,
      },
    };
  });
  return deepFreeze({
    ...artifact,
    recommendations,
    _authoritative: {
      ...(artifact._authoritative ?? {}),
      providerIndependenceRegistry: registry,
    },
  });
}
