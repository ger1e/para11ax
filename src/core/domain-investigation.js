import {
  createDomainInvestigation as createLegacyDomainInvestigation,
  importDomainSurface as importLegacyDomainSurface,
  importDomainVulnerabilities as importLegacyDomainVulnerabilities,
  DOMAIN_INVESTIGATION_SCHEMA_VERSION,
} from './domain-investigation-legacy.js';
import { applyProviderIndependencePolicy } from './domain-investigation-policy.js';
import {
  createPromotionState,
  applyPromotionEvent,
  deriveEffectiveAttestations,
} from './evidence-promotion.js';

function optionsObject(options) {
  if (options === undefined || options === null) return {};
  if (typeof options !== 'object' || Array.isArray(options)) throw new TypeError('Domain Investigation options must be an object');
  return options;
}

function registryFromArtifact(artifact) {
  return artifact?._authoritative?.providerIndependenceRegistry;
}

function promotionFromArtifact(artifact) {
  return artifact?._authoritative?.promotionState ?? null;
}

function applyAuthorityState(artifact, registry, promotionState) {
  const effectiveAttestations = promotionState
    ? deriveEffectiveAttestations(promotionState.candidates, promotionState.events)
    : [];
  const projected = promotionState
    ? {
        ...artifact,
        promotion: {
          candidates: promotionState.candidates,
          events: promotionState.events,
          effectiveAttestations,
        },
        _authoritative: {
          ...(artifact._authoritative ?? {}),
          promotionState,
        },
      }
    : artifact;
  return applyProviderIndependencePolicy(projected, registry, effectiveAttestations);
}

export function createDomainInvestigation(enrichment, expectedTarget, options) {
  const normalizedOptions = optionsObject(options);
  const artifact = createLegacyDomainInvestigation(enrichment, expectedTarget);
  const promotionState = normalizedOptions.operatorArtifacts
    ? createPromotionState(normalizedOptions.operatorArtifacts)
    : null;
  return applyAuthorityState(artifact, normalizedOptions.providerIndependenceRegistry, promotionState);
}

export function importDomainSurface(artifact, input) {
  const registry = registryFromArtifact(artifact);
  const promotionState = promotionFromArtifact(artifact);
  const rebuilt = importLegacyDomainSurface(artifact, input);
  return applyAuthorityState(rebuilt, registry, promotionState);
}

export function importDomainVulnerabilities(artifact, input) {
  const registry = registryFromArtifact(artifact);
  const promotionState = promotionFromArtifact(artifact);
  const rebuilt = importLegacyDomainVulnerabilities(artifact, input);
  return applyAuthorityState(rebuilt, registry, promotionState);
}

export function initializeDomainPromotion(artifact, operatorArtifacts) {
  if (!artifact || artifact.schemaVersion !== DOMAIN_INVESTIGATION_SCHEMA_VERSION) {
    throw new TypeError('valid Domain Investigation artifact is required');
  }
  const promotionState = createPromotionState(operatorArtifacts);
  return applyAuthorityState(artifact, registryFromArtifact(artifact), promotionState);
}

export function applyDomainPromotionEvent(artifact, event) {
  if (!artifact || artifact.schemaVersion !== DOMAIN_INVESTIGATION_SCHEMA_VERSION) {
    throw new TypeError('valid Domain Investigation artifact is required');
  }
  const current = promotionFromArtifact(artifact);
  if (!current) throw new TypeError('Domain Investigation promotion state is not initialized');
  const next = applyPromotionEvent(current, event);
  return applyAuthorityState(artifact, registryFromArtifact(artifact), next);
}

export { DOMAIN_INVESTIGATION_SCHEMA_VERSION };
