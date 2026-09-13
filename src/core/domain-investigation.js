import {
  createDomainInvestigation as createLegacyDomainInvestigation,
  importDomainSurface as importLegacyDomainSurface,
  importDomainVulnerabilities as importLegacyDomainVulnerabilities,
  DOMAIN_INVESTIGATION_SCHEMA_VERSION,
} from './domain-investigation-legacy.js';
import { applyProviderIndependencePolicy } from './domain-investigation-policy.js';

function registryFromOptions(options) {
  if (options === undefined || options === null) return undefined;
  if (typeof options !== 'object' || Array.isArray(options)) throw new TypeError('Domain Investigation options must be an object');
  return options.providerIndependenceRegistry;
}

function registryFromArtifact(artifact) {
  return artifact?._authoritative?.providerIndependenceRegistry;
}

export function createDomainInvestigation(enrichment, expectedTarget, options) {
  const artifact = createLegacyDomainInvestigation(enrichment, expectedTarget);
  return applyProviderIndependencePolicy(artifact, registryFromOptions(options));
}

export function importDomainSurface(artifact, input) {
  const registry = registryFromArtifact(artifact);
  const rebuilt = importLegacyDomainSurface(artifact, input);
  return applyProviderIndependencePolicy(rebuilt, registry);
}

export function importDomainVulnerabilities(artifact, input) {
  const registry = registryFromArtifact(artifact);
  const rebuilt = importLegacyDomainVulnerabilities(artifact, input);
  return applyProviderIndependencePolicy(rebuilt, registry);
}

export { DOMAIN_INVESTIGATION_SCHEMA_VERSION };
