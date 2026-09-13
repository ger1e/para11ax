import { PROVIDER_MANIFEST, validateProviderPolicy } from './manifest.js';
import { boundedCapabilityInteger, normalizeCapabilityPolicy } from './capability-policy.js';

function boundedFamily(name, value) {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || !/^[a-z0-9-]{1,64}$/.test(value)) {
    throw new Error(`invalid provider manifest: ${name}.providerFamily`);
  }
  return value;
}

export function validateIntelligenceProviderPolicy(name, input) {
  const base = validateProviderPolicy(name, input);
  const capability = normalizeCapabilityPolicy(name, input);
  const maxPages = boundedCapabilityInteger(name, 'maxPages', input.maxPages, 100);
  const maxRelationships = boundedCapabilityInteger(name, 'maxRelationships', input.maxRelationships, 1000);
  const providerFamily = boundedFamily(name, input.providerFamily);
  return Object.freeze({
    ...base,
    ...capability,
    ...(maxPages === undefined ? {} : { maxPages }),
    ...(maxRelationships === undefined ? {} : { maxRelationships }),
    ...(providerFamily === undefined ? {} : { providerFamily }),
  });
}

export const INTELLIGENCE_PROVIDER_MANIFEST = Object.freeze(Object.fromEntries(
  Object.entries(PROVIDER_MANIFEST).map(([name, policy]) => [name, validateIntelligenceProviderPolicy(name, policy)]),
));

export function intelligenceProviderPolicy(name) {
  const policy = INTELLIGENCE_PROVIDER_MANIFEST[name];
  if (!policy) throw new Error(`missing provider intelligence policy: ${String(name ?? 'unknown')}`);
  return policy;
}
