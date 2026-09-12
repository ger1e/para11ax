export const PROFILE_NAMES = Object.freeze(['fast', 'standard', 'full']);

function validProfile(profile) {
  return PROFILE_NAMES.includes(profile);
}

function isKnowledgeOnly(adapter) {
  return Array.isArray(adapter?.observationTypes) && adapter.observationTypes.includes('attack_knowledge');
}

function included(adapter, profile) {
  if (profile === 'full') return true;
  if (profile === 'standard') return adapter.costClass !== 'scarce';
  if (profile === 'fast') {
    if (adapter.costClass === 'scarce') return false;
    if (adapter.fastProfileEligible === false) return false;
    return adapter.tier <= 2 || isKnowledgeOnly(adapter);
  }
  return false;
}

export function selectProviders({ type, profile = 'standard', workflow, registry }) {
  if (!validProfile(profile)) throw new TypeError('invalid_profile');
  if (!Array.isArray(workflow)) return [];
  if (!registry || typeof registry.get !== 'function') throw new TypeError('provider registry is required');

  const admitted = [];
  for (const name of workflow) {
    const adapter = registry.get(name);
    if (!adapter || !Array.isArray(adapter.types) || !adapter.types.includes(type)) continue;
    if (!included(adapter, profile)) continue;
    admitted.push(name);
  }
  return admitted;
}
