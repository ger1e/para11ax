function uniqueSorted(values) {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function credentialPosture(policy) {
  if (!policy?.credentialEnv) return 'public';
  if (policy.optionalCredential === true) return 'mixed';
  return 'credentialed';
}

function collapseState(values, { active = false } = {}) {
  const unique = uniqueSorted(values);
  if (unique.length === 1) return unique[0];
  if (active && unique.every(value => value === 'active' || value === 'disabled')) return 'mixed';
  return 'mixed';
}

function normalizePolicy(id, policy) {
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) {
    throw new TypeError(`Invalid provider policy for ${id}`);
  }

  const declaredFamily = typeof policy.providerFamily === 'string' ? policy.providerFamily.trim() : '';
  return {
    family: declaredFamily || id,
    providerId: id,
    observableTypes: Array.isArray(policy.types)
      ? policy.types.filter(value => typeof value === 'string' && value.length > 0)
      : [],
    sourceRole: typeof policy.sourceRole === 'string' && policy.sourceRole.length > 0
      ? policy.sourceRole
      : 'unknown',
    freshnessClass: typeof policy.freshnessClass === 'string' && policy.freshnessClass.length > 0
      ? policy.freshnessClass
      : 'unknown',
    credentialState: credentialPosture(policy),
    activeState: policy.active === false ? 'disabled' : policy.active === true ? 'active' : 'unknown',
  };
}

export function buildProviderFamilyQa(manifest) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    throw new TypeError('Provider manifest must be an object');
  }

  const groups = new Map();
  for (const [id, rawPolicy] of Object.entries(manifest)) {
    const policy = normalizePolicy(id, rawPolicy);
    const group = groups.get(policy.family) ?? {
      family: policy.family,
      providerIds: [],
      observableTypes: [],
      sourceRoles: [],
      freshnessClasses: [],
      credentialStates: [],
      activeStates: [],
    };

    group.providerIds.push(policy.providerId);
    group.observableTypes.push(...policy.observableTypes);
    group.sourceRoles.push(policy.sourceRole);
    group.freshnessClasses.push(policy.freshnessClass);
    group.credentialStates.push(policy.credentialState);
    group.activeStates.push(policy.activeState);
    groups.set(policy.family, group);
  }

  const families = [...groups.values()]
    .map(group => ({
      family: group.family,
      providerIds: uniqueSorted(group.providerIds),
      observableTypes: uniqueSorted(group.observableTypes),
      sourceRoles: uniqueSorted(group.sourceRoles),
      freshnessClasses: uniqueSorted(group.freshnessClasses),
      credentialState: collapseState(group.credentialStates),
      activeState: collapseState(group.activeStates, { active: true }),
    }))
    .sort((left, right) => left.family.localeCompare(right.family));

  return {
    providerCount: Object.keys(manifest).length,
    familyCount: families.length,
    families,
  };
}
