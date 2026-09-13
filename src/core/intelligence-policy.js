const result = (allowed, reason) => Object.freeze({ allowed, reason });

function hasTrusted(authz) {
  return authz?.trusted === true;
}

export function authorizeCapability({ adapter, requestedMode, authz } = {}) {
  if (!adapter || typeof adapter !== 'object') return result(false, 'invalid_adapter');
  if (typeof adapter.mode !== 'string' || typeof requestedMode !== 'string' || requestedMode !== adapter.mode) {
    return result(false, 'mode_mismatch');
  }

  const authorization = adapter.authorization ?? 'none';
  const sensitivity = adapter.sensitivity ?? 'public';
  if ((authorization !== 'none' || sensitivity !== 'public') && !hasTrusted(authz)) {
    if (authorization === 'tenant') return result(false, 'tenant_required');
    if (authorization === 'verified_domain') return result(false, 'verified_domain_required');
    if (authorization === 'owned_network') return result(false, 'owned_network_required');
    if (authorization === 'explicit_case') return result(false, 'explicit_case_required');
    if (authorization === 'explicit_action') return result(false, 'explicit_action_required');
    return result(false, 'trusted_context_required');
  }

  if (authorization === 'none') {
    return sensitivity === 'public' ? result(true, 'allowed') : result(false, 'authorization_required');
  }
  if (authorization === 'tenant') {
    return authz?.tenant ? result(true, 'allowed') : result(false, 'tenant_required');
  }
  if (authorization === 'verified_domain') {
    return Array.isArray(authz?.verifiedDomains) && authz.verifiedDomains.length > 0
      ? result(true, 'allowed') : result(false, 'verified_domain_required');
  }
  if (authorization === 'owned_network') {
    return Array.isArray(authz?.ownedCidrs) && authz.ownedCidrs.length > 0
      ? result(true, 'allowed') : result(false, 'owned_network_required');
  }
  if (authorization === 'explicit_case') {
    return authz?.caseId ? result(true, 'allowed') : result(false, 'explicit_case_required');
  }
  if (authorization === 'explicit_action') {
    return authz?.explicitAnalysis === true ? result(true, 'allowed') : result(false, 'explicit_action_required');
  }
  return result(false, 'unknown_authorization');
}
