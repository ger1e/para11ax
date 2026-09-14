import { cidrContains, parseCanonicalCidr, parseIp } from './network.js';

const result = (allowed, reason) => Object.freeze({ allowed, reason });

function hasTrusted(authz) {
  return authz?.trusted === true;
}

function domainWithinScope(domain, scope) {
  return domain === scope || domain.endsWith(`.${scope}`);
}

function ipAsHostCidr(value) {
  const parsed = parseIp(value);
  if (!parsed) return null;
  return Object.freeze({ ...parsed, prefix: parsed.bits });
}

function ownedSubjectAllowed(authz, subject) {
  if (!subject || typeof subject.type !== 'string' || typeof subject.value !== 'string') {
    return result(false, 'owned_subject_required');
  }
  if (subject.type === 'ip') {
    const host = ipAsHostCidr(subject.value);
    if (!host) return result(false, 'owned_scope_invalid');
    return Array.isArray(authz?.ownedCidrs) && authz.ownedCidrs.some(cidr => cidrContains(cidr, host))
      ? result(true, 'allowed') : result(false, 'owned_scope_mismatch');
  }
  if (subject.type === 'cidr') {
    const subnet = parseCanonicalCidr(subject.value);
    if (!subnet) return result(false, 'owned_scope_invalid');
    return Array.isArray(authz?.ownedCidrs) && authz.ownedCidrs.some(cidr => cidrContains(cidr, subnet))
      ? result(true, 'allowed') : result(false, 'owned_scope_mismatch');
  }
  if (subject.type === 'domain') {
    const value = subject.value.toLowerCase();
    return Array.isArray(authz?.verifiedDomains) && authz.verifiedDomains.some(domain => domainWithinScope(value, domain))
      ? result(true, 'allowed') : result(false, 'owned_scope_mismatch');
  }
  return result(false, 'owned_scope_unsupported');
}

function sensitiveSubjectAllowed(authz, subject) {
  if (!subject || typeof subject.type !== 'string' || typeof subject.value !== 'string') {
    return result(false, 'sensitive_subject_required');
  }
  if (subject.type === 'domain') {
    if (!Array.isArray(authz?.verifiedDomains) || authz.verifiedDomains.length === 0) {
      return result(false, 'verified_domain_required');
    }
    const value = subject.value.toLowerCase();
    return authz.verifiedDomains.some(domain => domainWithinScope(value, domain))
      ? result(true, 'allowed') : result(false, 'verified_domain_scope_mismatch');
  }
  if (subject.type === 'email') {
    return authz?.caseId ? result(true, 'allowed') : result(false, 'explicit_case_required');
  }
  return result(false, 'sensitive_subject_unsupported');
}

export function authorizeCapability({ adapter, requestedMode, authz, subject = null } = {}) {
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
    if (authorization === 'sensitive_subject') return result(false, 'trusted_context_required');
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
    const hasScope = (Array.isArray(authz?.ownedCidrs) && authz.ownedCidrs.length > 0)
      || (Array.isArray(authz?.verifiedDomains) && authz.verifiedDomains.length > 0);
    if (!hasScope) return result(false, 'owned_network_required');
    return ownedSubjectAllowed(authz, subject);
  }
  if (authorization === 'explicit_case') {
    return authz?.caseId ? result(true, 'allowed') : result(false, 'explicit_case_required');
  }
  if (authorization === 'explicit_action') {
    return authz?.explicitAnalysis === true ? result(true, 'allowed') : result(false, 'explicit_action_required');
  }
  if (authorization === 'sensitive_subject') {
    return sensitiveSubjectAllowed(authz, subject);
  }
  return result(false, 'unknown_authorization');
}
