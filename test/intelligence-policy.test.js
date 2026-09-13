import test from 'node:test';
import assert from 'node:assert/strict';
import { createTrustedAuthorizationContext, normalizeAuthorizationContext } from '../src/core/authorization-context.js';
import { authorizeCapability } from '../src/core/intelligence-policy.js';

const adapter = (overrides = {}) => ({
  name: 'fixture', mode: 'enrich', sensitivity: 'public', authorization: 'none', ...overrides,
});

test('ordinary public enrichment is allowed without privileged context', () => {
  assert.deepEqual(authorizeCapability({
    adapter: adapter(), requestedMode: 'enrich', authz: normalizeAuthorizationContext({}),
  }), { allowed: true, reason: 'allowed' });
});

test('explicit-case capability requires a trusted server-created case context', () => {
  const protectedAdapter = adapter({ mode: 'sensitive', sensitivity: 'pii', authorization: 'explicit_case' });
  assert.equal(authorizeCapability({
    adapter: protectedAdapter,
    requestedMode: 'sensitive',
    authz: normalizeAuthorizationContext({ caseId: 'CASE-123' }),
  }).reason, 'explicit_case_required');

  assert.deepEqual(authorizeCapability({
    adapter: protectedAdapter,
    requestedMode: 'sensitive',
    authz: createTrustedAuthorizationContext({ caseId: 'CASE-123' }),
  }), { allowed: true, reason: 'allowed' });
});

test('owned-network monitoring requires trusted canonical CIDR scope', () => {
  const monitor = adapter({ mode: 'monitor', sensitivity: 'owned_asset', authorization: 'owned_network' });
  assert.equal(authorizeCapability({ adapter: monitor, requestedMode: 'monitor', authz: createTrustedAuthorizationContext({}) }).reason, 'owned_network_required');
  assert.deepEqual(authorizeCapability({
    adapter: monitor,
    requestedMode: 'monitor',
    authz: createTrustedAuthorizationContext({ ownedCidrs: ['192.0.2.0/24'] }),
  }), { allowed: true, reason: 'allowed' });
  assert.throws(() => createTrustedAuthorizationContext({ ownedCidrs: ['192.0.2.7/24'] }), /ownedCidrs/);
});

test('explicit analysis requires a trusted explicit action', () => {
  const analysis = adapter({ mode: 'analysis', sensitivity: 'sample', authorization: 'explicit_action' });
  assert.equal(authorizeCapability({
    adapter: analysis, requestedMode: 'analysis', authz: createTrustedAuthorizationContext({ explicitAnalysis: false }),
  }).reason, 'explicit_action_required');
  assert.deepEqual(authorizeCapability({
    adapter: analysis, requestedMode: 'analysis', authz: createTrustedAuthorizationContext({ explicitAnalysis: true }),
  }), { allowed: true, reason: 'allowed' });
});

test('tenant and verified-domain scopes require trusted matching context classes', () => {
  assert.equal(authorizeCapability({
    adapter: adapter({ mode: 'search', authorization: 'tenant' }), requestedMode: 'search',
    authz: createTrustedAuthorizationContext({}),
  }).reason, 'tenant_required');
  assert.equal(authorizeCapability({
    adapter: adapter({ mode: 'search', authorization: 'verified_domain' }), requestedMode: 'search',
    authz: createTrustedAuthorizationContext({}),
  }).reason, 'verified_domain_required');
  assert.deepEqual(createTrustedAuthorizationContext({ verifiedDomains: ['EXAMPLE.com', 'example.com'] }).verifiedDomains, ['example.com']);
});

test('mode mismatch and malformed authorization context fail closed', () => {
  assert.equal(authorizeCapability({ adapter: adapter(), requestedMode: 'graph', authz: normalizeAuthorizationContext({}) }).reason, 'mode_mismatch');
  assert.throws(() => normalizeAuthorizationContext({ verifiedDomains: ['not a domain'] }), /verifiedDomains/);
  assert.throws(() => normalizeAuthorizationContext({ explicitAnalysis: 'yes' }), /explicitAnalysis/);
});
