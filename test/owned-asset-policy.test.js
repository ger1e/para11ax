import test from 'node:test';
import assert from 'node:assert/strict';

import { createApp } from '../src/app.js';
import { createTrustedAuthorizationContext, normalizeAuthorizationContext } from '../src/core/authorization-context.js';
import { runIntelligenceMode } from '../src/core/intelligence-operation.js';
import { authorizeCapability } from '../src/core/intelligence-policy.js';

const monitor = (overrides = {}) => ({
  name: 'shadowserver-fixture',
  types: ['ip', 'cidr', 'domain'],
  mode: 'monitor',
  sensitivity: 'owned_asset',
  authorization: 'owned_network',
  fanoutEligible: false,
  ...overrides,
});

test('owned-network authorization is bound to the canonical subject scope', () => {
  const authz = createTrustedAuthorizationContext({
    ownedCidrs: ['192.0.2.0/24', '2001:db8::/32'],
    verifiedDomains: ['example.com'],
  });

  assert.deepEqual(authorizeCapability({
    adapter: monitor(), requestedMode: 'monitor', authz,
    subject: { type: 'ip', value: '192.0.2.25' },
  }), { allowed: true, reason: 'allowed' });

  assert.deepEqual(authorizeCapability({
    adapter: monitor(), requestedMode: 'monitor', authz,
    subject: { type: 'cidr', value: '192.0.2.64/26' },
  }), { allowed: true, reason: 'allowed' });

  assert.deepEqual(authorizeCapability({
    adapter: monitor(), requestedMode: 'monitor', authz,
    subject: { type: 'cidr', value: '2001:db8:abcd::/48' },
  }), { allowed: true, reason: 'allowed' });

  assert.deepEqual(authorizeCapability({
    adapter: monitor(), requestedMode: 'monitor', authz,
    subject: { type: 'domain', value: 'host.example.com' },
  }), { allowed: true, reason: 'allowed' });
});

test('owned-network authorization fails closed for unowned or missing subject scope', () => {
  const authz = createTrustedAuthorizationContext({
    ownedCidrs: ['192.0.2.0/24'],
    verifiedDomains: ['example.com'],
  });

  for (const subject of [
    { type: 'ip', value: '198.51.100.25' },
    { type: 'cidr', value: '192.0.2.0/23' },
    { type: 'domain', value: 'example.net' },
    null,
  ]) {
    const decision = authorizeCapability({ adapter: monitor(), requestedMode: 'monitor', authz, subject });
    assert.equal(decision.allowed, false);
    assert.match(decision.reason, /^owned_(?:scope|subject)_/);
  }
});

test('untrusted callers cannot self-assert an owned network', () => {
  const decision = authorizeCapability({
    adapter: monitor(),
    requestedMode: 'monitor',
    authz: normalizeAuthorizationContext({ ownedCidrs: ['192.0.2.0/24'] }),
    subject: { type: 'ip', value: '192.0.2.25' },
  });
  assert.deepEqual(decision, { allowed: false, reason: 'owned_network_required' });
});

test('ordinary enrichment cannot execute a monitor adapter', async () => {
  let calls = 0;
  const adapter = monitor({
    active: true,
    run: async () => { calls += 1; return {}; },
  });
  const result = await runIntelligenceMode({
    operation: 'search',
    mode: 'enrich',
    subject: { type: 'ip', value: '192.0.2.25' },
    registry: { values: () => [adapter] },
    authz: createTrustedAuthorizationContext({ ownedCidrs: ['192.0.2.0/24'] }),
  });
  assert.equal(calls, 0);
  assert.deepEqual(result.providers.executed, []);
});

test('HTTP callers cannot add ownership scope fields to intelligence requests', async () => {
  const app = createApp({ env: { PARA11AX_TOKEN: 'gateway-token' }, adapters: [] });
  const result = await app.handleIntelligence({
    method: 'POST',
    headers: { authorization: 'Bearer gateway-token', 'content-type': 'application/json' },
    body: {
      operation: 'asset',
      indicator: '192.0.2.25',
      ownedCidrs: ['192.0.2.0/24'],
    },
  });
  assert.equal(result.status, 400);
  assert.equal(result.body.error, 'unsupported_request_field');
});
