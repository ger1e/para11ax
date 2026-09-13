import test from 'node:test';
import assert from 'node:assert/strict';

import { createApp } from '../src/app.js';
import { createTrustedAuthorizationContext, normalizeAuthorizationContext } from '../src/core/authorization-context.js';
import { runIntelligenceMode } from '../src/core/intelligence-operation.js';
import { authorizeCapability } from '../src/core/intelligence-policy.js';
import { assertReportDistribution } from '../src/report/quality.js';

const sensitive = (overrides = {}) => ({
  name: 'sensitive-fixture',
  types: ['domain', 'email'],
  mode: 'sensitive',
  sensitivity: 'pii',
  authorization: 'sensitive_subject',
  fanoutEligible: false,
  retentionClass: 'no_store',
  distribution: 'internal_only',
  active: true,
  ...overrides,
});

test('sensitive domain authorization is bound to the verified canonical subject', () => {
  const authz = createTrustedAuthorizationContext({ verifiedDomains: ['example.com'] });
  assert.deepEqual(authorizeCapability({
    adapter: sensitive(), requestedMode: 'sensitive', authz,
    subject: { type: 'domain', value: 'example.com' },
  }), { allowed: true, reason: 'allowed' });
  assert.deepEqual(authorizeCapability({
    adapter: sensitive(), requestedMode: 'sensitive', authz,
    subject: { type: 'domain', value: 'login.example.com' },
  }), { allowed: true, reason: 'allowed' });
  assert.equal(authorizeCapability({
    adapter: sensitive(), requestedMode: 'sensitive', authz,
    subject: { type: 'domain', value: 'example.net' },
  }).allowed, false);
});

test('sensitive email authorization requires an explicit trusted case', () => {
  const noCase = createTrustedAuthorizationContext({ verifiedDomains: ['example.com'] });
  assert.equal(authorizeCapability({
    adapter: sensitive(), requestedMode: 'sensitive', authz: noCase,
    subject: { type: 'email', value: 'analyst@example.com' },
  }).allowed, false);

  assert.deepEqual(authorizeCapability({
    adapter: sensitive(), requestedMode: 'sensitive',
    authz: createTrustedAuthorizationContext({ caseId: 'CASE-123' }),
    subject: { type: 'email', value: 'analyst@example.com' },
  }), { allowed: true, reason: 'allowed' });
});

test('untrusted callers cannot self-assert a sensitive authorization scope', () => {
  const authz = normalizeAuthorizationContext({
    verifiedDomains: ['example.com'],
    caseId: 'CASE-123',
  });
  const decision = authorizeCapability({
    adapter: sensitive(), requestedMode: 'sensitive', authz,
    subject: { type: 'email', value: 'analyst@example.com' },
  });
  assert.equal(decision.allowed, false);
});

test('public identity requests do not inherit deployment verified-domain scope', async () => {
  let calls = 0;
  const adapter = sensitive({
    requiredEnv: null,
    run: async () => { calls += 1; return { observationType: 'identity_exposure', verdict: 'observed', confidence: null, attributes: {}, relationships: [], references: [] }; },
  });
  const result = await runIntelligenceMode({
    operation: 'identity',
    mode: 'sensitive',
    subject: { type: 'domain', value: 'example.com' },
    registry: { values: () => [adapter] },
    authz: createTrustedAuthorizationContext({ requestedMode: 'sensitive' }),
    env: { PARA11AX_VERIFIED_DOMAINS: 'example.com' },
  });
  assert.equal(calls, 0);
  assert.deepEqual(result.providers.executed, []);
});

test('ordinary enrichment cannot execute a sensitive adapter', async () => {
  let calls = 0;
  const result = await runIntelligenceMode({
    operation: 'identity',
    mode: 'enrich',
    subject: { type: 'email', value: 'analyst@example.com' },
    registry: { values: () => [sensitive({ run: async () => { calls += 1; return {}; } })] },
    authz: createTrustedAuthorizationContext({ caseId: 'CASE-123' }),
  });
  assert.equal(calls, 0);
  assert.deepEqual(result.providers.executed, []);
});

test('sensitive no-store providers bypass cache reads and writes', async () => {
  let runs = 0;
  let gets = 0;
  let sets = 0;
  const adapter = sensitive({
    run: async () => {
      runs += 1;
      return {
        observationType: 'identity_exposure', verdict: 'observed', confidence: null,
        attributes: { exposureCount: 1 }, relationships: [], references: [],
      };
    },
  });
  const result = await runIntelligenceMode({
    operation: 'identity',
    mode: 'sensitive',
    subject: { type: 'email', value: 'analyst@example.com' },
    registry: { values: () => [adapter] },
    authz: createTrustedAuthorizationContext({ caseId: 'CASE-123' }),
    cache: {
      get: () => { gets += 1; return undefined; },
      set: () => { sets += 1; },
    },
  });
  assert.equal(runs, 1);
  assert.equal(gets, 0);
  assert.equal(sets, 0);
  assert.deepEqual(result.providers.executed, ['sensitive-fixture']);
});

test('public HTTP callers cannot add case or verified-domain authorization fields', async () => {
  const app = createApp({ env: { PARA11AX_TOKEN: 'gateway-token' }, adapters: [] });
  for (const field of ['caseId', 'verifiedDomains']) {
    const result = await app.handleIntelligence({
      method: 'POST',
      headers: { authorization: 'Bearer gateway-token', 'content-type': 'application/json' },
      body: { operation: 'identity', indicator: 'analyst@example.com', [field]: field === 'caseId' ? 'CASE-123' : ['example.com'] },
    });
    assert.equal(result.status, 400);
    assert.equal(result.body.error, 'unsupported_request_field');
  }
});

test('sharing reports fail closed when sensitive internal-only evidence is present', () => {
  assert.throws(() => assertReportDistribution({
    evidence: [{ provider: 'hibp' }],
  }, 'sharing'), /report quality gate failed/);
});
