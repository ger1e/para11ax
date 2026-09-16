import test from 'node:test';
import assert from 'node:assert/strict';
import { planPivots } from '../src/core/intelligence-planner.js';
import { createTrustedAuthorizationContext, normalizeAuthorizationContext } from '../src/core/authorization-context.js';

function candidate(name, overrides = {}) {
  return {
    name,
    mode: 'graph',
    sensitivity: 'public',
    authorization: 'none',
    types: ['certificate'],
    tier: 2,
    costClass: 'free',
    schedulerByType: {
      certificate: { authorityClass: 'specialist', semanticUniqueness: 'unique', intelligenceValue: 'direct', pivotValue: 'high', latencyClass: 'fast' },
      cve: { authorityClass: 'specialist', semanticUniqueness: 'unique', intelligenceValue: 'direct', pivotValue: 'high', latencyClass: 'fast' },
    },
    ...overrides,
  };
}

const budget = { providerCalls: 0, providerCallLimit: 8, deadlineExhausted: false, callBudgetExhausted: false };

test('planner emits no pivots without baseline evidence or budget', () => {
  assert.deepEqual(planPivots({ type: 'domain', evidence: [], relationships: [], candidates: [candidate('censys')], authz: normalizeAuthorizationContext({}), budget }), []);
  assert.deepEqual(planPivots({ type: 'domain', evidence: [{}], relationships: [{ targetType: 'certificate', target: `cert-sha256:${'a'.repeat(64)}` }], candidates: [candidate('censys')], authz: normalizeAuthorizationContext({}), budget: { ...budget, providerCalls: 8 } }), []);
});

test('certificate relationship admits one configured graph provider', () => {
  const plans = planPivots({
    type: 'domain',
    evidence: [{ provider: 'urlscan', observation: { kind: 'internet_exposure' } }],
    relationships: [{ targetType: 'certificate', target: `cert-sha256:${'a'.repeat(64)}` }],
    candidates: [candidate('censys')],
    authz: normalizeAuthorizationContext({}), budget,
  });
  assert.deepEqual(plans, [{ provider: 'censys', mode: 'graph', input: { type: 'certificate', value: `cert-sha256:${'a'.repeat(64)}` }, reason: 'relationship_pivot' }]);
});

test('CVE without exploit maturity admits VulnCheck once', () => {
  const vulncheck = candidate('vulncheck', { types: ['cve'] });
  const plans = planPivots({ type: 'cve', evidence: [{ provider: 'nvd', observation: { kind: 'vulnerability_metadata' } }], relationships: [], candidates: [vulncheck], authz: normalizeAuthorizationContext({}), budget });
  assert.deepEqual(plans, [{ provider: 'vulncheck', mode: 'graph', input: { type: 'cve', value: null }, reason: 'exploit_maturity_gap' }]);
  assert.deepEqual(planPivots({ type: 'cve', evidence: [{ observation: { kind: 'exploit_maturity' } }], relationships: [], candidates: [vulncheck], authz: normalizeAuthorizationContext({}), budget }), []);
});

test('duplicated eligible providers collapse to the highest ranked provider', () => {
  const slower = candidate('secondary', { tier: 3, schedulerByType: { certificate: { authorityClass: 'aggregator', semanticUniqueness: 'duplicative', intelligenceValue: 'supporting', pivotValue: 'medium', latencyClass: 'slow' } } });
  const preferred = candidate('preferred');
  const plans = planPivots({
    type: 'domain', evidence: [{}], relationships: [{ targetType: 'certificate', target: `cert-sha256:${'b'.repeat(64)}` }],
    candidates: [slower, preferred], authz: normalizeAuthorizationContext({}), budget,
  });
  assert.equal(plans.length, 1);
  assert.equal(plans[0].provider, 'preferred');
});

test('protected candidates remain denied without trusted authorization', () => {
  const protectedProvider = candidate('protected', { sensitivity: 'pii', authorization: 'explicit_case' });
  const args = {
    type: 'domain', evidence: [{}], relationships: [{ targetType: 'certificate', target: `cert-sha256:${'c'.repeat(64)}` }],
    candidates: [protectedProvider], budget,
  };
  assert.deepEqual(planPivots({ ...args, authz: normalizeAuthorizationContext({ caseId: 'CASE-1' }) }), []);
  assert.equal(planPivots({ ...args, authz: createTrustedAuthorizationContext({ caseId: 'CASE-1' }) }).length, 1);
});
