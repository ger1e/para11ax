import test from 'node:test';
import assert from 'node:assert/strict';
import {
  INTELLIGENCE_PROVIDER_MANIFEST,
  validateIntelligenceProviderPolicy,
} from '../src/providers/intelligence-manifest.js';

const base = {
  displayName: 'Fixture',
  credentialEnv: null,
  optionalCredential: false,
  authType: 'none',
  tier: 1,
  costClass: 'free',
  types: ['domain'],
  observationTypes: ['dns_resolution'],
  timeoutMs: 1000,
  cacheTtlMs: 1000,
  negativeCacheTtlMs: 1000,
  maxResponseBytes: 1024,
  fixedHosts: ['example.org'],
  methods: ['GET'],
  protocols: ['https:'],
  parserVersion: '1',
  sourceUrl: 'https://example.org/docs',
  distribution: 'shareable',
  active: true,
  sourceRole: 'first_party',
  freshnessClass: 'live',
  admissionVersion: 'v8.1',
  executionPolicy: 'v8.1',
  mode: 'enrich',
  fanoutEligible: true,
  sensitivity: 'public',
  authorization: 'none',
  retentionClass: 'normal',
};

test('accepts validated intelligence capability policy', () => {
  const policy = validateIntelligenceProviderPolicy('fixture', base);
  assert.equal(policy.mode, 'enrich');
  assert.equal(policy.fanoutEligible, true);
  assert.equal(policy.sensitivity, 'public');
  assert.equal(policy.authorization, 'none');
  assert.equal(policy.retentionClass, 'normal');
});

test('rejects sensitive capability with automatic fanout', () => {
  assert.throws(() => validateIntelligenceProviderPolicy('fixture', {
    ...base,
    mode: 'sensitive',
    sensitivity: 'pii',
    authorization: 'explicit_case',
    fanoutEligible: true,
  }), /fanout/i);
});

test('rejects privileged enrich fanout combinations', () => {
  for (const override of [
    { authorization: 'tenant' },
    { sensitivity: 'credential' },
    { mode: 'graph' },
  ]) {
    assert.throws(() => validateIntelligenceProviderPolicy('fixture', { ...base, ...override }), /fanout/i);
  }
});

test('validates optional graph bounds', () => {
  assert.equal(validateIntelligenceProviderPolicy('fixture', { ...base, maxPages: 10, maxRelationships: 250 }).maxPages, 10);
  assert.throws(() => validateIntelligenceProviderPolicy('fixture', { ...base, maxPages: 0 }), /maxPages/);
  assert.throws(() => validateIntelligenceProviderPolicy('fixture', { ...base, maxPages: 101 }), /maxPages/);
  assert.throws(() => validateIntelligenceProviderPolicy('fixture', { ...base, maxRelationships: 0 }), /maxRelationships/);
  assert.throws(() => validateIntelligenceProviderPolicy('fixture', { ...base, maxRelationships: 1001 }), /maxRelationships/);
});

test('every registered provider has a deterministic capability policy', () => {
  for (const [name, policy] of Object.entries(INTELLIGENCE_PROVIDER_MANIFEST)) {
    assert.equal(typeof policy.mode, 'string', `${name}.mode`);
    assert.equal(typeof policy.fanoutEligible, 'boolean', `${name}.fanoutEligible`);
    assert.equal(policy.sensitivity, 'public', `${name}.sensitivity`);
    assert.equal(policy.authorization, 'none', `${name}.authorization`);
    assert.equal(typeof policy.retentionClass, 'string', `${name}.retentionClass`);
  }
});
