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

const MODES = new Set(['enrich', 'graph', 'search', 'monitor', 'analysis', 'knowledge', 'sensitive']);
const SENSITIVITY = new Set(['public', 'owned_asset', 'pii', 'credential', 'secret', 'sample']);
const AUTHORIZATION = new Set(['none', 'tenant', 'verified_domain', 'owned_network', 'explicit_case', 'explicit_action']);
const RETENTION = new Set(['normal', 'restricted', 'ephemeral', 'no_store']);

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
    assert.ok(MODES.has(policy.mode), `${name}.mode`);
    assert.equal(typeof policy.fanoutEligible, 'boolean', `${name}.fanoutEligible`);
    assert.ok(SENSITIVITY.has(policy.sensitivity), `${name}.sensitivity`);
    assert.ok(AUTHORIZATION.has(policy.authorization), `${name}.authorization`);
    assert.ok(RETENTION.has(policy.retentionClass), `${name}.retentionClass`);
    if (policy.fanoutEligible) {
      assert.equal(policy.mode, 'enrich', `${name}.fanoutEligible mode`);
      assert.equal(policy.sensitivity, 'public', `${name}.fanoutEligible sensitivity`);
      assert.equal(policy.authorization, 'none', `${name}.fanoutEligible authorization`);
    }
  }
});

test('GitGuardian HMSL remains explicit no-store secret-sensitive capability', () => {
  const policy = INTELLIGENCE_PROVIDER_MANIFEST['gitguardian-hmsl'];
  assert.ok(policy);
  assert.equal(policy.mode, 'graph');
  assert.equal(policy.fanoutEligible, false);
  assert.equal(policy.sensitivity, 'secret');
  assert.equal(policy.authorization, 'explicit_case');
  assert.equal(policy.retentionClass, 'no_store');
  assert.equal(policy.distribution, 'internal_only');
});
