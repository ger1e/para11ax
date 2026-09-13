import test from 'node:test';
import assert from 'node:assert/strict';
import { createProviderRegistry } from '../src/core/provider-registry.js';
import { buildCapabilityRegistry } from '../src/core/capability-registry.js';
import { OBSERVABLE_MANIFEST } from '../src/core/observable-registry.js';
import { EXECUTION_POLICY } from '../src/core/execution-policy.js';
import { PROVIDER_SCHEDULER_POLICY_VERSION } from '../src/core/provider-priority.js';
import { ALL_PROVIDERS } from '../src/providers/index.js';
import { WORKFLOWS, WORKFLOW_CALL_LIMITS } from '../src/workflows.js';

const EXPECTED_TYPES = ['asn', 'attack', 'certificate', 'cidr', 'cve', 'domain', 'hash', 'ip', 'url'];

test('capability registry is deterministic frozen and type-indexed', () => {
  const providerRegistry = createProviderRegistry(ALL_PROVIDERS);
  const capabilities = buildCapabilityRegistry({ providerRegistry, observableRegistry: OBSERVABLE_MANIFEST });
  assert.equal(Object.isFrozen(capabilities), true);
  assert.deepEqual(capabilities.observableTypes.map(item => item.type), EXPECTED_TYPES);
  assert.deepEqual(capabilities.providers.map(item => item.name), [...capabilities.providers.map(item => item.name)].sort());
  assert.ok(capabilities.byType.ip.providers.includes('censys'));
  assert.ok(capabilities.byType.cve.providers.includes('cisa-kev'));
  assert.deepEqual(capabilities.byType.certificate.providers, ['censys', 'censys-history', 'censys-search', 'virustotal']);
  assert.deepEqual(WORKFLOWS.certificate, ['censys', 'virustotal']);
  assert.ok(capabilities.byType.domain.providers.includes('cloudflare-dns'));
  assert.equal(Object.isFrozen(capabilities.byType.ip), true);
});

test('capability registry exposes credential mode but never credential environment names', () => {
  const providerRegistry = createProviderRegistry(ALL_PROVIDERS);
  const capabilities = buildCapabilityRegistry({ providerRegistry, observableRegistry: OBSERVABLE_MANIFEST });
  const serialized = JSON.stringify(capabilities);
  for (const provider of ALL_PROVIDERS) {
    if (provider.requiredEnv) assert.equal(serialized.includes(provider.requiredEnv), false, provider.name);
    if (provider.optionalEnv) assert.equal(serialized.includes(provider.optionalEnv), false, provider.name);
  }
  assert.doesNotMatch(serialized, /"credentialEnv"|"requiredEnv"|"optionalEnv"/);
  assert.ok(capabilities.providers.every(item => ['required', 'optional', 'none'].includes(item.credentialMode)));
});

test('capability registry exposes the canonical shared execution contract without duplicating policy', () => {
  const providerRegistry = createProviderRegistry(ALL_PROVIDERS);
  const capabilities = buildCapabilityRegistry({ providerRegistry, observableRegistry: OBSERVABLE_MANIFEST });
  assert.deepEqual(capabilities.execution, {
    version: EXECUTION_POLICY.version,
    providerConcurrencyMax: EXECUTION_POLICY.providerConcurrencyMax,
    providerMaxAttempts: EXECUTION_POLICY.providerMaxAttempts,
    requestDeadlineMs: EXECUTION_POLICY.requestDeadlineMs,
    workflowProviderCalls: { ...WORKFLOW_CALL_LIMITS },
  });
  assert.equal(Object.isFrozen(capabilities.execution), true);
  assert.equal(Object.isFrozen(capabilities.execution.workflowProviderCalls), true);
});

test('capability registry exposes scheduler version descriptors and per-type fallback without pretending runtime rank', () => {
  const providerRegistry = createProviderRegistry(ALL_PROVIDERS);
  const capabilities = buildCapabilityRegistry({ providerRegistry, observableRegistry: OBSERVABLE_MANIFEST });
  const threatfox = capabilities.providers.find(item => item.name === 'threatfox');
  assert.equal(threatfox.scheduler.version, PROVIDER_SCHEDULER_POLICY_VERSION);
  assert.deepEqual(threatfox.scheduler.byType.ip, {
    authorityClass: 'specialist',
    semanticUniqueness: 'unique',
    intelligenceValue: 'direct',
    pivotValue: 'high',
    latencyClass: 'normal',
    fallback: false,
  });
  const rdap = capabilities.providers.find(item => item.name === 'rdap');
  assert.deepEqual(rdap.scheduler.byType.asn, { fallback: true, rationale: 'legacy_priority_fallback' });
  assert.deepEqual(rdap.scheduler.byType.cidr, { fallback: true, rationale: 'legacy_priority_fallback' });
  const serialized = JSON.stringify(capabilities);
  assert.doesNotMatch(serialized, /"rank"|"workflowIndex"/);
  assert.equal(Object.isFrozen(threatfox.scheduler), true);
  assert.equal(Object.isFrozen(threatfox.scheduler.byType), true);
});
