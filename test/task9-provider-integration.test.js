import test from 'node:test';
import assert from 'node:assert/strict';
import { ALL_PROVIDERS } from '../src/providers/index.js';
import { INTELLIGENCE_PROVIDER_MANIFEST } from '../src/providers/intelligence-manifest.js';
import { WORKFLOWS } from '../src/workflows.js';

function byName(name) {
  return ALL_PROVIDERS.find(provider => provider.name === name);
}

test('Task 9 providers are registered as explicit intelligence capabilities', () => {
  const vulncheck = byName('vulncheck');
  const depsDev = byName('deps-dev');
  assert.ok(vulncheck, 'VulnCheck adapter must be registered');
  assert.ok(depsDev, 'deps.dev adapter must be registered');

  assert.deepEqual(vulncheck.types, ['cve']);
  assert.deepEqual(vulncheck.observationTypes, ['exploit_maturity']);
  assert.equal(vulncheck.mode, 'graph');
  assert.equal(vulncheck.fanoutEligible, false);
  assert.equal(vulncheck.sensitivity, 'public');
  assert.equal(vulncheck.authorization, 'none');
  assert.equal(vulncheck.retentionClass, 'normal');
  assert.equal(vulncheck.requiredEnv, 'VULNCHECK_API_TOKEN');
  assert.deepEqual(vulncheck.fixedHosts, ['api.vulncheck.com']);

  assert.deepEqual(depsDev.types, ['package']);
  assert.deepEqual(depsDev.observationTypes, ['supply_chain']);
  assert.equal(depsDev.mode, 'graph');
  assert.equal(depsDev.fanoutEligible, false);
  assert.equal(depsDev.sensitivity, 'public');
  assert.equal(depsDev.authorization, 'none');
  assert.equal(depsDev.retentionClass, 'normal');
  assert.equal(depsDev.requiredEnv, undefined);
  assert.deepEqual(depsDev.fixedHosts, ['api.deps.dev']);
});

test('Task 9 capabilities stay out of ordinary automatic enrichment fanout', () => {
  assert.equal(WORKFLOWS.cve.includes('vulncheck'), false);
  assert.equal(Object.hasOwn(WORKFLOWS, 'package'), false);
  assert.equal(INTELLIGENCE_PROVIDER_MANIFEST.vulncheck.mode, 'graph');
  assert.equal(INTELLIGENCE_PROVIDER_MANIFEST.vulncheck.fanoutEligible, false);
  assert.equal(INTELLIGENCE_PROVIDER_MANIFEST['deps-dev'].mode, 'graph');
  assert.equal(INTELLIGENCE_PROVIDER_MANIFEST['deps-dev'].fanoutEligible, false);
});
