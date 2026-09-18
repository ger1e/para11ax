import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { buildProviderFamilyQa } from '../src/eval/provider-qa.js';

const manifest = JSON.parse(readFileSync(new URL('../config/providers.json', import.meta.url), 'utf8'));

test('provider-family QA derives the canonical 39 upstream source families from the manifest', () => {
  const report = buildProviderFamilyQa(manifest);
  assert.equal(report.familyCount, 39);
  assert.equal(report.providerCount, Object.keys(manifest).length);
  assert.equal(report.families.length, 39);
});

test('provider variants collapse into their declared upstream family', () => {
  const report = buildProviderFamilyQa(manifest);
  const censys = report.families.find(entry => entry.family === 'censys');
  assert.ok(censys);
  assert.deepEqual(censys.providerIds, ['censys', 'censys-history', 'censys-search']);
  assert.ok(censys.observableTypes.includes('certificate'));
  assert.ok(censys.observableTypes.includes('ip'));
});

test('provider-family QA exposes safe normalized metadata only', () => {
  const report = buildProviderFamilyQa(manifest);
  const serialized = JSON.stringify(report);
  assert.doesNotMatch(serialized, /credentialEnv|fixedHosts|IPINFO_TOKEN|CENSYS_PAT|API_KEY|AUTHORIZATION/i);
  for (const family of report.families) {
    assert.deepEqual(Object.keys(family).sort(), [
      'activeState',
      'credentialState',
      'family',
      'freshnessClasses',
      'observableTypes',
      'providerIds',
      'sourceRoles',
    ]);
  }
});

test('provider-family QA is deterministic under manifest key-order changes', () => {
  const reversed = Object.fromEntries(Object.entries(manifest).reverse());
  assert.deepEqual(buildProviderFamilyQa(reversed), buildProviderFamilyQa(manifest));
});
