import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createProviderRegistry } from '../src/core/provider-registry.js';
import { manifestForRegistry } from '../src/core/provider-manifest.js';
import { EXECUTION_POLICY_VERSION } from '../src/core/execution-policy.js';
import { ALL_PROVIDERS } from '../src/providers/index.js';
import { WORKFLOWS, WORKFLOW_CALL_LIMITS } from '../src/workflows.js';
import { GATEWAY_VERSION, EVIDENCE_SCHEMA_VERSION } from '../src/core/version.js';

const registry = createProviderRegistry(ALL_PROVIDERS);
const manifest = manifestForRegistry(registry);

function packageJson() {
  return JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
}

test('every active workflow adapter is registered supports its routed type and fits the static call ceiling', () => {
  assert.equal(registry.names().length, 39);
  assert.equal(Object.keys(WORKFLOWS).length, 9);
  for (const [type, names] of Object.entries(WORKFLOWS)) {
    assert.ok(Number.isInteger(WORKFLOW_CALL_LIMITS[type]) && WORKFLOW_CALL_LIMITS[type] >= names.length, `${type} call ceiling too small`);
    for (const name of names) {
      const adapter = registry.get(name);
      assert.ok(adapter, `${type}: missing provider ${name}`);
      assert.equal(adapter.active === false, false, `${type}: inactive provider ${name}`);
      assert.ok(adapter.types.includes(type), `${type}: provider ${name} does not support routed type`);
    }
  }
});

test('provider manifest has complete immutable bounded transport and admission metadata', () => {
  assert.equal(manifest.length, registry.names().length);
  for (const provider of manifest) {
    assert.ok(provider.name);
    assert.ok(provider.types.length > 0);
    assert.ok(provider.observationTypes.length > 0);
    assert.ok([1,2,3,4,5].includes(provider.tier));
    assert.ok(['free','quota','scarce'].includes(provider.costClass));
    assert.ok(provider.timeoutMs > 0 && provider.timeoutMs <= 20_000);
    assert.ok(provider.maxResponseBytes > 0 && provider.maxResponseBytes <= 32_000_000);
    assert.ok(provider.fixedHosts.length > 0);
    for (const host of provider.fixedHosts) {
      assert.match(host, /^(?:[a-z0-9-]+\.)*[a-z0-9-]+$/i, `${provider.name}: invalid fixed host ${host}`);
      assert.equal(host.includes('/'), false);
      assert.equal(host.includes(':'), false);
    }
    assert.ok(provider.methods.every(method => ['GET','POST'].includes(method)));
    assert.deepEqual(provider.protocols, ['https:'], `${provider.name}: non-HTTPS provider protocol`);
    assert.match(provider.sourceUrl, /^https:\/\//);
    assert.ok(provider.parserVersion);
    assert.ok(['authoritative','first_party','aggregator','community','contextual'].includes(provider.sourceRole), `${provider.name}: sourceRole`);
    assert.ok(['live','near_real_time','periodic','reference'].includes(provider.freshnessClass), `${provider.name}: freshnessClass`);
    assert.equal(provider.admissionVersion, 'v8.1', `${provider.name}: admissionVersion`);
    assert.equal(provider.executionPolicy, EXECUTION_POLICY_VERSION, `${provider.name}: executionPolicy`);
  }
});

test('deprecated or deliberately removed provider classes cannot re-enter active registry', () => {
  for (const name of ['sslbl-c2', 'securitytrails']) assert.equal(registry.get(name), undefined);
});

test('gateway package major version and evidence schema major stay aligned', () => {
  const pkg = packageJson();
  assert.equal(pkg.version, GATEWAY_VERSION);
  assert.equal(GATEWAY_VERSION.split('.')[0], EVIDENCE_SCHEMA_VERSION.split('.')[0]);
  assert.equal(pkg.engines.node, '24.x');
});

test('Maltego covers all nine active workflow types after Train 6 certificate parity', () => {
  const init = readFileSync(new URL('../maltego/transforms/__init__.py', import.meta.url), 'utf8');
  const requirements = {
    ip: ['EnrichIPv4','EnrichIPv6'], domain: ['EnrichDomain'], url: ['EnrichURL'], hash: ['EnrichHash'],
    certificate: ['EnrichCertificate'], cve: ['EnrichCVE'], attack: ['EnrichATTACK'], asn: ['EnrichASN'], cidr: ['EnrichCIDR'],
  };
  const supported = Object.keys(requirements).sort();
  assert.deepEqual(supported, Object.keys(WORKFLOWS).sort());
  for (const [type, names] of Object.entries(requirements)) {
    for (const name of names) assert.ok(init.includes(name), `${type}: missing Maltego ${name}`);
  }
});
