import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ALL_PROVIDERS } from '../src/providers/index.js';
import { PROVIDER_MANIFEST, providerPolicy, providerSecretNames } from '../src/providers/manifest.js';
import { EXECUTION_POLICY_VERSION } from '../src/core/execution-policy.js';

const json = path => JSON.parse(readFileSync(new URL(`../${path}`, import.meta.url), 'utf8'));
const text = path => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');

const REQUIRED = [
  'displayName','credentialEnv','optionalCredential','authType','tier','costClass','types','observationTypes',
  'timeoutMs','cacheTtlMs','negativeCacheTtlMs','maxResponseBytes','fixedHosts','methods','protocols','parserVersion','sourceUrl','distribution',
  'sourceRole','freshnessClass','admissionVersion','executionPolicy',
];

const SOURCE_ROLES = new Set(['authoritative', 'first_party', 'aggregator', 'community', 'contextual']);
const FRESHNESS_CLASSES = new Set(['live', 'near_real_time', 'periodic', 'reference']);

test('canonical provider manifest has exactly one complete policy for every active adapter', () => {
  const names = ALL_PROVIDERS.map(p => p.name).sort();
  assert.deepEqual(Object.keys(PROVIDER_MANIFEST).sort(), names);
  for (const provider of ALL_PROVIDERS) {
    const policy = providerPolicy(provider.name);
    for (const field of REQUIRED) assert.ok(Object.hasOwn(policy, field), `${provider.name}.${field}`);
    assert.deepEqual(policy.types, provider.types);
    assert.deepEqual(policy.observationTypes, provider.observationTypes);
    assert.equal(policy.tier, provider.tier);
    assert.equal(policy.costClass, provider.costClass);
    assert.equal(policy.timeoutMs, provider.timeoutMs);
    assert.equal(policy.cacheTtlMs, provider.cacheTtlMs);
    assert.equal(policy.negativeCacheTtlMs, provider.negativeCacheTtlMs);
    assert.equal(policy.maxResponseBytes, provider.maxResponseBytes);
    assert.deepEqual(policy.fixedHosts, provider.fixedHosts);
    assert.deepEqual(policy.methods, provider.methods ?? ['GET']);
    assert.deepEqual(policy.protocols, provider.protocols ?? ['https:']);
    assert.equal(policy.parserVersion, provider.parserVersion);
    assert.equal(policy.sourceUrl, provider.sourceUrl);
    assert.equal(policy.sourceRole, provider.sourceRole);
    assert.equal(policy.freshnessClass, provider.freshnessClass);
    assert.equal(policy.admissionVersion, provider.admissionVersion);
    assert.equal(policy.executionPolicy, provider.executionPolicy);
    assert.match(policy.displayName, /^.{1,80}$/);
    assert.ok(['none','api_key','bearer','basic','token','hmac'].includes(policy.authType));
    assert.ok(['internal','shareable','internal_only'].includes(policy.distribution));
    assert.equal(SOURCE_ROLES.has(policy.sourceRole), true, `${provider.name}.sourceRole`);
    assert.equal(FRESHNESS_CLASSES.has(policy.freshnessClass), true, `${provider.name}.freshnessClass`);
    assert.equal(policy.admissionVersion, 'v8.1', `${provider.name}.admissionVersion`);
    assert.equal(policy.executionPolicy, EXECUTION_POLICY_VERSION, `${provider.name}.executionPolicy`);
  }
});

test('provider secret inventory remains exact while non-secret integration config stays explicit', () => {
  const providerNames = [...providerSecretNames()].sort();
  assert.deepEqual(providerNames, [...new Set(providerNames)].sort());
  assert.equal(providerNames.includes('PARA11AX_TOKEN'), false);
  assert.equal(providerNames.includes('SENTRY_AUTH_TOKEN'), false);
  assert.equal(providerNames.includes('CENSYS_ORG_ID'), false);
  assert.equal(providerNames.includes('SHADOWSERVER_API_KEY'), false);
  assert.equal(providerNames.includes('SHADOWSERVER_API_SECRET'), true);
  assert.equal(providerNames.some(name => name.startsWith('PARA11AX_USER_SCANNER_')), false);
  for (const name of providerNames) assert.match(name, /^[A-Z0-9_]+$/);

  const providerAndGateway = ['PARA11AX_TOKEN', ...providerNames, 'SENTRY_AUTH_TOKEN'].sort();
  const integrationConfig = [
    'CENSYS_ORG_ID',
    'PARA11AX_OWNED_CIDRS',
    'PARA11AX_USER_SCANNER_URL',
    'PARA11AX_USER_SCANNER_TOKEN',
    'SHADOWSERVER_API_KEY',
  ].sort();
  const envNames = text('.env.example').split(/\r?\n/).filter(line => /^[A-Z0-9_]+=$/.test(line)).map(line => line.slice(0, -1)).sort();
  assert.deepEqual(envNames, [...providerAndGateway, ...integrationConfig].sort());

  const bootstrap = text('scripts/bootstrap-vercel.ps1');
  const block = bootstrap.match(/\$SecretNames\s*=\s*@\(([\s\S]*?)\)\s*\n/);
  assert.ok(block, 'bootstrap SecretNames block missing');
  const bootstrapNames = [...block[1].matchAll(/'([A-Z0-9_]+)'/g)].map(match => match[1]);
  assert.equal(bootstrapNames.includes('PARA11AX_TOKEN'), true);
  assert.equal(new Set(bootstrapNames).size, bootstrapNames.length, 'bootstrap secret names must be unique');
  for (const name of bootstrapNames) assert.ok(providerAndGateway.includes(name), `bootstrap contains unknown secret ${name}`);
});

test('checked-in JSON manifests are identical to the runtime manifest projection and contain no credential values', () => {
  const raw = {
    ...json('config/providers.json'),
    ...json('config/intelligence-providers.json'),
    ...json('config/owned-asset-providers.json'),
  };
  assert.deepEqual(raw, PROVIDER_MANIFEST);
  const serialized = JSON.stringify(raw);
  assert.doesNotMatch(serialized, /eyJ[a-zA-Z0-9_-]{20,}\./);
  assert.doesNotMatch(serialized, /(?:sk-|sntryu_|AIza|AKIA)[A-Za-z0-9_-]{8,}/);
});
