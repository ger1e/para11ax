import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';

import { INTELLIGENCE_PROVIDER_MANIFEST } from '../src/providers/intelligence-manifest.js';
import { ALL_PROVIDERS } from '../src/providers/index.js';

const REMOVED_PROVIDERS = Object.freeze([
  'hibp',
  'hudson-rock',
  'spycloud',
  'dnsdb',
  'validin',
  'spur',
  'netify',
]);

const REMOVED_PROVIDER_FILES = Object.freeze([
  'hibp.js',
  'hudson-rock.js',
  'spycloud.js',
  'dnsdb.js',
  'validin.js',
  'spur.js',
  'netify.js',
]);

const REMOVED_ENV = Object.freeze([
  'HIBP_API_KEY',
  'HUDSONROCK_API_KEY',
  'SPYCLOUD_API_KEY',
  'DNSDB_API_KEY',
  'VALIDIN_API_KEY',
  'SPUR_TOKEN',
  'NETIFY_API_KEY',
]);

const PAID_ONLY_PLAN_TERMS = Object.freeze([
  'HIBP',
  'Hudson Rock',
  'SpyCloud',
  'DNSDB',
  'Validin',
  'Spur',
  'Netify',
  'DomainTools',
  'WhoisXML',
  'IBM X-Force',
  'Microsoft Threat Intelligence',
  'Recorded Future',
  'Google Threat Intelligence',
  'Flashpoint',
  'Flare',
  'DarkOwl',
  'Intel 471',
]);

test('paid-only intelligence providers are absent from the runtime registry and source tree', () => {
  const registered = new Set(ALL_PROVIDERS.map(provider => provider.name));
  for (const name of REMOVED_PROVIDERS) {
    assert.equal(Object.hasOwn(INTELLIGENCE_PROVIDER_MANIFEST, name), false, `${name} manifest entry`);
    assert.equal(registered.has(name), false, `${name} runtime registration`);
  }
  for (const file of REMOVED_PROVIDER_FILES) {
    assert.equal(existsSync(new URL(`../src/providers/${file}`, import.meta.url)), false, file);
  }
});

test('paid-only provider credentials are absent from the public environment template', () => {
  const envExample = readFileSync(new URL('../.env.example', import.meta.url), 'utf8');
  for (const name of REMOVED_ENV) assert.equal(envExample.includes(name), false, name);
});

test('intelligence design and implementation plans contain no paid-only provider roadmap', () => {
  const docs = [
    '../docs/superpowers/specs/2026-09-13-intelligence-fabric-design.md',
    '../docs/superpowers/plans/2026-09-13-intelligence-fabric-implementation-plan.md',
    '../docs/superpowers/plans/2026-09-13-intelligence-fabric-gap-closure-plan.md',
  ].map(path => readFileSync(new URL(path, import.meta.url), 'utf8')).join('\n');

  for (const term of PAID_ONLY_PLAN_TERMS) assert.equal(docs.includes(term), false, term);
});
