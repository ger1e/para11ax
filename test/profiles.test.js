import test from 'node:test';
import assert from 'node:assert/strict';
import { selectProviders, PROFILE_NAMES } from '../src/profiles.js';
import { ALL_PROVIDERS } from '../src/providers/index.js';
import { WORKFLOWS } from '../src/workflows.js';

function registry(items) {
  const map = new Map(items.map(item => [item.name, item]));
  return { get: name => map.get(name) };
}

const workflow = ['scarce', 'tier3', 'tier1b', 'tier1a', 'knowledge'];
const reg = registry([
  { name: 'scarce', types: ['hash'], tier: 4, costClass: 'scarce' },
  { name: 'tier3', types: ['hash'], tier: 3, costClass: 'quota' },
  { name: 'tier1b', types: ['hash'], tier: 1, costClass: 'free' },
  { name: 'tier1a', types: ['hash'], tier: 1, costClass: 'free' },
  { name: 'knowledge', types: ['hash'], tier: 5, costClass: 'free', observationTypes: ['attack_knowledge'] },
]);

test('profiles are fixed and reject arbitrary values', () => {
  assert.deepEqual(PROFILE_NAMES, ['fast', 'standard', 'full']);
  assert.throws(() => selectProviders({ type: 'hash', profile: 'whatever', workflow, registry: reg }), /invalid_profile/);
});

test('full is admission-only and preserves original workflow order despite scrambled tiers', () => {
  assert.deepEqual(selectProviders({ type: 'hash', profile: 'full', workflow, registry: reg }), workflow);
});

test('standard excludes scarce providers and preserves workflow order', () => {
  assert.deepEqual(selectProviders({ type: 'hash', profile: 'standard', workflow, registry: reg }), ['tier3', 'tier1b', 'tier1a', 'knowledge']);
});

test('fast excludes scarce and high-cost broad enrichment but preserves sole knowledge workflow', () => {
  assert.deepEqual(selectProviders({ type: 'hash', profile: 'fast', workflow, registry: reg }), ['tier1b', 'tier1a', 'knowledge']);
  const attackReg = registry([{ name: 'attack-taxii', types: ['attack'], tier: 5, costClass: 'free', observationTypes: ['attack_knowledge'] }]);
  assert.deepEqual(selectProviders({ type: 'attack', profile: 'fast', workflow: ['attack-taxii'], registry: attackReg }), ['attack-taxii']);
});

test('real fast IP profile excludes heavyweight MISP feeds while standard retains them', () => {
  const providerRegistry = registry(ALL_PROVIDERS);
  const fast = selectProviders({ type: 'ip', profile: 'fast', workflow: WORKFLOWS.ip, registry: providerRegistry });
  const standard = selectProviders({ type: 'ip', profile: 'standard', workflow: WORKFLOWS.ip, registry: providerRegistry });

  assert.equal(fast.includes('misp-circl-osint'), false);
  assert.equal(fast.includes('misp-botvrij-osint'), false);
  assert.equal(standard.includes('misp-circl-osint'), true);
  assert.equal(standard.includes('misp-botvrij-osint'), true);
});

test('scheduler descriptors cannot re-admit providers excluded by profile', () => {
  const schedulerAware = registry([
    {
      name: 'scarce-direct',
      types: ['ip'],
      tier: 4,
      costClass: 'scarce',
      schedulerByType: { ip: { authorityClass: 'authoritative', semanticUniqueness: 'unique', intelligenceValue: 'direct', pivotValue: 'high', latencyClass: 'fast' } },
    },
    {
      name: 'tier3-direct',
      types: ['ip'],
      tier: 3,
      costClass: 'quota',
      schedulerByType: { ip: { authorityClass: 'authoritative', semanticUniqueness: 'unique', intelligenceValue: 'direct', pivotValue: 'high', latencyClass: 'fast' } },
    },
    {
      name: 'tier2-context',
      types: ['ip'],
      tier: 2,
      costClass: 'free',
      schedulerByType: { ip: { authorityClass: 'contextual', semanticUniqueness: 'duplicative', intelligenceValue: 'contextual', pivotValue: 'none', latencyClass: 'slow' } },
    },
  ]);
  const names = ['scarce-direct', 'tier3-direct', 'tier2-context'];
  assert.deepEqual(selectProviders({ type: 'ip', profile: 'fast', workflow: names, registry: schedulerAware }), ['tier2-context']);
  assert.deepEqual(selectProviders({ type: 'ip', profile: 'standard', workflow: names, registry: schedulerAware }), ['tier3-direct', 'tier2-context']);
});
