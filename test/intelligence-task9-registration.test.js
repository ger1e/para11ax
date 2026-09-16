import test from 'node:test';
import assert from 'node:assert/strict';

import { createApp } from '../src/app.js';
import { ALL_PROVIDERS } from '../src/providers/index.js';
import { WORKFLOWS } from '../src/workflows.js';

function request(body) {
  return {
    method: 'POST',
    headers: {
      authorization: 'Bearer test-token',
      'content-type': 'application/json',
    },
    body,
  };
}

test('Task 9 registers VulnCheck and deps.dev as intelligence-only graph capabilities', () => {
  const providers = new Map(ALL_PROVIDERS.map(provider => [provider.name, provider]));
  const vulncheck = providers.get('vulncheck');
  const depsDev = providers.get('deps-dev');

  assert.ok(vulncheck);
  assert.deepEqual(vulncheck.types, ['cve']);
  assert.equal(vulncheck.mode, 'graph');
  assert.equal(vulncheck.fanoutEligible, false);

  assert.ok(depsDev);
  assert.deepEqual(depsDev.types, ['package']);
  assert.equal(depsDev.mode, 'graph');
  assert.equal(depsDev.fanoutEligible, false);

  assert.deepEqual(Object.keys(WORKFLOWS).sort(), [
    'asn', 'attack', 'certificate', 'cidr', 'cve', 'domain', 'hash', 'ip', 'url',
  ]);
  assert.equal(WORKFLOWS.cve.includes('vulncheck'), false);
  assert.equal(Object.hasOwn(WORKFLOWS, 'package'), false);
});

test('supply-chain intelligence routes a PURL only to deps.dev without widening legacy enrichment', async () => {
  const calls = [];
  const fetchImpl = async (url, options = {}) => {
    calls.push({ url: String(url), method: options.method ?? 'GET' });
    if (String(url).endsWith('/versions/1.2.3')) {
      return new Response(JSON.stringify({
        versionKey: { system: 'NPM', name: '@scope/pkg', version: '1.2.3' },
        publishedAt: '2026-01-01T00:00:00Z',
        isDefault: true,
        licenses: ['MIT'],
        advisoryKeys: [],
        links: [],
        isDeprecated: false,
        deprecatedReason: '',
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    if (String(url).endsWith('/versions/1.2.3:dependencies')) {
      return new Response(JSON.stringify({
        nodes: [
          { versionKey: { system: 'NPM', name: '@scope/pkg', version: '1.2.3' }, relation: 'SELF', errors: [], bundled: false },
          { versionKey: { system: 'NPM', name: 'direct-dep', version: '2.0.0' }, relation: 'DIRECT', errors: [], bundled: false },
        ],
        edges: [{ fromNode: 0, toNode: 1, requirement: '^2.0.0' }],
        error: '',
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    throw new Error(`unexpected test egress: ${String(url)}`);
  };

  const app = createApp({
    env: { PARA11AX_TOKEN: 'test-token' },
    fetchImpl,
    now: () => '2026-09-13T00:00:00.000Z',
    nowMs: () => 1789257600000,
  });

  const response = await app.handleIntelligence(request({
    operation: 'supply-chain',
    indicator: 'pkg:npm/%40scope/pkg@1.2.3',
  }));

  assert.equal(response.status, 200);
  assert.deepEqual(response.body.providers.selected, ['deps-dev']);
  assert.deepEqual(response.body.providers.executed, ['deps-dev']);
  assert.equal(response.body.failures.length, 0);
  assert.equal(response.body.evidence.length, 1);
  assert.deepEqual(response.body.relationships.map(item => [item.targetType, item.target, item.relationship]), [
    ['package', 'pkg:npm/direct-dep@2.0.0', 'direct_dependency'],
  ]);
  assert.equal(calls.length, 2);
  assert.ok(calls.every(call => call.url.startsWith('https://api.deps.dev/v3/')));
});
