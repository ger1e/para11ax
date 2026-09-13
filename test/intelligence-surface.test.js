import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/app.js';

const env = { PARA11AX_TOKEN: 'fixture-token' };
const req = body => ({ method: 'POST', headers: { authorization: `Bearer ${env.PARA11AX_TOKEN}`, 'content-type': 'application/json' }, body });

function adapter(name, mode, type = 'domain') {
  return {
    name,
    types: [type], observationTypes: ['web_archive_observation'], tier: 1, costClass: 'free',
    timeoutMs: 1000, cacheTtlMs: 1000, negativeCacheTtlMs: 1000, maxResponseBytes: 4096,
    fixedHosts: ['example.org'], methods: ['GET'], protocols: ['https:'], parserVersion: '1',
    sourceUrl: 'https://example.org/docs', sourceRole: 'first_party', distribution: 'shareable', active: true,
    mode, fanoutEligible: mode === 'enrich', sensitivity: 'public', authorization: 'none', retentionClass: 'normal',
    schedulerByType: { [type]: { authorityClass: 'first_party', semanticUniqueness: 'unique', intelligenceValue: 'direct', pivotValue: 'high', latencyClass: 'fast' } },
    async run(input) {
      return { observationType: 'web_archive_observation', verdict: 'observed', attributes: { value: input.value }, relationships: [], references: ['https://example.org/reference'] };
    },
  };
}

test('search operation executes only fixed-mode registered candidates', async () => {
  const app = createApp({ env, adapters: [adapter('search-fixture', 'search')] });
  const response = await app.handleIntelligence(req({ operation: 'search', indicator: 'example.com' }));
  assert.equal(response.status, 200);
  assert.equal(response.body.operation, 'search');
  assert.equal(response.body.mode, 'search');
  assert.equal(response.body.subject.type, 'domain');
  assert.deepEqual(response.body.providers.executed, ['search-fixture']);
  assert.equal(response.body.evidence.length, 1);
});

test('pivot operation preserves baseline evidence and returns phase-two projection separately', async () => {
  const enrich = adapter('cloudflare-dns', 'enrich');
  enrich.observationTypes = ['dns_resolution'];
  enrich.run = async () => ({
    observationType: 'dns_resolution', verdict: 'observed',
    relationships: [{ type: 'uses_certificate', targetType: 'certificate', target: `cert-sha256:${'a'.repeat(64)}` }], references: [],
  });
  const graph = adapter('graph-fixture', 'graph', 'certificate');
  const app = createApp({ env, adapters: [enrich, graph] });
  const response = await app.handleIntelligence(req({ operation: 'pivot', indicator: 'example.com', profile: 'standard' }));
  assert.equal(response.status, 200);
  assert.equal(response.body.operation, 'pivot');
  assert.equal(response.body.mode, 'graph');
  assert.equal(response.body.baseline.evidence.length, 1);
  assert.equal(response.body.intelligence.evidence.length, 1);
  assert.equal(response.body.baseline.evidence[0].provider, 'cloudflare-dns');
  assert.equal(response.body.intelligence.evidence[0].provider, 'graph-fixture');
});

test('intelligence surface rejects caller authorization claims and raw provider routing controls', async () => {
  const app = createApp({ env, adapters: [] });
  for (const extra of [
    { trusted: true }, { caseId: 'CASE-1' }, { verifiedDomains: ['example.com'] }, { ownedCidrs: ['192.0.2.0/24'] },
    { provider: 'fixture' }, { providerUrl: 'https://example.org' }, { path: '/vendor/raw' }, { mode: 'search' },
  ]) {
    const response = await app.handleIntelligence(req({ operation: 'search', indicator: 'example.com', ...extra }));
    assert.equal(response.status, 400, JSON.stringify(extra));
    assert.equal(response.body.error, 'unsupported_request_field');
  }
});

test('intelligence operation and asserted type are finite and strict', async () => {
  const app = createApp({ env, adapters: [] });
  assert.equal((await app.handleIntelligence(req({ operation: 'anything', indicator: 'example.com' }))).status, 400);
  assert.equal((await app.handleIntelligence(req({ operation: 'search', indicator: 'example.com', type: 'email' }))).status, 400);
  const username = await app.handleIntelligence(req({ operation: 'search', indicator: 'user:fixture_name' }));
  assert.equal(username.status, 503);
  assert.equal(username.body.error, 'user_scanner_unavailable');
});
