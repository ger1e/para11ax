import test from 'node:test';
import assert from 'node:assert/strict';
import { vulncheckProvider } from '../src/providers/vulncheck.js';

function json(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
}

function context(fetchImpl) {
  return {
    env: { VULNCHECK_API_TOKEN: 'test-token' },
    signal: new AbortController().signal,
    fetchImpl,
  };
}

test('VulnCheck emits bounded exploit maturity with explicit XDB, actor, and ransomware context', async () => {
  const seen = [];
  const result = await vulncheckProvider.run({ type: 'cve', value: 'CVE-2024-4577' }, context(async (url, options) => {
    seen.push({ url: String(url), options });
    return json({
      _meta: { queried_index_count: 12, indices_with_hits: 2, total_count: 2 },
      data: [
        {
          index: 'vulncheck-kev',
          id: 'kev-1',
          source: {
            cve: ['CVE-2024-4577'],
            knownRansomwareCampaignUse: 'Known',
            threat_actors: ['Lace Tempest'],
            ransomware: ['Cl0p'],
            vulncheck_xdb: [
              {
                xdb_id: '024996c990cc',
                xdb_url: 'https://vulncheck.com/xdb/024996c990cc',
                exploit_type: 'initial-access',
                date_added: '2025-02-14T19:38:10Z',
              },
            ],
          },
        },
        {
          index: 'exploits',
          id: 'exploit-1',
          source: { cve: ['CVE-2024-4577'], exploit_type: 'remote-code-execution' },
        },
      ],
    });
  }));

  assert.equal(seen.length, 1);
  const requestUrl = new URL(seen[0].url);
  assert.equal(requestUrl.origin, 'https://api.vulncheck.com');
  assert.equal(requestUrl.pathname, '/v3/search/cve');
  assert.equal(requestUrl.searchParams.get('cve'), 'CVE-2024-4577');
  assert.equal(requestUrl.searchParams.get('limit'), '100');
  assert.equal(seen[0].options.headers.Authorization, 'Bearer test-token');
  assert.equal(result.observationType, 'exploit_maturity');
  assert.equal(result.verdict, 'known_exploited');
  assert.equal(result.attributes.knownExploited, true);
  assert.equal(result.attributes.coverage, 'accessible_indices_only');
  assert.equal(result.attributes.queriedIndexCount, 12);
  assert.equal(result.attributes.indicesWithHits, 2);
  assert.equal(result.attributes.exploitCount, 2);
  assert.deepEqual(result.attributes.exploitTypes, ['initial-access', 'remote-code-execution']);
  assert.equal(result.attributes.knownRansomwareCampaignUse, 'Known');
  assert.deepEqual(result.relationships, [
    { targetType: 'actor', target: 'Lace Tempest', relationship: 'threat_actor_context' },
    { targetType: 'ransomware', target: 'Cl0p', relationship: 'ransomware_context' },
  ]);
  assert.ok(result.references.includes('https://vulncheck.com/xdb/024996c990cc'));
});

test('VulnCheck empty accessible-index result stays uncertainty-aware rather than claiming not exploited', async () => {
  const result = await vulncheckProvider.run({ type: 'cve', value: 'CVE-2026-12345' }, context(async () => json({
    _meta: { queried_index_count: 5, indices_with_hits: 0, total_count: 0 },
    data: [],
  })));

  assert.equal(result.verdict, 'no_result');
  assert.equal(result.attributes.knownExploited, null);
  assert.equal(result.attributes.exploitCount, 0);
  assert.equal(result.attributes.coverage, 'accessible_indices_only');
  assert.deepEqual(result.relationships, []);
});

test('VulnCheck preserves auth, entitlement, and rate-limit failures', async () => {
  for (const status of [401, 402, 403, 429]) {
    await assert.rejects(
      vulncheckProvider.run({ type: 'cve', value: 'CVE-2024-4577' }, context(async () => json({ error: true }, status))),
      error => error?.status === status,
    );
  }
});

test('VulnCheck rejects malformed responses and unsupported input', async () => {
  await assert.rejects(
    vulncheckProvider.run({ type: 'cve', value: 'CVE-2024-4577' }, context(async () => json({ data: {} }))),
    /invalid VulnCheck response/,
  );
  await assert.rejects(
    vulncheckProvider.run({ type: 'domain', value: 'example.com' }, context(async () => json({ data: [] }))),
    /unsupported VulnCheck input/,
  );
});
