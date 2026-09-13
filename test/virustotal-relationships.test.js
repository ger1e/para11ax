import test from 'node:test';
import assert from 'node:assert/strict';
import { intelligenceProviderPolicy } from '../src/providers/intelligence-manifest.js';
import { virustotalGraphProvider } from '../src/providers/virustotal.js';

function json(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
}

function context(fetchImpl) {
  return {
    env: { VIRUSTOTAL_API_KEY: 'test-key' },
    signal: new AbortController().signal,
    fetchImpl,
  };
}

test('VirusTotal manifest carries validated graph bounds without replacing point-enrichment policy', () => {
  const policy = intelligenceProviderPolicy('virustotal');
  assert.equal(policy.mode, 'enrich');
  assert.equal(policy.fanoutEligible, true);
  assert.equal(policy.providerFamily, 'virustotal');
  assert.equal(policy.maxPages, 1);
  assert.equal(policy.maxRelationships, 60);
});

test('VirusTotal graph rejects relationship rows whose declared VT object type contradicts the relationship', async () => {
  const hash = 'd'.repeat(64);
  const result = await virustotalGraphProvider.run({ type: 'hash', value: hash }, context(async url => {
    const value = String(url);
    if (value.includes('/contacted_domains?')) return json({ data: [{ type: 'ip_address', id: 'example.org' }] });
    if (value.includes('/contacted_ips?')) return json({ data: [{ type: 'domain', id: '198.51.100.9' }] });
    if (value.includes('/contacted_urls?')) return json({ data: [{ type: 'domain', attributes: { url: 'https://example.org/payload' } }] });
    throw new Error('unexpected URL');
  }));

  assert.deepEqual(result.relationships, []);
});
