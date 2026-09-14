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

test('VirusTotal graph is a separately selectable bounded policy while point enrichment remains unchanged', () => {
  const point = intelligenceProviderPolicy('virustotal');
  assert.equal(point.mode, 'enrich');
  assert.equal(point.fanoutEligible, true);

  const graph = intelligenceProviderPolicy('virustotal-graph');
  assert.equal(graph.mode, 'graph');
  assert.equal(graph.fanoutEligible, false);
  assert.equal(graph.providerFamily, 'virustotal');
  assert.equal(graph.maxPages, 1);
  assert.equal(graph.maxRelationships, 60);
});

test('VirusTotal domain relationships cover resolutions, communicating files, certificates, dedupe, and first-page-only traversal', async () => {
  const file = 'a'.repeat(64);
  const certificate = 'b'.repeat(64);
  const urls = [];
  const result = await virustotalGraphProvider.run({ type: 'domain', value: 'example.com' }, context(async url => {
    const value = String(url);
    urls.push(value);
    if (value.includes('/resolutions?')) return json({
      data: [
        { type: 'resolution', attributes: { host_name: 'example.com', ip_address: '203.0.113.7' } },
        { type: 'resolution', attributes: { host_name: 'example.com', ip_address: '203.0.113.7' } },
      ],
      links: { next: 'https://www.virustotal.com/api/v3/domains/example.com/resolutions?cursor=must-not-follow' },
    });
    if (value.includes('/communicating_files?')) return json({
      data: [{ type: 'file', id: file }, { type: 'file', id: file }],
      links: { next: 'https://www.virustotal.com/api/v3/domains/example.com/communicating_files?cursor=must-not-follow' },
    });
    if (value.includes('/historical_ssl_certificates?')) return json({ data: [{ type: 'ssl_cert', id: certificate }] });
    throw new Error(`unexpected URL: ${value}`);
  }));

  assert.equal(urls.length, 3);
  assert.equal(urls.every(url => url.startsWith('https://www.virustotal.com/api/v3/domains/example.com/')), true);
  assert.equal(urls.every(url => new URL(url).searchParams.get('limit') === '20'), true);
  assert.equal(urls.every(url => !new URL(url).searchParams.has('cursor')), true);
  assert.deepEqual(result.relationships, [
    { targetType: 'ip', target: '203.0.113.7', relationship: 'resolves_to' },
    { targetType: 'hash', target: file, relationship: 'communicating_file' },
    { targetType: 'certificate', target: `cert-sha256:${certificate}`, relationship: 'historical_ssl_certificate' },
  ]);
});

test('VirusTotal file relationships cover contacted domains, IPs, and URLs', async () => {
  const hash = 'c'.repeat(64);
  const urls = [];
  const result = await virustotalGraphProvider.run({ type: 'hash', value: hash }, context(async url => {
    const value = String(url);
    urls.push(value);
    if (value.includes('/contacted_domains?')) return json({ data: [{ type: 'domain', id: 'example.org' }] });
    if (value.includes('/contacted_ips?')) return json({ data: [{ type: 'ip_address', id: '198.51.100.9' }] });
    if (value.includes('/contacted_urls?')) return json({ data: [{ type: 'url', id: 'opaque-vt-id', attributes: { url: 'https://example.org/payload' } }] });
    throw new Error(`unexpected URL: ${value}`);
  }));

  assert.deepEqual(urls.map(url => new URL(url).pathname), [
    `/api/v3/files/${hash}/contacted_domains`,
    `/api/v3/files/${hash}/contacted_ips`,
    `/api/v3/files/${hash}/contacted_urls`,
  ]);
  assert.deepEqual(result.relationships, [
    { targetType: 'domain', target: 'example.org', relationship: 'contacted_domain' },
    { targetType: 'ip', target: '198.51.100.9', relationship: 'contacted_ip' },
    { targetType: 'url', target: 'https://example.org/payload', relationship: 'contacted_url' },
  ]);
});

test('VirusTotal relationship parsing enforces the per-class page cap', async () => {
  const hash = 'e'.repeat(64);
  const domains = Array.from({ length: 25 }, (_, index) => ({
    type: 'domain',
    id: `host-${index}.example.com`,
  }));
  const result = await virustotalGraphProvider.run({ type: 'hash', value: hash }, context(async url => {
    const value = String(url);
    if (value.includes('/contacted_domains?')) return json({
      data: domains,
      links: { next: 'https://www.virustotal.com/api/v3/files/x/contacted_domains?cursor=must-not-follow' },
    });
    if (value.includes('/contacted_ips?') || value.includes('/contacted_urls?')) return json({ data: [] });
    throw new Error(`unexpected URL: ${value}`);
  }));

  assert.equal(result.relationships.length, 20);
  assert.equal(result.relationships.at(0)?.target, 'host-0.example.com');
  assert.equal(result.relationships.at(-1)?.target, 'host-19.example.com');
});

test('VirusTotal graph treats 404 as neutral absence and preserves 403 entitlement failure', async () => {
  const missing = await virustotalGraphProvider.run({ type: 'domain', value: 'example.com' }, context(async () => json({ error: { code: 'NotFoundError' } }, 404)));
  assert.equal(missing.verdict, 'no_result');
  assert.deepEqual(missing.relationships, []);

  await assert.rejects(
    virustotalGraphProvider.run({ type: 'domain', value: 'example.com' }, context(async () => json({ error: { code: 'ForbiddenError' } }, 403))),
    error => error?.status === 403,
  );
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

test('VirusTotal graph rejects malformed relationship objects instead of manufacturing pivots', async () => {
  const hash = 'f'.repeat(64);
  const result = await virustotalGraphProvider.run({ type: 'hash', value: hash }, context(async url => {
    const value = String(url);
    if (value.includes('/contacted_domains?')) return json({ data: [null, [], {}, { type: 'domain' }, { type: 'domain', id: '<mark>example.org</mark>' }] });
    if (value.includes('/contacted_ips?')) return json({ data: [{ type: 'ip_address', id: 'not-an-ip' }] });
    if (value.includes('/contacted_urls?')) return json({ data: [{ type: 'url', attributes: { url: '<script>alert(1)</script>' } }] });
    throw new Error('unexpected URL');
  }));

  assert.deepEqual(result.relationships, []);
});
