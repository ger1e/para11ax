import test from 'node:test';
import assert from 'node:assert/strict';
import { virustotalGraphProvider, virustotalProvider } from '../src/providers/virustotal.js';

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

test('VirusTotal graph is a separate bounded non-fanout capability and leaves enrichment intact', () => {
  assert.equal(virustotalProvider.name, 'virustotal');
  assert.notEqual(virustotalProvider.mode, 'graph');
  assert.equal(virustotalGraphProvider.name, 'virustotal-graph');
  assert.equal(virustotalGraphProvider.mode, 'graph');
  assert.equal(virustotalGraphProvider.fanoutEligible, false);
  assert.deepEqual(virustotalGraphProvider.types, ['ip', 'domain', 'hash']);
});

test('VirusTotal domain graph uses fixed one-page relationships with explicit typed targets', async () => {
  const urls = [];
  const file = 'a'.repeat(64);
  const cert = 'b'.repeat(64);
  const result = await virustotalGraphProvider.run({ type: 'domain', value: 'example.com' }, context(async url => {
    const value = String(url);
    urls.push(value);
    if (value.includes('/resolutions?')) return json({
      data: [
        { type: 'resolution', attributes: { host_name: 'example.com', ip_address: '203.0.113.7', date: 1_787_248_000 } },
        { type: 'resolution', attributes: { host_name: 'example.com', ip_address: '<mark>203.0.113.8</mark>' } },
      ],
      links: { next: 'https://www.virustotal.com/api/v3/domains/example.com/resolutions?cursor=do-not-follow' },
    });
    if (value.includes('/communicating_files?')) return json({ data: [{ type: 'file', id: file }, { type: 'file', id: file }] });
    if (value.includes('/historical_ssl_certificates?')) return json({ data: [{ type: 'ssl_cert', id: cert }] });
    throw new Error('unexpected URL');
  }));

  assert.equal(urls.length, 3);
  assert.equal(urls.every(url => url.startsWith('https://www.virustotal.com/api/v3/domains/example.com/')), true);
  assert.equal(urls.every(url => url.endsWith('?limit=20')), true);
  assert.equal(urls.some(url => url.includes('cursor=')), false);
  assert.deepEqual(result.relationships, [
    { targetType: 'ip', target: '203.0.113.7', relationship: 'resolves_to' },
    { targetType: 'hash', target: file, relationship: 'communicating_file' },
    { targetType: 'certificate', target: `cert-sha256:${cert}`, relationship: 'historical_ssl_certificate' },
  ]);
});

test('VirusTotal file graph maps only hard-coded contacted relationships and ignores pagination links', async () => {
  const urls = [];
  const hash = 'c'.repeat(64);
  const result = await virustotalGraphProvider.run({ type: 'hash', value: hash }, context(async url => {
    const value = String(url);
    urls.push(value);
    if (value.includes('/contacted_domains?')) return json({ data: [{ type: 'domain', id: 'example.org' }] });
    if (value.includes('/contacted_ips?')) return json({ data: [{ type: 'ip_address', id: '198.51.100.9' }] });
    if (value.includes('/contacted_urls?')) return json({
      data: [{ type: 'url', id: 'opaque-vt-id', attributes: { url: 'https://example.org/payload' } }],
      links: { next: 'https://www.virustotal.com/api/v3/files/x/contacted_urls?cursor=do-not-follow' },
    });
    throw new Error('unexpected URL');
  }));

  assert.deepEqual(urls.map(url => new URL(url).pathname), [
    `/api/v3/files/${hash}/contacted_domains`,
    `/api/v3/files/${hash}/contacted_ips`,
    `/api/v3/files/${hash}/contacted_urls`,
  ]);
  assert.equal(urls.every(url => new URL(url).searchParams.get('limit') === '20'), true);
  assert.equal(urls.every(url => !new URL(url).searchParams.has('cursor')), true);
  assert.deepEqual(result.relationships, [
    { targetType: 'domain', target: 'example.org', relationship: 'contacted_domain' },
    { targetType: 'ip', target: '198.51.100.9', relationship: 'contacted_ip' },
    { targetType: 'url', target: 'https://example.org/payload', relationship: 'contacted_url' },
  ]);
});

test('VirusTotal graph treats 404 as neutral absence but never converts 403 into negative evidence', async () => {
  const missing = await virustotalGraphProvider.run({ type: 'domain', value: 'example.com' }, context(async () => json({ error: { code: 'NotFoundError' } }, 404)));
  assert.equal(missing.verdict, 'no_result');
  assert.deepEqual(missing.relationships, []);

  await assert.rejects(
    virustotalGraphProvider.run({ type: 'domain', value: 'example.com' }, context(async () => json({ error: { code: 'ForbiddenError' } }, 403))),
    error => error?.status === 403,
  );
});
