import test from 'node:test';
import assert from 'node:assert/strict';
import { urlscanGraphProvider, urlscanProvider } from '../src/providers/urlscan.js';

function json(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
}

function context(fetchImpl) {
  return {
    env: { URLSCAN_API_KEY: 'test-key' },
    signal: new AbortController().signal,
    fetchImpl,
  };
}

const UUID = '0196d976-07f6-7aae-8a57-aa019145f31c';
const BODY_HASH = 'a'.repeat(64);
const DOWNLOAD_HASH = 'b'.repeat(64);
const CERT_HASH = 'c'.repeat(64);

test('urlscan deep result is a separate bounded graph capability and leaves search enrichment intact', () => {
  assert.equal(urlscanProvider.name, 'urlscan');
  assert.notEqual(urlscanProvider.mode, 'graph');
  assert.equal(urlscanGraphProvider.name, 'urlscan-graph');
  assert.equal(urlscanGraphProvider.mode, 'graph');
  assert.equal(urlscanGraphProvider.fanoutEligible, false);
  assert.deepEqual(urlscanGraphProvider.types, ['ip', 'domain', 'url']);
});

test('urlscan graph fetches one search page and one detail result then emits canonical bounded pivots', async () => {
  const calls = [];
  const result = await urlscanGraphProvider.run({ type: 'domain', value: 'example.com' }, context(async (url, options = {}) => {
    const value = String(url);
    calls.push({ value, options });
    if (value.startsWith('https://urlscan.io/api/v1/search?')) {
      return json({
        results: [
          { _id: UUID, page: { domain: 'example.com', url: 'https://example.com/' } },
          { _id: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', page: { domain: 'ignored.example', url: 'https://ignored.example/' } },
        ],
        has_more: true,
      });
    }
    if (value === `https://urlscan.io/api/v1/result/${UUID}/`) {
      return json({
        task: { uuid: UUID, url: 'http://example.com/start' },
        page: { url: 'https://final.example/path', domain: 'final.example', ip: '203.0.113.7' },
        data: {
          redirects: [
            { url: 'http://example.com/start', type: 'http' },
            { url: 'https://example.com/redirect', type: 'http' },
            { url: '<mark>https://evil.example/markup</mark>', type: 'client' },
            { url: 'https://final.example/path', type: 'client' },
          ],
        },
        lists: {
          domains: ['cdn.example.com', '<mark>bad.example</mark>', 'cdn.example.com'],
          ips: ['198.51.100.9', '<mark>198.51.100.10</mark>'],
          urls: ['https://cdn.example.com/a.js', '<mark>https://bad.example/x</mark>'],
          hashes: [BODY_HASH, `<mark>${'d'.repeat(64)}</mark>`],
          certificates: [
            { sha256: CERT_HASH },
            { sha256: `<mark>${'e'.repeat(64)}</mark>` },
          ],
        },
        meta: {
          processors: {
            download: { data: [{ url: 'https://final.example/payload', sha256: DOWNLOAD_HASH }] },
            wappa: { data: [{ app: 'nginx' }, { app: '<mark>bad-tech</mark>' }, { app: 'nginx' }] },
          },
        },
      });
    }
    throw new Error(`unexpected URL: ${value}`);
  }));

  assert.equal(calls.length, 2);
  assert.equal(new URL(calls[0].value).searchParams.get('size'), '5');
  assert.equal(new URL(calls[0].value).searchParams.has('search_after'), false);
  assert.equal(calls[0].options.headers['api-key'], 'test-key');
  assert.equal(calls[1].options.headers['api-key'], 'test-key');
  assert.deepEqual(result.relationships, [
    { targetType: 'url', target: 'https://final.example/path', relationship: 'final_destination' },
    { targetType: 'url', target: 'http://example.com/start', relationship: 'redirect_step' },
    { targetType: 'url', target: 'https://example.com/redirect', relationship: 'redirect_step' },
    { targetType: 'domain', target: 'cdn.example.com', relationship: 'request_host' },
    { targetType: 'ip', target: '198.51.100.9', relationship: 'contacted_ip' },
    { targetType: 'url', target: 'https://cdn.example.com/a.js', relationship: 'requested_url' },
    { targetType: 'hash', target: BODY_HASH, relationship: 'response_body_hash' },
    { targetType: 'certificate', target: `cert-sha256:${CERT_HASH}`, relationship: 'tls_certificate' },
    { targetType: 'hash', target: DOWNLOAD_HASH, relationship: 'downloaded_file' },
  ]);
  assert.deepEqual(result.attributes.technologies, ['nginx']);
  assert.equal(JSON.stringify(result).includes('<mark>'), false);
});

test('urlscan graph treats missing or deleted detail as neutral absence and never follows search pagination', async () => {
  for (const status of [404, 410]) {
    const calls = [];
    const result = await urlscanGraphProvider.run({ type: 'url', value: 'https://example.com/' }, context(async url => {
      const value = String(url);
      calls.push(value);
      if (value.startsWith('https://urlscan.io/api/v1/search?')) {
        return json({ results: [{ _id: UUID }], has_more: true, search_after: ['do-not-follow'] });
      }
      if (value === `https://urlscan.io/api/v1/result/${UUID}/`) return json({ message: 'not available' }, status);
      throw new Error(`unexpected URL: ${value}`);
    }));
    assert.equal(calls.length, 2);
    assert.equal(calls.some(value => value.includes('search_after=')), false);
    assert.equal(result.verdict, 'no_result');
    assert.deepEqual(result.relationships, []);
  }
});

test('urlscan graph rejects malformed successful detail schemas instead of manufacturing relationships', async () => {
  await assert.rejects(
    urlscanGraphProvider.run({ type: 'domain', value: 'example.com' }, context(async url => {
      const value = String(url);
      if (value.startsWith('https://urlscan.io/api/v1/search?')) return json({ results: [{ _id: UUID }] });
      return json({ lists: { domains: 'not-an-array' } });
    })),
    /provider_schema_invalid/,
  );
});
