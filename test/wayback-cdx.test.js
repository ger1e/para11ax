import test from 'node:test';
import assert from 'node:assert/strict';
import { waybackCdxProvider } from '../src/providers/wayback-cdx.js';

test('Wayback CDX uses one bounded historical lookup and preserves captures as context only', async () => {
  const calls = [];
  const out = await waybackCdxProvider.run({ type: 'domain', value: 'example.com' }, {
    fetchImpl: async (url, options) => {
      calls.push([String(url), options]);
      return new Response(JSON.stringify([
        ['timestamp', 'original', 'statuscode', 'digest'],
        ['20250101000000', 'https://example.com/', '200', 'ABC'],
        ['20260101000000', 'https://example.com/login', '200', 'DEF'],
      ]), { status: 200, headers: { 'content-type': 'application/json' } });
    },
  });
  assert.equal(calls.length, 1);
  const url = new URL(calls[0][0]);
  assert.equal(url.origin, 'https://web.archive.org');
  assert.equal(url.pathname, '/cdx/search/cdx');
  assert.equal(url.searchParams.get('output'), 'json');
  assert.equal(url.searchParams.get('limit'), '25');
  assert.equal(url.searchParams.get('filter'), 'statuscode:200');
  assert.equal(url.searchParams.get('collapse'), 'digest');
  assert.equal(out.observationType, 'web_archive_observation');
  assert.equal(out.verdict, 'observed');
  assert.equal(out.attributes.captureCount, 2);
  assert.deepEqual(out.relationships.map(item => item.target), ['https://example.com/', 'https://example.com/login']);
});

test('Wayback historical presence is never emitted as reputation evidence', () => {
  assert.deepEqual(waybackCdxProvider.types, ['domain', 'url']);
});
