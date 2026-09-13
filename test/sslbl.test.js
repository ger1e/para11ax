import test from 'node:test';
import assert from 'node:assert/strict';
import { sslblProvider } from '../src/providers/sslbl.js';

const JA3 = '72a589da586844d7f0818ce684948eea';

function response(text, status = 200) {
  return new Response(text, { status, headers: { 'content-type': 'text/csv' } });
}

test('SSLBL performs one bounded passive JA3 blacklist lookup', async () => {
  const calls = [];
  const out = await sslblProvider.run({ type: 'tls-fingerprint', value: `ja3:${JA3}` }, {
    fetchImpl: async (url, options) => {
      calls.push([String(url), options]);
      return response(`# abuse.ch SSLBL JA3\n${JA3},2026-09-01 00:00:00,2026-09-12 00:00:00,Example malware C2\n`);
    },
    feedCache: new Map(),
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], 'https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv');
  assert.equal(calls[0][1].method, 'GET');
  assert.equal(out.observationType, 'tls_malware_infrastructure');
  assert.equal(out.verdict, 'listed');
  assert.equal(out.attributes.fingerprint, JA3);
  assert.equal(out.attributes.listingReason, 'Example malware C2');
  assert.deepEqual(out.relationships, []);
});

test('SSLBL absence remains contextual not-listed evidence', async () => {
  const out = await sslblProvider.run({ type: 'tls-fingerprint', value: `ja3:${JA3}` }, {
    fetchImpl: async () => response('# abuse.ch SSLBL JA3\n'),
    feedCache: new Map(),
  });
  assert.equal(out.verdict, 'not_listed');
  assert.equal(out.attributes.listed, false);
  assert.deepEqual(out.relationships, []);
});

test('SSLBL malformed successful feed fails closed', async () => {
  await assert.rejects(
    () => sslblProvider.run({ type: 'tls-fingerprint', value: `ja3:${JA3}` }, {
      fetchImpl: async () => response('not,a,valid,row\n'),
      feedCache: new Map(),
    }),
    /invalid SSLBL JA3 feed/,
  );
});

test('SSLBL rejects unsupported TLS fingerprint families before egress', async () => {
  let called = false;
  await assert.rejects(
    () => sslblProvider.run({ type: 'tls-fingerprint', value: `ja4:${'a'.repeat(36)}` }, { fetchImpl: async () => { called = true; } }),
    /unsupported/i,
  );
  assert.equal(called, false);
});
