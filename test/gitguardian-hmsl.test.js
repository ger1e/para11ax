import test from 'node:test';
import assert from 'node:assert/strict';
import { gitguardianHmslProvider } from '../src/providers/gitguardian-hmsl.js';

const HASH = '743d9fde380b7064cc6a8d3071184fc47905cf7440e5615cd46c7b6cbfb46d47';
const FINGERPRINT = `hmsl-sha256:${HASH}`;

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

test('GitGuardian HMSL queries only a privacy-preserving full fingerprint', async () => {
  const calls = [];
  const out = await gitguardianHmslProvider.run({ type: 'secret-fingerprint', value: FINGERPRINT }, {
    fetchImpl: async (url, options) => {
      calls.push([String(url), options]);
      return jsonResponse({ secrets: [{ hash: HASH, count: 7, location: null }] });
    },
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], 'https://api.hasmysecretleaked.com/v1/hashes');
  assert.equal(calls[0][1].method, 'POST');
  assert.deepEqual(JSON.parse(calls[0][1].body), { hashes: [HASH] });
  assert.equal(out.observationType, 'secret_exposure');
  assert.equal(out.verdict, 'observed');
  assert.equal(out.attributes.matched, true);
  assert.equal(out.attributes.exposureCount, 7);
  assert.equal(JSON.stringify(out).includes(HASH), false);
  assert.deepEqual(out.relationships, []);
});

test('GitGuardian HMSL rejects raw-secret-shaped values before egress', async () => {
  let called = false;
  await assert.rejects(
    () => gitguardianHmslProvider.run({ type: 'secret-fingerprint', value: 'github_pat_plaintext_secret' }, {
      fetchImpl: async () => { called = true; },
    }),
    /unsupported/i,
  );
  assert.equal(called, false);
  assert.equal(Object.hasOwn(gitguardianHmslProvider, 'scan'), false);
  assert.equal(Object.hasOwn(gitguardianHmslProvider, 'submit'), false);
});

test('GitGuardian HMSL no match is neutral absence and malformed success fails closed', async () => {
  const empty = await gitguardianHmslProvider.run({ type: 'secret-fingerprint', value: FINGERPRINT }, {
    fetchImpl: async () => jsonResponse({ secrets: [] }),
  });
  assert.equal(empty.verdict, 'not_found');
  assert.equal(empty.attributes.matched, false);
  await assert.rejects(
    () => gitguardianHmslProvider.run({ type: 'secret-fingerprint', value: FINGERPRINT }, { fetchImpl: async () => jsonResponse({ secrets: 'oops' }) }),
    /provider_schema_invalid/,
  );
});
