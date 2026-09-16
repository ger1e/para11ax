import test from 'node:test';
import assert from 'node:assert/strict';
import { yaraifyProvider } from '../src/providers/yaraify.js';

const HASH = 'de7fa65d5cd5314ba0ce6ab19a7dcd9853639a1152447457de7efb39a9ba1f46';

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

test('YARAify uses lookup_hash only and emits bounded malware similarity context', async () => {
  const calls = [];
  const out = await yaraifyProvider.run({ type: 'hash', value: HASH }, {
    env: { ABUSECH_API_KEY: 'test-key' },
    fetchImpl: async (url, options) => {
      calls.push([String(url), options]);
      return jsonResponse({
        query_status: 'ok',
        data: {
          metadata: { sha256_hash: HASH, md5_hash: 'b0bb095dd0ad8b8de1c83b13c38e68dd', sightings: 11 },
          yara_rules: [{ rule_name: 'MALWARE_Win_Example' }, { rule_name: 'MALWARE_Win_Example' }],
        },
      });
    },
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], 'https://yaraify-api.abuse.ch/api/v1/');
  assert.equal(calls[0][1].method, 'POST');
  assert.equal(calls[0][1].headers['Auth-Key'], 'test-key');
  assert.deepEqual(JSON.parse(calls[0][1].body), { query: 'lookup_hash', search_term: HASH });
  assert.equal(out.observationType, 'malware_similarity');
  assert.equal(out.verdict, 'observed');
  assert.deepEqual(out.attributes.yaraRules, ['MALWARE_Win_Example']);
  assert.deepEqual(out.relationships, []);
});

test('YARAify documented no-result remains no-result context', async () => {
  const out = await yaraifyProvider.run({ type: 'hash', value: HASH }, {
    env: { ABUSECH_API_KEY: 'test-key' },
    fetchImpl: async () => jsonResponse({ query_status: 'hash_not_found' }),
  });
  assert.equal(out.verdict, 'not_found');
  assert.deepEqual(out.attributes.yaraRules, []);
  assert.deepEqual(out.relationships, []);
});

test('YARAify malformed successful schema fails closed', async () => {
  await assert.rejects(
    () => yaraifyProvider.run({ type: 'hash', value: HASH }, {
      env: { ABUSECH_API_KEY: 'test-key' },
      fetchImpl: async () => jsonResponse({ query_status: 'ok', data: [] }),
    }),
    /provider_schema_invalid/,
  );
});

test('YARAify never exposes active scan or rescan operations', () => {
  assert.deepEqual(yaraifyProvider.types, ['hash']);
  assert.equal(Object.hasOwn(yaraifyProvider, 'submit'), false);
});
