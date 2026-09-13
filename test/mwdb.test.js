import test from 'node:test';
import assert from 'node:assert/strict';
import { mwdbProvider } from '../src/providers/mwdb.js';

const HASH = 'cea813cbef6581e0c95aacb2e747f5951325444b941e801164154917a17bfe71';

function jsonResponse(body, status = 200) {
  return new Response(body === null ? '' : JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

test('MWDB reads one file and one attached config and emits bounded C2 relationships', async () => {
  const calls = [];
  const out = await mwdbProvider.run({ type: 'hash', value: HASH }, {
    env: { MWDB_API_TOKEN: 'test-token' },
    fetchImpl: async (url, options) => {
      calls.push([String(url), options]);
      if (String(url).endsWith(`/api/file/${HASH}`)) {
        return jsonResponse({ id: HASH, sha256: HASH, type: 'file', tags: [{ tag: 'ripped:example' }], latest_config: 'cfg123' });
      }
      if (String(url).endsWith('/api/config/cfg123')) {
        return jsonResponse({ id: 'cfg123', type: 'config', family: 'example', config: { c2: [{ host: 'c2.example.com' }, { host: '203.0.113.9' }] } });
      }
      throw new Error('unexpected URL');
    },
  });
  assert.equal(calls.length, 2);
  assert.ok(calls.every(([, options]) => options.headers.Authorization === 'Bearer test-token'));
  assert.equal(out.observationType, 'malware_configuration');
  assert.equal(out.verdict, 'observed');
  assert.deepEqual(out.relationships, [
    { targetType: 'domain', target: 'c2.example.com', relationship: 'malware_config_c2' },
    { targetType: 'ip', target: '203.0.113.9', relationship: 'malware_config_c2' },
  ]);
});

test('MWDB unknown hash is neutral absence, not provider failure', async () => {
  const out = await mwdbProvider.run({ type: 'hash', value: HASH }, {
    env: { MWDB_API_TOKEN: 'test-token' },
    fetchImpl: async () => jsonResponse({ error: 'not found' }, 404),
  });
  assert.equal(out.verdict, 'not_found');
  assert.deepEqual(out.relationships, []);
});

test('MWDB malformed successful file schema fails closed', async () => {
  await assert.rejects(
    () => mwdbProvider.run({ type: 'hash', value: HASH }, {
      env: { MWDB_API_TOKEN: 'test-token' },
      fetchImpl: async () => jsonResponse({ type: 'file' }),
    }),
    /provider_schema_invalid/,
  );
});

test('MWDB hash lookup is read-only and fixed-destination', () => {
  assert.deepEqual(mwdbProvider.types, ['hash']);
  assert.equal(mwdbProvider.parserVersion.startsWith('mwdb-'), true);
  assert.equal(Object.hasOwn(mwdbProvider, 'submit'), false);
});
