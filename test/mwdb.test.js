import test from 'node:test';
import assert from 'node:assert/strict';
import { mwdbProvider } from '../src/providers/mwdb.js';

const HASH = 'cea813cbef6581e0c95aacb2e747f5951325444b941e801164154917a17bfe71';

test('MWDB reads one file and one attached config and emits bounded C2 relationships', async () => {
  const calls = [];
  const out = await mwdbProvider.run({ type: 'hash', value: HASH }, {
    env: { MWDB_API_TOKEN: 'test-token' },
    fetchImpl: async (url, options) => {
      calls.push([String(url), options]);
      if (String(url).endsWith(`/api/file/${HASH}`)) {
        return new Response(JSON.stringify({ id: HASH, sha256: HASH, type: 'file', tags: [{ tag: 'ripped:example' }], latest_config: 'cfg123' }), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      if (String(url).endsWith('/api/config/cfg123')) {
        return new Response(JSON.stringify({ id: 'cfg123', type: 'config', family: 'example', config: { c2: [{ host: 'c2.example.com' }, { host: '203.0.113.9' }] } }), { status: 200, headers: { 'content-type': 'application/json' } });
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

test('MWDB hash lookup is read-only and fixed-destination', () => {
  assert.deepEqual(mwdbProvider.types, ['hash']);
  assert.equal(mwdbProvider.parserVersion.startsWith('mwdb-'), true);
});
