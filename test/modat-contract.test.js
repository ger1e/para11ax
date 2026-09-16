import test from 'node:test';
import assert from 'node:assert/strict';
import { modatProvider } from '../src/providers/modat.js';

function json(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
}

test('Modat host 404 is neutral absence rather than provider failure', async () => {
  const output = await modatProvider.run(
    { type: 'ip', value: '192.0.2.44' },
    {
      env: { MODAT_API_KEY: 'test-key' },
      fetchImpl: async () => json({ detail: 'Not Found' }, 404),
    },
  );
  assert.equal(output.observationType, 'internet_exposure');
  assert.equal(output.verdict, 'no_result');
  assert.equal(output.attributes.ip, '192.0.2.44');
  assert.equal(output.attributes.serviceCount, 0);
});

test('Modat DNS-zone 404 is neutral absence rather than provider failure', async () => {
  const output = await modatProvider.run(
    { type: 'domain', value: 'missing.example' },
    {
      env: { MODAT_API_KEY: 'test-key' },
      fetchImpl: async () => json({ detail: 'Not Found' }, 404),
    },
  );
  assert.equal(output.observationType, 'passive_dns');
  assert.equal(output.verdict, 'no_result');
  assert.equal(output.attributes.fqdn, 'missing.example');
  assert.equal(output.attributes.addressCount, 0);
});
