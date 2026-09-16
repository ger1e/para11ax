import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';

import { shadowserverProvider } from '../src/providers/shadowserver.js';

const API_URL = 'https://transform.shadowserver.org/api2/reports/query';

function json(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

const env = {
  SHADOWSERVER_API_KEY: 'shadow-key',
  SHADOWSERVER_API_SECRET: 'shadow-secret',
};

test('Shadowserver performs a bounded signed passive reports query', async () => {
  let called = 0;
  const output = await shadowserverProvider.run({ type: 'ip', value: '192.0.2.25' }, {
    env,
    fetchImpl: async (url, init) => {
      called += 1;
      assert.equal(String(url), API_URL);
      assert.equal(init.method, 'POST');
      assert.equal(init.redirect, 'error');
      const headers = new Headers(init.headers);
      assert.equal(headers.get('content-type'), 'application/json');
      const body = JSON.parse(init.body);
      assert.deepEqual(body, {
        query: { ip: '192.0.2.25' },
        sort: 'descending',
        date: '-1:now',
        limit: 100,
        page: 1,
        apikey: 'shadow-key',
      });
      assert.equal(
        headers.get('hmac2'),
        createHmac('sha256', 'shadow-secret').update(init.body).digest('hex'),
      );
      assert.equal('scan' in body, false);
      assert.equal('target' in body, false);
      return json([
        {
          timestamp: '2026-09-13 11:00:00',
          ip: '192.0.2.25',
          port: '443',
          protocol: 'tcp',
          type: 'scan',
          tag: ['ssl'],
          severity: 'info',
          infection: 'ssl',
          domain: 'host.example.com',
          asn: '64500',
        },
        {
          timestamp: '2026-09-13 12:00:00',
          ip: '192.0.2.25',
          port: '22',
          protocol: 'tcp',
          type: 'scan',
          tag: ['ssh'],
          severity: 'info',
          infection: 'ssh',
          asn: '64500',
        },
      ]);
    },
  });

  assert.equal(called, 1);
  assert.equal(output.observationType, 'internet_exposure');
  assert.equal(output.verdict, 'observed');
  assert.equal(output.confidence, null);
  assert.equal(output.firstSeen, '2026-09-13 11:00:00');
  assert.equal(output.lastSeen, '2026-09-13 12:00:00');
  assert.equal(output.attributes.eventCount, 2);
  assert.equal(output.attributes.events.length, 2);
  assert.equal(output.attributes.events[0].ip, '192.0.2.25');
  assert.equal(output.relationships.length <= 32, true);
  assert.deepEqual(output.references, ['https://www.shadowserver.org/what-we-do/network-reporting/api-reports-query/']);
  assert.notEqual(output.verdict, 'malicious');
  assert.notEqual(output.verdict, 'clean');
});

test('Shadowserver maps an empty result to no_result rather than safe', async () => {
  const output = await shadowserverProvider.run({ type: 'ip', value: '192.0.2.25' }, {
    env,
    fetchImpl: async () => json([]),
  });
  assert.equal(output.verdict, 'no_result');
  assert.equal(output.confidence, null);
  assert.equal(output.attributes.eventCount, 0);
});

test('Shadowserver fails closed on missing credentials before network execution', async () => {
  let called = false;
  await assert.rejects(
    shadowserverProvider.run({ type: 'ip', value: '192.0.2.25' }, {
      env: { SHADOWSERVER_API_KEY: 'shadow-key' },
      fetchImpl: async () => { called = true; return json([]); },
    }),
    /not configured/i,
  );
  assert.equal(called, false);
});

test('Shadowserver rejects malformed or oversized successful responses', async () => {
  await assert.rejects(
    shadowserverProvider.run({ type: 'ip', value: '192.0.2.25' }, { env, fetchImpl: async () => json({ rows: [] }) }),
    /provider_schema_invalid/,
  );
  await assert.rejects(
    shadowserverProvider.run({ type: 'ip', value: '192.0.2.25' }, { env, fetchImpl: async () => json(Array.from({ length: 101 }, () => ({ ip: '192.0.2.25' }))) }),
    /provider_schema_invalid/,
  );
});

test('Shadowserver accepts only passive asset observable types', async () => {
  await assert.rejects(
    shadowserverProvider.run({ type: 'hash', value: 'a'.repeat(64) }, { env, fetchImpl: async () => json([]) }),
    /unsupported Shadowserver input/,
  );
});
