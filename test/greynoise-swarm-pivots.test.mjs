import test from 'node:test';
import assert from 'node:assert/strict';

import { createGatewayClient } from '../app/api-client.js';
import { createGreyNoiseSwarmCommandHandler } from '../src/greynoise-swarm-command.js';
import { parseSwarmArgs } from '../app/swarm-command.js';

const ENV = { PARA11AX_TOKEN: 'token', GREYNOISE_API_KEY: 'gn-key' };
const FROM = '2026-09-05T00:00:00Z';
const TO = '2026-09-06T00:00:00Z';

function request(body) {
  return {
    method: 'POST',
    headers: { authorization: 'Bearer token', 'content-type': 'application/json' },
    body,
  };
}

function jsonUpstream(body) {
  const bytes = new TextEncoder().encode(JSON.stringify(body));
  return {
    ok: true,
    status: 200,
    headers: new Headers({ 'content-type': 'application/json', 'content-length': String(bytes.byteLength) }),
    arrayBuffer: async () => bytes.buffer,
  };
}

test('parseSwarmArgs accepts bounded unique pivot', () => {
  assert.deepEqual(
    parseSwarmArgs(['unique', '--from', FROM, '--to', TO, '--field', 'source.ip', '--include-counts']),
    {
      command: 'unique', sessionId: null, scope: 'workspace', startTime: FROM, endTime: TO,
      query: null, page: null, pageSize: null, exportType: null,
      field: 'source.ip', includeCounts: true, interval: null, size: null,
    },
  );
});

test('parseSwarmArgs accepts bounded timeseries pivot', () => {
  assert.deepEqual(
    parseSwarmArgs(['timeseries', '--from', FROM, '--to', TO, '--field', 'classification', '--size', '20', '--interval', '1h']),
    {
      command: 'timeseries', sessionId: null, scope: 'workspace', startTime: FROM, endTime: TO,
      query: null, page: null, pageSize: null, exportType: null,
      field: 'classification', includeCounts: null, interval: '1h', size: 20,
    },
  );
});

test('Swarm pivots reject non-whitelisted fields before egress', async () => {
  let calls = 0;
  const handle = createGreyNoiseSwarmCommandHandler({ env: ENV, fetchImpl: async () => { calls += 1; return jsonUpstream({}); } });
  const response = await handle(request({ command: 'unique', scope: 'workspace', startTime: FROM, endTime: TO, field: 'srcPayload8' }));
  assert.equal(response.status, 400);
  assert.equal(response.body.error, 'invalid_swarm_field');
  assert.equal(calls, 0);
});

test('unique maps to the fixed GreyNoise unique endpoint', async () => {
  let seen;
  const handle = createGreyNoiseSwarmCommandHandler({ env: ENV, fetchImpl: async (url, init) => {
    seen = { url: new URL(url), init };
    return jsonUpstream({ values: [{ value: '1.2.3.4', count: 4 }] });
  } });
  const response = await handle(request({ command: 'unique', scope: 'workspace', startTime: FROM, endTime: TO, field: 'source.ip', includeCounts: true }));
  assert.equal(response.status, 200);
  assert.equal(seen.url.origin, 'https://api.greynoise.io');
  assert.equal(seen.url.pathname, '/v3/sessions/unique');
  assert.equal(seen.url.searchParams.get('field'), 'source.ip');
  assert.equal(seen.url.searchParams.get('include_counts'), 'true');
  assert.equal(seen.init.headers.key, 'gn-key');
  assert.equal(response.body.command, 'unique');
});

test('timeseries maps bounded grouping options to the fixed GreyNoise endpoint', async () => {
  let seen;
  const handle = createGreyNoiseSwarmCommandHandler({ env: ENV, fetchImpl: async (url) => {
    seen = new URL(url);
    return jsonUpstream({ buckets: [] });
  } });
  const response = await handle(request({ command: 'timeseries', scope: 'demo', startTime: FROM, endTime: TO, field: 'classification', size: 100, interval: '1d' }));
  assert.equal(response.status, 200);
  assert.equal(seen.pathname, '/v3/sessions/timeseries');
  assert.equal(seen.searchParams.get('scope'), 'demo');
  assert.equal(seen.searchParams.get('field'), 'classification');
  assert.equal(seen.searchParams.get('size'), '100');
  assert.equal(seen.searchParams.get('interval'), '1d');
});

test('timeseries rejects oversized groups and unsupported interval before egress', async () => {
  let calls = 0;
  const handle = createGreyNoiseSwarmCommandHandler({ env: ENV, fetchImpl: async () => { calls += 1; return jsonUpstream({}); } });
  const large = await handle(request({ command: 'timeseries', scope: 'workspace', startTime: FROM, endTime: TO, size: 101, interval: '1h' }));
  assert.equal(large.status, 400);
  assert.equal(large.body.error, 'invalid_swarm_size');
  const interval = await handle(request({ command: 'timeseries', scope: 'workspace', startTime: FROM, endTime: TO, size: 10, interval: '5m' }));
  assert.equal(interval.status, 400);
  assert.equal(interval.body.error, 'invalid_swarm_interval');
  assert.equal(calls, 0);
});

test('browser client forwards only bounded Swarm pivot payloads to the same-origin route', async () => {
  const bodies = [];
  const client = createGatewayClient({
    getToken: () => 'bearer-secret',
    fetchImpl: async (path, init) => {
      assert.equal(path, '/api/para11ax/swarm');
      bodies.push(JSON.parse(init.body));
      const command = bodies.at(-1).command;
      return new Response(JSON.stringify({
        requestId: `r-${command}`,
        source: 'greynoise-swarm',
        command,
        input: bodies.at(-1),
        data: command === 'unique' ? [{ value: '1.2.3.4', count: 2 }] : { buckets: [] },
        durationMs: 1,
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    },
  });

  const unique = await client.swarm({ command: 'unique', scope: 'workspace', startTime: FROM, endTime: TO, field: 'source.ip', includeCounts: true });
  assert.equal(unique.command, 'unique');
  assert.deepEqual(bodies[0], { command: 'unique', scope: 'workspace', startTime: FROM, endTime: TO, field: 'source.ip', includeCounts: true });

  const timeseries = await client.swarm({ command: 'timeseries', scope: 'demo', startTime: FROM, endTime: TO, field: 'classification', size: 20, interval: '1h' });
  assert.equal(timeseries.command, 'timeseries');
  assert.deepEqual(bodies[1], { command: 'timeseries', scope: 'demo', startTime: FROM, endTime: TO, field: 'classification', size: 20, interval: '1h' });

  await assert.rejects(
    client.swarm({ command: 'unique', scope: 'workspace', startTime: FROM, endTime: TO, field: 'srcPayload8' }),
    /invalid Swarm field/,
  );
  assert.equal(bodies.length, 2);
});
