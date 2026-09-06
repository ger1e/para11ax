import assert from 'node:assert/strict';
import test from 'node:test';

import { createGreyNoiseSwarmCommandHandler } from '../src/greynoise-swarm-command.js';

const TOKEN = 'gateway-token';
const KEY = 'greynoise-key';

function request(body, headers = {}) {
  return {
    method: 'POST',
    headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json', ...headers },
    body,
  };
}

function json(value, status = 200, headers = {}) {
  return new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json', ...headers } });
}

test('GreyNoise Swarm search is authenticated, fixed-destination and bounded', async () => {
  let captured;
  const handler = createGreyNoiseSwarmCommandHandler({
    env: { PARA11AX_TOKEN: TOKEN, GREYNOISE_API_KEY: KEY },
    fetchImpl: async (url, init) => {
      captured = { url: String(url), init };
      return json({ sessions: [{ id: 'session-1', sourceIP: '198.51.100.10' }], total: 1 });
    },
    nowMs: (() => { let value = 1000; return () => value += 5; })(),
  });

  const result = await handler(request({
    command: 'search', scope: 'workspace', startTime: '2026-09-05T00:00:00Z', endTime: '2026-09-06T00:00:00Z',
    query: 'classification:malicious', page: 1, pageSize: 50,
  }));

  assert.equal(result.status, 200);
  const url = new URL(captured.url);
  assert.equal(url.origin, 'https://api.greynoise.io');
  assert.equal(url.pathname, '/v3/sessions');
  assert.equal(url.searchParams.get('scope'), 'workspace');
  assert.equal(url.searchParams.get('start_time'), '2026-09-05T00:00:00Z');
  assert.equal(url.searchParams.get('end_time'), '2026-09-06T00:00:00Z');
  assert.equal(url.searchParams.get('query'), 'classification:malicious');
  assert.equal(url.searchParams.get('page_size'), '50');
  assert.equal(captured.init.headers.key, KEY);
  assert.equal(JSON.stringify(result.body).includes(KEY), false);
  assert.equal(result.body.source, 'greynoise-swarm');
  assert.equal(result.body.command, 'search');
});

test('GreyNoise Swarm get uses a single encoded session id and supports demo scope', async () => {
  let captured;
  const handler = createGreyNoiseSwarmCommandHandler({
    env: { PARA11AX_TOKEN: TOKEN, GREYNOISE_API_KEY: KEY },
    fetchImpl: async (url, init) => { captured = { url: String(url), init }; return json({ id: 'session-123', protocol: 'tcp' }); },
  });
  const result = await handler(request({ command: 'get', sessionId: 'session-123', scope: 'demo' }));
  assert.equal(result.status, 200);
  const url = new URL(captured.url);
  assert.equal(url.pathname, '/v3/sessions/session-123');
  assert.equal(url.searchParams.get('scope'), 'demo');
  assert.equal(result.body.command, 'get');
});

test('GreyNoise Swarm export rejects demo before egress and returns bounded binary for workspace', async () => {
  let calls = 0;
  const handler = createGreyNoiseSwarmCommandHandler({
    env: { PARA11AX_TOKEN: TOKEN, GREYNOISE_API_KEY: KEY },
    fetchImpl: async () => { calls += 1; return new Response(new Uint8Array([1, 2, 3]), { status: 200, headers: { 'content-type': 'application/octet-stream' } }); },
  });
  const denied = await handler(request({ command: 'export', sessionId: 'session-123', scope: 'demo', exportType: 'pcap' }));
  assert.equal(denied.status, 400);
  assert.equal(denied.body.error, 'swarm_demo_export_unsupported');
  assert.equal(calls, 0);

  const allowed = await handler(request({ command: 'export', sessionId: 'session-123', scope: 'workspace', exportType: 'rawSource' }));
  assert.equal(allowed.status, 200);
  assert.equal(calls, 1);
  assert.equal(allowed.binary, true);
  assert.deepEqual([...allowed.body], [1, 2, 3]);
  assert.match(allowed.headers['content-disposition'], /session-123-raw-source\.bin/);
});

test('GreyNoise Swarm workspace diff uses fixed POST egress and bounded aliases', async () => {
  let captured;
  let calls = 0;
  const handler = createGreyNoiseSwarmCommandHandler({
    env: { PARA11AX_TOKEN: TOKEN, GREYNOISE_API_KEY: KEY },
    fetchImpl: async (url, init) => {
      calls += 1;
      captured = { url: String(url), init };
      return json({ ips: [{ ip: '198.51.100.10', source: true, target: false }], next_token: 'next-1' });
    },
  });
  const result = await handler(request({
    command: 'diff', query: 'classification:malicious', sourceWorkspace: 'personal', targetWorkspace: 'greynoise',
    mode: 'source-only', size: 25, nextToken: 'token-1',
  }));
  assert.equal(result.status, 200);
  assert.equal(calls, 1);
  const url = new URL(captured.url);
  assert.equal(url.origin, 'https://api.greynoise.io');
  assert.equal(url.pathname, '/v3/workspaces/diff');
  assert.equal(url.search, '');
  assert.equal(captured.init.method, 'POST');
  assert.equal(captured.init.headers.key, KEY);
  assert.equal(captured.init.headers['content-type'], 'application/json');
  assert.deepEqual(JSON.parse(captured.init.body), {
    query: 'classification:malicious', source_workspace: 'personal', target_workspace: 'greynoise', size: 25,
    next_token: 'token-1', ips_from_source: true, require_both_workspaces: false,
  });
  assert.equal(result.body.command, 'diff');
  assert.equal(JSON.stringify(result.body).includes(KEY), false);
});

test('GreyNoise Swarm workspace diff rejects unsafe workspace and mode requests before egress', async () => {
  let calls = 0;
  const handler = createGreyNoiseSwarmCommandHandler({
    env: { PARA11AX_TOKEN: TOKEN, GREYNOISE_API_KEY: KEY },
    fetchImpl: async () => { calls += 1; return json({}); },
  });
  const cases = [
    { command: 'diff', query: '', sourceWorkspace: 'personal', targetWorkspace: 'greynoise' },
    { command: 'diff', query: 'classification:malicious', sourceWorkspace: '11111111-1111-1111-1111-111111111111', targetWorkspace: 'greynoise' },
    { command: 'diff', query: 'classification:malicious', sourceWorkspace: 'personal', targetWorkspace: 'personal' },
    { command: 'diff', query: 'classification:malicious', sourceWorkspace: 'personal', targetWorkspace: 'greynoise', mode: 'sideways' },
    { command: 'diff', query: 'classification:malicious', sourceWorkspace: 'personal', targetWorkspace: 'greynoise', size: 101 },
    { command: 'diff', query: 'classification:malicious', sourceWorkspace: 'personal', targetWorkspace: 'greynoise', unexpected: true },
  ];
  for (const body of cases) {
    const result = await handler(request(body));
    assert.equal(result.status, 400);
  }
  assert.equal(calls, 0);
});

test('GreyNoise Swarm rejects unsafe request shapes before upstream work', async () => {
  let calls = 0;
  const handler = createGreyNoiseSwarmCommandHandler({
    env: { PARA11AX_TOKEN: TOKEN, GREYNOISE_API_KEY: KEY },
    fetchImpl: async () => { calls += 1; return json({}); },
  });
  const cases = [
    { command: 'search', scope: 'workspace', startTime: 'not-a-date', endTime: '2026-09-06T00:00:00Z' },
    { command: 'search', scope: 'workspace', startTime: '2026-09-06T00:00:00Z', endTime: '2026-09-05T00:00:00Z' },
    { command: 'get', sessionId: '../escape', scope: 'workspace' },
    { command: 'search', scope: 'workspace', startTime: '2026-09-05T00:00:00Z', endTime: '2026-09-06T00:00:00Z', pageSize: 101 },
    { command: 'get', sessionId: 'session-1', scope: 'workspace', unexpected: true },
  ];
  for (const body of cases) {
    const result = await handler(request(body));
    assert.equal(result.status, 400);
  }
  assert.equal(calls, 0);
});
