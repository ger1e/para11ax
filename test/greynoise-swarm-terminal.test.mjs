import assert from 'node:assert/strict';
import test from 'node:test';

import { createGatewayClient } from '../app/api-client.js';
import { createBrowserShellExecutor } from '../app/shell-browser-executor.js';
import { COMMAND_DESCRIPTORS } from '../app/shell-core/catalog.js';
import { parseSwarmArgs } from '../app/swarm-command.js';

const descriptor = COMMAND_DESCRIPTORS.find(item => item.id === 'osint.greynoise-swarm');
const captureOperatorDescriptor = COMMAND_DESCRIPTORS.find(item => item.id === 'investigation.capture-operator');

test('terminal exposes a bounded GreyNoise Swarm session surface', () => {
  assert.ok(descriptor);
  assert.deepEqual(descriptor.tokens, ['swarm']);
  assert.deepEqual(descriptor.surfaces, ['web']);
  assert.equal(descriptor.auth, 'required');
  assert.equal(descriptor.egressClass, 'gateway');
  assert.equal(descriptor.handler, 'swarm');
  assert.deepEqual(descriptor.completion.values, ['search', 'get', 'export', 'unique', 'timeseries', 'diff']);

  assert.deepEqual(
    parseSwarmArgs(['get', 'session-123', '--scope', 'demo']),
    { command: 'get', sessionId: 'session-123', scope: 'demo', startTime: null, endTime: null, query: null, page: null, pageSize: null, exportType: null },
  );
  assert.deepEqual(
    parseSwarmArgs(['search', '--from', '2026-09-05T00:00:00Z', '--to', '2026-09-06T00:00:00Z', '--scope', 'workspace', '--query', 'classification:malicious', '--page-size', '50']),
    { command: 'search', sessionId: null, scope: 'workspace', startTime: '2026-09-05T00:00:00Z', endTime: '2026-09-06T00:00:00Z', query: 'classification:malicious', page: 1, pageSize: 50, exportType: null },
  );
  assert.deepEqual(
    parseSwarmArgs(['export', 'session-123', 'raw-source']),
    { command: 'export', sessionId: 'session-123', scope: 'workspace', startTime: null, endTime: null, query: null, page: null, pageSize: null, exportType: 'rawSource' },
  );
  assert.throws(() => parseSwarmArgs(['export', '../escape', 'pcap']));
});

test('Swarm diff defaults to personal-to-greynoise source-only and validates aliases', () => {
  assert.deepEqual(
    parseSwarmArgs(['diff', '--query', 'classification:malicious']),
    {
      command: 'diff', query: 'classification:malicious', sourceWorkspace: 'personal', targetWorkspace: 'greynoise',
      mode: 'source-only', size: 10, nextToken: null,
    },
  );
  assert.deepEqual(
    parseSwarmArgs(['diff', '--query', 'last_seen:1d', '--source', 'community', '--target', 'personal', '--mode', 'both', '--size', '50', '--next-token', 'opaque-token']),
    {
      command: 'diff', query: 'last_seen:1d', sourceWorkspace: 'community', targetWorkspace: 'personal',
      mode: 'both', size: 50, nextToken: 'opaque-token',
    },
  );
  assert.throws(() => parseSwarmArgs(['diff', '--query', 'classification:malicious', '--source', '11111111-1111-1111-1111-111111111111']));
  assert.throws(() => parseSwarmArgs(['diff', '--query', 'classification:malicious', '--source', 'personal', '--target', 'personal']));
  assert.throws(() => parseSwarmArgs(['diff', '--query', 'classification:malicious', '--size', '101']));
});

test('browser executor delegates Swarm search and explicitly downloads one export', async () => {
  const calls = [];
  const downloads = [];
  const executor = createBrowserShellExecutor({
    client: {
      swarm: async input => {
        calls.push(input);
        if (input.command === 'export') return {
          requestId: 'r2', source: 'greynoise-swarm', command: 'export', input: { scope: 'workspace', sessionId: input.sessionId },
          exportType: input.exportType, filename: `${input.sessionId}.pcap`, mediaType: 'application/octet-stream', bytes: 3, durationMs: 1,
          data: new Uint8Array([1, 2, 3]),
        };
        return { requestId: 'r1', source: 'greynoise-swarm', command: 'search', input, data: { sessions: [] }, durationMs: 1 };
      },
    },
    session: {},
    downloads: { save: (...args) => downloads.push(args) },
  });

  const search = await executor.execute({
    descriptor,
    args: ['search', '--from', '2026-09-05T00:00:00Z', '--to', '2026-09-06T00:00:00Z'],
    context: { surface: 'web' },
  });
  assert.equal(search.type, 'record');
  assert.equal(search.value.command, 'search');

  const exported = await executor.execute({ descriptor, args: ['export', 'session-123', 'pcap'], context: { surface: 'web' } });
  assert.equal(exported.type, 'record');
  assert.equal(exported.value.command, 'export');
  assert.equal(Object.hasOwn(exported.value, 'data'), false);
  assert.equal(downloads.length, 1);
  assert.deepEqual([...downloads[0][0]], [1, 2, 3]);
  assert.equal(downloads[0][2], 'session-123.pcap');
  assert.equal(calls.length, 2);
});

test('Swarm read results become capturable investigation operator context while exports do not replace them', async () => {
  const captured = [];
  const executor = createBrowserShellExecutor({
    client: {
      swarm: async input => {
        if (input.command === 'export') return {
          requestId: 'r2', source: 'greynoise-swarm', command: 'export', input: { scope: 'workspace', sessionId: input.sessionId },
          exportType: input.exportType, filename: `${input.sessionId}.pcap`, mediaType: 'application/octet-stream', bytes: 1, durationMs: 1,
          data: new Uint8Array([7]),
        };
        return { requestId: 'r1', source: 'greynoise-swarm', command: input.command, input, data: { sessions: [] }, durationMs: 1 };
      },
    },
    session: {},
    downloads: { save: () => {} },
    investigations: {
      handle: async () => ({}),
      captureOperator: async value => {
        captured.push(value);
        return { action: 'CAPTURE_OPERATOR', invalidated: [], investigation: { id: 'inv-1', revision: 2, status: { phase: 'scoped', readiness: {} } } };
      },
      state: () => ({ activeInvestigationId: 'inv-1', available: true }),
    },
  });

  await executor.execute({ descriptor, args: ['search', '--from', '2026-09-05T00:00:00Z', '--to', '2026-09-06T00:00:00Z'], context: { surface: 'web' } });
  await executor.execute({ descriptor: captureOperatorDescriptor, args: [], context: { surface: 'web' } });
  assert.equal(captured.length, 1);
  assert.equal(captured[0].kind, 'greynoise-swarm');
  assert.match(captured[0].summary, /\"command\":\"search\"/);

  await executor.execute({ descriptor, args: ['export', 'session-123', 'pcap'], context: { surface: 'web' } });
  await executor.execute({ descriptor: captureOperatorDescriptor, args: [], context: { surface: 'web' } });
  assert.equal(captured.length, 2);
  assert.equal(captured[1].kind, 'greynoise-swarm');
  assert.match(captured[1].summary, /\"command\":\"search\"/);
  assert.doesNotMatch(captured[1].summary, /\"command\":\"export\"/);
});

test('Swarm diff result becomes capturable operator context', async () => {
  const captured = [];
  const executor = createBrowserShellExecutor({
    client: {
      swarm: async input => ({ requestId: 'rd', source: 'greynoise-swarm', command: 'diff', input, data: { ips: [] }, durationMs: 1 }),
    },
    session: {},
    downloads: { save: () => {} },
    investigations: {
      handle: async () => ({}),
      captureOperator: async value => {
        captured.push(value);
        return { action: 'CAPTURE_OPERATOR', invalidated: [], investigation: { id: 'inv-1', revision: 2, status: { phase: 'scoped', readiness: {} } } };
      },
      state: () => ({ activeInvestigationId: 'inv-1', available: true }),
    },
  });
  await executor.execute({ descriptor, args: ['diff', '--query', 'classification:malicious'], context: { surface: 'web' } });
  await executor.execute({ descriptor: captureOperatorDescriptor, args: [], context: { surface: 'web' } });
  assert.equal(captured.length, 1);
  assert.equal(captured[0].kind, 'greynoise-swarm');
  assert.match(captured[0].summary, /\"command\":\"diff\"/);
});

test('gateway client sends Swarm search to the same-origin authenticated route', async () => {
  let captured;
  const client = createGatewayClient({
    getToken: () => 'bearer-secret',
    fetchImpl: async (path, init) => {
      captured = { path, init };
      return new Response(JSON.stringify({
        requestId: 'r1', source: 'greynoise-swarm', command: 'search', input: { scope: 'workspace' }, data: { sessions: [] }, durationMs: 2,
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    },
  });
  const result = await client.swarm({ command: 'search', scope: 'workspace', startTime: '2026-09-05T00:00:00Z', endTime: '2026-09-06T00:00:00Z', page: 1, pageSize: 25 });
  assert.equal(captured.path, '/api/para11ax/swarm');
  assert.equal(captured.init.method, 'POST');
  assert.equal(captured.init.headers.Authorization, 'Bearer bearer-secret');
  assert.equal(JSON.parse(captured.init.body).command, 'search');
  assert.equal(result.source, 'greynoise-swarm');
});

test('gateway client sends bounded Swarm diff and rejects unsafe aliases before egress', async () => {
  let calls = 0;
  let body;
  const client = createGatewayClient({
    getToken: () => 'bearer-secret',
    fetchImpl: async (path, init) => {
      calls += 1;
      body = JSON.parse(init.body);
      return new Response(JSON.stringify({
        requestId: 'rd', source: 'greynoise-swarm', command: 'diff', input: body, data: { ips: [] }, durationMs: 2,
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    },
  });
  const result = await client.swarm({ command: 'diff', query: 'classification:malicious', sourceWorkspace: 'personal', targetWorkspace: 'greynoise', mode: 'source-only', size: 25 });
  assert.equal(result.command, 'diff');
  assert.equal(body.sourceWorkspace, 'personal');
  assert.equal(body.targetWorkspace, 'greynoise');
  assert.equal(body.mode, 'source-only');
  assert.equal(body.size, 25);
  await assert.rejects(
    client.swarm({ command: 'diff', query: 'classification:malicious', sourceWorkspace: '11111111-1111-1111-1111-111111111111', targetWorkspace: 'greynoise' }),
    /invalid Swarm diff workspace/,
  );
  assert.equal(calls, 1);
});

test('gateway client accepts only bounded binary Swarm export responses', async () => {
  const client = createGatewayClient({
    getToken: () => 'bearer-secret',
    fetchImpl: async () => new Response(new Uint8Array([4, 5, 6]), {
      status: 200,
      headers: {
        'content-type': 'application/octet-stream',
        'content-disposition': 'attachment; filename=\"session-123.pcap\"',
        'x-para11ax-request-id': 'r2',
        'x-para11ax-duration-ms': '3',
      },
    }),
  });
  const result = await client.swarm({ command: 'export', scope: 'workspace', sessionId: 'session-123', exportType: 'pcap' });
  assert.equal(result.command, 'export');
  assert.equal(result.filename, 'session-123.pcap');
  assert.deepEqual([...result.data], [4, 5, 6]);
  await assert.rejects(
    client.swarm({ command: 'export', scope: 'demo', sessionId: 'session-123', exportType: 'pcap' }),
    /Swarm demo export unsupported/,
  );
});
