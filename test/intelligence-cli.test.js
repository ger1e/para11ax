import test from 'node:test';
import assert from 'node:assert/strict';

import { COMMAND_REGISTRY } from '../app/shell-core/catalog.js';
import { createNodeShellExecutor } from '../src/control/shell-node-executor.js';

const OPERATIONS = Object.freeze(['pivot', 'search', 'identity', 'asset', 'supply-chain', 'malware', 'knowledge']);

test('CLI registers normalized intelligence operations without stealing the legacy pivot alias', () => {
  for (const operation of OPERATIONS) {
    const resolved = COMMAND_REGISTRY.resolve(['intel', operation, 'example.com'], 'cli');
    assert.ok(resolved, `missing intel ${operation}`);
    assert.equal(resolved.descriptor.id, `intel.${operation}`);
    assert.equal(resolved.descriptor.handler, 'intelligence');
    assert.equal(resolved.descriptor.outputType, 'record');
    assert.deepEqual(resolved.args, ['example.com']);
    assert.equal(resolved.surfaceAvailable, true);
  }

  const legacy = COMMAND_REGISTRY.resolve(['pivot', 'example.com'], 'cli');
  assert.ok(legacy);
  assert.equal(legacy.descriptor.id, 'intel.enrich');
  assert.equal(legacy.descriptor.handler, 'enrich');
  assert.deepEqual(legacy.args, ['example.com']);
});

test('CLI intelligence command dispatches through the normalized app surface', async () => {
  const resolved = COMMAND_REGISTRY.resolve(['intel', 'knowledge', 'example.com'], 'cli');
  assert.ok(resolved);
  const executor = createNodeShellExecutor({
    env: {},
    registry: COMMAND_REGISTRY,
    fetchImpl: async () => { throw new Error('unexpected network call'); },
    now: () => new Date('2026-09-13T13:00:00.000Z'),
    nowMs: () => Date.parse('2026-09-13T13:00:00.000Z'),
  });

  const output = await executor.execute({ descriptor: resolved.descriptor, args: resolved.args });
  assert.equal(output.type, 'record');
  assert.equal(output.value.operation, 'knowledge');
  assert.equal(output.value.mode, 'knowledge');
  assert.deepEqual(output.value.subject, { type: 'domain', value: 'example.com' });
});
