import test from 'node:test';
import assert from 'node:assert/strict';
import { MCP_TOOLS } from '../src/mcp/server.js';

const tool = name => {
  const found = MCP_TOOLS.find(entry => entry.name === name);
  assert.ok(found, `missing MCP tool ${name}`);
  return found;
};

test('GreyNoise Swarm advertises its bounded runtime contract', () => {
  const input = tool('para11ax_swarm').inputSchema;
  assert.equal(input.type, 'object');
  assert.equal(input.additionalProperties, false);
  assert.deepEqual(input.required, ['command']);
  assert.deepEqual(input.properties.command.enum, ['search', 'get', 'export', 'unique', 'timeseries', 'diff']);
  assert.deepEqual(input.properties.scope.enum, ['workspace', 'demo']);
  assert.deepEqual(input.properties.exportType.enum, ['pcap', 'rawSource', 'rawDestination']);
  assert.deepEqual(input.properties.interval.enum, ['auto', '1s', '1m', '1h', '1d']);
  assert.deepEqual(input.properties.sourceWorkspace.enum, ['personal', 'community', 'greynoise']);
  assert.deepEqual(input.properties.targetWorkspace.enum, ['personal', 'community', 'greynoise']);
  assert.deepEqual(input.properties.mode.enum, ['source-only', 'both', 'all']);
  assert.equal(input.properties.page.minimum, 1);
  assert.equal(input.properties.page.maximum, 10000);
  assert.equal(input.properties.pageSize.minimum, 1);
  assert.equal(input.properties.pageSize.maximum, 100);
  assert.equal(input.properties.size.minimum, 1);
  assert.equal(input.properties.size.maximum, 100);
  for (const key of ['sessionId','startTime','endTime','query','field','includeCounts','nextToken']) {
    assert.ok(input.properties[key], `missing Swarm schema property ${key}`);
  }
});

test('User Scanner advertises its bounded runtime contract', () => {
  const input = tool('para11ax_user_scan').inputSchema;
  assert.equal(input.type, 'object');
  assert.equal(input.additionalProperties, false);
  assert.deepEqual(input.required, ['scanType', 'target']);
  assert.deepEqual(input.properties.scanType.enum, ['email', 'username']);
  assert.equal(input.properties.target.maxLength, 320);
  assert.equal(input.properties.category.maxLength, 64);
  assert.equal(input.properties.module.maxLength, 64);
  assert.equal(input.properties.crossScan.type, 'boolean');
  assert.equal(input.properties.noNsfw.type, 'boolean');
});
