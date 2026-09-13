import test from 'node:test';
import assert from 'node:assert/strict';
import { MCP_TOOLS } from '../src/mcp/server.js';
import { applyChatGptToolMetadata } from '../src/mcp/chatgpt-tool-metadata.js';

const OPERATIONS = ['pivot', 'search', 'identity', 'asset', 'supply-chain', 'malware', 'knowledge'];

test('MCP exposes one strict normalized intelligence tool', () => {
  const tools = applyChatGptToolMetadata(structuredClone(MCP_TOOLS));
  const tool = tools.find(item => item.name === 'para11ax_intelligence');
  assert.ok(tool, 'para11ax_intelligence missing');
  assert.deepEqual(tool.inputSchema.properties.operation.enum, OPERATIONS);
  assert.deepEqual(tool.inputSchema.required, ['operation', 'indicator']);
  assert.equal(tool.inputSchema.additionalProperties, false);
  assert.deepEqual(Object.keys(tool.inputSchema.properties).sort(), ['indicator', 'operation', 'profile', 'type']);
  assert.equal(tool.annotations.readOnlyHint, true);
  assert.equal(tool.annotations.openWorldHint, true);
});

test('MCP intelligence schema exposes no authorization or raw-provider routing fields', () => {
  const tool = applyChatGptToolMetadata(structuredClone(MCP_TOOLS)).find(item => item.name === 'para11ax_intelligence');
  for (const field of ['trusted','caseId','verifiedDomains','ownedCidrs','tenant','provider','providerUrl','path','mode','url']) {
    assert.equal(Object.hasOwn(tool.inputSchema.properties, field), false, field);
  }
});

test('MCP catalog grows by exactly one dedicated intelligence surface', () => {
  const names = MCP_TOOLS.map(tool => tool.name);
  assert.equal(names.length, 14);
  assert.equal(new Set(names).size, 14);
  assert.equal(names.filter(name => name === 'para11ax_intelligence').length, 1);
});
