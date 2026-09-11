import test from 'node:test';
import assert from 'node:assert/strict';

import { createMcpHttpHandler, MCP_PROTOCOL_VERSION } from '../src/mcp/transport.js';

const TOKEN = 'test-mcp-token';

function request(method, params = {}) {
  return {
    method: 'POST',
    headers: {
      authorization: `Bearer ${TOKEN}`,
      'content-type': 'application/json',
      'mcp-protocol-version': MCP_PROTOCOL_VERSION,
      'mcp-method': method,
    },
    body: { jsonrpc: '2.0', id: 1, method, params },
  };
}

async function listedTools() {
  const handle = createMcpHttpHandler({ env: { PARA11AX_TOKEN: TOKEN } });
  const result = await handle(request('tools/list'));
  assert.equal(result.status, 200);
  return result.body.result.tools;
}

test('ChatGPT-facing MCP tools expose explicit routing descriptions and behavior annotations', async () => {
  const tools = await listedTools();
  assert.equal(tools.length, 13);

  for (const tool of tools) {
    assert.match(tool.description, /^Use this when\b/, `${tool.name} description must start with a routing cue`);
    for (const hint of ['readOnlyHint', 'destructiveHint', 'openWorldHint', 'idempotentHint']) {
      assert.equal(typeof tool.annotations?.[hint], 'boolean', `${tool.name} must declare ${hint}`);
    }
  }
});

test('ChatGPT-facing MCP server advertises the canonical PARA11AX brand icon', async () => {
  const handle = createMcpHttpHandler({ env: { PARA11AX_TOKEN: TOKEN } });
  const result = await handle(request('initialize', { protocolVersion: MCP_PROTOCOL_VERSION }));
  assert.equal(result.status, 200);
  assert.equal(result.body.result.serverInfo.name, 'para11ax');
  assert.equal(result.body.result.serverInfo.title, 'PARA11AX');
  assert.equal(result.body.result.serverInfo.websiteUrl, 'https://para11ax.vercel.app/');
  assert.deepEqual(result.body.result.serverInfo.icons, [{
    src: 'https://para11ax.vercel.app/assets/brand/para11ax-mark.svg',
    mimeType: 'image/svg+xml',
    sizes: ['any'],
  }]);
});

test('User Scanner MCP schema exposes only its bounded authorized defensive controls', async () => {
  const tools = await listedTools();
  const scanner = tools.find(tool => tool.name === 'para11ax_user_scan');
  assert.ok(scanner, 'missing para11ax_user_scan');
  assert.match(scanner.description, /authorized defensive identity OSINT/i);
  assert.equal(scanner.inputSchema.additionalProperties, false);
  assert.deepEqual(Object.keys(scanner.inputSchema.properties).sort(), [
    'category', 'crossScan', 'module', 'noNsfw', 'scanType', 'target',
  ]);
  assert.equal(scanner.inputSchema.properties.crossScan.type, 'boolean');
  assert.equal(scanner.inputSchema.properties.noNsfw.type, 'boolean');
  assert.equal(scanner.inputSchema.properties.category.type, 'string');
  assert.equal(scanner.inputSchema.properties.module.type, 'string');
});
