import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

import { createMcpHttpHandler, MCP_PROTOCOL_VERSION } from '../src/mcp/server.js';

const TOKEN = 'test-mcp-token';

function request(method, params = {}, { token = TOKEN, id = 1 } = {}) {
  return {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'mcp-protocol-version': MCP_PROTOCOL_VERSION,
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: { jsonrpc: '2.0', id, method, params },
  };
}

function toolNames(result) {
  return result.body.result.tools.map(tool => tool.name);
}

test('MCP is authenticated and supports stateless discovery', async () => {
  const handle = createMcpHttpHandler({ env: { PARA11AX_TOKEN: TOKEN } });
  const denied = await handle(request('server/discover', {}, { token: null }));
  assert.equal(denied.status, 401);

  const result = await handle(request('server/discover'));
  assert.equal(result.status, 200);
  assert.equal(result.body.jsonrpc, '2.0');
  assert.equal(result.body.result.protocolVersion, MCP_PROTOCOL_VERSION);
  assert.equal(result.body.result.serverInfo.name, 'para11ax');
  assert.equal(result.body.result.capabilities.tools.listChanged, false);
});

test('tools/list exposes the complete functional control plane without local-admin escape hatches', async () => {
  const handle = createMcpHttpHandler({ env: { PARA11AX_TOKEN: TOKEN } });
  const result = await handle(request('tools/list'));
  assert.equal(result.status, 200);
  const names = toolNames(result);
  for (const expected of [
    'para11ax_capabilities', 'para11ax_enrich', 'para11ax_batch', 'para11ax_provider',
    'para11ax_shodan', 'para11ax_swarm', 'para11ax_user_scan', 'para11ax_stix',
    'para11ax_mission', 'para11ax_investigation', 'para11ax_case', 'para11ax_report',
    'para11ax_command',
  ]) assert.ok(names.includes(expected), `missing MCP tool ${expected}`);
  assert.equal(new Set(names).size, names.length);
  assert.ok(names.every(name => !/setup|repair|shell|filesystem|release_verify/.test(name)));
});

test('registered command fallback executes safe PARA11AX commands and denies local-admin/filesystem commands', async () => {
  const handle = createMcpHttpHandler({ env: { PARA11AX_TOKEN: TOKEN } });
  const ok = await handle(request('tools/call', {
    name: 'para11ax_command',
    arguments: { commandId: 'intel.validate', args: ['8.8.8.8'] },
  }));
  assert.equal(ok.status, 200);
  assert.equal(ok.body.result.isError, false);
  assert.deepEqual(ok.body.result.structuredContent.output.value, { valid: true, type: 'ip', value: '8.8.8.8' });

  for (const commandId of ['system.setup', 'system.repair', 'system.release-verify', 'provider.probe', 'provider.env-template', 'report.compile', 'report.diff']) {
    const denied = await handle(request('tools/call', {
      name: 'para11ax_command',
      arguments: { commandId, args: [] },
    }));
    assert.equal(denied.status, 200);
    assert.equal(denied.body.result.isError, true, commandId);
    assert.match(denied.body.result.content[0].text, /not exposed over MCP/i);
  }
});

test('mission state is explicit and round-trippable across stateless calls', async () => {
  const handle = createMcpHttpHandler({ env: { PARA11AX_TOKEN: TOKEN } });
  const created = await handle(request('tools/call', {
    name: 'para11ax_mission', arguments: { operation: 'new' },
  }));
  assert.equal(created.body.result.isError, false);
  const workspace = created.body.result.structuredContent.workspace;
  assert.ok(workspace);

  const shown = await handle(request('tools/call', {
    name: 'para11ax_mission', arguments: { operation: 'show', workspace },
  }));
  assert.equal(shown.body.result.isError, false);
  assert.deepEqual(shown.body.result.structuredContent.workspace, workspace);
});

test('case and investigation tools use visible state instead of hidden server sessions', async () => {
  const handle = createMcpHttpHandler({ env: { PARA11AX_TOKEN: TOKEN } });
  const caseCreated = await handle(request('tools/call', {
    name: 'para11ax_case', arguments: { operation: 'create', title: 'MCP case' },
  }));
  assert.equal(caseCreated.body.result.isError, false);
  const caseState = caseCreated.body.result.structuredContent.case;
  assert.equal(caseState.title, 'MCP case');

  const noted = await handle(request('tools/call', {
    name: 'para11ax_case', arguments: { operation: 'note', case: caseState, text: 'analyst note' },
  }));
  assert.equal(noted.body.result.structuredContent.case.notes.at(-1).text, 'analyst note');

  const invCreated = await handle(request('tools/call', {
    name: 'para11ax_investigation', arguments: { operation: 'create', title: 'MCP investigation' },
  }));
  assert.equal(invCreated.body.result.isError, false);
  const investigation = invCreated.body.result.structuredContent.investigation;
  assert.equal(investigation.title, 'MCP investigation');

  const status = await handle(request('tools/call', {
    name: 'para11ax_investigation', arguments: { operation: 'status', investigation },
  }));
  assert.equal(status.body.result.isError, false);
  assert.equal(status.body.result.structuredContent.investigation.id, investigation.id);
  assert.ok(status.body.result.structuredContent.status.phase);
});

test('Vercel exposes /mcp explicitly before the PARA11AX catch-all', async () => {
  const vercel = JSON.parse(await readFile(new URL('../vercel.json', import.meta.url), 'utf8'));
  const mcpIndex = vercel.routes.findIndex(route => route.src === '/mcp');
  const apiCatchAllIndex = vercel.routes.findIndex(route => route.src === '/api/para11ax/(.*)');
  assert.ok(mcpIndex >= 0, 'missing /mcp route');
  assert.ok(apiCatchAllIndex >= 0, 'missing existing API catch-all');
  assert.ok(mcpIndex < apiCatchAllIndex, '/mcp must route before the fail-closed API catch-all');
  assert.equal(vercel.routes[mcpIndex].dest, '/api/mcp.js');
});
