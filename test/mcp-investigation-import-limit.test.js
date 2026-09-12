import test from 'node:test';
import assert from 'node:assert/strict';

import { createMcpHttpHandler, MCP_PROTOCOL_VERSION } from '../src/mcp/server.js';
import {
  createInvestigation,
  exportInvestigation,
  reduceInvestigation,
} from '../src/core/investigation/index.js';

const TOKEN = 'test-mcp-token';
const NOW = '2026-09-12T11:30:00.000Z';

function importRequest(bundle, { authenticated = true } = {}) {
  return {
    method: 'POST',
    headers: {
      ...(authenticated ? { authorization: `Bearer ${TOKEN}` } : {}),
      'content-type': 'application/json',
      'mcp-protocol-version': MCP_PROTOCOL_VERSION,
      'mcp-method': 'tools/call',
      'mcp-name': 'para11ax_investigation',
    },
    body: {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: {
        name: 'para11ax_investigation',
        arguments: { operation: 'import', bundle },
      },
    },
  };
}

function oversizedCommandRequest() {
  return {
    method: 'POST',
    headers: {
      authorization: `Bearer ${TOKEN}`,
      'content-type': 'application/json',
      'mcp-protocol-version': MCP_PROTOCOL_VERSION,
      'mcp-method': 'tools/call',
      'mcp-name': 'para11ax_command',
    },
    body: {
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: {
        name: 'para11ax_command',
        arguments: { commandId: 'intel.validate', args: ['x'.repeat(140 * 1024)] },
      },
    },
  };
}

function largeBundle() {
  let investigation = createInvestigation({
    title: 'Large MCP round-trip',
    now: () => NOW,
    uuid: () => 'investigation-large-mcp-round-trip',
  });

  for (let index = 0; index < 40; index += 1) {
    investigation = reduceInvestigation(
      investigation,
      { type: 'NOTE_ADD', text: `note-${index}-${'x'.repeat(3900)}` },
      { now: () => NOW },
    );
  }

  const bundle = exportInvestigation(investigation);
  assert.ok(Buffer.byteLength(bundle, 'utf8') > 128 * 1024, 'fixture must exceed the public MCP body ceiling');
  assert.ok(Buffer.byteLength(bundle, 'utf8') < 4 * 1024 * 1024, 'fixture must remain a valid Investigation v2 bundle');
  return bundle;
}

function handler() {
  return createMcpHttpHandler({
    env: { PARA11AX_TOKEN: TOKEN },
    now: () => NOW,
    nowMs: () => Date.parse(NOW),
  });
}

test('authenticated MCP round-trips a valid Investigation v2 bundle larger than the public 128 KiB ceiling', async () => {
  const bundle = largeBundle();
  const response = await handler()(importRequest(bundle));

  assert.equal(response.status, 200);
  assert.equal(response.body.result?.isError, false, JSON.stringify(response.body));
  const imported = response.body.result.structuredContent.investigation;
  assert.equal(exportInvestigation(imported), bundle);
});

test('unauthenticated oversized investigation imports remain behind the 128 KiB public ceiling', async () => {
  const response = await handler()(importRequest(largeBundle(), { authenticated: false }));
  assert.equal(response.status, 413);
  assert.equal(response.body.error?.message, 'Payload too large');
});

test('authenticated oversized non-import tool calls remain rejected at 128 KiB', async () => {
  const response = await handler()(oversizedCommandRequest());
  assert.equal(response.status, 413);
  assert.equal(response.body.error?.message, 'Payload too large');
});
