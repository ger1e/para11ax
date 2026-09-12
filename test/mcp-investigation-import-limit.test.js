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

function importRequest(bundle) {
  return {
    method: 'POST',
    headers: {
      authorization: `Bearer ${TOKEN}`,
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

test('authenticated MCP round-trips a valid Investigation v2 bundle larger than the public 128 KiB ceiling', async () => {
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

  const handle = createMcpHttpHandler({
    env: { PARA11AX_TOKEN: TOKEN },
    now: () => NOW,
    nowMs: () => Date.parse(NOW),
  });
  const response = await handle(importRequest(bundle));

  assert.equal(response.status, 200);
  assert.equal(response.body.result?.isError, false, JSON.stringify(response.body));
  const imported = response.body.result.structuredContent.investigation;
  assert.equal(exportInvestigation(imported), bundle);
});
