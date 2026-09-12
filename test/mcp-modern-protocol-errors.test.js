import test from 'node:test';
import assert from 'node:assert/strict';

import { createMcpHttpHandler } from '../src/mcp/transport.js';

const TOKEN = 'test-mcp-token';

test('unsupported MCP protocol revisions use finalized -32022 with supported and requested versions', async () => {
  const handle = createMcpHttpHandler({ env: { PARA11AX_TOKEN: TOKEN } });
  const requested = '2099-01-01';
  const result = await handle({
    method: 'POST',
    headers: {
      authorization: `Bearer ${TOKEN}`,
      'content-type': 'application/json',
      'mcp-protocol-version': requested,
      'mcp-method': 'tools/list',
    },
    body: {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/list',
      params: {
        _meta: {
          'io.modelcontextprotocol/protocolVersion': requested,
          'io.modelcontextprotocol/clientCapabilities': {},
        },
      },
    },
  });

  assert.equal(result.status, 400);
  assert.equal(result.body.error?.code, -32022);
  assert.equal(result.body.error?.data?.requested, requested);
  assert.ok(result.body.error?.data?.supported?.includes('2026-07-28'));
});
