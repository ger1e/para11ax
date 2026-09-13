import test from 'node:test';
import assert from 'node:assert/strict';

import { createMcpHttpHandler, MCP_PROTOCOL_VERSION } from '../src/mcp/server.js';

const TOKEN = 'test-mcp-token';
const NOW = '2026-09-13T16:30:00.000Z';

function enrichment() {
  return {
    schemaVersion: '2.0',
    gatewayVersion: 'test',
    requestId: 'req-domain-mcp',
    indicator: 'suspicious.example',
    type: 'domain',
    queriedAt: NOW,
    profile: 'standard',
    status: 'ok',
    evidence: [],
    relationships: [],
    coverage: {},
    limitations: [],
    failures: [],
    huntContext: {
      indicator: 'suspicious.example',
      type: 'domain',
      firstSeen: null,
      lastSeen: null,
      families: [],
      actors: [],
      sourceReferences: [],
    },
  };
}

function request(name, args, { authenticated = true, id = 1 } = {}) {
  return {
    method: 'POST',
    headers: {
      ...(authenticated ? { authorization: `Bearer ${TOKEN}` } : {}),
      'content-type': 'application/json',
      'mcp-protocol-version': MCP_PROTOCOL_VERSION,
      'mcp-method': 'tools/call',
      'mcp-name': name,
    },
    body: {
      jsonrpc: '2.0',
      id,
      method: 'tools/call',
      params: { name, arguments: args },
    },
  };
}

function handler() {
  return createMcpHttpHandler({
    env: { PARA11AX_TOKEN: TOKEN },
    now: () => NOW,
    nowMs: () => Date.parse(NOW),
    fetchImpl: async () => { throw new Error('network must not be used by Domain Investigation MCP'); },
  });
}

async function call(handle, action, args = {}, options = {}) {
  return handle(request('para11ax_domain_investigation', { action, ...args }, options));
}

test('MCP discovers Domain Investigation as one grouped stateless tool', async () => {
  const handle = handler();
  const listed = await handle({
    method: 'POST',
    headers: {
      authorization: `Bearer ${TOKEN}`,
      'content-type': 'application/json',
      'mcp-protocol-version': MCP_PROTOCOL_VERSION,
      'mcp-method': 'tools/list',
    },
    body: { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} },
  });

  const tool = listed.body.result.tools.find(value => value.name === 'para11ax_domain_investigation');
  assert.ok(tool, 'missing para11ax_domain_investigation');
  assert.deepEqual(tool.inputSchema.properties.action.enum, [
    'build', 'surface_import', 'vulnerability_import', 'show', 'report', 'stix', 'handoff',
  ]);
  assert.equal(tool.annotations.readOnlyHint, false);
});

test('Domain Investigation MCP carries explicit artifact state while public projections stay sanitized', async () => {
  const handle = handler();
  const built = await call(handle, 'build', { enrichment: enrichment() });
  assert.equal(built.status, 200);
  assert.equal(built.body.result.isError, false, JSON.stringify(built.body));
  const artifact = built.body.result.structuredContent.artifact;
  assert.equal(artifact.schemaVersion, 'domain-investigation-v1.0');
  assert.ok(artifact._authoritative?.enrichment, 'stateful transition artifact must retain internal authority');
  assert.equal(built.body.result.structuredContent.result._authoritative, undefined);

  const shown = await call(handle, 'show', { artifact });
  assert.equal(shown.body.result.isError, false);
  assert.equal(shown.body.result.structuredContent.result.schemaVersion, 'domain-investigation-v1.0');
  assert.equal(shown.body.result.structuredContent.result._authoritative, undefined);
  assert.equal(shown.body.result.structuredContent.artifact, undefined, 'show must not dump internal authority');

  const surface = await call(handle, 'surface_import', {
    artifact,
    records: [{ host: 'cdn.suspicious.example', ip: '203.0.113.7', source: 'authorized-local-scan' }],
  });
  assert.equal(surface.body.result.isError, false);
  const withSurface = surface.body.result.structuredContent.artifact;
  assert.equal(withSurface.imports.surface.length, 1);
  assert.equal(surface.body.result.structuredContent.result._authoritative, undefined);

  const vulnerabilities = await call(handle, 'vulnerability_import', {
    artifact: withSurface,
    records: [{ host: 'suspicious.example', cve: 'CVE-2026-12345', severity: 'high', source: 'authorized-local-scan' }],
  });
  assert.equal(vulnerabilities.body.result.isError, false);
  const complete = vulnerabilities.body.result.structuredContent.artifact;
  assert.equal(complete.imports.vulnerabilities.length, 1);

  const report = await call(handle, 'report', { artifact: complete });
  assert.equal(report.body.result.isError, false);
  assert.match(report.body.result.structuredContent.report, /operator context/i);

  const stix = await call(handle, 'stix', { artifact: complete });
  assert.equal(stix.body.result.isError, false);
  assert.equal(stix.body.result.structuredContent.bundle.type, 'bundle');

  const handoff = await call(handle, 'handoff', { artifact: complete });
  assert.equal(handoff.body.result.isError, false);
  assert.match(handoff.body.result.structuredContent.handoff.schemaVersion, /handoff/i);
});

test('Domain Investigation MCP has no hidden server session', async () => {
  const handle = handler();
  const built = await call(handle, 'build', { enrichment: enrichment() });
  assert.equal(built.body.result.isError, false);

  const omitted = await call(handle, 'show');
  assert.equal(omitted.status, 200);
  assert.equal(omitted.body.result.isError, true);
  assert.match(omitted.body.result.content[0].text, /build|required|artifact/i);
});

test('authenticated Domain Investigation imports may exceed 128 KiB while unauthenticated calls remain bounded', async () => {
  const handle = handler();
  const built = await call(handle, 'build', { enrichment: enrichment() });
  const artifact = built.body.result.structuredContent.artifact;
  const records = Array.from({ length: 40 }, (_, index) => ({
    host: `host-${index}.suspicious.example`,
    source: `authorized-local-scan-${index}-${'x'.repeat(3900)}`,
  }));
  const authenticated = request('para11ax_domain_investigation', { action: 'surface_import', artifact, records });
  assert.ok(Buffer.byteLength(JSON.stringify(authenticated.body), 'utf8') > 128 * 1024, 'fixture must cross the public MCP ceiling');

  const accepted = await handle(authenticated);
  assert.equal(accepted.status, 200);
  assert.equal(accepted.body.result.isError, false, JSON.stringify(accepted.body));
  assert.equal(accepted.body.result.structuredContent.artifact.imports.surface.length, 40);

  const denied = await handle(request('para11ax_domain_investigation', { action: 'surface_import', artifact, records }, { authenticated: false }));
  assert.equal(denied.status, 413);
  assert.equal(denied.body.error?.message, 'Payload too large');
});
