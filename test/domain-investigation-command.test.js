import test from 'node:test';
import assert from 'node:assert/strict';

import { COMMAND_REGISTRY } from '../app/shell-core/catalog.js';
import { MISSION_HANDLERS, executeMissionCommand } from '../src/core/mission/command-adapter.js';

const EXPECTED = Object.freeze([
  ['domain-investigation', 'build'],
  ['domain-investigation', 'surface-import'],
  ['domain-investigation', 'vulnerability-import'],
  ['domain-investigation', 'show'],
  ['domain-investigation', 'report'],
  ['domain-investigation', 'stix'],
  ['domain-investigation', 'handoff'],
  ['domain-investigation', 'clear'],
]);

function enrichment() {
  return {
    schemaVersion: 'evidence-v2.0', gatewayVersion: 'test', requestId: 'req-shell-domain',
    indicator: 'suspicious.example', type: 'domain', queriedAt: '2026-09-13T12:00:00.000Z',
    profile: 'standard', status: 'ok', evidence: [], relationships: [], coverage: {}, limitations: [], failures: [],
    huntContext: { indicator: 'suspicious.example', type: 'domain', firstSeen: null, lastSeen: null, families: [], actors: [], sourceReferences: [] },
  };
}

const loader = async ({ kind }) => {
  if (kind === 'domain-enrichment') return JSON.stringify(enrichment());
  if (kind === 'domain-surface') return JSON.stringify([{ host: 'cdn.suspicious.example', ip: '203.0.113.7', source: 'authorized-local-scan' }]);
  if (kind === 'domain-vulnerability') return JSON.stringify([{ host: 'suspicious.example', cve: 'CVE-2026-12345', severity: 'high', source: 'authorized-local-scan' }]);
  throw new Error(`unexpected kind ${kind}`);
};

test('Domain Investigation shell commands are registered on CLI with bounded local semantics', () => {
  for (const tokens of EXPECTED) {
    const resolved = COMMAND_REGISTRY.resolve(tokens, 'cli');
    assert.ok(resolved, `${tokens.join(' ')} must resolve on CLI`);
    assert.equal(resolved.descriptor.namespace, 'domain-investigation');
    assert.equal(resolved.descriptor.egressClass, 'none');
    assert.equal(resolved.descriptor.auth, 'none');
    assert.ok(resolved.descriptor.handler.startsWith('domain-investigation-'));
  }
});

test('Domain Investigation build/import commands never request scanner/provider capability', () => {
  for (const tokens of [EXPECTED[0], EXPECTED[1], EXPECTED[2]]) {
    const resolved = COMMAND_REGISTRY.resolve(tokens, 'cli');
    assert.ok(resolved);
    assert.deepEqual(resolved.descriptor.capabilities, []);
    assert.equal(resolved.descriptor.sideEffect, 'session');
  }
});

test('shared command adapter keeps volatile Domain Investigation state and preserves authority boundaries', async () => {
  for (const name of ['domain-investigation-build', 'domain-investigation-surface-import', 'domain-investigation-vulnerability-import', 'domain-investigation-show', 'domain-investigation-report', 'domain-investigation-stix', 'domain-investigation-handoff', 'domain-investigation-clear']) {
    assert.ok(MISSION_HANDLERS.includes(name), `${name} must be dispatched by the shared shell adapter`);
  }

  let workspace = null;
  let outcome = await executeMissionCommand({ handler: 'domain-investigation-build', args: ['--stdin'], workspace, loadContent: loader });
  workspace = outcome.workspace;
  assert.equal(outcome.output.value.schemaVersion, 'domain-investigation-v1.0');

  const prior = workspace;
  outcome = await executeMissionCommand({ handler: 'domain-investigation-surface-import', args: ['--stdin'], workspace, loadContent: loader });
  workspace = outcome.workspace;
  assert.notEqual(workspace, prior);
  assert.equal(outcome.output.value.operatorContext.surface.length, 1);
  assert.ok(outcome.output.value.operatorContext.surface.every(item => item.authority === undefined));

  outcome = await executeMissionCommand({ handler: 'domain-investigation-vulnerability-import', args: ['--stdin'], workspace, loadContent: loader });
  workspace = outcome.workspace;
  assert.equal(outcome.output.value.operatorContext.vulnerabilities.length, 1);

  const shown = await executeMissionCommand({ handler: 'domain-investigation-show', workspace, loadContent: loader });
  assert.equal(shown.output.value._authoritative, undefined);
  const report = await executeMissionCommand({ handler: 'domain-investigation-report', workspace, loadContent: loader });
  assert.equal(report.output.type, 'text');
  assert.match(report.output.value, /operator context/i);
  const stix = await executeMissionCommand({ handler: 'domain-investigation-stix', workspace, loadContent: loader });
  assert.equal(stix.output.value.type, 'bundle');
  const handoff = await executeMissionCommand({ handler: 'domain-investigation-handoff', workspace, loadContent: loader });
  assert.match(handoff.output.value.schemaVersion, /handoff/i);

  const cleared = await executeMissionCommand({ handler: 'domain-investigation-clear', workspace, loadContent: loader });
  assert.equal(cleared.workspace.domainInvestigation, null);
});
