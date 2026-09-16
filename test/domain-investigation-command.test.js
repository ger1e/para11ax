import test from 'node:test';
import assert from 'node:assert/strict';

import { COMMAND_REGISTRY } from '../app/shell-core/catalog.js';
import { createBrowserShellExecutor } from '../app/shell-browser-executor.js';
import { WORKFLOW_HANDLERS, executeMissionCommand } from '../src/core/mission/command-adapter.js';
import { createMissionContentLoader } from '../src/control/mission-content-loader.js';
import { createNodeShellExecutor } from '../src/control/shell-node-executor.js';

const EXPECTED = Object.freeze([
  ['domain-investigation', 'build'], ['domain-investigation', 'surface-import'],
  ['domain-investigation', 'vulnerability-import'], ['domain-investigation', 'show'],
  ['domain-investigation', 'report'], ['domain-investigation', 'stix'],
  ['domain-investigation', 'handoff'], ['domain-investigation', 'promotion-candidates'],
  ['domain-investigation', 'promote'], ['domain-investigation', 'reject-promotion'],
  ['domain-investigation', 'revoke-promotion'], ['domain-investigation', 'graph'],
  ['domain-investigation', 'clear'],
]);

function enrichment() {
  return {
    schemaVersion: '2.0', gatewayVersion: 'test', requestId: 'req-shell-domain',
    indicator: 'suspicious.example', type: 'domain', queriedAt: '2026-09-13T12:00:00.000Z',
    profile: 'standard', status: 'ok', evidence: [], relationships: [], coverage: {}, limitations: [], failures: [],
    huntContext: { indicator: 'suspicious.example', type: 'domain', firstSeen: null, lastSeen: null, families: [], actors: [], sourceReferences: [] },
  };
}

const loader = async ({ kind }) => {
  if (kind === 'domain-enrichment') return JSON.stringify(enrichment());
  if (kind === 'domain-surface') return JSON.stringify([{
    host: 'suspicious.example',
    ip: '203.0.113.7',
    status: 'observed',
    source: 'authorized-local-scan',
    reference: 'https://scanner.invalid/run/surface-1',
  }]);
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
  for (const name of [
    'domain-investigation-build', 'domain-investigation-surface-import', 'domain-investigation-vulnerability-import',
    'domain-investigation-show', 'domain-investigation-report', 'domain-investigation-stix', 'domain-investigation-handoff',
    'domain-investigation-promotion-candidates', 'domain-investigation-promote', 'domain-investigation-reject-promotion',
    'domain-investigation-revoke-promotion', 'domain-investigation-graph', 'domain-investigation-clear',
  ]) {
    assert.ok(WORKFLOW_HANDLERS.includes(name), `${name} must be dispatched by the shared shell adapter`);
  }

  let workspace = null;
  let outcome = await executeMissionCommand({ handler: 'domain-investigation-build', args: ['--stdin'], workspace, loadContent: loader });
  workspace = outcome.workspace;
  assert.equal(outcome.output.value.schemaVersion, 'domain-investigation-v1.0');
  assert.equal(outcome.output.value._authoritative, undefined);

  const prior = workspace;
  outcome = await executeMissionCommand({ handler: 'domain-investigation-surface-import', args: ['--stdin'], workspace, loadContent: loader });
  workspace = outcome.workspace;
  assert.notEqual(workspace, prior);
  assert.equal(outcome.output.value.imports.surface.length, 1);
  assert.equal(outcome.output.value._authoritative, undefined);

  outcome = await executeMissionCommand({ handler: 'domain-investigation-vulnerability-import', args: ['--stdin'], workspace, loadContent: loader });
  workspace = outcome.workspace;
  assert.equal(outcome.output.value.imports.vulnerabilities.length, 1);

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
  assert.equal(cleared.workspace, null);
});

test('promotion shell actions are explicit, atomic, volatile and graph projection-only', async () => {
  let workspace = null;
  let outcome = await executeMissionCommand({ handler: 'domain-investigation-build', args: ['--stdin'], workspace, loadContent: loader });
  workspace = outcome.workspace;
  outcome = await executeMissionCommand({ handler: 'domain-investigation-surface-import', args: ['--stdin'], workspace, loadContent: loader });
  workspace = outcome.workspace;

  outcome = await executeMissionCommand({ handler: 'domain-investigation-promotion-candidates', workspace, loadContent: loader });
  workspace = outcome.workspace;
  assert.equal(outcome.output.type, 'records');
  assert.equal(outcome.output.value.length, 1);
  assert.equal(outcome.output.value[0].status, 'candidate');
  assert.equal(outcome.output.value[0].authority, undefined);
  const candidateId = outcome.output.value[0].id;

  const beforeInvalid = workspace;
  await assert.rejects(
    () => executeMissionCommand({
      handler: 'domain-investigation-promote',
      args: [JSON.stringify({ candidateId: 'missing', at: '2026-09-13T12:30:00.000Z', actorLabel: 'analyst:g', reason: 'Invalid candidate must fail atomically.' })],
      workspace,
      loadContent: loader,
    }),
    error => error?.code === 'INVALID_ARGUMENT',
  );
  assert.equal(workspace, beforeInvalid);
  let shown = await executeMissionCommand({ handler: 'domain-investigation-show', workspace, loadContent: loader });
  assert.equal(shown.output.value.promotion.events.length, 0);

  outcome = await executeMissionCommand({
    handler: 'domain-investigation-promote',
    args: [JSON.stringify({ candidateId, at: '2026-09-13T13:00:00.000Z', actorLabel: 'analyst:g', reason: 'Validated against authorized investigation context.' })],
    workspace,
    loadContent: loader,
  });
  workspace = outcome.workspace;
  assert.equal(outcome.output.value._authoritative, undefined);
  assert.equal(outcome.output.value.promotion.events.at(-1).type, 'approved');
  assert.equal(outcome.output.value.promotion.effectiveAttestations.length, 1);
  const attestationId = outcome.output.value.promotion.effectiveAttestations[0].id;

  const graph = await executeMissionCommand({ handler: 'domain-investigation-graph', workspace, loadContent: loader });
  assert.equal(graph.output.type, 'graph');
  assert.ok(graph.output.value.nodes.some(node => node.type === 'promotion_candidate'));
  assert.ok(graph.output.value.nodes.some(node => node.type === 'promoted_evidence'));
  assert.ok(graph.output.value.edges.some(edge => edge.type === 'promoted_from'));

  outcome = await executeMissionCommand({
    handler: 'domain-investigation-revoke-promotion',
    args: [JSON.stringify({ attestationId, at: '2026-09-13T14:00:00.000Z', actorLabel: 'analyst:g', reason: 'Later validation disproved the finding.' })],
    workspace,
    loadContent: loader,
  });
  workspace = outcome.workspace;
  assert.equal(outcome.output.value.promotion.events.length, 2);
  assert.equal(outcome.output.value.promotion.events.at(-1).type, 'revoked');
  assert.equal(outcome.output.value.promotion.effectiveAttestations.length, 0);

  outcome = await executeMissionCommand({ handler: 'domain-investigation-clear', workspace, loadContent: loader });
  workspace = outcome.workspace;
  assert.equal(workspace, null);
  await assert.rejects(
    () => executeMissionCommand({ handler: 'domain-investigation-promotion-candidates', workspace, loadContent: loader }),
    error => error?.code === 'INVALID_ARGUMENT',
  );

  outcome = await executeMissionCommand({ handler: 'domain-investigation-build', args: ['--stdin'], workspace, loadContent: loader });
  workspace = outcome.workspace;
  outcome = await executeMissionCommand({ handler: 'domain-investigation-surface-import', args: ['--stdin'], workspace, loadContent: loader });
  workspace = outcome.workspace;
  outcome = await executeMissionCommand({ handler: 'domain-investigation-promotion-candidates', workspace, loadContent: loader });
  workspace = outcome.workspace;
  const rejectCandidateId = outcome.output.value[0].id;
  outcome = await executeMissionCommand({
    handler: 'domain-investigation-reject-promotion',
    args: [JSON.stringify({ candidateId: rejectCandidateId, at: '2026-09-13T13:00:00.000Z', actorLabel: 'analyst:g', reason: 'Not sufficient for promotion.' })],
    workspace,
    loadContent: loader,
  });
  assert.equal(outcome.output.value.promotion.events.at(-1).type, 'rejected');
  assert.equal(outcome.output.value.promotion.effectiveAttestations.length, 0);
});

test('bounded local content loader accepts only explicit Domain Investigation payload kinds', async () => {
  const content = JSON.stringify(enrichment());
  const load = createMissionContentLoader({ stdinContent: content, readFile: async () => content });
  assert.equal(await load({ kind: 'domain-enrichment', args: ['--stdin'] }), content);
  assert.equal(await load({ kind: 'domain-surface', args: ['--file', '/tmp/surface.json'] }), content);
  assert.equal(await load({ kind: 'domain-vulnerability', args: ['--stdin'] }), content);
  await assert.rejects(() => load({ kind: 'arbitrary-file', args: ['--stdin'] }), error => error?.code === 'POLICY_DENIED');
});

test('Node shell executor dispatches Domain Investigation through volatile workflow state', async () => {
  const content = JSON.stringify(enrichment());
  const executor = createNodeShellExecutor({
    registry: COMMAND_REGISTRY,
    missionStdin: content,
    missionReadFile: async () => content,
    fetchImpl: async () => { throw new Error('network must not be used'); },
  });
  const resolved = COMMAND_REGISTRY.resolve(['domain-investigation', 'build', '--stdin'], 'cli');
  assert.ok(resolved?.surfaceAvailable);
  const output = await executor.execute({ descriptor: resolved.descriptor, args: resolved.args, context: { surface: 'cli' } });
  assert.equal(output.type, 'record');
  assert.equal(output.value.schemaVersion, 'domain-investigation-v1.0');
  assert.equal(output.value._authoritative, undefined);

  const shown = COMMAND_REGISTRY.resolve(['domain-investigation', 'show'], 'cli');
  const showOutput = await executor.execute({ descriptor: shown.descriptor, args: shown.args, context: { surface: 'cli' } });
  assert.equal(showOutput.value.schemaVersion, 'domain-investigation-v1.0');
});

test('Web shell executor dispatches Domain Investigation through the shared workflow adapter', async () => {
  const executor = createBrowserShellExecutor({ client: {}, session: {} });
  const built = COMMAND_REGISTRY.resolve(['domain-investigation', 'build', JSON.stringify(enrichment())], 'web');
  assert.ok(built?.surfaceAvailable);
  const output = await executor.execute({ descriptor: built.descriptor, args: built.args, context: { surface: 'web' } });
  assert.equal(output.type, 'record');
  assert.equal(output.value.schemaVersion, 'domain-investigation-v1.0');
  assert.equal(output.value._authoritative, undefined);

  const shown = COMMAND_REGISTRY.resolve(['domain-investigation', 'show'], 'web');
  const showOutput = await executor.execute({ descriptor: shown.descriptor, args: shown.args, context: { surface: 'web' } });
  assert.equal(showOutput.value.schemaVersion, 'domain-investigation-v1.0');
  assert.equal(showOutput.value._authoritative, undefined);
});
