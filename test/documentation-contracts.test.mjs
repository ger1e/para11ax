import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { WORKFLOWS } from '../src/workflows.js';
import { createProviderRegistry } from '../src/core/provider-registry.js';
import { ALL_PROVIDERS } from '../src/providers/index.js';
import { EVIDENCE_SCHEMA_VERSION } from '../src/core/version.js';
import { EVIDENCE_GRAPH_SCHEMA_VERSION } from '../src/core/evidence-graph.js';
import { GUIDANCE_SCHEMA_VERSION } from '../src/core/guidance.js';

const read = path => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
const workflows = Object.keys(WORKFLOWS).sort();
const providerCount = createProviderRegistry(ALL_PROVIDERS).names().length;

function requireTokens(text, tokens, label) {
  for (const token of tokens) assert.ok(text.includes(token), `${label}: missing ${token}`);
}

function workflowTokens() {
  return workflows.map(type => `\`${type}\``);
}

test('architecture and API document all canonical workflow types', () => {
  const architecture = read('docs/ARCHITECTURE.md');
  const api = read('docs/API.md');
  requireTokens(architecture, workflowTokens(), 'architecture workflow contract');
  requireTokens(api, workflowTokens(), 'API workflow contract');
});

test('README provider count and production identity match canonical policy', () => {
  const readme = read('README.md');
  assert.ok(readme.includes(`${providerCount} upstream APIs and feeds`), 'README provider count drifted');
  assert.match(
    readme,
    /https:\/\/para11ax\.vercel\.app(?:\/app\/|\/)?/,
    'README canonical production identity drifted',
  );
});

test('current evidence projection versions are first-class documented contracts', () => {
  const schema = read('docs/EVIDENCE-SCHEMA.md');
  requireTokens(schema, [
    `Evidence Schema v${EVIDENCE_SCHEMA_VERSION.split('.')[0]}`,
    `Evidence Graph v${EVIDENCE_GRAPH_SCHEMA_VERSION}`,
    `Guidance v${GUIDANCE_SCHEMA_VERSION}`,
    '`evidenceGraph`',
    '`guidance`',
  ], 'evidence documentation');
  assert.match(
    schema,
    /(?:error[^\n]*(?:does not|do not|without)[^\n]*(?:evidenceGraph|guidance)|(?:evidenceGraph|guidance)[^\n]*(?:absent|not added)[^\n]*error)/i,
    'error-envelope boundary for Train 5 additive fields must be documented',
  );
});

test('API docs cover canonical public and protected route names', () => {
  const api = read('docs/API.md');
  for (const route of ['meta', 'health', 'status', 'enrich', 'batch', 'stix', 'swarm']) {
    assert.ok(api.includes(`/api/para11ax/${route}`), `API docs missing ${route}`);
  }
});

test('authoritative docs expose the current GreyNoise Swarm operator contract', () => {
  const shell = read('docs/SHELL.md');
  const swarm = read('docs/GREYNOISE-SWARM.md');
  const readme = read('README.md');
  const architecture = read('docs/ARCHITECTURE.md');
  const operations = read('docs/OPERATIONS.md');
  const providers = read('docs/PROVIDERS.md');
  const controls = read('docs/SECURITY-CONTROLS.md');
  const threatModel = read('docs/THREAT-MODEL.md');
  const endToEnd = read('docs/END-TO-END-EXAMPLE.md');

  for (const text of [shell, swarm, readme]) {
    requireTokens(text, [
      'swarm search',
      'swarm get',
      'swarm unique',
      'swarm timeseries',
      'swarm export',
    ], 'Swarm shell contract');
  }

  requireTokens(swarm, [
    'scope=workspace',
    'scope=demo',
    'Sensors entitlement',
    'Swarm entitlement',
    '4 MiB',
    'Evidence v2',
  ], 'Swarm boundary contract');

  for (const [label, text] of [
    ['architecture', architecture],
    ['operations', operations],
    ['providers', providers],
    ['security controls', controls],
    ['threat model', threatModel],
    ['end-to-end example', endToEnd],
  ]) {
    assert.match(text, /GreyNoise(?: Project)? Swarm/i, `${label}: missing GreyNoise Swarm coverage`);
  }
});

test('Maltego documentation covers every canonical workflow and certificate transport semantics', () => {
  const maltegoReadme = read('maltego/README.md');
  requireTokens(maltegoReadme, workflowTokens(), 'Maltego workflow documentation');
  requireTokens(maltegoReadme, ['EnrichCertificate', 'cert-sha256:'], 'certificate Maltego semantics');
});

test('Maltego CI documentation matches the bounded Ubuntu workflow', () => {
  const workflow = read('.github/workflows/tooling-smoke.yml');
  const maltegoReadme = read('maltego/README.md');
  const runsOn = [...workflow.matchAll(/runs-on:\s*([^\n]+)/g)].map(match => match[1].trim());
  assert.deepEqual(runsOn, ['ubuntu-latest']);
  assert.ok(maltegoReadme.includes('one bounded Ubuntu job'));
  assert.doesNotMatch(maltegoReadme, /Ubuntu, macOS and Windows/i);
});

test('contribution and security docs describe the repository as public', () => {
  const contributing = read('CONTRIBUTING.md');
  const controls = read('docs/SECURITY-CONTROLS.md');
  assert.match(contributing, /public personal-research\/lab PARA11AX project/);
  assert.doesNotMatch(contributing, /private personal-research\/lab/i);
  assert.doesNotMatch(controls, /private repository/i);
});

test('changelog records completed v8 consolidation capabilities', () => {
  const changelog = read('CHANGELOG.md');
  requireTokens(changelog, [
    'local case',
    'Evidence Graph v1.0',
    'Guidance v1.0',
    'certificate Maltego parity',
  ], 'v8 changelog');
});

test('core documentation explicitly rejects a universal maliciousness score', () => {
  const docs = ['README.md', 'docs/EVIDENCE-SCHEMA.md', 'docs/ARCHITECTURE.md'].map(read).join('\n');
  assert.match(docs, /no universal maliciousness score|does not[^\n]*universal[^\n]*score/i);
});
