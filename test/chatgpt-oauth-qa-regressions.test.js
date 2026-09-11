import test from 'node:test';
import assert from 'node:assert/strict';

import { fetchJson } from '../src/core/fetch-json.js';
import { greynoiseProvider } from '../src/providers/greynoise.js';
import { toStixBundle } from '../src/export/stix.js';
import { runBatch } from '../src/core/batch.js';
import { correlateEvidence } from '../src/core/correlate.js';
import { buildEvidenceGraph } from '../src/core/evidence-graph.js';
import { buildDecisionSupport } from '../src/core/decision-engine.js';
import { createUserScannerHandler } from '../src/user-scanner.js';
import { MCP_TOOLS } from '../src/mcp/server.js';
import { applyChatGptToolMetadata } from '../src/mcp/chatgpt-tool-metadata.js';

const FP = 'a'.repeat(64);

function gatewayEnrichment(indicator = 'CVE-2021-44228', type = 'cve') {
  return {
    schemaVersion: '2.0',
    gatewayVersion: '2.0.0',
    requestId: 'qa-regression',
    indicator,
    type,
    queriedAt: '2026-09-11T18:00:00.000Z',
    evidence: [],
    relationships: [],
  };
}

function evidence(provider, kind, verdict = 'unknown', attributes = {}, extra = {}) {
  return {
    provider,
    indicator: extra.indicator ?? 'x',
    type: extra.type ?? 'ip',
    observation: {
      kind,
      verdict,
      confidence: null,
      firstSeen: extra.firstSeen ?? null,
      lastSeen: extra.lastSeen ?? null,
      tags: [],
      malwareFamily: null,
      actor: null,
      attributes,
    },
    relationships: [],
    references: [],
    retrievedAt: extra.retrievedAt ?? '2026-09-11T18:00:00.000Z',
    integrity: { parserVersion: 'qa', fingerprint: extra.fingerprint ?? FP, rawHash: null },
    semantics: { sourceRole: extra.sourceRole ?? 'first_party', semanticClass: extra.semanticClass ?? 'network_context' },
  };
}

test('caller Accept header overrides fetchJson default case-insensitively', async () => {
  await fetchJson('https://fixture.invalid/data', {
    headers: { Accept: 'application/dns-json' },
    fetchImpl: async (_url, init) => {
      const headers = new Headers(init.headers);
      assert.equal(headers.get('accept'), 'application/dns-json');
      return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
    },
  });
});

test('GreyNoise default lookup omits entitlement-gated workspace_labels', async () => {
  let requestUrl;
  await greynoiseProvider.run({ type: 'ip', value: '8.8.8.8' }, {
    env: { GREYNOISE_API_KEY: 'test-key' },
    fetchImpl: async url => {
      requestUrl = new URL(String(url));
      return new Response(JSON.stringify({ ip: '8.8.8.8', seen: false }), { status: 200, headers: { 'content-type': 'application/json' } });
    },
  });
  assert.equal(requestUrl.searchParams.has('workspace_labels'), false);
});

test('STIX identifiers are deterministic by default across repeated exports', () => {
  const input = gatewayEnrichment();
  const first = toStixBundle(input, { now: () => '2026-09-11T18:00:00.000Z' });
  const second = toStixBundle(input, { now: () => '2026-09-12T18:00:00.000Z' });
  assert.equal(first.id, second.id);
  assert.equal(first.objects[0].id, second.objects[0].id);
});

test('batch propagates partial enrichment status instead of masking it as ok', async () => {
  const out = await runBatch({
    indicators: ['example.com'],
    classify: value => ({ type: 'domain', value }),
    callLimitFor: () => 1,
    nowMs: (() => { let now = 1; return () => now++; })(),
    enrichOne: async () => ({ status: 'partial', budget: { providerCalls: 1 }, evidence: [], relationships: [] }),
  });
  assert.equal(out.results[0].status, 'partial');
  assert.equal(out.results[0].requestStatus, 'completed');
});

test('nested NVD CVSS object is projected into CVE risk axes', () => {
  const corr = correlateEvidence({
    indicator: 'CVE-2021-44228',
    type: 'cve',
    now: '2026-09-11T18:00:00.000Z',
    evidence: [evidence('nvd', 'vulnerability_metadata', 'cataloged', {
      cvss: { version: '3.1', score: 10, severity: 'CRITICAL', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' },
    }, { type: 'cve', indicator: 'CVE-2021-44228' })],
  });
  assert.deepEqual(corr.riskAxes.cvss, {
    score: 10,
    version: '3.1',
    severity: 'CRITICAL',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    provider: 'nvd',
  });
});

test('freshly retrieved KEV membership is current persistent state even when dateAdded is old', () => {
  const corr = correlateEvidence({
    indicator: 'CVE-2021-44228',
    type: 'cve',
    now: '2026-09-11T18:00:00.000Z',
    evidence: [evidence('cisa-kev', 'known_exploited', 'known_exploited', { cataloged: true }, {
      type: 'cve', indicator: 'CVE-2021-44228', firstSeen: '2021-12-10', retrievedAt: '2026-09-11T17:59:00.000Z',
    })],
  });
  assert.equal(corr.freshness.items[0].class, 'current');
  assert.equal(corr.freshness.items[0].observationClass, 'current');
  assert.equal(corr.freshness.overall, 'current');
});

test('hash evidence graph canonicalizes case-equivalent values and suppresses self pivots', () => {
  const hash = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';
  const graph = buildEvidenceGraph({
    indicator: hash,
    type: 'hash',
    relationships: [{ type: 'same_file_sha256', targetType: 'hash', target: hash.toUpperCase(), provider: 'circl-hashlookup' }],
  });
  const hashNodes = graph.nodes.filter(node => node.type === 'observable' && node.observableType === 'hash');
  assert.equal(hashNodes.length, 1);
  assert.equal(hashNodes[0].value, hash);
  assert.equal(graph.edges.some(edge => edge.type === 'related_to' && edge.source === edge.target), false);
});

test('hunt planner rejects GHSA aliases as Defender CveId pivots', () => {
  const ev = evidence('osv', 'open_source_vulnerability', 'cataloged', {}, { type: 'cve', indicator: 'CVE-2021-44228' });
  const decision = buildDecisionSupport({
    indicator: 'CVE-2021-44228',
    type: 'cve',
    evidence: [ev],
    relationships: [{ type: 'alias', targetType: 'cve', target: 'GHSA-jfh8-c2jp-5v3q', provider: 'osv' }],
    correlation: { evidenceQuality: { level: 'low' }, threatAssessment: { state: 'not_applicable' }, freshness: { overall: 'current' }, huntability: { level: 'medium' }, limitations: [], riskAxes: { kev: null, epss: null, cvss: null } },
    coverage: { materialLoss: false },
    now: '2026-09-11T18:00:00.000Z',
  });
  assert.equal(decision.huntPlan.some(hunt => hunt.kql.includes('GHSA-')), false);
});

test('hunt planner suppresses uncorroborated Modat passive-DNS hostname pivots', () => {
  const ev = evidence('modat', 'internet_exposure', 'observed', {}, { indicator: '8.8.8.8', type: 'ip' });
  const decision = buildDecisionSupport({
    indicator: '8.8.8.8',
    type: 'ip',
    evidence: [ev],
    relationships: [{ type: 'hostname', targetType: 'domain', target: 'random-passive-dns.example', provider: 'modat' }],
    correlation: { evidenceQuality: { level: 'low' }, threatAssessment: { state: 'insufficient', assessmentBasis: { providers: [] } }, freshness: { overall: 'unknown' }, huntability: { level: 'medium' }, limitations: ['infrastructure_only_evidence'] },
    coverage: { materialLoss: false },
    now: '2026-09-11T18:00:00.000Z',
  });
  assert.equal(decision.huntPlan.some(hunt => hunt.kql.includes('random-passive-dns.example')), false);
});

test('User Scanner downgrades generic/search-result hits instead of counting them as confirmed finds', async () => {
  const handler = createUserScannerHandler({
    env: {
      PARA11AX_TOKEN: 'secret',
      PARA11AX_USER_SCANNER_URL: 'https://worker.example/scan',
      PARA11AX_USER_SCANNER_TOKEN: 'worker-secret',
    },
    nowMs: (() => { let now = 100; return () => (now += 10); })(),
    fetchImpl: async () => new Response(JSON.stringify({
      summary: { total_scanned: 260, found: 2, not_found: 218, errors: 40, skipped: 0 },
      results: [
        { status: 'Found', site_name: 'Protonmail', category: 'Email', url: 'https://account.proton.me', extra: {} },
        { status: 'Found', site_name: 'Orcid', category: 'Learning', url: 'https://orcid.org/orcid-search/search?searchQuery=para11ax-qa-nonexistent-9f3a41', extra: { name: 'Unrelated Person', orcid_id: '0000-0000-0000-0000' } },
      ],
      errored_sites: [],
    }), { status: 200, headers: { 'content-type': 'application/json' } }),
  });
  const out = await handler({
    method: 'POST',
    headers: { authorization: 'Bearer secret', 'content-type': 'application/json' },
    body: { scanType: 'username', target: 'para11ax-qa-nonexistent-9f3a41' },
  });
  assert.equal(out.status, 200);
  assert.equal(out.body.summary.found, 0);
  assert.equal(out.body.summary.unverified, 2);
  assert.deepEqual(out.body.results.map(item => item.matchConfidence).sort(), ['search_result_only', 'unverified']);
  assert.equal(out.body.results.every(item => item.status === 'Unverified'), true);
});

test('Swarm MCP schema is explicit and rejects undeclared properties', () => {
  const tools = structuredClone(MCP_TOOLS);
  applyChatGptToolMetadata(tools);
  const swarm = tools.find(tool => tool.name === 'para11ax_swarm');
  assert.ok(swarm);
  assert.equal(swarm.inputSchema.additionalProperties, false);
  for (const field of ['command', 'sessionId', 'scope', 'startTime', 'endTime', 'query', 'page', 'pageSize', 'exportType', 'field', 'includeCounts', 'interval', 'size', 'sourceWorkspace', 'targetWorkspace', 'mode', 'nextToken']) {
    assert.ok(swarm.inputSchema.properties[field], `missing ${field}`);
  }
  assert.match(swarm.inputSchema.properties.startTime.description, /search|unique|timeseries/i);
});

test('MCP tool catalog remains stable across repeated metadata application', () => {
  const tools = structuredClone(MCP_TOOLS);
  applyChatGptToolMetadata(tools);
  const first = JSON.stringify(tools);
  applyChatGptToolMetadata(tools);
  assert.equal(JSON.stringify(tools), first);
  assert.equal(tools.length, 13);
});
