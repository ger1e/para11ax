import test from 'node:test';
import assert from 'node:assert/strict';

import { createApp } from '../src/app.js';
import { toStixBundle } from '../src/export/stix.js';
import { createMcpHttpHandler } from '../src/mcp/server.js';
import {
  d3fendProvider,
  depsDevProvider,
  rdapProvider,
  shadowserverProvider,
  teamCymruProvider,
} from '../src/providers/index.js';

const TOKEN = 'e2e-fixture-token';
const NOW = '2026-09-14T06:00:00.000Z';
const env = { PARA11AX_TOKEN: TOKEN };

function json(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
}

function text(value, status = 200, contentType = 'text/plain') {
  return new Response(value, { status, headers: { 'content-type': contentType } });
}

function request(body) {
  return {
    method: 'POST',
    headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' },
    body,
  };
}

function mcpRequest(name, args, id = 1) {
  return request({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } });
}

function mcpStructured(response) {
  assert.equal(response.status, 200);
  assert.equal(response.body?.result?.isError, false, JSON.stringify(response.body));
  return response.body.result.structuredContent;
}

function seedDnsProvider() {
  return {
    name: 'cloudflare-dns',
    types: ['domain'],
    observationTypes: ['dns_resolution'],
    tier: 1,
    costClass: 'free',
    timeoutMs: 1000,
    cacheTtlMs: 1000,
    negativeCacheTtlMs: 1000,
    maxResponseBytes: 4096,
    fixedHosts: ['example.org'],
    methods: ['GET'],
    protocols: ['https:'],
    parserVersion: 'e2e.1',
    sourceUrl: 'https://example.org/docs',
    sourceRole: 'first_party',
    distribution: 'shareable',
    active: true,
    mode: 'enrich',
    fanoutEligible: true,
    sensitivity: 'public',
    authorization: 'none',
    retentionClass: 'normal',
    schedulerByType: {
      domain: {
        authorityClass: 'first_party',
        semanticUniqueness: 'unique',
        intelligenceValue: 'direct',
        pivotValue: 'high',
        latencyClass: 'fast',
      },
    },
    async run() {
      return {
        observationType: 'dns_resolution',
        verdict: 'observed',
        attributes: { resolver: 'fixture' },
        relationships: [{ type: 'resolves_to', targetType: 'ip', target: '216.90.108.31' }],
        references: ['https://example.org/reference'],
      };
    },
  };
}

test('public enrichment remains Evidence v2 compatible and does not absorb graph-only providers', async () => {
  const calls = [];
  const app = createApp({
    env,
    adapters: [rdapProvider, teamCymruProvider],
    now: () => NOW,
    nowMs: () => 1_000,
    fetchImpl: async (url) => {
      calls.push(String(url));
      if (String(url) === 'https://data.iana.org/rdap/ipv4.json') {
        return json({ services: [[['8.0.0.0/8'], ['https://rdap.arin.net/registry/']]] });
      }
      if (String(url) === 'https://rdap.arin.net/registry/ip/8.8.8.8') {
        return json({
          handle: 'NET-8-0-0-0-1', name: 'LVLT-GOGL-8-8-8', country: 'US',
          startAddress: '8.0.0.0', endAddress: '8.255.255.255',
          cidr0_cidrs: [{ v4prefix: '8.0.0.0', length: 8 }],
        });
      }
      throw new Error(`unexpected e2e fetch: ${url}`);
    },
  });

  const response = await app.handleEnrich(request({ indicator: '8.8.8.8', profile: 'standard' }));
  assert.equal(response.status, 200);
  assert.equal(response.body.schemaVersion, '2.0');
  assert.equal(typeof response.body.gatewayVersion, 'string');
  assert.equal(typeof response.body.requestId, 'string');
  assert.equal(response.body.indicator, '8.8.8.8');
  assert.equal(response.body.type, 'ip');
  assert.ok(Array.isArray(response.body.evidence));
  assert.ok(Array.isArray(response.body.relationships));
  assert.deepEqual(response.body.evidence.map(item => item.provider), ['rdap']);
  assert.equal(calls.some(value => value.includes('whois.cymru.com')), false);
});

test('graph pivot uses bounded Team Cymru network identity without widening baseline enrich', async () => {
  let cymruCalls = 0;
  const app = createApp({
    env,
    adapters: [seedDnsProvider(), teamCymruProvider],
    now: () => NOW,
    nowMs: (() => { let value = 2_000; return () => value++; })(),
    fetchImpl: async (url) => {
      if (String(url) !== 'https://v4.whois.cymru.com/cgi-bin/whois.cgi') throw new Error(`unexpected e2e fetch: ${url}`);
      cymruCalls += 1;
      return text('<PRE>AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name\n23028 | 216.90.108.31 | 216.90.108.0/24 | US | arin | 1998-09-25 | TEAM-CYMRU - Team Cymru Inc., US\n</PRE>', 200, 'text/html');
    },
  });

  const response = await app.handleIntelligence(request({ operation: 'pivot', indicator: 'example.com' }));
  assert.equal(response.status, 200);
  assert.deepEqual(response.body.baseline.evidence.map(item => item.provider), ['cloudflare-dns']);
  assert.deepEqual(response.body.intelligence.evidence.map(item => item.provider), ['team-cymru']);
  assert.equal(response.body.intelligence.evidence[0].observation.kind, 'network_identity');
  assert.equal(cymruCalls, 1);
});

test('supply-chain and defensive-knowledge lanes execute real adapters through the normalized intelligence surface', async () => {
  const app = createApp({
    env,
    adapters: [depsDevProvider, d3fendProvider],
    now: () => NOW,
    nowMs: (() => { let value = 3_000; return () => value++; })(),
    fetchImpl: async (url) => {
      const value = String(url);
      if (value === 'https://api.deps.dev/v3/systems/npm/packages/react/versions/18.2.0') {
        return json({
          versionKey: { system: 'NPM', name: 'react', version: '18.2.0' },
          publishedAt: '2022-06-14T19:46:42Z', isDefault: false, isDeprecated: false,
          deprecatedReason: '', licenses: ['MIT'], advisoryKeys: [], links: [],
        });
      }
      if (value === 'https://api.deps.dev/v3/systems/npm/packages/react/versions/18.2.0:dependencies') {
        return json({
          nodes: [
            { versionKey: { system: 'NPM', name: 'react', version: '18.2.0' }, bundled: false, relation: 'SELF', errors: [] },
            { versionKey: { system: 'NPM', name: 'loose-envify', version: '1.4.0' }, bundled: false, relation: 'DIRECT', errors: [] },
          ],
          edges: [{ fromNode: 0, toNode: 1, requirement: '^1.1.0' }], error: '',
        });
      }
      if (value === 'https://d3fend.mitre.org/api/offensive-technique/attack/T1059.json') {
        return json({
          off_to_def: { results: { bindings: [{
            off_tech_label: { value: 'Command and Scripting Interpreter' },
            def_tech_id: { value: 'D3-SCA' },
            def_tech_label: { value: 'Script Execution Analysis' },
            def_tactic_label: { value: 'Detect' },
          }] } },
          description: { '@graph': [] }, subtechniques: { '@graph': [] },
        });
      }
      throw new Error(`unexpected e2e fetch: ${url}`);
    },
  });

  const supply = await app.handleIntelligence(request({ operation: 'supply-chain', indicator: 'pkg:npm/react@18.2.0' }));
  assert.equal(supply.status, 200);
  assert.deepEqual(supply.body.providers.executed, ['deps-dev']);
  assert.equal(supply.body.evidence[0].observation.kind, 'supply_chain');
  assert.equal(supply.body.relationships[0].type, 'direct_dependency');

  const knowledge = await app.handleIntelligence(request({ operation: 'knowledge', indicator: 'T1059' }));
  assert.equal(knowledge.status, 200);
  assert.deepEqual(knowledge.body.providers.executed, ['d3fend']);
  assert.equal(knowledge.body.evidence[0].observation.kind, 'defensive_knowledge');
});

test('owned-asset lane fails closed without a server-owned scope and performs no egress', async () => {
  let egress = 0;
  const app = createApp({
    env: { ...env, SHADOWSERVER_API_KEY: 'fixture-key', SHADOWSERVER_API_SECRET: 'fixture-secret' },
    adapters: [shadowserverProvider],
    now: () => NOW,
    fetchImpl: async () => { egress += 1; throw new Error('owned-asset denial must precede egress'); },
  });

  const response = await app.handleIntelligence(request({ operation: 'asset', indicator: '203.0.113.10' }));
  assert.equal(response.status, 200);
  assert.deepEqual(response.body.providers.executed, []);
  assert.equal(response.body.providers.denied.some(item => item.provider === 'shadowserver'), true);
  assert.equal(egress, 0);
});

test('MCP intelligence and investigation/report surfaces remain compatible', async () => {
  const handler = createMcpHttpHandler({
    env,
    now: () => NOW,
    nowMs: () => 4_000,
    fetchImpl: async (url) => {
      if (String(url) === 'https://d3fend.mitre.org/api/offensive-technique/attack/T1059.json') {
        return json({
          off_to_def: { results: { bindings: [{
            off_tech_label: { value: 'Command and Scripting Interpreter' },
            def_tech_id: { value: 'D3-SCA' }, def_tech_label: { value: 'Script Execution Analysis' },
            def_tactic_label: { value: 'Detect' },
          }] } },
          description: { '@graph': [] }, subtechniques: { '@graph': [] },
        });
      }
      throw new Error(`unexpected e2e fetch: ${url}`);
    },
  });

  const intelligence = mcpStructured(await handler(mcpRequest('para11ax_intelligence', { operation: 'knowledge', indicator: 'T1059' }, 10)));
  assert.equal(intelligence.intelligence.evidence[0].provider, 'd3fend');

  const created = mcpStructured(await handler(mcpRequest('para11ax_investigation', { operation: 'create', title: 'Fabric E2E' }, 11)));
  assert.equal(created.investigation.title, 'Fabric E2E');
  const quality = mcpStructured(await handler(mcpRequest('para11ax_report', {
    kind: 'investigation', operation: 'quality', investigation: created.investigation,
  }, 12)));
  assert.equal(quality.ok, true);
  assert.equal(typeof quality.report, 'object');
});

test('shareable STIX excludes relationships originating from internal-only evidence', () => {
  const bundle = toStixBundle({
    schemaVersion: '2.0', gatewayVersion: 'e2e', requestId: 'e2e-stix',
    indicator: 'example.com', type: 'domain', queriedAt: NOW,
    evidence: [{
      provider: 'internal-fixture',
      policy: { distribution: 'internal_only' },
      references: ['https://internal.example/reference'],
      observation: { kind: 'malware_context', attributes: {} },
    }],
    relationships: [{
      provider: 'internal-fixture', source: 'example.com', sourceType: 'domain',
      type: 'uses', targetType: 'malware', target: 'InternalFixtureRAT',
    }],
  }, { now: () => NOW });

  assert.equal(bundle.objects.length, 1);
  assert.equal(bundle.objects[0].type, 'indicator');
  assert.equal(bundle.objects.some(item => item.type === 'malware'), false);
  assert.equal(JSON.stringify(bundle).includes('InternalFixtureRAT'), false);
  assert.equal(JSON.stringify(bundle).includes('internal.example'), false);
});
