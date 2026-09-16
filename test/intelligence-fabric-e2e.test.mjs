import test from 'node:test';
import assert from 'node:assert/strict';

import { createApp } from '../src/app.js';
import { teamCymruProvider } from '../src/providers/team-cymru.js';
import { createIntelligenceFabricFixture } from './helpers/intelligence-fabric-fixture.js';

const env = {
  PARA11AX_API_KEY: 'test-key',
};

function request(body, headers = {}) {
  return {
    method: 'POST',
    headers: {
      authorization: `Bearer ${env.PARA11AX_API_KEY}`,
      'content-type': 'application/json',
      ...headers,
    },
    body,
  };
}

function seedDnsProvider() {
  return {
    name: 'rdap',
    types: ['ip'],
    cacheTtlMs: 60_000,
    negativeCacheTtlMs: 60_000,
    costClass: 'free',
    timeoutMs: 1000,
    async run() {
      return {
        observationType: 'registration',
        verdict: 'observed',
        confidence: 0.8,
        attributes: { handle: 'NET-8-0-0-0-1' },
        relationships: [],
        references: ['https://rdap.arin.net/registry/ip/8.8.8.8'],
      };
    },
  };
}

test('intelligence fixture exposes the retained explicit capabilities', () => {
  const fixture = createIntelligenceFabricFixture();
  assert.ok(fixture.capabilities.includes('team-cymru'));
  assert.ok(fixture.capabilities.includes('shadowserver'));
  assert.ok(fixture.capabilities.includes('virustotal-graph'));
});

test('baseline enrich remains narrow and does not call Team Cymru', async () => {
  const calls = [];
  const app = createApp({
    env,
    adapters: [seedDnsProvider(), teamCymruProvider],
    fetchImpl: async (url) => {
      calls.push(String(url));
      throw new Error('unexpected fetch');
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
  assert.equal(calls.some(value => value === 'https://v4.whois.cymru.com/cgi-bin/whois.cgi'), false);
});

test('graph pivot uses bounded Team Cymru network identity without widening baseline enrich', async () => {
  let cymruCalls = 0;
  const app = createApp({
    env,
    adapters: [seedDnsProvider(), teamCymruProvider],
    fetchImpl: async (url) => {
      if (String(url) === 'https://v4.whois.cymru.com/cgi-bin/whois.cgi') {
        cymruCalls += 1;
        return new Response(
          '<PRE>AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name\n15169 | 8.8.8.8 | 8.8.8.0/24 | US | arin | 1992-12-01 | GOOGLE, US\n</PRE>',
          { status: 200, headers: { 'content-type': 'text/html' } },
        );
      }
      throw new Error(`unexpected fetch ${url}`);
    },
  });

  const response = await app.handleIntelligence(request({
    indicator: '8.8.8.8',
    capability: 'team-cymru',
  }));
  assert.equal(response.status, 200);
  assert.equal(cymruCalls, 1);
  assert.equal(response.body.evidence[0].provider, 'team-cymru');
  assert.equal(response.body.evidence[0].attributes.asn, 'AS15169');
});
