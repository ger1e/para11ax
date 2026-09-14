import test from 'node:test';
import assert from 'node:assert/strict';

import { INTELLIGENCE_PROVIDER_MANIFEST } from '../src/providers/intelligence-manifest.js';
import { semanticClass } from '../src/core/semantics.js';

function json(value, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json', ...extraHeaders },
  });
}

function text(value, status = 200, contentType = 'text/plain') {
  return new Response(value, { status, headers: { 'content-type': contentType } });
}

async function provider(path, exportName) {
  const mod = await import(path);
  return mod[exportName];
}

const first = 1756684800;
const last = 1756771200;
const firstIso = new Date(first * 1000).toISOString();
const lastIso = new Date(last * 1000).toISOString();

test('Task 14 capabilities are explicit non-fanout infrastructure context only', () => {
  const expected = {
    dnsdb: ['graph', 'passive_dns_history'],
    validin: ['graph', 'dns_history'],
    spur: ['graph', 'anonymization_infrastructure'],
    netify: ['graph', 'network_identity'],
    'team-cymru': ['graph', 'network_identity'],
  };
  for (const [name, [mode, kind]] of Object.entries(expected)) {
    const policy = INTELLIGENCE_PROVIDER_MANIFEST[name];
    assert.ok(policy, name);
    assert.equal(policy.mode, mode, `${name}.mode`);
    assert.equal(policy.fanoutEligible, false, `${name}.fanoutEligible`);
    assert.equal(policy.authorization, 'none', `${name}.authorization`);
    assert.equal(policy.sensitivity, 'public', `${name}.sensitivity`);
    assert.equal(policy.observationTypes.includes(kind), true, `${name}.observationTypes`);
  }
  assert.equal(semanticClass('dns_history'), 'dns_history');
  assert.equal(semanticClass('passive_dns_history'), 'passive_dns_history');
  assert.notEqual(semanticClass('dns_history'), semanticClass('passive_dns_history'));
});

test('DNSDB parses one bounded SAF stream and preserves historical DNS timestamps', async () => {
  const dnsdbProvider = await provider('../src/providers/dnsdb.js', 'dnsdbProvider');
  let calls = 0;
  const output = await dnsdbProvider.run({ type: 'domain', value: 'example.com' }, {
    env: { DNSDB_API_KEY: 'dnsdb-key' },
    fetchImpl: async (url, init) => {
      calls += 1;
      assert.equal(String(url), 'https://api.dnsdb.info/dnsdb/v2/lookup/rrset/name/example.com?limit=100');
      const headers = new Headers(init.headers);
      assert.equal(headers.get('x-api-key'), 'dnsdb-key');
      assert.equal(headers.get('accept'), 'application/x-ndjson');
      return text([
        JSON.stringify({ cond: 'begin' }),
        JSON.stringify({ obj: {
          count: 7,
          time_first: first,
          time_last: last,
          rrname: 'example.com.',
          rrtype: 'A',
          bailiwick: 'example.com.',
          rdata: ['203.0.113.10'],
        } }),
        JSON.stringify({ cond: 'limited', msg: 'Result limit reached' }),
      ].join('\n'), 200, 'application/x-ndjson');
    },
  });
  assert.equal(calls, 1);
  assert.equal(output.observationType, 'passive_dns_history');
  assert.equal(output.verdict, 'observed');
  assert.equal(output.confidence, null);
  assert.equal(output.firstSeen, firstIso);
  assert.equal(output.lastSeen, lastIso);
  assert.equal(output.attributes.truncated, true);
  assert.equal(output.attributes.recordCount, 1);
  assert.deepEqual(output.relationships, [{
    targetType: 'ip',
    target: '203.0.113.10',
    relationship: 'historical_dns_resolution',
    firstSeen: firstIso,
    lastSeen: lastIso,
  }]);
});

test('Validin keeps active historical DNS distinct from passive DNS and preserves seen windows', async () => {
  const validinProvider = await provider('../src/providers/validin.js', 'validinProvider');
  let calls = 0;
  const output = await validinProvider.run({ type: 'domain', value: 'example.com' }, {
    env: { VALIDIN_API_KEY: 'validin-key' },
    fetchImpl: async (url, init) => {
      calls += 1;
      assert.equal(String(url), 'https://api.validin.com/api/axon/domain/dns/history/example.com?exclude_nx=true&limit=100');
      assert.equal(new Headers(init.headers).get('authorization'), 'Bearer validin-key');
      return json({ records: [{
        rrname: 'example.com',
        rrtype: 'A',
        rdata: '203.0.113.20',
        time_first: first,
        time_last: last,
      }] });
    },
  });
  assert.equal(calls, 1);
  assert.equal(output.observationType, 'dns_history');
  assert.equal(output.verdict, 'observed');
  assert.equal(output.firstSeen, firstIso);
  assert.equal(output.lastSeen, lastIso);
  assert.equal(output.attributes.recordCount, 1);
  assert.deepEqual(output.relationships, [{
    targetType: 'ip',
    target: '203.0.113.20',
    relationship: 'historical_dns_resolution',
    firstSeen: firstIso,
    lastSeen: lastIso,
  }]);
});

test('Spur emits anonymization context without manufacturing a threat verdict', async () => {
  const spurProvider = await provider('../src/providers/spur.js', 'spurProvider');
  let calls = 0;
  const output = await spurProvider.run({ type: 'ip', value: '89.39.106.191' }, {
    env: { SPUR_TOKEN: 'spur-token' },
    fetchImpl: async (url, init) => {
      calls += 1;
      assert.equal(String(url), 'https://api.spur.us/v2/context/89.39.106.191');
      assert.equal(new Headers(init.headers).get('token'), 'spur-token');
      return json({
        as: { number: 49981, organization: 'WorldStream' },
        infrastructure: 'DATACENTER',
        ip: '89.39.106.191',
        organization: 'WorldStream B.V.',
        risks: ['CALLBACK_PROXY', 'TUNNEL'],
        services: ['OPENVPN'],
        tunnels: [{ anonymous: true, operator: 'PROTON_VPN', type: 'VPN', entries: ['89.39.106.82'] }],
      }, 200, { 'x-result-dt': '20260901' });
    },
  });
  assert.equal(calls, 1);
  assert.equal(output.observationType, 'anonymization_infrastructure');
  assert.equal(output.verdict, 'observed');
  assert.equal(output.confidence, null);
  assert.equal(output.firstSeen ?? null, null);
  assert.equal(output.lastSeen ?? null, null);
  assert.equal(output.attributes.resultDate, '2026-09-01');
  assert.equal(output.attributes.asn, 49981);
  assert.deepEqual(output.attributes.risks, ['CALLBACK_PROXY', 'TUNNEL']);
  assert.deepEqual(output.attributes.services, ['OPENVPN']);
  assert.deepEqual(output.attributes.anonymizationOperators, ['PROTON_VPN']);
});

test('Netify uses one point lookup and keeps application/network identity contextual', async () => {
  const netifyProvider = await provider('../src/providers/netify.js', 'netifyProvider');
  let calls = 0;
  const output = await netifyProvider.run({ type: 'ip', value: '8.8.8.8' }, {
    env: { NETIFY_API_KEY: 'netify-key' },
    fetchImpl: async (url, init) => {
      calls += 1;
      assert.equal(String(url), 'https://feeds.netify.ai/api/v2/ips/8.8.8.8');
      assert.equal(new Headers(init.headers).get('x-api-key'), 'netify-key');
      return json({
        status_code: 0,
        status_message: 'Success.',
        data: {
          address: '8.8.8.8',
          shared_score: 95,
          is_anycast: true,
          asn_route: '8.8.8.0/24',
          asn: { tag: 'AS15169', label: 'Google' },
          network: { tag: 'google', label: 'Google' },
          platform: { tag: 'google-cloud', label: 'Google Cloud' },
          application_list: [
            { id: 1, tag: 'google-dns', label: 'Google DNS' },
            { id: 1, tag: 'google-dns', label: 'Google DNS' },
          ],
          hostnames: ['dns.google', 'dns.google'],
        },
      });
    },
  });
  assert.equal(calls, 1);
  assert.equal(output.observationType, 'network_identity');
  assert.equal(output.verdict, 'observed');
  assert.equal(output.confidence, null);
  assert.equal(output.attributes.asn, 'AS15169');
  assert.equal(output.attributes.asnRoute, '8.8.8.0/24');
  assert.deepEqual(output.attributes.applications, ['google-dns']);
  assert.deepEqual(output.relationships, [{ targetType: 'domain', target: 'dns.google', relationship: 'network_hostname' }]);
});

test('Team Cymru stays one explicit HTTPS graph lookup and parses registry context only', async () => {
  const teamCymruProvider = await provider('../src/providers/team-cymru.js', 'teamCymruProvider');
  let calls = 0;
  const output = await teamCymruProvider.run({ type: 'ip', value: '216.90.108.31' }, {
    fetchImpl: async (url, init) => {
      calls += 1;
      assert.equal(String(url), 'https://v4.whois.cymru.com/cgi-bin/whois.cgi');
      assert.equal(init.method, 'POST');
      const headers = new Headers(init.headers);
      assert.equal(headers.get('content-type'), 'application/x-www-form-urlencoded');
      const form = new URLSearchParams(init.body);
      assert.equal(form.get('action'), 'do_whois');
      assert.equal(form.get('family'), 'ipv4');
      assert.equal(form.get('method_whois'), 'whois');
      assert.equal(form.get('bulk_paste'), '216.90.108.31');
      return text('<PRE>AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name\n23028 | 216.90.108.31 | 216.90.108.0/24 | US | arin | 1998-09-25 | TEAM-CYMRU - Team Cymru Inc., US\n</PRE>', 200, 'text/html');
    },
  });
  assert.equal(calls, 1);
  assert.equal(output.observationType, 'network_identity');
  assert.equal(output.verdict, 'observed');
  assert.equal(output.confidence, null);
  assert.deepEqual(output.attributes, {
    asn: 'AS23028',
    prefix: '216.90.108.0/24',
    countryCode: 'US',
    registry: 'arin',
    allocated: '1998-09-25',
    asName: 'TEAM-CYMRU - Team Cymru Inc., US',
  });
});

test('Task 14 providers use truthful no-result semantics and preserve entitlement failures', async () => {
  const dnsdbProvider = await provider('../src/providers/dnsdb.js', 'dnsdbProvider');
  const validinProvider = await provider('../src/providers/validin.js', 'validinProvider');
  const netifyProvider = await provider('../src/providers/netify.js', 'netifyProvider');
  const teamCymruProvider = await provider('../src/providers/team-cymru.js', 'teamCymruProvider');
  const spurProvider = await provider('../src/providers/spur.js', 'spurProvider');

  const dnsdbEmpty = await dnsdbProvider.run({ type: 'domain', value: 'empty.example' }, {
    env: { DNSDB_API_KEY: 'key' },
    fetchImpl: async () => text('{"cond":"begin"}\n{"cond":"succeeded"}', 200, 'application/x-ndjson'),
  });
  assert.equal(dnsdbEmpty.verdict, 'no_result');

  const validinEmpty = await validinProvider.run({ type: 'domain', value: 'empty.example' }, {
    env: { VALIDIN_API_KEY: 'key' }, fetchImpl: async () => json({ records: [] }),
  });
  assert.equal(validinEmpty.verdict, 'no_result');

  const netifyEmpty = await netifyProvider.run({ type: 'ip', value: '203.0.113.9' }, {
    env: { NETIFY_API_KEY: 'key' }, fetchImpl: async () => json({ message: 'not found' }, 404),
  });
  assert.equal(netifyEmpty.verdict, 'no_result');

  const cymruEmpty = await teamCymruProvider.run({ type: 'ip', value: '203.0.113.9' }, {
    fetchImpl: async () => text('<PRE>AS | IP | AS Name\nNA | 203.0.113.9 | NA\n</PRE>', 200, 'text/html'),
  });
  assert.equal(cymruEmpty.verdict, 'no_result');

  for (const [candidate, input, env] of [
    [dnsdbProvider, { type: 'domain', value: 'example.com' }, { DNSDB_API_KEY: 'key' }],
    [validinProvider, { type: 'domain', value: 'example.com' }, { VALIDIN_API_KEY: 'key' }],
    [spurProvider, { type: 'ip', value: '8.8.8.8' }, { SPUR_TOKEN: 'key' }],
    [netifyProvider, { type: 'ip', value: '8.8.8.8' }, { NETIFY_API_KEY: 'key' }],
  ]) {
    await assert.rejects(
      candidate.run(input, { env, fetchImpl: async () => json({ error: 'forbidden' }, 403) }),
      error => error?.status === 403,
      candidate.name,
    );
  }
});

test('credentialed Task 14 providers fail before egress when not configured', async () => {
  const cases = [
    [await provider('../src/providers/dnsdb.js', 'dnsdbProvider'), { type: 'domain', value: 'example.com' }],
    [await provider('../src/providers/validin.js', 'validinProvider'), { type: 'domain', value: 'example.com' }],
    [await provider('../src/providers/spur.js', 'spurProvider'), { type: 'ip', value: '8.8.8.8' }],
    [await provider('../src/providers/netify.js', 'netifyProvider'), { type: 'ip', value: '8.8.8.8' }],
  ];
  for (const [candidate, input] of cases) {
    let called = false;
    await assert.rejects(candidate.run(input, {
      env: {},
      fetchImpl: async () => { called = true; return json({}); },
    }), /not configured/i);
    assert.equal(called, false, candidate.name);
  }
});
