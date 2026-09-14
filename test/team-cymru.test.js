import test from 'node:test';
import assert from 'node:assert/strict';

import { INTELLIGENCE_PROVIDER_MANIFEST } from '../src/providers/intelligence-manifest.js';
import { teamCymruProvider } from '../src/providers/team-cymru.js';

function text(value, status = 200, contentType = 'text/plain') {
  return new Response(value, { status, headers: { 'content-type': contentType } });
}

test('Team Cymru remains explicit free non-fanout network identity context', () => {
  const policy = INTELLIGENCE_PROVIDER_MANIFEST['team-cymru'];
  assert.ok(policy);
  assert.equal(policy.mode, 'graph');
  assert.equal(policy.fanoutEligible, false);
  assert.equal(policy.authorization, 'none');
  assert.equal(policy.sensitivity, 'public');
  assert.equal(policy.credentialEnv, null);
  assert.equal(policy.observationTypes.includes('network_identity'), true);
});

test('Team Cymru performs one bounded IP-to-ASN lookup and parses registry context only', async () => {
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

test('Team Cymru no-match is no_result, never safe', async () => {
  const output = await teamCymruProvider.run({ type: 'ip', value: '203.0.113.9' }, {
    fetchImpl: async () => text('<PRE>AS | IP | AS Name\nNA | 203.0.113.9 | NA\n</PRE>', 200, 'text/html'),
  });
  assert.equal(output.verdict, 'no_result');
});
