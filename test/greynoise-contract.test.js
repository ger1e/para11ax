import test from 'node:test';
import assert from 'node:assert/strict';
import { greynoiseProvider } from '../src/providers/greynoise.js';
import { PROVIDER_MANIFEST } from '../src/providers/manifest.js';

function json(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
}

test('GreyNoise default v3 IP lookup uses the global dataset without entitlement-gated workspace labels', async () => {
  let request;
  const output = await greynoiseProvider.run(
    { type: 'ip', value: '8.8.8.8' },
    {
      env: { GREYNOISE_API_KEY: 'test-key' },
      fetchImpl: async (url, init) => {
        request = { url: String(url), init };
        return json({
          ip: '8.8.8.8',
          classification: 'suspicious',
          actor: 'example-actor',
          first_seen: '2026-09-01',
          last_seen: '2026-09-06',
          spoofable: false,
          tags: ['SSH Scanner'],
          cve: ['CVE-2026-1234'],
          metadata: {
            asn: 'AS15169',
            organization: 'Google LLC',
            rdns: 'dns.google',
            source_country_code: 'US',
          },
          raw_data: { scan: [{ port: 22, protocol: 'TCP' }, { port: 443, protocol: 'TCP' }] },
        });
      },
    },
  );

  const url = new URL(request.url);
  assert.equal(url.pathname, '/v3/ip/8.8.8.8');
  assert.equal(url.searchParams.has('workspace_labels'), false);
  assert.equal(request.init.headers.key, 'test-key');
  assert.equal(output.verdict, 'suspicious');
  assert.deepEqual(output.attributes.datasetScopes, ['greynoise']);
  assert.equal(output.attributes.actor, 'example-actor');
  assert.deepEqual(output.attributes.cves, ['CVE-2026-1234']);
  assert.deepEqual(output.attributes.scannedPorts, ['22/TCP', '443/TCP']);
});

test('GreyNoise allows an explicit restricted Project Swarm dataset scope list', async () => {
  let requestUrl;
  const output = await greynoiseProvider.run(
    { type: 'ip', value: '1.1.1.1' },
    {
      env: {
        GREYNOISE_API_KEY: 'test-key',
        GREYNOISE_WORKSPACE_LABELS: 'personal, community,invalid,personal',
      },
      fetchImpl: async url => {
        requestUrl = String(url);
        return json({ ip: '1.1.1.1', seen: false });
      },
    },
  );

  assert.equal(new URL(requestUrl).searchParams.get('workspace_labels'), 'personal,community');
  assert.deepEqual(output.attributes.datasetScopes, ['personal', 'community']);
});

test('GreyNoise normalizes an explicit v3 no-result response', async () => {
  const output = await greynoiseProvider.run(
    { type: 'ip', value: '203.0.113.8' },
    {
      env: { GREYNOISE_API_KEY: 'test-key' },
      fetchImpl: async () => json({ ip: '203.0.113.8', seen: false }),
    },
  );

  assert.equal(output.verdict, 'no_result');
  assert.equal(output.attributes.noise, false);
  assert.deepEqual(output.attributes.datasetScopes, ['greynoise']);
});

test('GreyNoise adapter fails closed without revealing credential identifiers', async () => {
  await assert.rejects(
    () => greynoiseProvider.run(
      { type: 'ip', value: '8.8.8.8' },
      { fetchImpl: async () => json({}) },
    ),
    error => error?.message === 'provider credential not configured' && !error.message.includes('GREYNOISE_API_KEY'),
  );
});

test('GreyNoise manifest requires the configured API credential', () => {
  assert.equal(PROVIDER_MANIFEST.greynoise.credentialEnv, 'GREYNOISE_API_KEY');
  assert.equal(PROVIDER_MANIFEST.greynoise.optionalCredential, false);
});
