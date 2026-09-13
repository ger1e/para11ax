import test from 'node:test';
import assert from 'node:assert/strict';
import { modatProvider } from '../src/providers/modat.js';

function json(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
}

test('Modat host 404 is neutral absence rather than provider failure', async () => {
  const output = await modatProvider.run(
    { type: 'ip', value: '192.0.2.44' },
    {
      env: { MODAT_API_KEY: 'test-key' },
      fetchImpl: async () => json({ detail: 'Not Found' }, 404),
    },
  );
  assert.equal(output.observationType, 'internet_exposure');
  assert.equal(output.verdict, 'no_result');
  assert.equal(output.attributes.ip, '192.0.2.44');
  assert.equal(output.attributes.serviceCount, 0);
});

test('Modat DNS-zone 404 is neutral absence rather than provider failure', async () => {
  const output = await modatProvider.run(
    { type: 'domain', value: 'missing.example' },
    {
      env: { MODAT_API_KEY: 'test-key' },
      fetchImpl: async () => json({ detail: 'Not Found' }, 404),
    },
  );
  assert.equal(output.observationType, 'passive_dns');
  assert.equal(output.verdict, 'no_result');
  assert.equal(output.attributes.fqdn, 'missing.example');
  assert.equal(output.attributes.addressCount, 0);
});

test('Modat host parser preserves current Magnify host fields', async () => {
  let request;
  const output = await modatProvider.run(
    { type: 'ip', value: '1.1.1.1' },
    {
      env: { MODAT_API_KEY: 'test-key' },
      fetchImpl: async (url, options) => {
        request = { url, options };
        return json({
          page_nr: 1,
          total_pages: 1,
          total_records: 1,
          page: [{
            ip: '1.1.1.1',
            asn: { number: 13335, org: 'Cloudflare, Inc.' },
            geo: { country_iso_code: 'US' },
            fqdns: ['one.one.one.one'],
            tags: ['DNS'],
            cves: [{ id: 'CVE-2026-0001', is_kev: false }],
            services: [{
              transport: 'tcp',
              ports: [443, 8443],
              last_scanned_port: 443,
              protocol: 'http',
              scanned_at: '2026-09-12T12:00:00Z',
            }],
          }],
        });
      },
    },
  );

  assert.equal(request.url, 'https://api.magnify.modat.io/host/search/v1');
  assert.equal(request.options.headers.Authorization, 'Bearer test-key');
  assert.deepEqual(JSON.parse(request.options.body), {
    query: 'ip:"1.1.1.1"',
    page: 1,
    page_size: 10,
  });
  assert.equal(output.verdict, 'observed');
  assert.equal(output.attributes.asn, 'AS13335');
  assert.equal(output.attributes.organization, 'Cloudflare, Inc.');
  assert.equal(output.attributes.country, 'US');
  assert.deepEqual(output.attributes.ports, [443, 8443]);
  assert.deepEqual(output.attributes.serviceTags, ['DNS']);
  assert.deepEqual(output.attributes.cves, ['CVE-2026-0001']);
});

test('Modat DNS parser preserves current Magnify DNS record field names', async () => {
  const output = await modatProvider.run(
    { type: 'domain', value: 'example.com' },
    {
      env: { MODAT_API_KEY: 'test-key' },
      fetchImpl: async () => json({
        fqdn: 'example.com',
        discovered_at: '2026-09-10T00:00:00Z',
        created_at: '2026-09-10T00:00:00Z',
        modified_at: '2026-09-12T18:30:00Z',
        records: {
          a: [{ ttl: 300, created_at: '2026-09-10T00:00:00Z', ip: '93.184.216.34' }],
          aaaa: [{ ttl: 300, created_at: '2026-09-10T00:00:00Z', ip: '2606:2800:220:1:248:1893:25c8:1946' }],
          cname: [{ ttl: 300, created_at: '2026-09-10T00:00:00Z', cname: 'www.example.net' }],
          ns: [{ ttl: 300, created_at: '2026-09-10T00:00:00Z', ns: 'ns1.example.net' }],
          mx: [{ ttl: 300, created_at: '2026-09-10T00:00:00Z', priority: 10, host: 'mail.example.net' }],
        },
      }),
    },
  );

  assert.equal(output.verdict, 'observed');
  assert.equal(output.lastSeen, '2026-09-12T18:30:00Z');
  assert.equal(output.attributes.addressCount, 2);
  assert.equal(output.attributes.aliasCount, 1);
  assert.equal(output.attributes.nameserverCount, 1);
  assert.equal(output.attributes.mailExchangerCount, 1);
  assert.deepEqual(
    output.relationships.map(item => [item.type, item.value, item.relationship]),
    [
      ['ip', '93.184.216.34', 'resolves_to'],
      ['ip', '2606:2800:220:1:248:1893:25c8:1946', 'resolves_to'],
      ['domain', 'www.example.net', 'cname'],
      ['domain', 'ns1.example.net', 'nameserver'],
      ['domain', 'mail.example.net', 'mail_exchanger'],
    ],
  );
});
