import test from 'node:test';
import assert from 'node:assert/strict';
import { vulncheckProvider } from '../src/providers/vulncheck.js';

function json(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
}

function context(fetchImpl, env = {}) {
  return {
    env: { VULNCHECK_API_TOKEN: 'test-token', ...env },
    signal: new AbortController().signal,
    fetchImpl,
  };
}

const CVE = 'CVE-2024-4577';

function exploitRecord(overrides = {}) {
  return {
    id: CVE,
    public_exploit_found: true,
    commercial_exploit_found: true,
    weaponized_exploit_found: true,
    max_exploit_maturity: 'weaponized',
    reported_exploited_by_honeypot_service: true,
    reported_exploited_by_vulncheck_canaries: true,
    reported_exploited: true,
    reported_exploited_by_threat_actors: true,
    reported_exploited_by_ransomware: true,
    reported_exploited_by_botnets: true,
    inKEV: true,
    inVCKEV: true,
    timeline: {
      first_exploit_published: '2023-01-13T00:00:00Z',
      first_exploit_published_weaponized_or_higher: '2024-06-07T00:00:00Z',
      first_reported_threat_actor: '2024-06-07T00:00:00Z',
      first_reported_ransomware: '2024-06-10T00:00:00Z',
    },
    counts: { exploits: 92, threat_actors: 4, botnets: 3, ransomware_families: 2 },
    exploits: [
      {
        url: 'https://example.test/poc',
        name: 'PoC',
        exploit_maturity: 'poc',
        exploit_availability: 'publicly-available',
        validation_level: 'vulncheck-exploit-dev-review',
      },
      {
        url: 'https://example.test/weaponized',
        name: 'Weaponized exploit',
        exploit_maturity: 'weaponized',
        exploit_availability: 'commercially-available',
        exploit_type: 'initial-access',
        validation_level: 'vulncheck-exploit-dev-review',
      },
    ],
    ...overrides,
  };
}

test('VulnCheck is a bounded CVE exploit-maturity provider', () => {
  assert.equal(vulncheckProvider.name, 'vulncheck');
  assert.deepEqual(vulncheckProvider.types, ['cve']);
  assert.equal(vulncheckProvider.observationType, 'exploit_maturity');
});

test('VulnCheck queries the documented exploits index once with bearer auth and normalizes maturity', async () => {
  const calls = [];
  const result = await vulncheckProvider.run({ type: 'cve', value: CVE }, context(async (url, options = {}) => {
    calls.push({ url: String(url), options });
    return json({ data: [exploitRecord()] });
  }));

  assert.equal(calls.length, 1);
  const url = new URL(calls[0].url);
  assert.equal(url.origin, 'https://api.vulncheck.com');
  assert.equal(url.pathname, '/v3/index/exploits');
  assert.equal(url.searchParams.get('cve'), CVE);
  assert.equal(url.searchParams.get('limit'), '1');
  assert.equal(calls[0].options.headers.Authorization, 'Bearer test-token');

  assert.equal(result.observationType, 'exploit_maturity');
  assert.equal(result.verdict, 'weaponized');
  assert.equal(result.confidence, 100);
  assert.equal(result.attributes.maxExploitMaturity, 'weaponized');
  assert.equal(result.attributes.publicExploitFound, true);
  assert.equal(result.attributes.commercialExploitFound, true);
  assert.equal(result.attributes.weaponizedExploitFound, true);
  assert.equal(result.attributes.reportedExploited, true);
  assert.equal(result.attributes.reportedExploitedByThreatActors, true);
  assert.equal(result.attributes.reportedExploitedByRansomware, true);
  assert.equal(result.attributes.inKev, true);
  assert.equal(result.attributes.inVcKev, true);
  assert.deepEqual(result.attributes.counts, { exploits: 92, threatActors: 4, botnets: 3, ransomwareFamilies: 2 });
  assert.equal(result.attributes.validatedExploitCount, 2);
  assert.deepEqual(result.relationships, []);
  assert.deepEqual(result.references, ['https://api.vulncheck.com/v3/index/exploits?cve=CVE-2024-4577&limit=1']);
});

test('VulnCheck never manufactures named actor or ransomware relationships from flags and counts alone', async () => {
  const result = await vulncheckProvider.run({ type: 'cve', value: CVE }, context(async () => json({
    data: [exploitRecord({
      reported_exploited_by_threat_actors: true,
      reported_exploited_by_ransomware: true,
      counts: { exploits: 1, threat_actors: 99, botnets: 0, ransomware_families: 88 },
    })],
  })));
  assert.deepEqual(result.relationships, []);
});

test('VulnCheck returns a truthful no-result record when the CVE has no exploit record', async () => {
  const result = await vulncheckProvider.run({ type: 'cve', value: 'CVE-2099-9999' }, context(async () => json({ data: [] })));
  assert.equal(result.observationType, 'exploit_maturity');
  assert.equal(result.verdict, 'no_result');
  assert.equal(result.confidence, 100);
  assert.deepEqual(result.relationships, []);
});

test('VulnCheck propagates auth and entitlement errors and rejects malformed successful schemas', async () => {
  await assert.rejects(
    vulncheckProvider.run({ type: 'cve', value: CVE }, context(async () => json({ error: true }, 401))),
    error => error?.status === 401,
  );
  await assert.rejects(
    vulncheckProvider.run({ type: 'cve', value: CVE }, context(async () => json({ error: true }, 403))),
    error => error?.status === 403,
  );
  await assert.rejects(
    vulncheckProvider.run({ type: 'cve', value: CVE }, context(async () => json({ data: 'not-an-array' }))),
    /provider_schema_invalid/,
  );
  await assert.rejects(
    vulncheckProvider.run({ type: 'cve', value: CVE }, context(async () => json({ data: [exploitRecord({ id: 'CVE-2024-0001' })] }))),
    /provider_schema_invalid/,
  );
});
