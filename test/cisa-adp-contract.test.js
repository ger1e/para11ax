import test from 'node:test';
import assert from 'node:assert/strict';

import { cisaAdpProvider } from '../src/providers/cisa-adp.js';

const CVE = 'CVE-2026-26021';
const CISA_ORG_ID = '134c704f-9b21-4f2e-91b3-4a467353bcc0';

function record({ includeCisa = true, malformedSsvc = false, kev = false } = {}) {
  const adp = [
    {
      title: 'CVE Program Container',
      providerMetadata: {
        orgId: 'af854a3a-2127-422b-91ae-364da2661108',
        shortName: 'CVE',
        dateUpdated: '2026-01-01T00:00:00.000Z',
      },
      metrics: [{ other: { type: 'ssvc', content: { options: [{ Exploitation: 'active' }] } } }],
    },
  ];

  if (includeCisa) {
    adp.push({
      title: 'CISA ADP Vulnrichment',
      providerMetadata: {
        orgId: CISA_ORG_ID,
        shortName: 'CISA-ADP',
        dateUpdated: '2026-02-12T21:15:58.717Z',
      },
      metrics: [
        {
          other: {
            type: 'ssvc',
            content: malformedSsvc
              ? { id: CVE, role: 'CISA Coordinator', version: '2.0.3', timestamp: '2026-02-12T21:15:49.981553Z' }
              : {
                  id: CVE,
                  role: 'CISA Coordinator',
                  options: [
                    { Exploitation: 'poc' },
                    { Automatable: 'no' },
                    { 'Technical Impact': 'total' },
                  ],
                  version: '2.0.3',
                  timestamp: '2026-02-12T21:15:49.981553Z',
                },
          },
        },
        ...(kev ? [{ other: { type: 'kev', content: { dateAdded: '2026-02-13' } } }] : []),
      ],
    });
  }

  return {
    dataType: 'CVE_RECORD',
    dataVersion: '5.2',
    cveMetadata: { cveId: CVE, state: 'PUBLISHED' },
    containers: { cna: { title: 'Fixture' }, adp },
  };
}

function jsonResponse(value, init = {}) {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { 'content-type': 'application/json', ...(init.headers ?? {}) },
  });
}

test('CISA ADP uses one fixed public CVE record GET and preserves all SSVC axes separately', async () => {
  const calls = [];
  const result = await cisaAdpProvider.run(
    { type: 'cve', value: CVE },
    {
      fetchImpl: async (url, options = {}) => {
        calls.push({ url: String(url), options });
        return jsonResponse(record({ kev: true }));
      },
    },
  );

  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, `https://cveawg.mitre.org/api/cve/${CVE}`);
  assert.equal(calls[0].options.method ?? 'GET', 'GET');
  assert.equal(calls[0].options.redirect, 'error');

  assert.equal(result.observationType, 'ssvc_assessment');
  assert.equal(result.verdict, 'assessed');
  assert.equal(result.attributes.exploitation, 'poc');
  assert.equal(result.attributes.automatable, 'no');
  assert.equal(result.attributes.technicalImpact, 'total');
  assert.equal(result.attributes.ssvcVersion, '2.0.3');
  assert.equal(result.attributes.assessedAt, '2026-02-12T21:15:49.981553Z');
  assert.equal(result.attributes.cisaAdpUpdatedAt, '2026-02-12T21:15:58.717Z');
  assert.equal(result.attributes.kevCataloged, true);
  assert.equal('score' in result, false);
  assert.equal('score' in result.attributes, false);
});

test('CISA ADP ignores unrelated ADP containers and represents missing CISA enrichment as no_result', async () => {
  const result = await cisaAdpProvider.run(
    { type: 'cve', value: CVE },
    { fetchImpl: async () => jsonResponse(record({ includeCisa: false })) },
  );

  assert.equal(result.observationType, 'ssvc_assessment');
  assert.equal(result.verdict, 'no_result');
  assert.deepEqual(result.attributes, {
    exploitation: null,
    automatable: null,
    technicalImpact: null,
    ssvcVersion: null,
    assessedAt: null,
    cisaAdpUpdatedAt: null,
    kevCataloged: false,
  });
});

test('CISA ADP fails closed on malformed successful CISA SSVC schema', async () => {
  await assert.rejects(
    () => cisaAdpProvider.run(
      { type: 'cve', value: CVE },
      { fetchImpl: async () => jsonResponse(record({ malformedSsvc: true })) },
    ),
    /invalid CISA ADP SSVC record/,
  );
});

test('CISA ADP enforces a bounded CVE record response before parsing', async () => {
  await assert.rejects(
    () => cisaAdpProvider.run(
      { type: 'cve', value: CVE },
      {
        fetchImpl: async () => new Response('{}', {
          status: 200,
          headers: {
            'content-type': 'application/json',
            'content-length': '3000000',
          },
        }),
      },
    ),
    /response_too_large|response too large/i,
  );
});
