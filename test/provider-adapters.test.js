import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ipinfoProvider, ripestatProvider, greynoiseProvider, abuseipdbProvider,
  shodanProvider, censysProvider, cloudflareRadarProvider, virustotalProvider,
  otxProvider, threatfoxProvider, urlscanProvider, webamonProvider,
  pulsediveProvider, urlhausProvider, circlHashlookupProvider,
  malwarebazaarProvider, malpediaProvider, hybridAnalysisProvider,
  nvdProvider, osvProvider,
} from '../src/providers/index.js';

const SECRET = 'TOPSECRET';
function json(value, status = 200, headers = {}) {
  return new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json', ...headers } });
}
async function invoke(adapter, input, raw, env = {}) {
  let captured;
  const fetchImpl = async (url, init) => { captured = { url: String(url), init }; return json(raw); };
  const data = await adapter.run(input, { fetchImpl, env, signal: new AbortController().signal });
  return { captured, data };
}
function noSecret(data) { assert.equal(JSON.stringify(data).includes(SECRET), false); }

const cases = [
  [ipinfoProvider, { value: '8.8.8.8', type: 'ip' }, { ip: '8.8.8.8', asn: 'AS15169', as_name: 'Google LLC', as_domain: 'google.com', country_code: 'US' }, { IPINFO_TOKEN: SECRET }, 'api.ipinfo.io', '/lite/8.8.8.8', 'GET'],
  [ripestatProvider, { value: '8.8.8.8', type: 'ip' }, { data: { asns: [15169], prefix: '8.8.8.0/24' } }, {}, 'stat.ripe.net', '/data/network-info/data.json', 'GET'],
  [greynoiseProvider, { value: '8.8.8.8', type: 'ip' }, { ip: '8.8.8.8', noise: false, riot: true, classification: 'benign', name: 'Google Public DNS', link: 'https://viz.greynoise.io/ip/8.8.8.8', last_seen: '2026-08-20' }, { GREYNOISE_API_KEY: SECRET }, 'api.greynoise.io', '/v3/ip/8.8.8.8', 'GET'],
  [abuseipdbProvider, { value: '8.8.8.8', type: 'ip' }, { data: { ipAddress: '8.8.8.8', abuseConfidenceScore: 10, totalReports: 3, countryCode: 'US', isp: 'Google', domain: 'google.com', lastReportedAt: '2026-08-19T00:00:00+00:00' } }, { ABUSEIPDB_API_KEY: SECRET }, 'api.abuseipdb.com', '/api/v2/check', 'GET'],
  [shodanProvider, { value: '8.8.8.8', type: 'ip' }, { ip_str: '8.8.8.8', asn: 'AS15169', org: 'Google LLC', country_code: 'US', ports: [53, 443], hostnames: ['dns.google'], data: [] }, { SHODAN_API_KEY: SECRET }, 'api.shodan.io', '/shodan/host/8.8.8.8', 'GET'],
  [censysProvider, { value: '8.8.8.8', type: 'ip' }, { result: { resource: { ip: '8.8.8.8', autonomous_system: { asn: 15169, name: 'GOOGLE' }, location: { country: 'United States' }, services: [{ port: 443, service_name: 'HTTP' }] } } }, { CENSYS_PAT: SECRET }, 'api.platform.censys.io', '/v3/global/asset/host/8.8.8.8', 'GET'],
  [cloudflareRadarProvider, { value: '8.8.8.8', type: 'ip' }, { success: true, result: { ip: '8.8.8.8', asn: 15169, asName: 'GOOGLE', country: 'US' } }, { CLOUDFLARE_RADAR_TOKEN: SECRET }, 'api.cloudflare.com', '/client/v4/radar/entities/ip', 'GET'],
  [virustotalProvider, { value: 'example.com', type: 'domain' }, { data: { id: 'example.com', attributes: { last_analysis_stats: { malicious: 1, suspicious: 0, harmless: 10, undetected: 2 }, reputation: -1, tags: ['test'], last_analysis_date: 1787200000 } } }, { VIRUSTOTAL_API_KEY: SECRET }, 'www.virustotal.com', '/api/v3/domains/example.com', 'GET'],
  [otxProvider, { value: 'example.com', type: 'domain' }, { pulse_info: { count: 1, pulses: [{ name: 'Demo', tags: ['tag1'] }] }, reputation: 1 }, { OTX_API_KEY: SECRET }, 'otx.alienvault.com', '/api/v1/indicators/domain/example.com/general', 'GET'],
  [threatfoxProvider, { value: 'example.com', type: 'domain' }, { query_status: 'ok', data: [{ ioc: 'example.com', threat_type: 'botnet_cc', malware_printable: 'ExampleMal', confidence_level: 90, first_seen: '2026-08-19 00:00:00 UTC', last_seen: '2026-08-20 00:00:00 UTC', tags: ['x'] }] }, { ABUSECH_API_KEY: SECRET }, 'threatfox-api.abuse.ch', '/api/v1/', 'POST'],
  [urlscanProvider, { value: 'example.com', type: 'domain' }, { results: [{ task: { url: 'https://example.com/' }, page: { domain: 'example.com', ip: '192.0.2.10', url: 'https://example.com/' }, verdicts: { overall: { malicious: false } }, indexedAt: '2026-08-20T00:00:00Z' }] }, { URLSCAN_API_KEY: SECRET }, 'urlscan.io', '/api/v1/search', 'GET'],
  [webamonProvider, { value: 'example.com', type: 'domain' }, { results: [{ domain: 'example.com', ip: '192.0.2.10', url: 'https://example.com/' }], total: 1 }, { WEBAMON_API_KEY: SECRET }, 'pro.webamon.com', '/search', 'GET'],
  [pulsediveProvider, { value: 'example.com', type: 'domain' }, { indicator: 'example.com', type: 'domain', risk: 'medium', stamp_added: '2026-08-01 00:00:00', stamp_updated: '2026-08-20 00:00:00', threats: [{ name: 'DemoThreat' }] }, { PULSEDIVE_API_KEY: SECRET }, 'pulsedive.com', '/api/indicator.php', 'GET'],
  [urlhausProvider, { value: 'https://example.com/a', type: 'url' }, { query_status: 'ok', url: 'https://example.com/a', url_status: 'online', threat: 'malware_download', tags: ['x'], date_added: '2026-08-20 00:00:00 UTC', payloads: [{ response_sha256: 'a'.repeat(64) }] }, { ABUSECH_API_KEY: SECRET }, 'urlhaus-api.abuse.ch', '/v1/url/', 'POST'],
  [circlHashlookupProvider, { value: 'a'.repeat(64), type: 'hash' }, { SHA256: 'a'.repeat(64), MD5: 'b'.repeat(32), SHA1: 'c'.repeat(40), FileName: 'demo.exe' }, {}, 'hashlookup.circl.lu', `/lookup/sha256/${'a'.repeat(64)}`, 'GET'],
  [malwarebazaarProvider, { value: 'a'.repeat(64), type: 'hash' }, { query_status: 'ok', data: [{ sha256_hash: 'a'.repeat(64), sha1_hash: 'c'.repeat(40), md5_hash: 'b'.repeat(32), file_name: 'demo.exe', file_type: 'exe', signature: 'ExampleMal', first_seen: '2026-08-20 00:00:00', tags: ['x'] }] }, { ABUSECH_API_KEY: SECRET }, 'mb-api.abuse.ch', '/api/v1/', 'POST'],
  [malpediaProvider, { value: 'a'.repeat(64), type: 'hash' }, { sha256: 'a'.repeat(64), md5: 'b'.repeat(32), family: 'win.example' }, { MALPEDIA_API_TOKEN: SECRET }, 'malpedia.caad.fkie.fraunhofer.de', `/api/get/sample/${'a'.repeat(64)}/info`, 'GET'],
  [hybridAnalysisProvider, { value: 'a'.repeat(64), type: 'hash' }, { sha256s: ['a'.repeat(64)], reports: [{ id: 'r1', environment_id: 160, state: 'SUCCESS', verdict: 'malicious' }] }, { HYBRID_ANALYSIS_API_KEY: SECRET }, 'hybrid-analysis.com', '/api/v2/search/hash', 'GET'],
  [nvdProvider, { value: 'CVE-2026-12345', type: 'cve' }, { vulnerabilities: [{ cve: { id: 'CVE-2026-12345', published: '2026-08-01T00:00:00.000', lastModified: '2026-08-20T00:00:00.000', descriptions: [{ lang: 'en', value: 'demo' }], metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8, baseSeverity: 'CRITICAL' } }] }, weaknesses: [] } }] }, { NVD_API_KEY: SECRET }, 'services.nvd.nist.gov', '/rest/json/cves/2.0', 'GET'],
  [osvProvider, { value: 'CVE-2026-12345', type: 'cve' }, { id: 'CVE-2026-12345', aliases: ['GHSA-demo'], published: '2026-08-01T00:00:00Z', modified: '2026-08-20T00:00:00Z', summary: 'demo', affected: [] }, {}, 'api.osv.dev', '/v1/vulns/CVE-2026-12345', 'GET'],
];

for (const [adapter, input, raw, env, host, path, method] of cases) {
  test(`${adapter.name} uses fixed read-only endpoint and keeps secrets out of evidence`, async () => {
    const { captured, data } = await invoke(adapter, input, raw, env);
    const u = new URL(captured.url);
    assert.equal(u.protocol, 'https:');
    assert.equal(u.hostname, host);
    assert.equal(u.pathname, path);
    assert.equal(captured.init.method, method);
    noSecret(data);
    for (const ref of data.references ?? []) noSecret(ref);
    assert.equal(/\/(scan|submit|download|analyse|analyze|takedown|file-collection)(\/|$)/i.test(u.pathname), false);
  });
}

test('credential headers are exact for representative adapters', async () => {
  const a = await invoke(abuseipdbProvider, { value: '8.8.8.8', type: 'ip' }, { data: {} }, { ABUSEIPDB_API_KEY: SECRET });
  assert.equal(a.captured.init.headers.Key, SECRET);
  const c = await invoke(censysProvider, { value: '8.8.8.8', type: 'ip' }, { result: {} }, { CENSYS_PAT: SECRET });
  assert.equal(c.captured.init.headers.Authorization, `Bearer ${SECRET}`);
  const w = await invoke(webamonProvider, { value: 'example.com', type: 'domain' }, { results: [] }, { WEBAMON_API_KEY: SECRET });
  assert.equal(w.captured.init.headers['x-api-key'], SECRET);
  const t = await invoke(threatfoxProvider, { value: 'example.com', type: 'domain' }, { query_status: 'no_result' }, { ABUSECH_API_KEY: SECRET });
  assert.equal(t.captured.init.headers['Auth-Key'], SECRET);
  const h = await invoke(hybridAnalysisProvider, { value: 'a'.repeat(64), type: 'hash' }, { sha256s: [], reports: [] }, { HYBRID_ANALYSIS_API_KEY: SECRET });
  assert.equal(h.captured.init.headers['api-key'], SECRET);
});

test('query-string credentials are never copied into references', async () => {
  for (const [adapter, input, raw, env] of [cases[0], cases[4], cases[12]]) {
    const { data } = await invoke(adapter, input, raw, env);
    assert.equal((data.references ?? []).some(ref => String(ref).includes(SECRET)), false);
  }
});

test('ThreatFox and MalwareBazaar only send read-only query bodies', async () => {
  const tf = await invoke(threatfoxProvider, { value: 'example.com', type: 'domain' }, { query_status: 'no_result' }, { ABUSECH_API_KEY: SECRET });
  assert.equal(JSON.parse(tf.captured.init.body).query, 'search_ioc');
  const mb = await invoke(malwarebazaarProvider, { value: 'a'.repeat(64), type: 'hash' }, { query_status: 'no_result' }, { ABUSECH_API_KEY: SECRET });
  assert.match(String(mb.captured.init.body), /(?:^|&)query=get_info(?:&|$)/);
  assert.doesNotMatch(String(mb.captured.init.body), /get_file|upload/i);
});

test('URLhaus only performs URL lookup and never submission', async () => {
  const out = await invoke(urlhausProvider, { value: 'https://example.com/a', type: 'url' }, { query_status: 'no_results' }, { ABUSECH_API_KEY: SECRET });
  assert.equal(out.captured.init.method, 'POST');
  assert.equal(new URL(out.captured.url).pathname, '/v1/url/');
  assert.match(String(out.captured.init.body), /^url=/);
});