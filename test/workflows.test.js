import test from 'node:test';
import assert from 'node:assert/strict';
import { rdapProvider } from '../src/providers/rdap.js';
import { epssProvider } from '../src/providers/epss.js';
import { cisaKevProvider } from '../src/providers/cisa-kev.js';
import { ALL_PROVIDERS } from '../src/providers/index.js';
import { rankProvidersForExecution } from '../src/core/provider-priority.js';
import { WORKFLOWS, WORKFLOW_BLUEPRINTS, WORKFLOW_CALL_LIMITS } from '../src/workflows.js';

const IP_WORKFLOW_BASELINE = Object.freeze(['ipinfo', 'rdap', 'ripestat', 'dshield', 'spamhaus-drop', 'tor-exit', 'feodo-tracker', 'threatminer', 'misp-circl-osint', 'misp-botvrij-osint', 'tweetfeed', 'ransomlook', 'greynoise', 'abuseipdb', 'shodan', 'censys', 'modat', 'cloudflare-radar', 'virustotal', 'otx', 'threatfox', 'urlscan', 'webamon', 'pulsedive']);
const IP_EXECUTION_ORDER_V1 = Object.freeze(['rdap', 'tor-exit', 'ripestat', 'ipinfo', 'cloudflare-radar', 'feodo-tracker', 'threatfox', 'spamhaus-drop', 'abuseipdb', 'webamon', 'greynoise', 'urlscan', 'shodan', 'censys', 'modat', 'virustotal', 'threatminer', 'pulsedive', 'otx', 'misp-circl-osint', 'tweetfeed', 'dshield', 'misp-botvrij-osint', 'ransomlook']);

function jsonFetch(expectedUrl, payload) {
  return async (url, options = {}) => {
    assert.equal(String(url), expectedUrl);
    assert.equal(options.method ?? 'GET', 'GET');
    return new Response(JSON.stringify(payload), { status: 200, headers: { 'content-type': 'application/json' } });
  };
}

test('RDAP adapter uses IANA bootstrap and an allowlisted RIR for bounded network identifiers', async () => {
  assert.deepEqual(rdapProvider.types, ['ip', 'asn', 'cidr']);
  const seen = [];
  const data = await rdapProvider.run({ value: '8.8.8.8', type: 'ip' }, {
    feedCache: new Map(),
    fetchImpl: async (url, options = {}) => {
      const u = String(url); seen.push(u);
      assert.equal(options.method ?? 'GET', 'GET');
      if (u === 'https://data.iana.org/rdap/ipv4.json') {
        return new Response(JSON.stringify({ services: [[['8.0.0.0/8'], ['https://rdap.arin.net/registry/']]] }), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      if (u === 'https://rdap.arin.net/registry/ip/8.8.8.8') {
        return new Response(JSON.stringify({ handle: 'NET-8-8-8-0-2', name: 'GOGL', country: 'US', startAddress: '8.8.8.0', endAddress: '8.8.8.255' }), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      throw new Error(`unexpected ${u}`);
    },
    signal: new AbortController().signal,
  });
  assert.equal(data.observationType, 'registration');
  assert.equal(data.attributes.handle, 'NET-8-8-8-0-2');
  assert.deepEqual(data.references, ['https://data.iana.org/rdap/ipv4.json', 'https://rdap.arin.net/registry/ip/8.8.8.8']);
  assert.deepEqual(seen, data.references);
});

test('EPSS adapter queries FIRST by CVE and preserves probability separately', async () => {
  const data = await epssProvider.run({ value: 'CVE-2026-12345', type: 'cve' }, {
    fetchImpl: jsonFetch('https://api.first.org/data/v1/epss?cve=CVE-2026-12345', { data: [{ cve: 'CVE-2026-12345', epss: '0.42', percentile: '0.91', date: '2026-08-20' }] }),
    signal: new AbortController().signal,
  });
  assert.equal(data.observationType, 'exploit_probability');
  assert.equal(data.attributes.epss, 0.42);
  assert.equal(data.attributes.percentile, 0.91);
});

test('CISA KEV adapter identifies catalog membership', async () => {
  const url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
  const data = await cisaKevProvider.run({ value: 'CVE-2026-12345', type: 'cve' }, {
    fetchImpl: jsonFetch(url, { vulnerabilities: [{ cveID: 'CVE-2026-12345', vendorProject: 'Vendor', product: 'Thing', vulnerabilityName: 'Thing RCE', dateAdded: '2026-08-20', dueDate: '2026-09-10', knownRansomwareCampaignUse: 'Known', requiredAction: 'Patch', notes: '', cwes: ['CWE-78'] }] }),
    signal: new AbortController().signal,
  });
  assert.equal(data.verdict, 'known_exploited');
  assert.equal(data.confidence, 100);
  assert.equal(data.attributes.product, 'Thing');
});

test('every active workflow provider has an implemented adapter', () => {
  const names = new Set(ALL_PROVIDERS.map(p => p.name));
  for (const [type, providers] of Object.entries(WORKFLOWS)) {
    assert.ok(providers.length > 0, `${type} workflow must not be empty`);
    for (const name of providers) assert.equal(names.has(name), true, `${name} missing adapter`);
  }
});

test('active workflows preserve MAX routing order', () => {
  assert.deepEqual(WORKFLOWS.ip, IP_WORKFLOW_BASELINE);
  assert.equal(JSON.stringify(WORKFLOWS.ip), JSON.stringify(IP_WORKFLOW_BASELINE), 'IP workflow bytes must remain unchanged');
  assert.deepEqual(WORKFLOWS.domain, ['threatminer', 'cloudflare-dns', 'openphish', 'misp-circl-osint', 'misp-botvrij-osint', 'tweetfeed', 'ransomlook', 'urlscan', 'webamon', 'modat', 'ransomware-live', 'virustotal', 'otx', 'threatfox', 'pulsedive']);
  assert.deepEqual(WORKFLOWS.url, ['openphish', 'threatminer', 'misp-circl-osint', 'misp-botvrij-osint', 'tweetfeed', 'ransomlook', 'urlscan', 'webamon', 'urlhaus', 'ransomware-live', 'virustotal', 'otx', 'threatfox', 'pulsedive']);
  assert.deepEqual(WORKFLOWS.hash, ['circl-hashlookup', 'threatminer', 'misp-circl-osint', 'misp-botvrij-osint', 'tweetfeed', 'ransomlook', 'malwarebazaar', 'malpedia', 'virustotal', 'hybrid-analysis', 'otx', 'threatfox']);
  assert.deepEqual(WORKFLOWS.cve, ['cisa-kev', 'cisa-adp', 'epss', 'circl-vulnerability', 'misp-circl-osint', 'misp-botvrij-osint', 'nvd', 'osv', 'otx']);
  assert.deepEqual(WORKFLOWS.attack, ['attack-taxii']);
  assert.deepEqual(WORKFLOWS.asn, ['rdap', 'ripestat', 'spamhaus-drop']);
  assert.deepEqual(WORKFLOWS.cidr, ['rdap', 'ripestat', 'spamhaus-drop']);
  assert.deepEqual(WORKFLOWS.certificate, ['censys', 'virustotal']);
  for (const [type, providers] of Object.entries(WORKFLOWS)) {
    assert.equal(WORKFLOW_CALL_LIMITS[type], providers.length * 2, `${type} workflow must reserve two bounded attempts per provider`);
  }
  assert.equal(WORKFLOW_CALL_LIMITS.ip, WORKFLOWS.ip.length * 2);
  assert.equal(WORKFLOW_BLUEPRINTS, WORKFLOWS);
});

test('IP scheduler policy v1 has an exact deterministic execution order over the unchanged workflow', () => {
  const registry = new Map(ALL_PROVIDERS.map(provider => [provider.name, provider]));
  const indexed = WORKFLOWS.ip.map((name, workflowIndex) => ({ ...registry.get(name), workflowIndex }));
  const ranked = rankProvidersForExecution({ providers: indexed, type: 'ip' }).map(item => item.adapter.name);
  assert.deepEqual(ranked, IP_EXECUTION_ORDER_V1);
});