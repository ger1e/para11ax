import test from 'node:test';
import assert from 'node:assert/strict';
import { ALL_PROVIDERS } from '../src/providers/index.js';
import { WORKFLOWS } from '../src/workflows.js';

function provider(name) {
  const item = ALL_PROVIDERS.find(p => p.name === name);
  assert.ok(item, `${name} provider must be registered`);
  return item;
}

function json(value, status = 200, headers = {}) {
  return new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json', ...headers } });
}

function text(value, status = 200, headers = {}) {
  return new Response(value, { status, headers: { 'content-type': 'text/plain', ...headers } });
}

function feedContext(fetchImpl, feedCache = new Map()) {
  return { fetchImpl, feedCache, signal: new AbortController().signal, nowMs: () => 1_787_248_000_000 };
}

test('all approved public intelligence providers are registered without credentials', () => {
  for (const name of ['threatminer', 'dshield', 'cisa-adp', 'circl-vulnerability', 'spamhaus-drop', 'tor-exit', 'openphish', 'feodo-tracker', 'misp-circl-osint', 'misp-botvrij-osint', 'attack-taxii', 'tweetfeed', 'ransomlook']) {
    const p = provider(name);
    assert.equal(p.requiredEnv, undefined, `${name} must not require a secret`);
    assert.equal(p.optionalEnv, undefined, `${name} must not require an optional secret`);
    assert.equal(p.costClass, 'free');
  }
});

test('ThreatMiner performs one fixed read-only pivot and preserves passive-DNS semantics', async () => {
  const p = provider('threatminer');
  let calls = 0;
  const data = await p.run({ value: '8.8.8.8', type: 'ip' }, {
    fetchImpl: async (url, init) => {
      calls += 1;
      assert.equal(String(url), 'https://api.threatminer.org/v2/host.php?q=8.8.8.8&rt=2');
      assert.equal(init.method, 'GET');
      return json({ status_code: '200', status_message: 'Results found.', results: [{ domain: 'dns.google', ip: '8.8.8.8', last_seen: '2026-08-20' }] });
    },
    signal: new AbortController().signal,
  });
  assert.equal(calls, 1);
  assert.equal(data.observationType, 'passive_dns');
  assert.equal(data.verdict, 'unknown');
  assert.ok(data.relationships.some(r => r.targetType === 'domain' && r.target === 'dns.google'));
  assert.equal(data.relationships.some(r => r.targetType === 'ip' && r.target === '8.8.8.8'), false);
});

test('ThreatMiner URL pivots use the host endpoint when the URL hostname is an IP', async () => {
  const p = provider('threatminer');
  await p.run({ value: 'https://192.0.2.44/a', type: 'url' }, {
    fetchImpl: async (url) => {
      assert.equal(String(url), 'https://api.threatminer.org/v2/host.php?q=192.0.2.44&rt=2');
      return json({ status_code: '404', results: [] });
    },
    signal: new AbortController().signal,
  });
});

test('DShield IP lookup is context, not an automatic malicious verdict', async () => {
  const p = provider('dshield');
  const data = await p.run({ value: '192.0.2.44', type: 'ip' }, {
    fetchImpl: async (url, init) => {
      assert.equal(String(url), 'https://isc.sans.edu/api/ip/192.0.2.44?json');
      assert.equal(init.method, 'GET');
      return json({ ip: { number: '192.0.2.44', attacks: '91', count: '12', maxdate: '2026-08-20', mindate: '2026-08-19', asname: 'EXAMPLE' } });
    },
    signal: new AbortController().signal,
  });
  assert.equal(data.observationType, 'scanner_activity');
  assert.equal(data.verdict, 'observed');
  assert.equal(data.attributes.attacks, 91);
  assert.equal(data.attributes.reports, 12);
});

test('Spamhaus DROP performs IPv4 CIDR membership and reuses a source-level feed cache', async () => {
  const p = provider('spamhaus-drop');
  const feedCache = new Map();
  let calls = 0;
  const fetchImpl = async (url, init) => {
    calls += 1;
    assert.equal(String(url), 'https://www.spamhaus.org/drop/drop_v4.json');
    assert.equal(init.method, 'GET');
    return text('{"cidr":"192.0.2.0/24","sblid":"SBL999999"}\n{"type":"metadata","timestamp":1787248000,"copyright":"Spamhaus"}\n');
  };
  const listed = await p.run({ value: '192.0.2.44', type: 'ip' }, feedContext(fetchImpl, feedCache));
  const notListed = await p.run({ value: '198.51.100.5', type: 'ip' }, feedContext(fetchImpl, feedCache));
  assert.equal(calls, 1);
  assert.equal(listed.observationType, 'drop_netblock');
  assert.equal(listed.verdict, 'listed');
  assert.equal(listed.attributes.cidr, '192.0.2.0/24');
  assert.equal(listed.attributes.feedTimestamp, 1787248000);
  assert.equal(notListed.verdict, 'not_listed');
});

test('Tor exit membership remains contextual and never becomes a malware verdict', async () => {
  const p = provider('tor-exit');
  const data = await p.run({ value: '192.0.2.44', type: 'ip' }, feedContext(async (url, init) => {
    assert.equal(String(url), 'https://check.torproject.org/torbulkexitlist');
    assert.equal(init.method, 'GET');
    return text('192.0.2.44\n198.51.100.9\n');
  }));
  assert.equal(data.observationType, 'tor_exit');
  assert.equal(data.verdict, 'observed');
  assert.equal(data.attributes.isTorExit, true);
});

test('Feodo Tracker is an exact IP match with botnet-C2 semantics', async () => {
  const p = provider('feodo-tracker');
  const data = await p.run({ value: '192.0.2.44', type: 'ip' }, feedContext(async (url) => {
    assert.equal(String(url), 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt');
    return text('# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (IPs only)\n# Last updated: 2026-08-20 00:00:00 UTC\n192.0.2.44\n# END 1 entries\n');
  }));
  assert.equal(data.observationType, 'botnet_c2');
  assert.equal(data.verdict, 'listed');
  assert.equal(data.attributes.feedUpdatedAt, '2026-08-20 00:00:00 UTC');
});

test('deprecated SSLBL IP/C2 feeds are intentionally excluded from the active gateway', () => {
  assert.equal(ALL_PROVIDERS.some(p => p.name === 'sslbl-c2'), false);
  assert.equal(Object.values(WORKFLOWS).flat().includes('sslbl-c2'), false);
});

test('OpenPhish pins the official raw community feed and caches it', async () => {
  const p = provider('openphish');
  const feedCache = new Map();
  let calls = 0;
  const fetchImpl = async (url) => {
    calls += 1;
    assert.equal(String(url), 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt');
    return text('https://login.example.test/verify\nhttps://other.test/a\n');
  };
  const u = await p.run({ value: 'https://login.example.test/verify', type: 'url' }, feedContext(fetchImpl, feedCache));
  const d = await p.run({ value: 'login.example.test', type: 'domain' }, feedContext(fetchImpl, feedCache));
  assert.equal(calls, 1);
  assert.equal(u.observationType, 'phishing_feed_match');
  assert.equal(u.verdict, 'phishing');
  assert.equal(d.verdict, 'phishing');
});

test('CIRCL Vulnerability-Lookup uses the public read endpoint and keeps aggregate metadata separate', async () => {
  const p = provider('circl-vulnerability');
  const data = await p.run({ value: 'CVE-2026-12345', type: 'cve' }, {
    fetchImpl: async (url, init) => {
      assert.equal(String(url), 'https://vulnerability.circl.lu/api/vulnerability/CVE-2026-12345');
      assert.equal(init.method, 'GET');
      return json({
        cveMetadata: { cveId: 'CVE-2026-12345', datePublished: '2026-08-01T00:00:00Z', dateUpdated: '2026-08-20T00:00:00Z', state: 'PUBLISHED' },
        containers: { cna: { title: 'Demo issue', references: [{ url: 'https://example.test/advisory' }] } },
        'vulnerability-lookup:meta': { epss: { epss: '0.42', percentile: '0.91' }, cisa_kev: { dateAdded: '2026-08-20' } },
      });
    },
    signal: new AbortController().signal,
  });
  assert.equal(data.observationType, 'vulnerability_catalog');
  assert.equal(data.verdict, 'cataloged');
  assert.equal(data.attributes.epss, 0.42);
  assert.equal(data.attributes.kev, true);
  assert.ok(data.references.includes('https://example.test/advisory'));
});

test('public feed response limits fail closed before parsing oversized content', async () => {
  const p = provider('openphish');
  await assert.rejects(
    () => p.run({ value: 'https://example.test/', type: 'url' }, feedContext(async () => text('x', 200, { 'content-length': '9000000' }))),
    error => error?.status === 502,
  );
});

test('malformed public feeds fail as provider errors instead of false-negative not-listed verdicts', async () => {
  const cases = [
    ['spamhaus-drop', { value: '192.0.2.44', type: 'ip' }],
    ['tor-exit', { value: '192.0.2.44', type: 'ip' }],
    ['feodo-tracker', { value: '192.0.2.44', type: 'ip' }],
    ['openphish', { value: 'https://example.test/', type: 'url' }],
  ];
  for (const [name, input] of cases) {
    await assert.rejects(() => provider(name).run(input, feedContext(async () => text('<html>upstream error</html>'))));
  }
});

test('MAX workflows place public sources by semantics before scarce enrichment', () => {
  assert.deepEqual(WORKFLOWS.ip, ['ipinfo', 'rdap', 'ripestat', 'dshield', 'spamhaus-drop', 'tor-exit', 'feodo-tracker', 'threatminer', 'misp-circl-osint', 'misp-botvrij-osint', 'tweetfeed', 'ransomlook', 'greynoise', 'abuseipdb', 'shodan', 'censys', 'modat', 'cloudflare-radar', 'virustotal', 'otx', 'threatfox', 'urlscan', 'webamon', 'pulsedive']);
  assert.deepEqual(WORKFLOWS.domain, ['threatminer', 'cloudflare-dns', 'openphish', 'misp-circl-osint', 'misp-botvrij-osint', 'tweetfeed', 'ransomlook', 'urlscan', 'webamon', 'modat', 'ransomware-live', 'virustotal', 'otx', 'threatfox', 'pulsedive']);
  assert.deepEqual(WORKFLOWS.url, ['openphish', 'threatminer', 'misp-circl-osint', 'misp-botvrij-osint', 'tweetfeed', 'ransomlook', 'urlscan', 'webamon', 'urlhaus', 'ransomware-live', 'virustotal', 'otx', 'threatfox', 'pulsedive']);
  assert.deepEqual(WORKFLOWS.hash, ['circl-hashlookup', 'threatminer', 'misp-circl-osint', 'misp-botvrij-osint', 'tweetfeed', 'ransomlook', 'malwarebazaar', 'malpedia', 'virustotal', 'hybrid-analysis', 'otx', 'threatfox']);
  assert.deepEqual(WORKFLOWS.cve, ['cisa-kev', 'cisa-adp', 'epss', 'circl-vulnerability', 'misp-circl-osint', 'misp-botvrij-osint', 'nvd', 'osv', 'otx']);
  assert.deepEqual(WORKFLOWS.attack, ['attack-taxii']);
});
