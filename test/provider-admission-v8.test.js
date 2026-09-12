import test from 'node:test';
import assert from 'node:assert/strict';
import { PROVIDER_MANIFEST } from '../src/providers/manifest.js';
import { ALL_PROVIDERS } from '../src/providers/index.js';
import { EXECUTION_POLICY_VERSION } from '../src/core/execution-policy.js';

const EXPECTED = Object.freeze({
  ipinfo: ['first_party', 'live'],
  rdap: ['authoritative', 'reference'],
  ripestat: ['first_party', 'near_real_time'],
  dshield: ['community', 'periodic'],
  'spamhaus-drop': ['first_party', 'periodic'],
  'tor-exit': ['first_party', 'periodic'],
  'feodo-tracker': ['first_party', 'near_real_time'],
  threatminer: ['aggregator', 'periodic'],
  'misp-circl-osint': ['community', 'periodic'],
  'misp-botvrij-osint': ['community', 'periodic'],
  greynoise: ['first_party', 'near_real_time'],
  abuseipdb: ['first_party', 'near_real_time'],
  shodan: ['first_party', 'near_real_time'],
  censys: ['first_party', 'near_real_time'],
  modat: ['first_party', 'near_real_time'],
  'cloudflare-radar': ['first_party', 'near_real_time'],
  'cloudflare-dns': ['first_party', 'live'],
  virustotal: ['aggregator', 'near_real_time'],
  otx: ['aggregator', 'near_real_time'],
  threatfox: ['first_party', 'near_real_time'],
  urlscan: ['first_party', 'near_real_time'],
  webamon: ['first_party', 'near_real_time'],
  pulsedive: ['aggregator', 'near_real_time'],
  openphish: ['first_party', 'periodic'],
  urlhaus: ['first_party', 'near_real_time'],
  'circl-hashlookup': ['first_party', 'periodic'],
  malwarebazaar: ['first_party', 'near_real_time'],
  malpedia: ['contextual', 'reference'],
  'hybrid-analysis': ['first_party', 'near_real_time'],
  'cisa-kev': ['authoritative', 'periodic'],
  'cisa-adp': ['authoritative', 'near_real_time'],
  epss: ['authoritative', 'periodic'],
  'circl-vulnerability': ['aggregator', 'periodic'],
  nvd: ['authoritative', 'periodic'],
  osv: ['aggregator', 'near_real_time'],
  'attack-taxii': ['authoritative', 'reference'],
  tweetfeed: ['community', 'near_real_time'],
  ransomlook: ['contextual', 'near_real_time'],
  'ransomware-live': ['contextual', 'near_real_time'],
});

test('all 39 canonical providers have the approved v8 source and execution admission semantics', () => {
  assert.equal(Object.keys(PROVIDER_MANIFEST).length, 39);
  assert.deepEqual(Object.keys(PROVIDER_MANIFEST).sort(), Object.keys(EXPECTED).sort());
  for (const [name, [sourceRole, freshnessClass]] of Object.entries(EXPECTED)) {
    const policy = PROVIDER_MANIFEST[name];
    assert.equal(policy.sourceRole, sourceRole, `${name}.sourceRole`);
    assert.equal(policy.freshnessClass, freshnessClass, `${name}.freshnessClass`);
    assert.equal(policy.admissionVersion, 'v8.1', `${name}.admissionVersion`);
    assert.equal(policy.executionPolicy, EXECUTION_POLICY_VERSION, `${name}.executionPolicy`);
  }
});

test('runtime adapters project exactly the canonical v8 admission metadata', () => {
  assert.equal(ALL_PROVIDERS.length, 39);
  for (const provider of ALL_PROVIDERS) {
    const policy = PROVIDER_MANIFEST[provider.name];
    assert.equal(provider.sourceRole, policy.sourceRole, `${provider.name}.sourceRole`);
    assert.equal(provider.freshnessClass, policy.freshnessClass, `${provider.name}.freshnessClass`);
    assert.equal(provider.admissionVersion, policy.admissionVersion, `${provider.name}.admissionVersion`);
    assert.equal(provider.executionPolicy, policy.executionPolicy, `${provider.name}.executionPolicy`);
  }
});
